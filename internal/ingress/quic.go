package ingress

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/internal/quicinitial"
	"github.com/nning/juist/ipc"
)

// Bounds of a QUIC flow at the ingress.
const (
	// flowIdle ends a flow quiet for that long either way: longer than the
	// idle timeout a terminator gives its QUIC connections.
	flowIdle = 2 * time.Minute

	// heldDatagrams bounds what waits for the rest of a ClientHello.
	heldDatagrams = 4

	// maxUnproven and maxUnprovenPerSource bound the flows whose client has
	// not proven its address, in all and from one host, which a spoofed
	// address may start: they hold no slot of the bounds TCP shares until
	// it has, end after twice helloTimeout unless, and past maxUnproven the
	// oldest gives way.
	maxUnproven          = 1024
	maxUnprovenPerSource = 16

	// Flows started a second, from one host and in all, each costing an
	// Initial's keys and decryption.
	newPerSource = 20
	newInAll     = 2000

	// maxServerIDs bounds the connection IDs a target is seen to give, and
	// maxConnections the connections of one client address a flow carries.
	maxServerIDs   = 4
	maxConnections = 8

	// maxDatagram is the largest datagram read: QUIC sends none past the
	// path's MTU.
	maxDatagram = 2048

	// minDCID is the shortest Destination Connection ID a client's first
	// Initial carries (RFC 9000, 7.2).
	minDCID = 8
)

// A flow is one client address's QUIC through the ingress, with a socket of
// its own toward the target, so that each flow's replies find their client.
// It carries each connection from that address to the same target: one
// socket of the client's may connect to several names, as quic-go's does.
type flow struct {
	from    netip.AddrPort // the client as received, to answer
	client  netip.AddrPort // and as logged
	started time.Time

	mu        sync.Mutex // what follows, to closed
	hello     quicinitial.Hello
	held      [][]byte
	dcids     [][]byte // the first Destination Connection ID of each connection
	serverIDs [][]byte // the Source Connection IDs the target's long headers give
	joining   *joining // another connection's hello, under way
	names     []string // the first the flow's
	t         ipc.PublishedTarget
	target    net.Conn
	header    []byte // a PROXY v2 header naming the client, sent until the client is proven
	live      int    // the connections the target has not said ended
	slotted   bool   // holding a slot of the bounds TCP shares
	closed    bool

	unproven   *list.Element // among the unproven flows, in unprovenIn; under quicFlows.mu
	unprovenIn *list.List
	proven     atomic.Bool
	up, down   atomic.Int64
	last       atomic.Int64 // unix nanoseconds
	outcome    atomic.Pointer[string]
}

// joining is the hello of another connection from a flow's address.
type joining struct {
	dcid    []byte
	hello   quicinitial.Hello
	held    [][]byte
	started time.Time
}

func (f *flow) setOutcome(s string) { f.outcome.Store(&s) }

// quicFlows passes QUIC on 443/udp by the name a client's Initial packets
// ask for, read with the Initial keys anyone may derive; the ingress
// decrypts nothing else.
type quicFlows struct {
	in *ingress
	pc *net.UDPConn

	mu        sync.Mutex
	flows     map[netip.AddrPort]*flow
	waiting   *list.List           // unproven flows of *flow without a target, the oldest first
	unproven  *list.List           // and with one
	bySource  map[netip.Prefix]int // unproven flows by host
	perSource map[netip.Prefix]*rate.Limiter
	inAll     *rate.Limiter
	saidAt    time.Time
	unsaid    int // lines of unproven flows not logged since saidAt
}

// serveQUIC passes what pc takes until it is closed.
func (in *ingress) serveQUIC(ctx context.Context, pc *net.UDPConn) {
	q := &quicFlows{in: in, pc: pc, flows: map[netip.AddrPort]*flow{}, waiting: list.New(), unproven: list.New(),
		bySource: map[netip.Prefix]int{}, perSource: map[netip.Prefix]*rate.Limiter{},
		inAll: rate.NewLimiter(newInAll, 2*newInAll)}
	in.quic.Store(q)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { q.janitor(stop) })
	defer func() {
		close(stop)
		wg.Wait()
		q.closeWhere(func(*flow) bool { return true })
	}()
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		q.handle(ctx, buf[:n], from)
	}
}

// handle takes one datagram: on to its flow's target, or toward the name
// its ClientHello asks for, which a flow waits for. A datagram that is no
// client's first Initial, or does not parse, keeps nothing. A connection
// from a flow's address joins it where its name goes to the same target,
// and is refused otherwise; before the flow has a target, it is dropped,
// which its client sends again.
func (q *quicFlows) handle(ctx context.Context, d []byte, from netip.AddrPort) {
	if proxyproto.IsHeader(d) {
		return // a client's would name another to the target
	}
	client := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	q.mu.Lock()
	f := q.flows[client]
	q.mu.Unlock()
	if f != nil && quicinitial.IsInitial(d) && f.joiningBy(d) {
		if packets, err := quicinitial.Parse(d); err == nil {
			q.join(f, d, packets)
		}
		return
	}
	if f == nil || quicinitial.IsInitial(d) && !f.sameConnection(d) {
		// An Initial of f's connection to another connection ID does not
		// parse: its keys are of the first one.
		packets, fresh := q.fresh(d, client)
		switch {
		case fresh == refused || fresh == notFresh && f == nil:
			return
		case fresh == isFresh && f == nil:
			q.start(ctx, d, from, client, packets)
			return
		case fresh == isFresh:
			// Before f has a target, the client sends it again.
			if f.spliced() {
				q.join(f, d, packets)
			}
			return
		}
	}
	f.last.Store(time.Now().UnixNano())
	f.mu.Lock()
	target := f.target
	f.mu.Unlock()
	if target != nil {
		f.up.Add(int64(len(d)))
		q.forward(f, d)
		return
	}
	var packets []quicinitial.Packet
	if quicinitial.IsInitial(d) {
		var err error
		if packets, err = quicinitial.Parse(d); err != nil {
			return
		}
	}
	q.wait(ctx, f, d, packets)
}

type freshness int

const (
	notFresh freshness = iota // of a connection under way, or none
	isFresh
	refused // past the rates, whatever it is
)

// fresh reads d where it is a client's first Initial of a connection,
// within the rates of flows started: its first packet's Destination
// Connection ID as long as a client's first is, and decrypting by the keys
// it gives. A shorter ID is one a server gave.
func (q *quicFlows) fresh(d []byte, client netip.AddrPort) ([]quicinitial.Packet, freshness) {
	if len(d) < quicinitial.MinDatagram || !quicinitial.IsInitial(d) {
		return nil, notFresh
	}
	if dcid, _, ok := quicinitial.ConnectionIDs(d); !ok || len(dcid) < minDCID {
		return nil, notFresh
	}
	q.mu.Lock()
	allowed := q.allowLocked(client.Addr())
	if !allowed {
		q.sayLocked(fmt.Sprintf("access: quic %v refused: too many new flows", client))
	}
	q.mu.Unlock()
	if !allowed {
		return nil, refused
	}
	packets, err := quicinitial.Parse(d)
	if err != nil {
		return nil, notFresh
	}
	return packets, isFresh
}

// start starts a flow for d, a client's first Initial, within the bounds on
// flows unproven: past the bound from its host it is refused, past the bound
// in all the oldest unproven flow gives way, one still without a target
// first.
func (q *quicFlows) start(ctx context.Context, d []byte, from, client netip.AddrPort, packets []quicinitial.Packet) {
	host := hostOf(client.Addr())
	var oldest *flow
	q.mu.Lock()
	if q.bySource[host] >= maxUnprovenPerSource {
		q.sayLocked(fmt.Sprintf("access: quic %v refused: too many unproven flows", client))
		q.mu.Unlock()
		return
	}
	switch {
	case q.waiting.Len()+q.unproven.Len() < q.in.o.maxUnproven:
	case q.waiting.Len() > 0:
		oldest = q.waiting.Front().Value.(*flow)
	default:
		oldest = q.unproven.Front().Value.(*flow)
	}
	q.mu.Unlock()
	if oldest != nil {
		oldest.setOutcome("ended for a newer unproven flow")
		q.close(oldest)
	}
	f := &flow{from: from, client: client, started: time.Now(), dcids: [][]byte{bytes.Clone(packets[0].DCID)}}
	f.last.Store(f.started.UnixNano())
	f.setOutcome("no hello")
	q.mu.Lock()
	if q.flows[client] != nil {
		q.mu.Unlock()
		return // another datagram started one meanwhile
	}
	q.flows[client] = f
	f.unproven, f.unprovenIn = q.waiting.PushBack(f), q.waiting
	q.bySource[host]++
	q.mu.Unlock()
	q.wait(ctx, f, d, packets)
}

// hostOf is the prefix of a host: an IPv4 address, or an IPv6 /64.
func hostOf(a netip.Addr) netip.Prefix {
	bits := 64
	if a.Is4() {
		bits = 32
	}
	host, _ := a.Prefix(bits)
	return host
}

// allowLocked reports whether a flow may start from a now, by the rates
// from one host and in all. q.mu is held.
func (q *quicFlows) allowLocked(a netip.Addr) bool {
	host := hostOf(a)
	l := q.perSource[host]
	if l == nil {
		if len(q.perSource) >= 4*q.in.o.maxUnproven {
			return q.inAll.Allow() // past the bound, the rate in all alone
		}
		l = rate.NewLimiter(newPerSource, 2*newPerSource)
		q.perSource[host] = l
	}
	return l.Allow() && q.inAll.Allow()
}

// sayLocked logs a line of a flow whose client is unproven, one a second at
// most, saying how many went unsaid: a spoofed address may start any number.
// q.mu is held.
func (q *quicFlows) sayLocked(line string) {
	if time.Since(q.saidAt) < time.Second {
		q.unsaid++
		return
	}
	if q.unsaid > 0 {
		line += fmt.Sprintf(", and %d more unsaid", q.unsaid)
	}
	q.in.o.Access("%s", line)
	q.saidAt, q.unsaid = time.Now(), 0
}

// say logs a line as sayLocked does.
func (q *quicFlows) say(line string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sayLocked(line)
}

// sameConnection reports whether d, an Initial, is of a connection f
// carries: to a client's first connection ID, or one the target gave, as
// after a Retry.
func (f *flow) sameConnection(d []byte) bool {
	dcid, _, ok := quicinitial.ConnectionIDs(d)
	f.mu.Lock()
	defer f.mu.Unlock()
	is := func(id []byte) bool { return bytes.Equal(id, dcid) }
	return ok && (slices.ContainsFunc(f.dcids, is) || slices.ContainsFunc(f.serverIDs, is))
}

// joiningBy reports whether d, an Initial, is of the connection whose hello
// f holds.
func (f *flow) joiningBy(d []byte) bool {
	dcid, _, ok := quicinitial.ConnectionIDs(d)
	f.mu.Lock()
	defer f.mu.Unlock()
	return ok && f.joining != nil && bytes.Equal(f.joining.dcid, dcid)
}

// spliced reports whether f goes to a target.
func (f *flow) spliced() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.target != nil
}

// join holds d, an Initial of another connection from f's address, until
// its hello is whole: where its name goes to f's target, the connection is
// f's too, and it is refused otherwise.
func (q *quicFlows) join(f *flow, d []byte, packets []quicinitial.Packet) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	j := f.joining
	if j == nil || !bytes.Equal(j.dcid, packets[0].DCID) {
		if j != nil {
			j.hello.Close()
		}
		j = &joining{dcid: bytes.Clone(packets[0].DCID), started: time.Now()}
		f.joining = j
	}
	if len(j.held) >= heldDatagrams {
		f.mu.Unlock()
		return
	}
	j.held = append(j.held, append([]byte(nil), d...))
	name, done, err := j.hello.Add(packets)
	if err != nil || !done {
		if err != nil {
			j.hello.Close()
			f.joining = nil
		}
		f.mu.Unlock()
		return
	}
	j.hello.Close()
	f.joining = nil
	t, served := q.in.lookupPublished(name)
	same := served && t.Port == f.t.Port && slices.Equal(t.Addrs, f.t.Addrs)
	joined := same && f.live < maxConnections
	if joined {
		if len(f.dcids) >= 2*maxConnections {
			f.dcids = slices.Delete(f.dcids, 0, 1)
		}
		f.dcids = append(f.dcids, j.dcid)
		if !slices.Contains(f.names, t.Name) {
			f.names = append(f.names, t.Name)
		}
		f.live++
	}
	f.mu.Unlock()
	switch {
	case !served:
		q.say(fmt.Sprintf("access: quic %v %q not served", f.client, name))
	case !same:
		q.say(fmt.Sprintf("access: quic %v %q refused: another name's flow from its address", f.client, t.Name))
	case !joined:
		q.say(fmt.Sprintf("access: quic %v %q refused: too many connections from its address", f.client, t.Name))
	default:
		// Named again: the terminator may have let go of what it was told.
		f.mu.Lock()
		target, header := f.target, f.header
		f.mu.Unlock()
		_, _ = target.Write(header)
		for _, d := range j.held {
			f.up.Add(int64(len(d)))
			q.forward(f, d)
		}
	}
}

// prove has f, its client proven, hold a slot of the bounds TCP shares
// instead of one of the unproven flows'; past those bounds it ends.
func (q *quicFlows) prove(f *flow) {
	f.proven.Store(true)
	q.doneUnproven(f)
	select {
	case q.in.conns <- struct{}{}:
	default:
		f.setOutcome("refused: too many connections")
		q.close(f)
		return
	}
	if !q.in.sources.Take(f.client.Addr()) {
		<-q.in.conns
		f.setOutcome("refused: too many connections from it")
		q.close(f)
		return
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		<-q.in.conns
		q.in.sources.Done(f.client.Addr())
		return
	}
	f.slotted = true
	f.mu.Unlock()
}

// doneUnproven takes f off the unproven flows, once.
func (q *quicFlows) doneUnproven(f *flow) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if f.unproven == nil {
		return
	}
	f.unprovenIn.Remove(f.unproven)
	f.unproven, f.unprovenIn = nil, nil
	host := hostOf(f.client.Addr())
	if q.bySource[host]--; q.bySource[host] <= 0 {
		delete(q.bySource, host)
	}
}

// wait holds d until f's ClientHello is whole, packets being its Initial
// packets, then passes f on to the name it asks for.
func (q *quicFlows) wait(ctx context.Context, f *flow, d []byte, packets []quicinitial.Packet) {
	f.mu.Lock()
	if f.closed || f.target != nil {
		f.mu.Unlock()
		return
	}
	if len(f.held) >= heldDatagrams {
		f.mu.Unlock()
		q.close(f)
		return
	}
	f.held = append(f.held, append([]byte(nil), d...))
	f.up.Store(sumLen(f.held))
	name, done, err := f.hello.Add(packets)
	if err != nil || !done {
		f.mu.Unlock()
		if err != nil {
			q.close(f)
		}
		return
	}
	f.hello.Close()
	f.names = []string{name}
	t, ok := q.in.lookupPublished(name)
	if !ok {
		f.mu.Unlock()
		f.setOutcome("not served")
		q.close(f)
		return
	}
	target, err := q.dial(ctx, t)
	if err != nil {
		f.mu.Unlock()
		f.setOutcome("target unreachable")
		q.close(f)
		return
	}
	f.names, f.t, f.target, f.live = []string{t.Name}, t, target, 1
	// To the port alone: the address the client reached is the wildcard
	// socket's. Sent whatever the name asks: the terminator names the
	// client back as it says what became of its connections.
	to := netip.AddrPortFrom(netip.IPv6Unspecified(), 443)
	if f.client.Addr().Is4() {
		to = netip.AddrPortFrom(netip.IPv4Unspecified(), 443)
	}
	f.header = proxyproto.HeaderUDP(f.client, to)
	held := f.held
	f.held = nil
	f.mu.Unlock()
	f.setOutcome("spliced")
	q.mu.Lock()
	if f.unprovenIn == q.waiting {
		q.waiting.Remove(f.unproven)
		f.unproven, f.unprovenIn = q.unproven.PushBack(f), q.unproven
	}
	q.mu.Unlock()
	for _, d := range held {
		q.forward(f, d)
	}
	go q.answer(f, target)
}

func sumLen(ds [][]byte) int64 {
	var n int64
	for _, d := range ds {
		n += int64(len(d))
	}
	return n
}

// forward sends d on to f's target, after the header naming the client
// while the client is unproven: a header lost is sent again.
func (q *quicFlows) forward(f *flow, d []byte) {
	f.mu.Lock()
	target, header := f.target, f.header
	f.mu.Unlock()
	if target == nil {
		return
	}
	if header != nil && !f.proven.Load() {
		_, _ = target.Write(header)
	}
	_, _ = target.Write(d)
}

// answer passes what f's target sends back to its client: no more than
// three times what the client sent until the target says by a LOCAL header
// naming the client that it proved its address (RFC 9000, 8.1), and until
// it says so of each of f's connections that it ended. It notes the
// connection IDs the target's long headers give, as a Retry's.
func (q *quicFlows) answer(f *flow, target net.Conn) {
	defer q.close(f)
	buf := make([]byte, maxDatagram)
	for {
		n, err := target.Read(buf)
		if err != nil {
			if f.down.Load() == 0 {
				f.setOutcome("target unreachable")
			}
			return
		}
		if proxyproto.IsHeader(buf[:n]) {
			// One naming another client is of a flow this socket was before.
			client, done, ok := proxyproto.ReadLocalUDP(buf[:n])
			switch {
			case !ok || client != f.client:
			case done:
				f.mu.Lock()
				f.live--
				ended := f.live <= 0
				f.mu.Unlock()
				if ended {
					return
				}
			case !f.proven.Load():
				q.prove(f)
			}
			continue
		}
		if ids := quicinitial.SourceIDs(buf[:n]); len(ids) > 0 {
			f.mu.Lock()
			for _, scid := range ids {
				if len(scid) > 0 && len(f.serverIDs) < maxServerIDs && !slices.ContainsFunc(f.serverIDs,
					func(id []byte) bool { return bytes.Equal(id, scid) }) {
					f.serverIDs = append(f.serverIDs, bytes.Clone(scid))
				}
			}
			f.mu.Unlock()
		}
		if !f.proven.Load() && f.down.Load()+int64(n) > 3*f.up.Load() {
			continue
		}
		f.last.Store(time.Now().UnixNano())
		if _, err := q.pc.WriteToUDPAddrPort(buf[:n], f.from); err == nil {
			f.down.Add(int64(n))
		}
	}
}

// dial opens a socket toward t, IPv4 first: a client's Initials take 1200
// bytes and more, which the tunnel's MTU of 1280 carries over IPv4 whole.
func (q *quicFlows) dial(ctx context.Context, t ipc.PublishedTarget) (net.Conn, error) {
	addrs := append([]netip.Addr(nil), t.Addrs...)
	for i, a := range addrs {
		if a.Is4() {
			addrs[0], addrs[i] = addrs[i], addrs[0]
			break
		}
	}
	err := errors.New("ingress: the target has no address")
	for _, a := range addrs {
		var c net.Conn
		if c, err = q.in.o.DialUDP(ctx, netip.AddrPortFrom(a, t.Port)); err == nil {
			return c, nil
		}
	}
	return nil, err
}

// close ends f once, gives back what it holds and logs it, at most once a
// second where its client is unproven.
func (q *quicFlows) close(f *flow) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	target, slotted := f.target, f.slotted
	name := ""
	if len(f.names) > 0 {
		name = f.names[0]
	}
	f.hello.Close()
	if f.joining != nil {
		f.joining.hello.Close()
		f.joining = nil
	}
	f.held = nil
	f.mu.Unlock()
	q.doneUnproven(f)
	line := fmt.Sprintf("access: quic %v %q %s up=%d down=%d %v", f.client, name, *f.outcome.Load(), f.up.Load(),
		f.down.Load(), time.Since(f.started).Round(time.Millisecond))
	q.mu.Lock()
	if q.flows[f.client] == f {
		delete(q.flows, f.client)
	}
	if !f.proven.Load() {
		q.sayLocked(line)
		line = ""
	}
	q.mu.Unlock()
	if target != nil {
		target.Close()
	}
	if slotted {
		<-q.in.conns
		q.in.sources.Done(f.client.Addr())
	}
	if line != "" {
		q.in.o.Access("%s", line)
	}
}

// janitor ends the flows gone quiet, and those whose client has not proven
// itself in time, until stop; and forgets the hellos of joining connections
// and the rates no longer kept.
func (q *quicFlows) janitor(stop chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		now := time.Now()
		q.closeWhere(func(f *flow) bool {
			if j := f.joining; j != nil && now.Sub(j.started) > q.in.o.helloTimeout {
				j.hello.Close()
				f.joining = nil
			}
			switch {
			case f.target == nil:
				return now.Sub(f.started) > q.in.o.helloTimeout
			case !f.proven.Load():
				// The target's handshake timeout is one of idleness.
				if now.Sub(f.started) > 2*q.in.o.helloTimeout {
					f.setOutcome("not proven")
					return true
				}
				return false
			}
			return now.Sub(time.Unix(0, f.last.Load())) > q.in.o.flowIdle
		})
		q.mu.Lock()
		for host, l := range q.perSource {
			if l.Tokens() >= 2*newPerSource {
				delete(q.perSource, host)
			}
		}
		q.mu.Unlock()
	}
}

// closeUnless ends the flows passed for a name served no longer.
func (q *quicFlows) closeUnless(served func(name string) bool) {
	q.closeWhere(func(f *flow) bool {
		return f.target != nil && slices.ContainsFunc(f.names, func(n string) bool { return !served(n) })
	})
}

// closeWhere ends the flows end says, which it is asked of under the
// flow's lock.
func (q *quicFlows) closeWhere(end func(*flow) bool) {
	var done []*flow
	q.mu.Lock()
	for _, f := range q.flows {
		f.mu.Lock()
		if end(f) {
			done = append(done, f)
		}
		f.mu.Unlock()
	}
	q.mu.Unlock()
	for _, f := range done {
		q.close(f)
	}
}
