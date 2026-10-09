// Package host is the inviting device's half of an enrollment: listen for the
// guest on TCP, answer for the code on the LAN, meet through the public DHT
// where the link's addresses do not reach, and run one guest's session at a
// time. It holds no admin key. What is signed — the admission, and the
// admin's statement of it that a guest checks — is asked of an [Admitter],
// which is where the keys are: the CLI, which rebuilds and checks everything
// it signs against its own verified log. The daemon runs this package; the
// CLI runs it itself only on a state directory no daemon owns.
package host

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/admit"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// DefaultPort is the TCP port an invite listens on unless told otherwise:
// fixed, so a firewall can be opened for it once.
const DefaultPort = 41642

// Bounds on the host's side of an enrollment. Sessions run one at a time, so
// that an invite is never guessed at twice at once; what a connection may
// cost before it has shown anything is kept short, so one that says nothing
// cannot hold that one session while the real guest waits.
const (
	// helloTimeout bounds how long a connection may take to say hello. A
	// guest sends it at once, and it is read concurrently, before the
	// connection is queued for the session.
	helloTimeout = 5 * time.Second

	// confirmTimeout bounds the key exchange once a session has begun: the
	// host's reply and the guest's confirmation, which also follows at once.
	confirmTimeout = 5 * time.Second

	// joinedTimeout bounds how long an admitted guest may take to say it
	// stored the log.
	joinedTimeout = time.Minute

	// maxGreeting and maxGreetingPerSource bound connections still to say
	// hello, and maxQueued and maxQueuedPerSource those waiting for the
	// session: one source cannot fill the queue with hellos it then leaves
	// unconfirmed.
	maxGreeting          = 64
	maxGreetingPerSource = 4
	maxQueued            = 8
	maxQueuedPerSource   = 1

	// failedEvery is how often a failed connection is reported at most; a
	// flood of them would scroll the code off the screen.
	failedEvery = 5 * time.Second

	// waitingInterval is how often a guest waiting for approval hears that
	// it still is; the guest gives up after a minute of silence.
	waitingInterval = 15 * time.Second
)

// Errors [Host.Serve] ends with.
var (
	ErrExpired   = errors.New("the invite expired before a device joined")
	ErrCancelled = errors.New("the invite was cancelled")
)

// Options configures an invite.
type Options struct {
	// Port is the TCP port to listen on. DefaultPort gives way to one the OS
	// picks when another program holds it; any other is held to.
	Port uint16

	// LAN answers for the code's nameplate over mDNS, on every interface but
	// SkipInterface.
	LAN           bool
	SkipInterface string

	// Helpers are the public services to meet a guest through where the
	// link's addresses do not reach; nil meets through none.
	Helpers *rendezvous.Helpers

	// Addrs lists where a guest can reach this device at port; nil scans
	// the interfaces, leaving out Exclude.
	Addrs   func(port uint16) []netip.AddrPort
	Exclude []netip.Prefix

	// Relays are member relays to wait at for a guest that cannot reach this
	// device, as Identity, which the relay checks is a member. The link names
	// them.
	Relays   []forward.Relay
	Identity types.PrivateIdentity

	// HTTPSOnly waits at the relays' public names on 443 alone, through
	// Proxy, as a device that reaches nothing else does.
	HTTPSOnly bool
	Proxy     forward.Proxy
}

// An Admitter admits a guest into the network. It is the side holding admin
// keys, and the less trusted host asks it for everything that is signed.
type Admitter interface {
	// Admit decides a guest's admission and returns the name it was
	// admitted under and the admin's admission statement. It may hand the
	// guest a salt through compare, once, for the words a person checks on
	// both screens, and gets back the nonce the guest committed to in req
	// (checked against the commitment here, and to be checked again by
	// whoever does not trust this side). It may keep the guest waiting
	// through wait while other admins approve. The guest hears that it is
	// still waiting in between anyway.
	Admit(ctx context.Context, req *enroll.JoinRequest, wait func(votes, quorum uint32) error,
		compare func(enroll.Salt) (enroll.Nonce, error)) (name string, admission *enroll.Admission, err error)
}

// A Chain supplies what the guest is sent once admitted: the log, anchor
// first, and the hints for finding the members.
type Chain func() (records []types.AUM, endpoints, leases [][]byte, err error)

// An EventKind is something the person waiting on an invite should hear.
type EventKind uint8

const (
	// Failed: a connection ended before its guest proved anything; the
	// invite stays open.
	Failed EventKind = 2
	// Joined: the guest verified and stored the log. Addr is where it
	// connected from, and Announcement its signed endpoint record if it sent
	// one, unverified.
	Joined EventKind = 3
	// NoLAN and NoDHT: the code cannot be found on the LAN, or the link
	// cannot meet through the DHT, for the reason in Err.
	NoLAN EventKind = 4
	NoDHT EventKind = 5
	// CodeVoided: someone spent the typed code's one guess, from Addr. The
	// link still works.
	CodeVoided EventKind = 6
	// NoRelay: the invite cannot wait at the relay at Addr, for the reason
	// in Err. It keeps trying.
	NoRelay EventKind = 7
)

// An Event reports progress.
type Event struct {
	Kind         EventKind
	Name         string
	Identity     types.Identity
	Addr         string
	Err          string
	Announcement []byte
}

// A Host is an invite being offered.
type Host struct {
	o    Options
	ln   net.Listener
	port uint16
	inv  *enroll.Invite
}

// Listen opens the invite's TCP port and draws the invite, whose link names
// the addresses a guest can reach it at.
func Listen(o Options) (*Host, error) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(o.Port)))
	if err != nil && o.Port == DefaultPort && errors.Is(err, syscall.EADDRINUSE) {
		ln, err = net.Listen("tcp", ":0")
	}
	if err != nil {
		return nil, fmt.Errorf("listening for the invite: %w", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	addrs := o.Addrs
	if addrs == nil {
		addrs = func(port uint16) []netip.AddrPort { return Addrs(port, o.Exclude) }
	}
	inv, err := enroll.NewInvite(addrs(port))
	if err != nil {
		ln.Close()
		return nil, err
	}
	if o.HTTPSOnly {
		o.Relays = slices.DeleteFunc(slices.Clone(o.Relays), func(r forward.Relay) bool { return r.Name == "" })
	}
	inv.WaitAt(relayAddrs(o.Relays), relayNames(o.Relays))
	return &Host{o: o, ln: ln, port: port, inv: inv}, nil
}

// relayNames are the relays' public names, within what a link holds.
func relayNames(relays []forward.Relay) []string {
	var out []string
	for _, r := range relays {
		if r.Name != "" && len(out) < enroll.MaxLinkNamed {
			out = append(out, r.Name)
		}
	}
	return out
}

// relayAddrs is where the link sends a guest to the relays: each relay's
// public addresses before its private ones, and every relay before the
// second address of any, within what a link holds.
func relayAddrs(relays []forward.Relay) []netip.AddrPort {
	var out []netip.AddrPort
	for round := 0; len(out) < enroll.MaxLinkRelays; round++ {
		added := false
		for _, r := range relays {
			addrs := slices.Clone(r.Addrs)
			slices.SortStableFunc(addrs, func(a, b netip.AddrPort) int {
				return cmp.Compare(rank(a.Addr()), rank(b.Addr()))
			})
			if round < len(addrs) && len(out) < enroll.MaxLinkRelays {
				out = append(out, addrs[round])
				added = true
			}
		}
		if !added {
			break
		}
	}
	return out
}

// rank orders addresses by how far away a guest can reach them from.
func rank(a netip.Addr) int {
	switch {
	case a.IsLoopback():
		return 3
	case a.IsPrivate() || a.IsLinkLocalUnicast():
		return 2
	default:
		return 1
	}
}

// waitAtRelay keeps one connection waiting at r for as long as the invite is
// open, and greets each guest the relay joins to it as a meeting: the relay's
// word for the guest's address is what the bounds per source count.
func (h *Host) waitAtRelay(ctx context.Context, r forward.Relay, g *greeter, emit func(Event)) {
	pub := h.o.Identity.Public()
	sign := func(msg []byte) ([]byte, error) {
		sig, err := h.o.Identity.Sign(msg)
		return sig[:], err
	}
	id := h.inv.Link().ForwardID()
	// All of a relay's guests are one source to the bounds: the address it
	// reports is its word, and a relay that lied about it could fill every
	// slot. One of its connections is greeted at a time.
	src := source{relay: hex.EncodeToString(r.CertHash[:8])}
	backoff, reported := time.Second, false
	// By name where it is all the relay announces, or where the relay's own
	// port fails this device: the guest may come either way.
	named := h.o.HTTPSOnly || len(r.Addrs) == 0
	pause := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
		return true
	}
	for ctx.Err() == nil {
		var c net.Conn
		var err error
		if named {
			c, _, err = forward.WaitNamed(ctx, r, id, pub, sign, h.o.Proxy)
		} else {
			c, _, err = forward.Wait(ctx, r, id, pub, sign)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if r.Name != "" && len(r.Addrs) > 0 && !h.o.HTTPSOnly {
				named = !named
			}
			if !reported {
				at := r.Name
				if len(r.Addrs) > 0 && !h.o.HTTPSOnly {
					at = r.Addrs[0].String()
				}
				emit(Event{Kind: NoRelay, Addr: at, Err: err.Error()})
				reported = true
			}
			if !pause() {
				return
			}
			continue
		}
		t, ok := g.enter(c, src)
		if !ok {
			c.Close()
			if !pause() {
				return
			}
			continue
		}
		if g.hello(c, src, t, true) {
			backoff = time.Second
		} else if !pause() {
			// A guest that joined and said nothing, or a relay joining
			// nobody: either way, not straight back.
			return
		}
	}
}

// Port is the TCP port the invite listens on.
func (h *Host) Port() uint16 { return h.port }

// Invite is the invite being offered.
func (h *Host) Invite() *enroll.Invite { return h.inv }

// Close stops listening. [Host.Serve] closes it too.
func (h *Host) Close() error { return h.ln.Close() }

// Serve offers the invite until a guest joins, the invite is voided, or ctx
// ends — its deadline is the invite's expiry. events is called from one
// goroutine at a time, and not after Serve returns.
func (h *Host) Serve(ctx context.Context, admit Admitter, chain Chain, events func(Event)) error {
	defer h.ln.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var evMu sync.Mutex
	ended := false
	emit := func(e Event) {
		evMu.Lock()
		defer evMu.Unlock()
		if !ended && events != nil {
			events(e)
		}
	}
	defer func() {
		evMu.Lock()
		ended = true
		evMu.Unlock()
	}()

	if h.o.LAN {
		r, err := mdns.AnswerInvite(h.inv.Code().Nameplate, h.port, mdns.InviteOptions{SkipInterface: h.o.SkipInterface})
		if err != nil {
			emit(Event{Kind: NoLAN, Err: err.Error()})
		} else {
			defer r.Close()
		}
	}
	g := newGreeter(ctx, h.o.LAN)
	defer g.drain()
	failed := make(chan error, 2)
	if hp := h.o.Helpers; hp != nil {
		// Joining the DHT takes a few seconds, which the TCP listener does
		// not wait for.
		go func() {
			rl, err := rendezvous.Listen(ctx, hp.Options(h.inv.Link(), nil))
			if err != nil {
				emit(Event{Kind: NoDHT, Err: err.Error()})
				return
			}
			context.AfterFunc(ctx, func() { rl.Close() })
			acceptInto(ctx, rl, func(c net.Conn) { g.greet(c, sourceOf(c.RemoteAddr()), true) }, failed)
		}()
	}
	context.AfterFunc(ctx, func() { h.ln.Close() })
	go acceptInto(ctx, h.ln, func(c net.Conn) { g.greet(c, sourceOf(c.RemoteAddr()), false) }, failed)
	// Only at the relays the link names: the others would learn the
	// invite's forward id and carry no guest.
	link := h.inv.Link()
	for _, r := range h.o.Relays {
		if slices.ContainsFunc(r.Addrs, func(a netip.AddrPort) bool { return slices.Contains(link.Relays, a) }) ||
			r.Name != "" && slices.Contains(link.Named, r.Name) {
			go h.waitAtRelay(ctx, r, g, emit)
		}
	}

	var lastFailed time.Time
	unreported := 0
	endReason := func() error {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ErrExpired
		}
		return ErrCancelled
	}
	for {
		var q greeted
		select {
		case q = <-g.queue:
		case err := <-failed:
			return err
		case <-ctx.Done():
			return endReason()
		}
		q.queued.Release()
		codeOpen := h.inv.CodeOpen()
		done, err := h.session(ctx, q, admit, chain, emit)
		q.conn.Close()
		switch {
		case done && err == nil:
			return nil
		case ctx.Err() != nil:
			return endReason()
		case done:
			return err
		case codeOpen && h.inv.Open() && !h.inv.CodeOpen():
			// A wrong guess, or too many hellos for other numbers: either way
			// the admin hears that the code is gone and the link is not.
			ev := Event{Kind: CodeVoided, Addr: q.src.String()}
			if !errors.Is(err, enroll.ErrWrongCode) {
				ev.Err = "too many connections asked for other invite numbers"
			}
			emit(ev)
		case !h.inv.Open():
			return fmt.Errorf("a device proved it knows the invite, but the connection failed before it "+
				"could join: %w", err)
		case err != nil:
			if time.Since(lastFailed) < failedEvery {
				unreported++
				continue
			}
			msg := err.Error()
			if unreported > 0 {
				msg += fmt.Sprintf(" (and %d more connections since)", unreported)
			}
			lastFailed, unreported = time.Now(), 0
			emit(Event{Kind: Failed, Addr: q.conn.RemoteAddr().String(), Err: msg})
		}
	}
}

// A greeted connection has said hello and waits for the session.
type greeted struct {
	conn   net.Conn
	hello  *enroll.Hello
	src    source
	queued *admit.Ticket[source]
}

// A greeter reads hellos concurrently, bounded overall and per source, and
// queues the connections that sent one.
type greeter struct {
	ctx      context.Context
	queue    chan greeted
	lan      bool
	greeting *admit.Set[source]
	queued   *admit.Set[source]
}

func newGreeter(ctx context.Context, lan bool) *greeter {
	return &greeter{ctx: ctx, queue: make(chan greeted, maxQueued), lan: lan,
		greeting: admit.New[source](admit.Limits{PerSource: maxGreetingPerSource,
			Total: maxGreeting, OnTotal: admit.EvictOldest}),
		queued: admit.New[source](admit.Limits{PerSource: maxQueuedPerSource})}
}

// drain closes the connections still queued when the invite ends, rather
// than leaving their guests to time out.
func (g *greeter) drain() {
	for {
		select {
		case q := <-g.queue:
			q.queued.Release()
			q.conn.Close()
		default:
			return
		}
	}
}

// greet reads a connection's hello, from src, and queues it; see hello.
func (g *greeter) greet(c net.Conn, src source, met bool) {
	t, ok := g.enter(c, src)
	if !ok {
		c.Close()
		return
	}
	go g.hello(c, src, t, met)
}

// enter takes a greeting place for c, without blocking. Where every place is
// taken, the connection that has said nothing for longest gives its place up:
// a guest says hello at once, so what fills them is connections that never
// do.
func (g *greeter) enter(c net.Conn, src source) (*admit.Ticket[source], bool) {
	return g.greeting.Admit(src, func() { c.Close() })
}

// hello reads c's hello, then gives up its greeting place, and queues it,
// reporting whether it did. The typed code is a LAN secret: a hello for it is
// not queued from a meeting through the DHT or a relay (met), which a guest
// using the code never makes, nor from off the link, nor when the invite does
// not answer for the code on the LAN.
func (g *greeter) hello(c net.Conn, src source, greeting *admit.Ticket[source], met bool) bool {
	stop := context.AfterFunc(g.ctx, func() { c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	hello, err := enroll.ReadHello(c)
	greeting.Release()
	stop()
	if err != nil || g.ctx.Err() != nil || hello.Code() && (met || !g.lan || !fromTheLink(c)) {
		c.Close()
		return false
	}
	_ = c.SetReadDeadline(time.Time{})
	queued, ok := g.queued.Admit(src, nil)
	if !ok {
		c.Close()
		return false
	}
	select {
	case g.queue <- greeted{conn: c, hello: hello, src: src, queued: queued}:
		if g.ctx.Err() != nil {
			g.drain() // the invite ended as this was queued
		}
		return true
	default:
		// The queue is full; the guest's join fails, and can be run again.
		queued.Release()
		c.Close()
		return false
	}
}

// A source is what the bounds per source count a connection under: its
// address, or for IPv6 its /64, which one host holds entire; or the relay
// that joined it, whose word for the guest's address is all there is.
type source struct {
	addr  netip.Addr
	relay string
}

func sourceOf(a net.Addr) source {
	addr := admit.Source(a)
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		addr = p.Addr()
	}
	return source{addr: addr}
}

func (s source) String() string {
	switch {
	case s.relay != "":
		return "relay " + s.relay
	case s.addr.Is6():
		return netip.PrefixFrom(s.addr, 64).String()
	}
	return s.addr.String()
}

// fromTheLink reports whether a connection comes from this host's own
// subnets: the typed code is a LAN secret, and its nameplate a LAN number,
// so a hello for it from anywhere else is not a guest's.
func fromTheLink(c net.Conn) bool {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	return err == nil && mdns.OnLink(ap.Addr().Unmap())
}

// acceptInto hands ln's connections to greet until ctx ends or ln fails for
// good. A temporary failure — out of file descriptors, say — is waited out
// rather than ending the invite.
func acceptInto(ctx context.Context, ln net.Listener, greet func(net.Conn), failed chan<- error) {
	backoff := 50 * time.Millisecond
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				if ctx.Err() == nil {
					failed <- err
				}
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 50 * time.Millisecond
		greet(conn)
	}
}

// session runs one guest's enrollment. done reports that the invite has been
// used up, successfully or not; a session that failed before the guest proved
// it knows the invite leaves the invite open for the next one.
func (h *Host) session(ctx context.Context, q greeted, admit Admitter, chain Chain, events func(Event)) (done bool, err error) {
	conn := q.conn
	// Registered first, so that the invite ending interrupts the key
	// exchange too.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(confirmTimeout))
	ch, err := h.inv.AcceptHello(q.hello, conn)
	if err != nil {
		// A wrong code spends the code's guess and leaves the link open:
		// not the end of the invite.
		return false, err
	}
	// From here the invite is spent. The connection lives as long as the
	// invite would have, since admission may wait on other admins.
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if err := h.enroll(ctx, conn, ch, admit, chain, events); err != nil {
		_ = ch.Send(&enroll.Message{Kind: enroll.KindRefused, Reason: enroll.ReasonText(err)})
		return true, err
	}
	return true, nil
}

func (h *Host) enroll(ctx context.Context, conn net.Conn, ch *enroll.Channel, admit Admitter, chain Chain,
	events func(Event)) error {
	msg, err := ch.Receive()
	if err != nil {
		return err
	}
	if msg.Kind != enroll.KindJoin {
		return fmt.Errorf("the device sent a %v instead of asking to join", msg.Kind)
	}
	req := msg.Join
	if err := req.Verify(ch); err != nil {
		return err
	}
	name, admission, err := h.admitting(ctx, conn, ch, admit, req)
	if err != nil {
		return err
	}
	records, endpoints, leases, err := chain()
	if err != nil {
		return err
	}
	for _, aum := range records {
		body, err := aum.Encode()
		if err != nil {
			return err
		}
		if err := ch.Send(&enroll.Message{Kind: enroll.KindRecord, Record: body}); err != nil {
			return err
		}
	}
	if err := ch.Send(&enroll.Message{Kind: enroll.KindWelcome, Welcome: &enroll.Welcome{
		Name:      name,
		Records:   uint32(len(records)),
		Endpoints: endpoints,
		Leases:    leases,
		Admission: admission,
	}}); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(joinedTimeout))
	reply, err := ch.Receive()
	if err != nil {
		return fmt.Errorf("%s was admitted, but did not confirm it received the log: %w", name, err)
	}
	switch reply.Kind {
	case enroll.KindJoined:
		events(Event{Kind: Joined, Name: name, Identity: req.Identity, Addr: conn.RemoteAddr().String(),
			Announcement: reply.Announcement})
		return nil
	case enroll.KindRefused:
		return fmt.Errorf("%s was admitted, but could not use the log it was sent: %s", name, reply.Reason)
	default:
		return fmt.Errorf("%s answered with a %v", name, reply.Kind)
	}
}

// admitting runs the admitter while this goroutine alone writes to the
// channel: what the admitter asks to send, and, while it decides — a person
// comparing words, other admins approving — a reminder every waitingInterval,
// since the guest gives up after a minute of silence.
func (h *Host) admitting(ctx context.Context, conn net.Conn, ch *enroll.Channel, admit Admitter,
	req *enroll.JoinRequest) (string, *enroll.Admission, error) {
	type outgoing struct {
		msg  *enroll.Message
		sent chan error
	}
	sends := make(chan outgoing)
	send := func(m *enroll.Message) error {
		o := outgoing{m, make(chan error, 1)}
		select {
		case sends <- o:
			return <-o.sent
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var nonce enroll.Nonce
	compared := false
	compare := func(s enroll.Salt) (enroll.Nonce, error) {
		if compared {
			return enroll.Nonce{}, errors.New("the words are compared once per guest")
		}
		compared = true
		// The loop sends the salt and reads the guest's reveal before it
		// answers, so nothing else is written in between.
		if err := send(&enroll.Message{Kind: enroll.KindCompare, Compare: &s}); err != nil {
			return enroll.Nonce{}, err
		}
		return nonce, nil
	}
	type result struct {
		name      string
		admission *enroll.Admission
		err       error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		name, adm, err := admit.Admit(ctx, req, func(v, q uint32) error {
			return send(&enroll.Message{Kind: enroll.KindWaiting, Waiting: &enroll.Waiting{Votes: v, Quorum: q}})
		}, compare)
		done <- result{name, adm, err}
	}()
	tick := time.NewTicker(waitingInterval)
	defer tick.Stop()
	var lastWaiting enroll.Waiting
	var lastSent time.Time
	for {
		select {
		case o := <-sends:
			if o.msg.Kind == enroll.KindWaiting {
				// The admitter reports as often as it likes; the guest hears
				// what changed, and the same news at most every interval.
				if *o.msg.Waiting == lastWaiting && time.Since(lastSent) < waitingInterval {
					o.sent <- nil
					continue
				}
				lastWaiting, lastSent = *o.msg.Waiting, time.Now()
			}
			err := ch.Send(o.msg)
			if err != nil {
				err = fmt.Errorf("the device stopped waiting: %w", err)
			}
			if err == nil && o.msg.Kind == enroll.KindCompare {
				nonce, err = readReveal(conn, ch, req)
			}
			o.sent <- err
		case <-tick.C:
			if time.Since(lastSent) < waitingInterval {
				continue
			}
			w := lastWaiting
			lastSent = time.Now()
			if err := ch.Send(&enroll.Message{Kind: enroll.KindWaiting, Waiting: &w}); err != nil {
				cancel()
				r := <-done
				if r.err == nil {
					r.err = fmt.Errorf("the device stopped waiting: %w", err)
				}
				return "", nil, r.err
			}
		case r := <-done:
			return r.name, r.admission, r.err
		}
	}
}

// readReveal reads the nonce a guest reveals once it holds the salt, and holds
// it to the request's commitment.
func readReveal(conn net.Conn, ch *enroll.Channel, req *enroll.JoinRequest) (enroll.Nonce, error) {
	_ = conn.SetReadDeadline(time.Now().Add(confirmTimeout))
	defer conn.SetReadDeadline(time.Time{})
	msg, err := ch.Receive()
	if err != nil {
		return enroll.Nonce{}, fmt.Errorf("the device did not answer the words' salt: %w", err)
	}
	if msg.Kind != enroll.KindReveal {
		return enroll.Nonce{}, fmt.Errorf("the device answered the words' salt with a %v", msg.Kind)
	}
	if enroll.CommitNonce(*msg.Reveal) != req.Commit {
		return enroll.Nonce{}, errors.New("the device revealed a nonce other than the one it committed to")
	}
	return *msg.Reveal, nil
}

// Addrs lists the addresses a guest could reach this host at: every usable
// interface address outside the overlay, IPv4 first.
func Addrs(port uint16, exclude []netip.Prefix) []netip.AddrPort {
	addrs, _ := underlay.Scan()
	var v4, v6 []netip.AddrPort
next:
	for _, ip := range addrs {
		if !ip.IsGlobalUnicast() || types.IsOverlayV4(ip) {
			continue
		}
		for _, x := range exclude {
			if x.Contains(ip) {
				continue next
			}
		}
		if ip.Is4() {
			v4 = append(v4, netip.AddrPortFrom(ip, port))
		} else {
			v6 = append(v6, netip.AddrPortFrom(ip, port))
		}
	}
	out := append(v4, v6...)
	if len(out) > enroll.MaxLinkAddrs {
		out = out[:enroll.MaxLinkAddrs]
	}
	return out
}
