// Package rendezvous lets the two ends of an invite link meet when neither
// can reach the other, as when both are behind NAT: each asks public STUN
// servers for its public address, leaves its addresses sealed in the public
// DHT at a key only the link derives, and both send UDP toward the other's
// until the NATs let the packets through. What comes out is a reliable stream
// the enrollment runs over exactly as it would over TCP.
//
// Nothing here is trusted. The DHT and the STUN servers can withhold, delay
// or misreport, which costs the meeting and nothing else: the items are
// sealed under a key derived from the link's secret, so no one without the
// link can read them or write one the other side accepts, and the enrollment
// over the stream authenticates both ends. What the helpers learn is that
// this address is meeting someone: STUN servers see the address, and DHT
// nodes see the address store or fetch an item at a key unrelated to anything
// else.
//
// It fails where both NATs pick a new public port for every destination
// (symmetric NAT on both sides); then the only way through is a relay, and
// the link has to be used from a network that can reach the host.
package rendezvous

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"tailscale.com/net/stun"

	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// DefaultSTUN are the public STUN servers a device asks for its own public
// address. Two operators, so neither alone can deny it; each learns only that
// this address runs juist.
var DefaultSTUN = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

const (
	// maxCandidates bounds the addresses one side offers, and so the item.
	maxCandidates = 8

	stunWait     = 2 * time.Second
	stunRefresh  = 25 * time.Second // shorter than the NAT mapping timeouts seen in practice
	pollEvery    = 3 * time.Second
	punchEvery   = 250 * time.Millisecond
	republishIn  = 30 * time.Minute // BEP 44 nodes forget an item after about two hours
	retryPublish = 10 * time.Second

	// Labels for the item's role, sealed as its epoch, so a host's item
	// cannot be passed off as a guest's.
	roleHost  = 1
	roleGuest = 2
)

// ErrNoPublicAddress is returned when no STUN server answered: the device
// may be offline, or UDP blocked.
var ErrNoPublicAddress = errors.New("no STUN server answered, so this device does not know its public address")

// Keys are what a link derives for its meeting: where each side leaves its
// addresses, and the key both are sealed under.
type Keys struct {
	Host, Guest, Seal [32]byte
}

// KeysOf derives a link's keys.
func KeysOf(l enroll.Link) Keys {
	var k Keys
	k.Host, k.Guest, k.Seal = l.RendezvousKeys()
	return k
}

// A Store holds one value per seed; [dht.Store] is the public one.
type Store interface {
	Put(ctx context.Context, seed [32]byte, value []byte) error
	Get(ctx context.Context, seed [32]byte) ([]byte, error)
}

// Helpers are the public services a meeting relies on, as a device is
// configured to use them.
type Helpers struct {
	STUN      []string `cbor:"1,keyasint,omitempty"`
	Bootstrap []string `cbor:"2,keyasint,omitempty"`
}

// Options are the options for meeting at link through h.
func (h *Helpers) Options(link enroll.Link, logf func(string, ...any)) Options {
	return Options{Keys: KeysOf(link), STUN: h.STUN, Bootstrap: h.Bootstrap, Logf: logf}
}

// Meeter is guest.Options.Meet through h: nil where h is.
func (h *Helpers) Meeter(logf func(string, ...any)) func(context.Context, enroll.Link) (net.Conn, error) {
	if h == nil {
		return nil
	}
	return func(ctx context.Context, link enroll.Link) (net.Conn, error) {
		return Dial(ctx, h.Options(link, logf))
	}
}

// Options configures either side of a meeting.
type Options struct {
	Keys Keys

	// STUN are the servers asked for this device's public address; at least
	// one is needed.
	STUN []string

	// Store is where the addresses are left. Nil joins the public DHT,
	// starting from Bootstrap, or its usual routers if that is empty.
	Store     Store
	Bootstrap []string

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)

	// open replaces joining the public DHT, for tests.
	open func() (Store, func(), error)
}

func (o *Options) check() error {
	if len(o.STUN) == 0 {
		return errors.New("rendezvous: no STUN server to learn a public address from")
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return nil
}

// store is o.Store, or the public DHT; close releases what it opened.
func (o *Options) store() (s Store, close func(), err error) {
	if o.Store != nil {
		return o.Store, func() {}, nil
	}
	if o.open != nil {
		return o.open()
	}
	d, err := dht.NewStore(dht.StoreOptions{Bootstrap: o.Bootstrap})
	if err != nil {
		return nil, nil, err
	}
	return d, func() { d.Close() }, nil
}

// An item is what one side leaves for the other.
type item struct {
	// ID names the session. The guest draws it and every packet on the
	// punched path carries it; the host's changes whenever it publishes new
	// addresses, so the guest can tell.
	ID    uint32           `cbor:"1,keyasint"`
	Addrs []netip.AddrPort `cbor:"2,keyasint"`
}

// The item codec is the project's strict one, like every other parser here.
var (
	itemEnc = func() cbor.EncMode {
		m, err := cbor.CTAP2EncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		return m
	}()
	itemDec = func() cbor.DecMode {
		m, err := types.StrictDecOptions(4, 16, 16).DecMode()
		if err != nil {
			panic(err)
		}
		return m
	}()
)

func seal(key [32]byte, role uint64, it item) ([]byte, error) {
	body, err := itemEnc.Marshal(it)
	if err != nil {
		return nil, err
	}
	return aead.Seal(key, role, body)
}

func open(key [32]byte, role uint64, blob []byte) (item, error) {
	var it item
	if r, err := aead.Epoch(blob); err != nil {
		return it, err
	} else if r != role {
		return it, fmt.Errorf("rendezvous: the item is labelled role %d, not %d", r, role)
	}
	body, err := aead.Open(key, blob)
	if err != nil {
		return it, err
	}
	if err := itemDec.Unmarshal(body, &it); err != nil {
		return it, fmt.Errorf("rendezvous: the item does not decode: %w", err)
	}
	if it.ID == 0 || len(it.Addrs) == 0 {
		return it, errors.New("rendezvous: the item is empty")
	}
	if len(it.Addrs) > maxCandidates {
		return it, fmt.Errorf("rendezvous: the item offers %d addresses, over the %d allowed", len(it.Addrs), maxCandidates)
	}
	for _, a := range it.Addrs {
		if !punchable(a) {
			return it, errors.New("rendezvous: the item holds an address nothing should be sent to")
		}
	}
	return it, nil
}

// withReflexive returns cands with the address a STUN response reports put
// first, where the response answers a request in pending, which it takes off,
// and the address is punchable and new. It reports false where cands stays.
func withReflexive(cands []netip.AddrPort, resp []byte, pending map[stun.TxID]bool) ([]netip.AddrPort, bool) {
	tx, addr, err := stun.ParseResponse(resp)
	if err != nil || !pending[tx] {
		return cands, false
	}
	delete(pending, tx)
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	if !punchable(addr) || slices.Contains(cands, addr) {
		return cands, false
	}
	out := append([]netip.AddrPort{addr}, cands...)
	return out[:min(len(out), maxCandidates)], true
}

// punchable reports whether an address may be punched toward: not loopback,
// multicast or unspecified, which a peer — or a STUN server lying about the
// host's address — could otherwise steer this device's packets at.
func punchable(a netip.AddrPort) bool {
	ip := a.Addr().Unmap()
	return a.IsValid() && a.Port() != 0 && (!ip.IsLoopback() || loopbackMeetings) && !ip.IsMulticast() &&
		!ip.IsUnspecified()
}

// loopbackMeetings lets the tests meet on loopback.
var loopbackMeetings = false

func randomID() uint32 {
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		if id := binary.BigEndian.Uint32(b[:]); id != 0 {
			return id
		}
	}
}

// --- the socket ----------------------------------------------------------

type inbound struct {
	from netip.AddrPort
	b    []byte
}

// A socket is the UDP socket a side meets on, read by one goroutine until it
// is handed to the stream.
type socket struct {
	pc      *net.UDPConn
	packets chan inbound
	stopped chan struct{}
	done    chan struct{}
}

func listen() (*socket, error) {
	c, err := underlay.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("rendezvous: binding a UDP socket: %w", err)
	}
	pc := c.(*net.UDPConn)
	s := &socket{pc: pc, packets: make(chan inbound, 64), stopped: make(chan struct{}), done: make(chan struct{})}
	go s.read()
	return s, nil
}

func (s *socket) read() {
	defer close(s.done)
	buf := make([]byte, 2048)
	for {
		n, from, err := s.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		select {
		case s.packets <- inbound{from: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), b: slices.Clone(buf[:n])}:
		case <-s.stopped:
			return
		default: // a flood is dropped, not queued
		}
	}
}

// handOff stops the reader and returns the socket for a stream to own.
func (s *socket) handOff() *net.UDPConn {
	close(s.stopped)
	_ = s.pc.SetReadDeadline(time.Unix(1, 0))
	<-s.done
	_ = s.pc.SetReadDeadline(time.Time{})
	return s.pc
}

func (s *socket) close() {
	s.pc.Close()
	<-s.done
}

func (s *socket) send(to netip.AddrPort, b []byte) {
	_, _ = s.pc.WriteToUDPAddrPort(b, to)
}

func (s *socket) port() uint16 { return uint16(s.pc.LocalAddr().(*net.UDPAddr).Port) }

// stunRequests sends a binding request to every server, returning the
// transactions to expect answers for.
func (s *socket) stunRequests(ctx context.Context, servers []string) map[stun.TxID]bool {
	txs := make(map[stun.TxID]bool)
	for _, server := range servers {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", hostOf(server))
		if err != nil || len(addrs) == 0 {
			continue
		}
		port, err := portOf(server)
		if err != nil {
			continue
		}
		tx := stun.NewTxID()
		txs[tx] = true
		s.send(netip.AddrPortFrom(addrs[0], port), stun.Request(tx))
	}
	return txs
}

// gather learns this socket's candidates: its public addresses as the STUN
// servers see them, and its addresses on the local networks, for a peer
// behind the same NAT.
func (s *socket) gather(ctx context.Context, servers []string) ([]netip.AddrPort, error) {
	txs := s.stunRequests(ctx, servers)
	var public []netip.AddrPort
	timer := time.NewTimer(stunWait)
	defer timer.Stop()
	for len(txs) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			txs = nil
		case p := <-s.packets:
			if !stun.Is(p.b) {
				continue
			}
			tx, addr, err := stun.ParseResponse(p.b)
			if err != nil || !txs[tx] {
				continue
			}
			delete(txs, tx)
			addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
			if punchable(addr) && !slices.Contains(public, addr) {
				public = append(public, addr)
			}
		}
	}
	if len(public) == 0 {
		return nil, ErrNoPublicAddress
	}
	out := append(public, localCandidates(s.port())...)
	if len(out) > maxCandidates {
		out = out[:maxCandidates]
	}
	return out, nil
}

func hostOf(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}

func portOf(hostPort string) (uint16, error) {
	_, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return 0, err
	}
	ap, err := netip.ParseAddrPort("0.0.0.0:" + p)
	if err != nil {
		return 0, err
	}
	return ap.Port(), nil
}

// localCandidates are this device's addresses outside any overlay: private
// IPv4 addresses reach a peer behind the same NAT, and global IPv6 addresses
// a peer whose firewall lets the punch through.
func localCandidates(port uint16) []netip.AddrPort {
	addrs, _ := underlay.Scan()
	var out []netip.AddrPort
	for _, ip := range addrs {
		if !ip.IsGlobalUnicast() || types.IsOverlayV4(ip) || ulas.Contains(ip) {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	return out
}

// ulas are unique local IPv6 addresses, where the overlay lives.
var ulas = netip.MustParsePrefix("fc00::/7")

// punched reports whether p is a packet of session id: a punch, or the
// stream's first data when the other side got through first.
func punched(p inbound, id uint32) bool {
	kind, got, _, _, ok := parsePacket(p.b)
	return ok && got == id && (kind == pktPunch || kind == pktData)
}

// connect turns the socket into the session's stream, telling the peer at
// once so it stops punching too.
func connect(s *socket, peer netip.AddrPort, id uint32) net.Conn {
	pc := s.handOff()
	st := newStream(pc, peer, id)
	st.mu.Lock()
	st.send(pktPunch, 1, nil)
	st.mu.Unlock()
	return st
}

// poll fetches the item at seed every pollEvery until ctx ends, delivering
// each that opens.
func poll(ctx context.Context, store Store, seed, key [32]byte, role uint64, logf func(string, ...any)) <-chan item {
	out := make(chan item, 1)
	go func() {
		defer close(out)
		for {
			if blob, err := store.Get(ctx, seed); err == nil {
				if it, err := open(key, role, blob); err == nil {
					select {
					case out <- it:
					case <-ctx.Done():
						return
					}
				} else {
					logf("rendezvous: ignoring an item: %v", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollEvery):
			}
		}
	}()
	return out
}

// publish stores it at seed until it succeeds or ctx ends.
func publish(ctx context.Context, store Store, seed, key [32]byte, role uint64, it item, logf func(string, ...any)) {
	blob, err := seal(key, role, it)
	if err != nil {
		logf("rendezvous: sealing: %v", err)
		return
	}
	for {
		err := store.Put(ctx, seed, blob)
		if err == nil || ctx.Err() != nil {
			return
		}
		logf("rendezvous: publishing: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryPublish):
		}
	}
}

// --- the guest -----------------------------------------------------------

// Dial meets the host of the link o.Keys came from. It runs until the two
// are connected or ctx ends; the caller bounds how long that may take.
func Dial(ctx context.Context, o Options) (net.Conn, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type opened struct {
		store Store
		close func()
		err   error
	}
	storeCh := make(chan opened, 1)
	go func() {
		s, c, err := o.store()
		storeCh <- opened{s, c, err}
	}()
	// Every return before the store was taken leaves it to this: a DHT node
	// left running would be a socket, goroutines and a presence on the
	// public DHT for as long as the daemon runs.
	taken := false
	defer func() {
		if !taken {
			go func() {
				if st := <-storeCh; st.err == nil {
					st.close()
				}
			}()
		}
	}()
	sock, err := listen()
	if err != nil {
		return nil, err
	}
	handed := false
	defer func() {
		if !handed {
			sock.close()
		}
	}()
	cands, err := sock.gather(ctx, o.STUN)
	if err != nil {
		return nil, err
	}
	var st opened
	select {
	case st = <-storeCh:
		taken = true
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if st.err != nil {
		return nil, st.err
	}
	// Stops what uses the store before closing it.
	defer func() {
		cancel()
		st.close()
	}()

	id := randomID()
	o.Logf("rendezvous: offering %v as session %08x", cands, id)
	go publish(ctx, st.store, o.Keys.Guest, o.Keys.Seal, roleGuest, item{ID: id, Addrs: cands}, o.Logf)
	hosts := poll(ctx, st.store, o.Keys.Host, o.Keys.Seal, roleHost, o.Logf)

	var host item
	punch := time.NewTicker(punchEvery)
	defer punch.Stop()
	for {
		select {
		case <-ctx.Done():
			if host.ID == 0 {
				return nil, errors.New("the inviting device left no addresses in the public DHT; " +
					"it may have stopped waiting, or be unable to reach the DHT")
			}
			return nil, fmt.Errorf("no packet got through to the inviting device at %v: both devices are "+
				"probably behind NATs that cannot be traversed without a relay", host.Addrs)
		case it, ok := <-hosts:
			if ok && it.ID != host.ID {
				o.Logf("rendezvous: the host offers %v", it.Addrs)
				host = it
			}
		case <-punch.C:
			for _, a := range host.Addrs {
				sock.send(a, packet(pktPunch, id, 0, nil))
			}
		case p := <-sock.packets:
			if punched(p, id) {
				o.Logf("rendezvous: reached the host at %v", p.from)
				handed = true
				return connect(sock, p.from, id), nil
			}
		}
	}
}

// --- the host ------------------------------------------------------------

// A Listener waits for guests of one link. It implements [net.Listener], so
// an invite accepts from it as from TCP.
type Listener struct {
	o      Options
	ctx    context.Context
	cancel context.CancelFunc
	store  Store
	close  func()
	served map[uint32]bool
}

// Listen starts waiting for guests. It joins the DHT before returning; the
// addresses are published by Accept.
func Listen(ctx context.Context, o Options) (*Listener, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	store, closeStore, err := o.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Listener{o: o, ctx: ctx, cancel: cancel, store: store, close: closeStore, served: map[uint32]bool{}}, nil
}

// Close stops waiting; an Accept in progress returns.
func (l *Listener) Close() error {
	l.cancel()
	l.close()
	return nil
}

// Addr is a placeholder: a listener has as many addresses as the NAT gives.
func (l *Listener) Addr() net.Addr { return &net.UDPAddr{} }

// Accept waits for the next guest, on a fresh socket each time: its public
// address is the one published, so each session needs its own. It is not
// safe to call from two goroutines at once.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.accept()
		if l.ctx.Err() != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, net.ErrClosed
		}
		if err == nil {
			return conn, nil
		}
		l.o.Logf("rendezvous: %v; trying again", err)
		select {
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		case <-time.After(retryPublish):
		}
	}
}

func (l *Listener) accept() (net.Conn, error) {
	ctx, cancel := context.WithCancel(l.ctx)
	defer cancel()
	sock, err := listen()
	if err != nil {
		return nil, err
	}
	handed := false
	defer func() {
		if !handed {
			sock.close()
		}
	}()
	cands, err := sock.gather(ctx, l.o.STUN)
	if err != nil {
		return nil, err
	}

	// Publishing runs beside everything else and is restarted whenever the
	// addresses change; the guest tells by the new ID.
	pubCtx, stopPub := context.WithCancel(ctx)
	republish := func() {
		stopPub()
		pubCtx, stopPub = context.WithCancel(ctx)
		it := item{ID: randomID(), Addrs: cands}
		l.o.Logf("rendezvous: offering %v", cands)
		go publish(pubCtx, l.store, l.o.Keys.Host, l.o.Keys.Seal, roleHost, it, l.o.Logf)
	}
	republish()
	defer func() { stopPub() }()
	guests := poll(ctx, l.store, l.o.Keys.Guest, l.o.Keys.Seal, roleGuest, l.o.Logf)

	var guest item
	punch := time.NewTicker(punchEvery)
	defer punch.Stop()
	refresh := time.NewTicker(stunRefresh)
	defer refresh.Stop()
	renew := time.NewTicker(republishIn)
	defer renew.Stop()
	pending := map[stun.TxID]bool{}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case it, ok := <-guests:
			if ok && it.ID != guest.ID && !l.served[it.ID] {
				l.o.Logf("rendezvous: a guest offers %v as session %08x", it.Addrs, it.ID)
				guest = it
			}
		case <-punch.C:
			for _, a := range guest.Addrs {
				sock.send(a, packet(pktPunch, guest.ID, 0, nil))
			}
		case <-refresh.C:
			// Also what keeps the NAT's mapping, and so the published
			// address, alive while no guest comes.
			pending = sock.stunRequests(ctx, l.o.STUN)
		case <-renew.C:
			republish()
		case p := <-sock.packets:
			if stun.Is(p.b) {
				if more, ok := withReflexive(cands, p.b, pending); ok {
					cands = more
					republish()
				}
				continue
			}
			if guest.ID != 0 && punched(p, guest.ID) {
				l.o.Logf("rendezvous: reached the guest at %v", p.from)
				l.served[guest.ID] = true
				handed = true
				return connect(sock, p.from, guest.ID), nil
			}
		}
	}
}

var _ net.Listener = (*Listener)(nil)
