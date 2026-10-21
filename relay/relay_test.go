package relay

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/nettest"
)

// testRelay starts a relay on loopback whose member set the test controls.
func testRelay(t *testing.T, members map[key.NodePublic]bool) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	s, err := New(Options{
		Admit:    func(k [32]byte) bool { return members[key.NodePublicFromRaw32(mem.B(k[:]))] },
		Listener: ln,
		Logf:     t.Logf,
	})
	if err != nil {
		t.Fatalf("starting the relay: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// region renders a relay as the DERP region a member would put in its map:
// dialled at the address its announcement carries, with its certificate
// pinned by hash and its name never resolved.
func region(s *Server) *tailcfg.DERPRegion {
	ap := s.localAddrs()[0]
	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "juist1",
		Nodes: []*tailcfg.DERPNode{{
			Name:     "juist1a",
			RegionID: 1,
			HostName: s.HostName(),
			CertName: conn.CertPin(s.CertHash()),
			IPv4:     ap.Addr().String(),
			IPv6:     "none",
			DERPPort: int(s.Port()),
			STUNPort: -1,
		}},
	}
}

// waitClients waits for the relay to hold exactly n admitted connections.
// A DERP client's Connect returns once the HTTP upgrade is answered, which is
// before the server has checked its key, so this is what tells a connection
// that was admitted from one that is about to be dropped.
func waitClients(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if got := s.Clients(); got == n {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("the relay holds %d clients, want %d", got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testClient(t *testing.T, s *Server, priv key.NodePrivate) *derphttp.Client {
	t.Helper()
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	mon, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatalf("network monitor: %v", err)
	}
	t.Cleanup(func() { mon.Close() })
	reg := region(s)
	c := derphttp.NewRegionClient(priv, t.Logf, mon, func() *tailcfg.DERPRegion { return reg })
	t.Cleanup(func() { c.Close() })
	return c
}

// TestMembersRelayThroughAMember is the control every negative result here
// depends on: two members connect to a third's relay and a packet crosses it.
func TestMembersRelayThroughAMember(t *testing.T) {
	a, b := key.NewNode(), key.NewNode()
	s := testRelay(t, map[key.NodePublic]bool{a.Public(): true, b.Public(): true})

	ca, cb := testClient(t, s, a), testClient(t, s, b)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ca.Connect(ctx); err != nil {
		t.Fatalf("member a could not reach the relay: %v", err)
	}
	if err := cb.Connect(ctx); err != nil {
		t.Fatalf("member b could not reach the relay: %v", err)
	}
	waitClients(t, s, 2)

	want := []byte("over the relay")
	// The relay drops a packet for a client it has not seen yet, so this
	// repeats until b's registration has landed.
	deadline := time.Now().Add(20 * time.Second)
	got := make(chan []byte, 1)
	go func() {
		for {
			m, err := cb.Recv()
			if err != nil {
				return
			}
			if rp, ok := m.(derp.ReceivedPacket); ok {
				got <- append([]byte(nil), rp.Data...)
				return
			}
		}
	}()
	for {
		if err := ca.Send(b.Public(), want); err != nil {
			t.Fatalf("sending through the relay: %v", err)
		}
		select {
		case have := <-got:
			if string(have) != string(want) {
				t.Fatalf("relayed %q, want %q", have, want)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing crossed the relay")
		}
	}
}

// TestNonMemberCannotUseTheRelay is M3b exit criterion (3): a device holding
// perfectly good keys, that the log does not carry, gets no relay.
//
// It drives a real DERP client rather than calling the admission check, on
// purpose: the check reaches the DERP server through an upstream hook, and if
// an upgrade ever stopped consulting that hook every non-member would be
// admitted with nothing that looks like a failure. This is the test that
// notices.
func TestNonMemberCannotUseTheRelay(t *testing.T) {
	member, outsider := key.NewNode(), key.NewNode()
	s := testRelay(t, map[key.NodePublic]bool{member.Public(): true})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The control: the same code path, with a key the log carries. Without
	// it a refusal below could be a broken listener.
	if err := testClient(t, s, member).Connect(ctx); err != nil {
		t.Fatalf("a member could not reach the relay, so a refusal proves nothing: %v", err)
	}
	waitClients(t, s, 1)

	// Connect only completes the HTTP upgrade, so a non-member gets that far
	// too; what it must not get is a usable session.
	c := testClient(t, s, outsider)
	if err := c.Connect(ctx); err != nil {
		t.Logf("the non-member was refused at connect: %v", err)
	}
	failed := make(chan struct{})
	go func() {
		defer close(failed)
		for {
			if _, err := c.Recv(); err != nil {
				return
			}
		}
	}()
	select {
	case <-failed:
	case <-time.After(20 * time.Second):
		t.Fatal("a non-member holds a working session on a member's relay")
	}
	if n := s.Clients(); n != 1 {
		t.Errorf("the relay holds %d clients, want only the member", n)
	}
}

// TestRemovedMemberLosesTheConnectionItHolds covers the half of the criterion
// admission alone does not reach: the check runs when a connection opens and
// never again, so a revoked device would keep relaying through the session it
// already has until it chose to reconnect.
func TestRemovedMemberLosesTheConnectionItHolds(t *testing.T) {
	doomed := key.NewNode()
	members := map[key.NodePublic]bool{doomed.Public(): true}
	s := testRelay(t, members)

	c := testClient(t, s, doomed)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	// The removal must land on an established session, not race the
	// admission check: otherwise this passes on the connect-time refusal and
	// proves nothing about the session already held.
	waitClients(t, s, 1)
	failed := make(chan error, 1)
	go func() {
		for {
			if _, err := c.Recv(); err != nil {
				failed <- err
				return
			}
		}
	}()

	delete(members, doomed.Public())
	s.Reauthorize()
	select {
	case <-failed:
	case <-time.After(20 * time.Second):
		t.Fatal("a removed member kept the relay connection it already held")
	}
	// The record is dropped when the handler returns, which the client
	// noticing the closed socket does not wait for.
	waitClients(t, s, 0)
}

// TestWrongCertPinIsRefused covers what authenticates the relay in place of a
// certificate authority: the hash in the member's signed announcement. A
// relay whose certificate does not match it must not be talked to, or a
// stranger on the path could take every relayed session.
func TestWrongCertPinIsRefused(t *testing.T) {
	member := key.NewNode()
	s := testRelay(t, map[key.NodePublic]bool{member.Public(): true})

	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatalf("network monitor: %v", err)
	}
	defer mon.Close()

	reg := region(s)
	var wrong [32]byte
	wrong[0] = 1
	reg.Nodes[0].CertName = conn.CertPin(wrong)
	c := derphttp.NewRegionClient(member, t.Logf, mon, func() *tailcfg.DERPRegion { return reg })
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err == nil {
		t.Fatal("a relay presenting an unpinned certificate was accepted")
	}
}

// TestSTUNReflectsTheQuerier covers the half of a relay that is not DERP: a
// member learns its own reflexive address from another member, which is what
// keeps NAT traversal free of a public STUN server.
func TestSTUNReflectsTheQuerier(t *testing.T) {
	s := testRelay(t, map[key.NodePublic]bool{})
	if s.STUNPort() == 0 {
		t.Skip("no STUN port could be bound here")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer c.Close()

	txid := stun.NewTxID()
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.STUNPort())
	if _, err := c.WriteToUDPAddrPort(stun.Request(txid), to); err != nil {
		t.Fatalf("sending a binding request: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, _, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("reading the binding response: %v", err)
	}
	gotID, addr, err := stun.ParseResponse(buf[:n])
	if err != nil {
		t.Fatalf("parsing the binding response: %v", err)
	}
	if gotID != txid {
		t.Errorf("response carries another transaction ID")
	}
	want := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if addr.Port() != want.Port() {
		t.Errorf("reflected port %d, want %d", addr.Port(), want.Port())
	}
}

// TestSTUNRepliesFromTheAddressItWasAsked is what makes a relay usable on a
// multi-homed host. A wildcard socket replies from whichever source the route
// table picks, and a reply from an address the querier never wrote to is
// dropped by the querier's own NAT — so the answer is lost for exactly the
// querier who needed it, and silently.
func TestSTUNRepliesFromTheAddressItWasAsked(t *testing.T) {
	s := testRelay(t, map[key.NodePublic]bool{})
	if s.STUNPort() == 0 {
		t.Skip("no STUN port could be bound here")
	}
	// A second loopback address, which every Linux host has: 127.0.0.0/8 is
	// entirely local. Asking at one and being answered from the other is the
	// bug this covers.
	second := netip.MustParseAddr("127.0.0.2")
	if !nettest.HasLoopbackAddr(second) {
		nettest.SkipUnlessRequired(t, "this host carries no %v to ask at", second)
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer c.Close()

	to := netip.AddrPortFrom(second, s.STUNPort())
	txid := stun.NewTxID()
	if _, err := c.WriteToUDPAddrPort(stun.Request(txid), to); err != nil {
		nettest.SkipUnlessRequired(t, "this host does not route to %v: %v", second, err)
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no answer from %v: %v", to, err)
	}
	if got := from.Addr().Unmap(); got != second {
		t.Errorf("asked %v, answered from %v; a NAT between the two would drop that", second, got)
	}
	if _, _, err := stun.ParseResponse(buf[:n]); err != nil {
		t.Errorf("the answer does not parse: %v", err)
	}
}

// Reauthorize asks Admit holding no lock of the relay's: Admit may take a lock
// of its own under which its caller asks whether a member is connected.
func TestReauthorizeAsksWithoutItsLock(t *testing.T) {
	member := key.NewNode()
	var srv atomic.Pointer[Server]
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Listener: ln, Logf: t.Logf, Admit: func(k [32]byte) bool {
		if r := srv.Load(); r != nil {
			r.Connected(k)
		}
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c := testClient(t, s, member)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	waitClients(t, s, 1)
	srv.Store(s)
	done := make(chan struct{})
	go func() {
		s.Reauthorize()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reauthorize deadlocked on an Admit that asks the relay")
	}
}

// A binding request carries no identity, so the answer rate is what keeps an
// open responder from being worth using as a reflector.
func TestSTUNAnswersAreRateLimited(t *testing.T) {
	s := testRelay(t, map[key.NodePublic]bool{})
	if s.STUNPort() == 0 {
		t.Skip("no STUN port could be bound here")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer c.Close()
	_ = c.SetReadBuffer(4 << 20)
	type count struct {
		n    int
		last time.Time
	}
	answers := make(chan count)
	start := time.Now()
	go func() {
		var got count
		buf := make([]byte, 1500)
		for {
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, _, err := c.ReadFromUDPAddrPort(buf); err != nil {
				answers <- got
				return
			}
			got.n, got.last = got.n+1, time.Now()
		}
	}()
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.STUNPort())
	const asked = 3 * stunBurst
	for range asked {
		if _, err := c.WriteToUDPAddrPort(stun.Request(stun.NewTxID()), to); err != nil {
			t.Fatalf("sending a binding request: %v", err)
		}
	}
	res := <-answers
	got, elapsed := res.n, res.last.Sub(start)
	limit := stunBurst + int(elapsed.Seconds()*stunAnswersPerSecond) + 1
	t.Logf("%d of %d requests answered in %v", got, asked, elapsed)
	if got == 0 || got > limit {
		t.Fatalf("%d of %d requests answered in %v; the limit allows %d", got, asked, elapsed, limit)
	}
}

// One host's flood spends its own answers, not another's netcheck.
func TestSTUNFloodFromOneHostStarvesNoOther(t *testing.T) {
	s := testRelay(t, map[key.NodePublic]bool{})
	if s.STUNPort() == 0 {
		t.Skip("no STUN port could be bound here")
	}
	flooder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer flooder.Close()
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("no second loopback address here: %v", err)
	}
	defer other.Close()
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.STUNPort())
	stop := make(chan struct{})
	flooding := make(chan struct{})
	go func() {
		defer close(flooding)
		req := stun.Request(stun.NewTxID())
		// 20,000 requests a second, a hundred times the rate in all.
		for tick := time.NewTicker(10 * time.Millisecond); ; <-tick.C {
			select {
			case <-stop:
				tick.Stop()
				return
			default:
			}
			for range 200 {
				_, _ = flooder.WriteToUDPAddrPort(req, to)
			}
		}
	}()
	defer func() { close(stop); <-flooding }()
	time.Sleep(time.Second) // past the burst in all

	buf := make([]byte, 1500)
	for range 3 {
		txid := stun.NewTxID()
		if _, err := other.WriteToUDPAddrPort(stun.Request(txid), to); err != nil {
			t.Fatalf("sending a binding request: %v", err)
		}
		_ = other.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := other.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		if got, _, err := stun.ParseResponse(buf[:n]); err != nil || got != txid {
			t.Fatalf("the other host got %v, %v", got, err)
		}
		return
	}
	t.Fatal("the other host went unanswered during the flood")
}

// localAddrs reports where the relay's own listener is bound.
func (s *Server) localAddrs() []netip.AddrPort {
	ta, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	ap := ta.AddrPort()
	return []netip.AddrPort{netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
}
