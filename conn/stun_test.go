package conn

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/nning/juist/relay"
)

// stunCounter is a STUN server on this host's address that answers every
// binding request and counts them.
type stunCounter struct {
	pc   *net.UDPConn
	seen atomic.Int64

	mu     sync.Mutex
	byPort map[uint16]int
}

func newSTUNCounter(t *testing.T) *stunCounter {
	t.Helper()
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(hostAddr(t), 0)))
	if err != nil {
		t.Fatal(err)
	}
	s := &stunCounter{pc: pc, byPort: map[uint16]int{}}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			s.seen.Add(1)
			s.mu.Lock()
			s.byPort[from.Port()]++
			s.mu.Unlock()
			pc.WriteToUDPAddrPort(stun.Response(tx, from), from)
		}
	}()
	return s
}

func (s *stunCounter) addr() string { return s.pc.LocalAddr().String() }

// from is how many requests came from port.
func (s *stunCounter) from(port uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPort[port]
}

// TestAnIdleNodeWithoutARelayStopsAskingSTUN: with STUN servers and no member
// relay, the engine took a STUN server for its home and asked again every few
// seconds as it failed to connect, which kept a phone's radio awake.
func TestAnIdleNodeWithoutARelayStopsAskingSTUN(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	withSTUN := func(o *Options) { o.STUN = []string{srv.addr()} }
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", withSTUN)
	b := startNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128", withSTUN)
	for _, n := range []*node{a, b} {
		if err := n.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(10 * time.Second); srv.seen.Load() == 0; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no STUN request")
		}
	}
	time.Sleep(3 * time.Second)
	before := srv.seen.Load()
	const window = 20 * time.Second
	time.Sleep(window)
	// Two nodes, each with at most one netcheck of a few requests in the window.
	if asked := srv.seen.Load() - before; asked > 8 {
		t.Errorf("%d STUN requests from two idle nodes in %v", asked, window)
	}
	for _, n := range []*node{a, b} {
		if eps := n.mgr.(*tsManager).LocalEndpoints(); len(eps) == 0 {
			t.Errorf("node %d knows no endpoint of its own", n.id)
		}
	}
}

// TestASavingNodeAsksNoSTUNThoughProbed: a peer's probes keep a node's
// tunnel active, which would have it ask STUN every 25 s while saving.
func TestASavingNodeAsksNoSTUNThoughProbed(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	withSTUN := func(o *Options) { o.STUN = []string{srv.addr()} }
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", withSTUN)
	b := startNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128", withSTUN)
	for _, n := range []*node{a, b} {
		if err := n.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
			t.Fatal(err)
		}
	}
	a.mgr.(*tsManager).SetSaving(true)
	if _, ok := pingUntil(t, b, a.pingAddr(), 10*time.Second); !ok {
		t.Fatal("no answer from the saving node")
	}
	// The endpoint updates setting the peers began may still be asking, as
	// on FreeBSD, whose netcheck takes longer: wait for three quiet probes.
	before := srv.from(a.mgr.LocalPort())
	for quiet, deadline := 0, time.Now().Add(stunEvery); quiet < 3; {
		if time.Now().After(deadline) {
			t.Fatal("the saving node kept asking STUN after its peers were set")
		}
		ping(t, b, a.pingAddr(), time.Second)
		time.Sleep(2 * time.Second)
		if now := srv.from(a.mgr.LocalPort()); now != before {
			before, quiet = now, 0
		} else {
			quiet++
		}
	}
	for end := time.Now().Add(2*stunEvery + 5*time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		ping(t, b, a.pingAddr(), time.Second)
	}
	if asked := srv.from(a.mgr.LocalPort()) - before; asked > 0 {
		t.Errorf("the saving node asked STUN %d times while probed", asked)
	}
}

// A homeless node says nothing of a home it does not take, at each netcheck.
func TestAHomelessNodeSaysNoHomeItDoesNotTake(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	var mu sync.Mutex
	var said []string
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) {
		o.STUN = []string{srv.addr()}
		o.Logf = func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			said = append(said, fmt.Sprintf(format, args...))
		}
	})
	for deadline := time.Now().Add(10 * time.Second); srv.seen.Load() == 0; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no STUN request")
		}
	}
	a.mgr.(*tsManager).magic.ReSTUN("test")
	time.Sleep(3 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	for _, l := range said {
		if strings.Contains(l, "home DERP changing") {
			t.Fatalf("a homeless node said %q", l)
		}
	}
	if len(said) == 0 {
		t.Fatal("the node said nothing at all, so this proves nothing")
	}
}

// A node with relays homes at one it reaches and, where it reaches none, is
// homeless rather than homed at a STUN server, which nothing connects to and
// which the engine would ask again every few seconds.
func TestAHomeIsARelayReachedOrNone(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	gone, err := net.Listen("tcp", net.JoinHostPort(hostAddr(t).String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	deadAt := netip.MustParseAddrPort(gone.Addr().String())
	gone.Close()
	dead := Relay{Region: 7, HostName: "abcdefgh.relay.juist.invalid", Addrs: []netip.AddrPort{deadAt},
		STUNPort: deadAt.Port(), CertHash: [32]byte{1}}
	if err := m.SetRelays([]Relay{dead}); err != nil {
		t.Fatal(err)
	}
	m.magic.ReSTUN("test")
	waitUntil(t, 15*time.Second, "homeless with no relay reached", m.homeless.Load)
	time.Sleep(time.Second)
	before := srv.seen.Load()
	const window = 12 * time.Second
	time.Sleep(window)
	// At most one netcheck by stunEvery and one after homedAgain, each
	// asking the one server at most twice.
	if asked := srv.seen.Load() - before; asked > 4 {
		t.Errorf("%d STUN requests in %v with no relay reached", asked, window)
	}

	cert, err := relay.NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	start := func(port uint16) *relay.Server {
		s, err := relay.New(relay.Options{Port: port, Certificate: cert, Admit: func([32]byte) bool { return true }, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	s := start(0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay reached", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })

	// The relay going and coming back at its address: homeless meanwhile,
	// and homed again once a report reaches it, though the map is the same.
	s.Close()
	m.magic.ReSTUN("test")
	waitUntil(t, 30*time.Second, "homeless with the relay gone", m.homeless.Load)
	for range 3 { // reports alike, homeless, which the engine passes on once
		m.magic.ReSTUN("test")
		time.Sleep(time.Second)
	}
	start(live.Addrs[0].Port())
	waitUntil(t, 30*time.Second, "a home at the relay back", func() bool {
		m.magic.ReSTUN("test")
		return m.HomeRelay() == 8 && !m.homeless.Load()
	})
}

// A connection the engine opens to the STUN servers' region is dropped: it
// never comes up, and magicsock, whose home connect may run after it was told
// it has none, would measure again at each failed reconnect until it drops
// idle connections a minute later.
func TestAConnectionToTheSTUNRegionIsDropped(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	var added, dropped atomic.Int64
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) {
		o.STUN = []string{srv.addr()}
		logf := o.Logf
		o.Logf = func(format string, args ...any) {
			if format == addingDERPConn {
				added.Add(1)
			}
			if strings.HasPrefix(format, "magicsock: closing connection to derp-") && slices.Contains(args, any("derp-region-redefined")) {
				dropped.Add(1)
			}
			logf(format, args...)
		}
	})
	m := n.mgr.(*tsManager)
	waitUntil(t, 15*time.Second, "homeless with STUN alone", m.homeless.Load)
	var region tailcfg.DERPRegionID
	for r := range *m.stunRegions.Load() {
		region = r
	}
	// A connection made while homeless, as that late home connect's, which
	// SetHomeless can no longer close.
	before := added.Load()
	if _, err := m.magic.SendDERPPacketTo(key.NewNode().Public(), region, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if added.Load() == before {
		t.Fatal("no connection to the STUN region made")
	}
	waitUntil(t, 10*time.Second, "the connection to the STUN region dropped", func() bool { return m.magic.DERPs() == 0 })

	// Opened again with every packet, as to a peer whose home has the STUN
	// region's number, it is dropped once a stunDropEvery.
	dropped.Store(0)
	const sending = 3 * stunDropEvery
	for end := time.Now().Add(sending); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		m.magic.SendDERPPacketTo(key.NewNode().Public(), region, []byte("x"))
	}
	if d := dropped.Load(); d > int64(sending/stunDropEvery)+1 {
		t.Errorf("dropped %d times in %v", d, sending)
	}
}

func waitUntil(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(limit); !ok(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}
