package conn

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func setSelf(t *testing.T, n *node) {
	t.Helper()
	if err := n.mgr.SetSelf(Self{ID: n.id, NodeKey: n.nodeKey, DiscoKey: n.discoKey, Addrs: n.addrs}); err != nil {
		t.Fatalf("SetSelf: %v", err)
	}
}

func setPeer(t *testing.T, n, other *node) {
	t.Helper()
	if err := n.mgr.SetPeers([]Peer{other.peer()}); err != nil {
		t.Fatal(err)
	}
}

// A node given a new key on its running data plane is reached under it as
// soon as its peer holds it, and no longer under the old one.
func TestANewKeyInPlace(t *testing.T) {
	t.Parallel()
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	setPeer(t, a, b)
	setPeer(t, b, a)
	if _, ok := pingUntil(t, b, a.pingAddr(), 30*time.Second); !ok {
		t.Fatal("b did not reach a")
	}
	port := a.mgr.LocalPort()

	old := a.peer()
	a.nodeKey = key.NewNode()
	setSelf(t, a)
	if a.mgr.LocalPort() != port {
		t.Error("a new key rebound the port")
	}
	if res, ok := pingUntil(t, b, a.pingAddr(), 6*time.Second); ok {
		t.Fatalf("a was reached under the key it gave up: %+v", res)
	}
	setPeer(t, b, a)
	if _, ok := pingUntil(t, b, a.pingAddr(), 30*time.Second); !ok {
		t.Fatal("b did not reach a under its new key")
	}
	if err := b.mgr.SetPeers([]Peer{old}); err != nil {
		t.Fatal(err)
	}
	if res, ok := pingUntil(t, b, a.pingAddr(), 6*time.Second); ok {
		t.Fatalf("a was reached under the key it gave up: %+v", res)
	}
}

// A node given new addresses on its running data plane answers on them,
// and no longer on the ones it gave up.
func TestNewAddressesInPlace(t *testing.T) {
	t.Parallel()
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	setPeer(t, a, b)
	setPeer(t, b, a)
	if _, ok := pingUntil(t, b, a.pingAddr(), 30*time.Second); !ok {
		t.Fatal("b did not reach a")
	}
	// The engine's own echo answers IPv4 alone.
	gone := a.pingAddr()
	a.addrs = []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32"), a.addrs[1]}
	setSelf(t, a)
	setPeer(t, b, a)
	if _, ok := pingUntil(t, b, a.pingAddr(), 10*time.Second); !ok {
		t.Errorf("a does not answer on %v", a.pingAddr())
	}
	// b still sends a what is for the old address.
	stale := a.peer()
	stale.Addrs = append(stale.Addrs, netip.PrefixFrom(gone, 32))
	if err := b.mgr.SetPeers([]Peer{stale}); err != nil {
		t.Fatal(err)
	}
	if res, ok := pingUntil(t, b, gone, 4*time.Second); ok {
		t.Errorf("a answers on %v, which it gave up: %+v", gone, res)
	}
}

func TestSetSelfRefuses(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	setPeer(t, a, b)
	self := func() Self { return Self{ID: a.id, NodeKey: a.nodeKey, DiscoKey: a.discoKey, Addrs: a.addrs} }
	for name, s := range map[string]func(*Self){
		"another ID":        func(s *Self) { s.ID = 3 },
		"another disco key": func(s *Self) { s.DiscoKey = key.NewDisco() },
		"no key":            func(s *Self) { s.NodeKey = key.NodePrivate{} },
		"no address":        func(s *Self) { s.Addrs = nil },
		"a peer's address":  func(s *Self) { s.Addrs = append(s.Addrs, b.addrs[0]) },
		"a peer's key":      func(s *Self) { s.NodeKey = b.nodeKey },
	} {
		next := self()
		s(&next)
		if err := a.mgr.SetSelf(next); err == nil {
			t.Errorf("%s: SetSelf took it", name)
		}
	}
	if m := a.mgr.(*tsManager); !m.self.NodeKey.Equal(a.nodeKey) || len(m.self.Addrs) != 2 {
		t.Error("a refused Self was kept")
	}
}

// A peer that took a new key, with no relay to fall back on, is reached as
// soon as disco proves the path: the first handshake waits for it rather
// than going nowhere and waiting out WireGuard's five-second retry.
func TestANewKeyIsReachedAtOnce(t *testing.T) {
	// Not parallel: it bounds a latency, which contention stretches.
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	setPeer(t, a, b)
	setPeer(t, b, a)
	if _, ok := pingUntil(t, b, a.pingAddr(), 30*time.Second); !ok {
		t.Fatal("b did not reach a")
	}
	a.nodeKey = key.NewNode()
	setSelf(t, a)
	setPeer(t, b, a)
	start := time.Now()
	for {
		if _, ok := ping(t, b, a.pingAddr(), 300*time.Millisecond); ok {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("b did not reach a under its new key")
		}
	}
	if took := time.Since(start); took > 4500*time.Millisecond {
		t.Errorf("b reached a under its new key after %v, a handshake's retry", took)
	}
}

func TestTheHoldOutlastsTheLastPing(t *testing.T) {
	var last time.Duration
	for _, w := range warmSchedule {
		last += w
	}
	if unprovenWait <= last {
		t.Errorf("held %v, ending before the last ping at %v", unprovenWait, last)
	}
}

func TestWhatWaitsForAProvenPath(t *testing.T) {
	ep := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	for _, tc := range []struct {
		name   string
		p      Peer
		relays bool
		want   bool
	}{
		{"no relay at all", Peer{Endpoints: ep}, false, true},
		{"a home relay this node has", Peer{Endpoints: ep, HomeRelay: 1}, true, false},
		{"a home relay this node has none of", Peer{Endpoints: ep, HomeRelay: 1}, false, true},
		{"a relay this peer does not use", Peer{Endpoints: ep}, true, true},
		{"no address to try", Peer{}, false, false},
	} {
		if got := heldUnproven(tc.p, tc.relays); got != tc.want {
			t.Errorf("%s: held %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A peer no path is proven to is sent nothing for a while, and then all
// the same: the hold never blackholes it; removed, it is forgotten.
func TestAnUnprovenPeerIsHeldForAWhileAlone(t *testing.T) {
	defer func(w time.Duration) { unprovenWait = w }(unprovenWait)
	unprovenWait = 300 * time.Millisecond
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	nowhere := Peer{ID: 2, NodeKey: key.NewNode().Public(), DiscoKey: key.NewDisco().Public(),
		Addrs:     []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}}
	if err := a.mgr.SetPeers([]Peer{nowhere}); err != nil {
		t.Fatal(err)
	}
	m := a.mgr.(*tsManager)
	to := netip.MustParseAddr("100.64.0.2")
	if _, ok := m.sendTo(to); ok {
		t.Fatal("sent to a peer before any path was proven")
	}
	time.Sleep(unprovenWait + 50*time.Millisecond)
	if nk, ok := m.sendTo(to); !ok || nk != nowhere.NodeKey {
		t.Fatal("a peer no path was proven to stays held past the bound")
	}
	if err := a.mgr.SetPeers([]Peer{nowhere}); err != nil {
		t.Fatal(err)
	}
	if err := a.mgr.SetPeers(nil); err != nil {
		t.Fatal(err)
	}
	m.unproven.Range(func(k, _ any) bool {
		t.Errorf("a removed peer is still held: %v", k)
		return true
	})
}

type recordingGuard struct{ own [][]netip.Addr }

func (g *recordingGuard) guardOverlay(own, _ []netip.Addr) error {
	g.own = append(g.own, own)
	return nil
}

// New addresses are guarded with the old before the router adds them; what
// only goes needs no guard ahead.
func TestNewAddressesAreGuardedAhead(t *testing.T) {
	g := &recordingGuard{}
	m := &tsManager{inGuard: g}
	m.state.Store(&peerState{})
	p := netip.MustParsePrefix
	old := []netip.Prefix{p("100.64.0.1/32"), p("fd7a:115c:a1e0::1/128")}
	if err := m.guardAhead(old, []netip.Prefix{p("fd7a:115c:a1e0::1/128")}); err != nil || len(g.own) != 0 {
		t.Fatalf("addresses that only go were guarded ahead: %v", g.own)
	}
	if err := m.guardAhead(old, append(slices.Clone(old), p("10.7.0.1/32"))); err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1"), netip.MustParseAddr("10.7.0.1")}
	if len(g.own) != 1 || !slices.Equal(g.own[0], want) {
		t.Fatalf("guarded %v ahead, want %v", g.own, want)
	}
}
