package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// node is a test node: its keys, its overlay addresses, and its live manager.
// Each carries both families the design assigns; tests ping over v4, see
// pingAddr.
type node struct {
	id       uint64
	nodeKey  key.NodePrivate
	discoKey key.DiscoPrivate
	addrs    []netip.Prefix
	endpoint netip.Addr
	mgr      Manager
}

func newNode(t *testing.T, id uint64, v4, v6 string) *node {
	t.Helper()
	return startNode(t, id, v4, v6, nil)
}

// startNode builds and starts a test node. mutate, if non-nil, adjusts the
// Options before the manager starts — see newEchoNode.
func startNode(t *testing.T, id uint64, v4, v6 string, mutate func(*Options)) *node {
	t.Helper()
	n := &node{
		id:       id,
		nodeKey:  key.NewNode(),
		discoKey: key.NewDisco(),
		addrs: []netip.Prefix{
			netip.MustParsePrefix(v4),
			netip.MustParsePrefix(v6),
		},
		endpoint: hostAddr(t),
	}
	opts := Options{
		Self: Self{
			ID:       id,
			NodeKey:  n.nodeKey,
			DiscoKey: n.discoKey,
			Addrs:    n.addrs,
		},
		RespondToPing: true,
		Debug:         true,
		Logf:          logger.WithPrefix(t.Logf, fmt.Sprintf("n%d: ", id)),
	}
	if mutate != nil {
		mutate(&opts)
	}
	mgr, err := New(opts)
	if err != nil {
		t.Fatalf("starting node %d: %v", id, err)
	}
	t.Cleanup(func() { mgr.Close() })
	n.mgr = mgr
	return n
}

// peer renders n as a Peer reachable on loopback, the way the reconciler will
// render it from membership-log state plus gossiped endpoint records.
func (n *node) peer() Peer {
	return Peer{
		ID:        n.id,
		NodeKey:   n.nodeKey.Public(),
		DiscoKey:  n.discoKey.Public(),
		Addrs:     n.addrs,
		Endpoints: []netip.AddrPort{netip.AddrPortFrom(n.endpoint, n.mgr.LocalPort())},
	}
}

// hostAddr is this host's primary address. Loopback is not usable: Tailscale's
// netns binds UDP sockets to the default interface, so a datagram to 127.0.0.1
// leaves through it and never arrives.
func hostAddr(t *testing.T) netip.Addr {
	t.Helper()
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1; no packet is sent
	if err != nil {
		t.Fatalf("cannot determine this host's address: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}

// pingAddr must be the v4 address: the engine's RespondToPing helper panics on
// an ICMPv6 echo. Both families are asserted in echotun_test.go, whose nodes
// answer from their own fake TUN.
func (n *node) pingAddr() netip.Addr { return n.addrs[0].Addr() }

// ping sends one overlay ICMP echo and reports whether it was answered.
func ping(t *testing.T, from *node, to netip.Addr, timeout time.Duration) (PingResult, bool) {
	t.Helper()
	res := make(chan PingResult, 1)
	from.mgr.Ping(to, func(r PingResult) {
		select {
		case res <- r:
		default:
		}
	})
	select {
	case r := <-res:
		return r, r.Err == ""
	case <-time.After(timeout):
		return PingResult{Err: "timeout waiting for ping callback"}, false
	}
}

// pingUntil retries because the first packet primes a disco and a WireGuard
// handshake; nothing is expected to answer instantly.
func pingUntil(t *testing.T, from *node, to netip.Addr, deadline time.Duration) (PingResult, bool) {
	t.Helper()
	until := time.Now().Add(deadline)
	var last PingResult
	for time.Now().Before(until) {
		r, ok := ping(t, from, to, 2*time.Second)
		if ok {
			return r, true
		}
		last = r
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("last ping result: err=%q", last.Err)
	return last, false
}

// TestTwoNodeOverlayPing is milestone M0: two independently configured nodes
// bring up a WireGuard tunnel through the embedded engine and exchange an
// overlay ICMP echo, with no coordination server and no relay of any kind.
func TestTwoNodeOverlayPing(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")

	// The reconciler passes the full authorized set, which includes the
	// local node itself: a matching self entry must be tolerated. (A
	// diverging one is refused — see validate_test.go.)
	if err := a.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
		t.Fatalf("a.SetPeers: %v", err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
		t.Fatalf("b.SetPeers: %v", err)
	}

	res, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second)
	if !ok {
		t.Fatal("a could not ping b over the overlay")
	}
	// Direct-only (no relay) is asserted by TestNoThirdPartyEgress: the
	// ICMP ping result carries no path information to assert on here.
	t.Logf("a -> b: %v", res.Latency)
}

// A peer that restarts keeps its node key and draws a new disco key; the
// sessions its old process held are dead, and nothing in the engine discards
// them but conn. Without that, a's traffic to it goes nowhere until the
// sessions expire minutes later.
func TestARestartedPeerIsReachedAtOnce(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	for _, n := range []*node{a, b} {
		if err := n.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second); !ok {
		t.Fatal("a could not ping b before the restart")
	}

	b.mgr.Close()
	b.discoKey = key.NewDisco()
	mgr, err := New(Options{
		Self:          Self{ID: b.id, NodeKey: b.nodeKey, DiscoKey: b.discoKey, Addrs: b.addrs},
		RespondToPing: true,
		Logf:          logger.WithPrefix(t.Logf, "n2': "),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close() })
	b.mgr = mgr
	// b first, so a's first probes find it knowing a.
	for _, n := range []*node{b, a} {
		if err := n.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
			t.Fatal(err)
		}
	}
	// Time for the path warm-up, so a handshake is not dropped for want of
	// one and what is left is the sessions.
	time.Sleep(time.Second)
	start := time.Now()
	if _, ok := pingUntil(t, a, b.pingAddr(), 10*time.Second); !ok {
		t.Fatal("a could not reach b after b restarted")
	}
	t.Logf("reached the restarted peer after %v", time.Since(start))
}

// TestSetPeersAfterClose pins the shutdown contract: Close is idempotent, and
// a SetPeers that loses the race with Close must refuse rather than drive a
// torn-down engine.
func TestSetPeersAfterClose(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	if err := a.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := a.mgr.SetPeers([]Peer{b.peer()})
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("SetPeers after Close: got %v, want a 'closed' error", err)
	}
	if err := a.mgr.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestNonMemberIsDenied is the property everything else rests on: a node
// absent from the peer set cannot exchange an overlay packet, even knowing a
// member's address and endpoint.
func TestNonMemberIsDenied(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	outsider := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")

	// a and b are members of each other. Neither has ever heard of outsider.
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatalf("a.SetPeers: %v", err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatalf("b.SetPeers: %v", err)
	}
	// The outsider knows everything about b except how to be authorized.
	if err := outsider.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatalf("outsider.SetPeers: %v", err)
	}

	// Control: the mesh must actually work, or the negative result below
	// proves nothing.
	if _, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second); !ok {
		t.Fatal("control ping a->b failed; the negative result would be meaningless")
	}

	if res, ok := ping(t, outsider, b.pingAddr(), 10*time.Second); ok {
		t.Fatalf("non-member reached a member over the overlay: %+v", res)
	}
}

// TestListenPortInUse: a port the caller asked for and the engine could not
// bind must fail the manager rather than moving the data plane silently. An
// operator who passes a port has usually opened it in a firewall, and the
// symptom of the move is that nothing connects.
func TestListenPortInUse(t *testing.T) {
	// Held on udp4 because that is the socket magicsock.LocalPort reports,
	// and the port the endpoint announcements are built from.
	held, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("holding a port: %v", err)
	}
	defer held.Close()
	port := uint16(held.LocalAddr().(*net.UDPAddr).Port)
	before := socketInodes(t)

	mgr, err := New(Options{
		Self: Self{
			ID:       1,
			NodeKey:  key.NewNode(),
			DiscoKey: key.NewDisco(),
			Addrs:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		ListenPort: port,
		Logf:       t.Logf,
	})
	if err == nil {
		mgr.Close()
		t.Fatalf("New took port %d while it was in use, and reported no error; "+
			"it must refuse rather than bind somewhere else", port)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(port)) {
		t.Errorf("the error does not name the port that could not be bound (%d): %v", port, err)
	}
	if !errors.Is(err, ErrPortTaken) {
		t.Errorf("the error is not ErrPortTaken: %v", err)
	}
	// The engine had started, so its sockets are what shows it was torn down.
	var leaked []uint64
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		leaked = leaked[:0]
		for ino := range socketInodes(t) {
			if !before[ino] {
				leaked = append(leaked, ino)
			}
		}
		if len(leaked) == 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(leaked) > 0 {
		t.Fatalf("a failed New left %d sockets open", len(leaked))
	}
}

// A probe is answered by the peer's data plane itself, so it proves the tunnel
// where the peer answers no ICMP, and the handshake it causes shows in
// Tunnels. A peer that is gone leaves it unanswered.
func TestProbeProvesTheTunnel(t *testing.T) {
	quiet := func(o *Options) { o.RespondToPing = false }
	a := startNode(t, 1, "198.18.0.1/32", "fd7a:115c:a1e0::1/128", quiet)
	b := startNode(t, 2, "198.18.0.2/32", "fd7a:115c:a1e0::2/128", quiet)
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatal(err)
	}
	if hs := a.mgr.Tunnels()[b.id].LastHandshake; !hs.IsZero() {
		t.Fatalf("a handshake at %v before any traffic", hs)
	}
	probe := func() bool {
		res := make(chan bool, 1)
		a.mgr.Probe(b.pingAddr(), 2*time.Second, func(ok bool) { res <- ok })
		return <-res
	}
	answered := false
	for deadline := time.Now().Add(15 * time.Second); !answered && time.Now().Before(deadline); {
		answered = probe()
	}
	if !answered {
		t.Fatal("the probe was never answered")
	}
	if _, ok := ping(t, a, b.pingAddr(), time.Second); ok {
		t.Fatal("the peer answered ICMP, so the probe proved nothing beyond a ping")
	}
	if a.mgr.Tunnels()[b.id].LastHandshake.IsZero() {
		t.Fatal("an answered probe left no handshake")
	}

	b.mgr.Close()
	if probe() {
		t.Fatal("a closed peer answered the probe")
	}
}
