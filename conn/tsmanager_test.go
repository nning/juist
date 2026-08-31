package conn

import (
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
//
// Each node carries both families the design assigns (docs/04-architecture.md):
// a v6 ULA address derived from its identity key, and an explicit v4 address.
// Tests ping over v4 — see pingAddr.
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

// hostAddr is this host's primary address. Loopback is not usable here:
// Tailscale's netns binds its UDP sockets to the default interface, so a
// datagram addressed to 127.0.0.1 is sent out that interface and never
// arrives.
func hostAddr(t *testing.T) netip.Addr {
	t.Helper()
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1; no packet is sent
	if err != nil {
		t.Fatalf("cannot determine this host's address: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}

// pingAddr is the address tests ping when the node was built by newNode. It
// must be the v4 one: the engine's RespondToPing helper calls ICMP4Header
// unconditionally on anything IsEchoRequest matches, so an ICMPv6 echo panics
// it. That is scaffolding for TUN-less tests only — nothing in the product
// depends on it. Both families are asserted in echotun_test.go, whose nodes
// answer echoes from their own fake TUN instead.
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

// TestNonMemberIsDenied is the property everything else rests on: holding
// valid WireGuard keys is not membership. A node absent from the peer set
// cannot exchange a single overlay packet, even knowing the address and
// endpoint of a member.
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

// TestListenPortInUse asserts that a port the caller asked for and the engine
// could not bind fails the manager, rather than moving the data plane
// somewhere the caller was never told about.
//
// magicsock treats ListenPort as a preference: bindSocket's candidate list
// always ends in 0, so a port already in use costs one log line and an
// OS-assigned port. An operator who passes a port has usually opened it in a
// firewall or forwarded it at a NAT, and the symptom of the silent move is
// that nothing connects, with the cause far up a verbose log.
func TestListenPortInUse(t *testing.T) {
	// Held on udp4 because that is the socket magicsock.LocalPort reports,
	// and the port the endpoint announcements are built from.
	held, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("holding a port: %v", err)
	}
	defer held.Close()
	port := uint16(held.LocalAddr().(*net.UDPAddr).Port)

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
}
