//go:build linux

package conn

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"tailscale.com/types/key"
)

// TestNetnsOverlayCarriesTraffic is M3a exit criterion (1)
// (docs/05-roadmap.md): two nodes, each with a real device in its own
// namespace, exchange ICMP over both families and carry a TCP stream, driven
// by ordinary host tools rather than the engine's internal ping. The tap also
// closes the M0 egress criterion's gap, by watching what actually left.
func TestNetnsOverlayCarriesTraffic(t *testing.T) {
	lab := newNetnsLab(t)
	a := lab.addNode("a", 1)
	b := lab.addNode("b", 2)

	// Tapping before either node starts, so nothing a node does at startup —
	// a netcheck, a relay connection — happens unobserved.
	tap := lab.tapEgress(a)
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, tcpEchoPort)

	// Both families. The v6 ULA is the design's primary address, and the one
	// the Linux router skips silently where the kernel has no IPv6 — a skip
	// that would show up here as an unreachable peer, not as a passing test.
	for _, pfx := range b.addrs {
		if err := a.pingUntil(pfx.Addr(), 60*time.Second); err != nil {
			t.Fatalf("a could not reach b at %v over the overlay: %v", pfx.Addr(), err)
		}
	}
	// The reverse direction, now that the path is up: a tunnel that carries
	// traffic only one way is not a tunnel.
	for _, pfx := range a.addrs {
		if err := b.pingUntil(pfx.Addr(), 30*time.Second); err != nil {
			t.Errorf("b could not reach a at %v over the overlay: %v", pfx.Addr(), err)
		}
	}

	// A megabyte of TCP over the v6 ULA: enough segments that the MTU the
	// device was created with has to be right for it to complete.
	streamTCP(t, a, netip.AddrPortFrom(b.addrs[1].Addr(), tcpEchoPort), 1<<20)

	if strangers := tap.strangers(); len(strangers) > 0 {
		t.Errorf("node a sent packets to %v; the data plane must reach no third party", strangers)
	}
}

// TestNetnsDefaultDenySurvivesTheRouter is M3a exit criterion (2): a node
// holding valid WireGuard keys but absent from the log — or removed from it —
// gets no route and no handshake, against a real device and routing table.
// The filter entry the criterion also names is asserted in filter_test.go.
func TestNetnsDefaultDenySurvivesTheRouter(t *testing.T) {
	lab := newNetnsLab(t)
	a := lab.addNode("a", 1)
	b := lab.addNode("b", 2)
	outsider := lab.addNode("x", 3)

	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	// The outsider knows a's keys, addresses and endpoint, and considers
	// itself a's peer. Only a's own peer set says otherwise.
	outsider.start([]*netnsNode{a}, 0)

	// Control: the mesh must work, or the negative results below prove
	// nothing.
	if err := a.pingUntil(b.addrs[0].Addr(), 60*time.Second); err != nil {
		t.Fatalf("control ping a->b failed; a negative result would be meaningless: %v", err)
	}

	// The outsider's own control. Without it every ping below could be
	// failing for a reason that has nothing to do with membership — a veth
	// that never came up would read exactly like default-deny. Its underlay
	// reaches a's, on the same bridge; only the overlay must not.
	if err := outsider.pingUntil(a.underlay, 15*time.Second); err != nil {
		t.Fatalf("the outsider cannot reach %v on the underlay, so its silence on "+
			"the overlay would prove nothing: %v", a.underlay, err)
	}
	for _, pfx := range a.addrs {
		mustNotReach(t, outsider, pfx.Addr(), 10*time.Second)
	}
	routes := a.routes()
	for _, pfx := range b.addrs {
		if !slices.Contains(routes, pfx) {
			t.Errorf("member route %v missing from a's device; have %v", pfx, routes)
		}
	}
	for _, pfx := range outsider.addrs {
		if slices.Contains(routes, pfx) {
			t.Errorf("non-member prefix %v was routed into a's device", pfx)
		}
	}

	// Removal is the other half of the criterion. The tunnel is established
	// in this direction first, so that its loss below is the removal's doing
	// rather than something that never worked.
	for _, pfx := range a.addrs {
		if err := b.pingUntil(pfx.Addr(), 30*time.Second); err != nil {
			t.Fatalf("b could not reach a at %v before the removal: %v", pfx.Addr(), err)
		}
	}
	a.setPeers("none")
	for _, pfx := range a.addrs {
		if err := unreachableWithin(b, pfx.Addr(), 20*time.Second); err != nil {
			t.Error(err)
		}
	}
	routes = a.routes()
	for _, pfx := range b.addrs {
		if slices.Contains(routes, pfx) {
			t.Errorf("route %v to a removed peer survived on a's device", pfx)
		}
	}
}

// streamTCP runs the TCP client helper inside a node's namespace and requires
// the whole stream back.
func streamTCP(t *testing.T, from *netnsNode, to netip.AddrPort, size int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating this test binary: %v", err)
	}
	cmd := from.lab.exec(from, self, "-test.run", "^TestHelperNetnsTCP$", "-test.timeout", "5m")
	cmd.Env = append(os.Environ(),
		netnsHelperEnv+"=tcp",
		envTCPDial+"="+to.String(),
		envTCPBytes+"="+strconv.Itoa(size),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("TCP stream from %s to %v: %v\n%s", from.name, to, err, out)
	}
}

// mustNotReach requires every ping in the window to fail. One failed ping
// proves little — a working path may simply not be up yet — so this keeps
// trying for at least as long as a working path would have taken to appear.
func mustNotReach(t *testing.T, from *netnsNode, to netip.Addr, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if err := from.ping(to); err == nil {
			t.Fatalf("%s reached %v over the overlay; it is not a member", from.name, to)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// unreachableWithin waits for a path to stop working, then requires it to stay
// that way rather than flicker back.
func unreachableWithin(from *netnsNode, to netip.Addr, within time.Duration) error {
	deadline := time.Now().Add(within)
	for from.ping(to) == nil {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s still reaches %v %v after the peer was removed", from.name, to, within)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		if err := from.ping(to); err == nil {
			return fmt.Errorf("%s reached %v again after it had gone unreachable", from.name, to)
		}
	}
	return nil
}

// TestNetnsPeerEncoding covers the lab's own wire format, which otherwise runs
// only in the privileged job: a typo would show up there as a node coming up
// with the wrong peers.
func TestNetnsPeerEncoding(t *testing.T) {
	discoPriv, discoPub, err := NewDiscoKey()
	if err != nil {
		t.Fatalf("generating a disco key: %v", err)
	}
	n := &netnsNode{
		id:        7,
		nodeKey:   key.NewNode(),
		discoPriv: discoPriv,
		discoPub:  discoPub,
		underlay:  netip.MustParseAddr("10.77.0.7"),
		addrs: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.7/32"),
			netip.MustParsePrefix("fd7a:115c:a1e0::7/128"),
		},
	}
	peers, err := decodePeers(encodePeers([]*netnsNode{n}))
	if err != nil {
		t.Fatalf("decodePeers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("decoded %d peers, want 1", len(peers))
	}
	got := peers[0]
	if got.ID != n.id {
		t.Errorf("ID = %d, want %d", got.ID, n.id)
	}
	if got.NodeKey != n.nodeKey.Public() {
		t.Errorf("node key = %v, want %v", got.NodeKey, n.nodeKey.Public())
	}
	if got.DiscoKey != DiscoPublicFromRaw32(n.discoPub) {
		t.Errorf("disco key = %v, want the generated one", got.DiscoKey)
	}
	if !slices.Equal(got.Addrs, n.addrs) {
		t.Errorf("addrs = %v, want %v", got.Addrs, n.addrs)
	}
	want := netip.AddrPortFrom(n.underlay, underlayPort)
	if len(got.Endpoints) != 1 || got.Endpoints[0] != want {
		t.Errorf("endpoints = %v, want [%v]", got.Endpoints, want)
	}

	// An empty peer set is how a removed member is expressed, so it must
	// decode to no peers rather than to one malformed one.
	if peers, err := decodePeers(""); err != nil || peers != nil {
		t.Errorf("decodePeers(\"\") = %v, %v; want nil, nil", peers, err)
	}
}

// TestNetnsFrameDsts pins the egress tap's parser. It reads raw frames, so a
// wrong offset would not fail — it would report a plausible wrong address, or
// silently see no traffic at all and pass.
func TestNetnsFrameDsts(t *testing.T) {
	v4 := make([]byte, 34)
	copy(v4[12:], []byte{0x08, 0x00})
	copy(v4[30:], []byte{93, 184, 216, 34})
	v6 := make([]byte, 54)
	copy(v6[12:], []byte{0x86, 0xdd})
	copy(v6[38:], netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946").AsSlice())

	// An ARP request for a third party: what a host emits, and all it emits,
	// when its route to that address is on-link.
	arp := make([]byte, 42)
	copy(arp[12:], []byte{0x08, 0x06})
	copy(arp[14:], []byte{0, 1, 0x08, 0x00, 6, 4, 0, 1})
	copy(arp[38:], []byte{93, 184, 216, 34})

	// A neighbour solicitation for a third party, to a solicited-node
	// multicast address: the destination is housekeeping, the target is not.
	ns := make([]byte, 78)
	copy(ns[12:], []byte{0x86, 0xdd})
	ns[20] = 58 // ICMPv6
	copy(ns[38:], netip.MustParseAddr("ff02::1:ffc8:1946").AsSlice())
	ns[54] = 135 // neighbour solicitation
	copy(ns[62:], netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946").AsSlice())

	for _, tc := range []struct {
		name  string
		frame []byte
		want  []string // empty: nothing this frame is aimed at
	}{
		{"ipv4", v4, []string{"93.184.216.34"}},
		{"ipv6", v6, []string{"2606:2800:220:1:248:1893:25c8:1946"}},
		{"arp request", arp, []string{"93.184.216.34"}},
		{"neighbour solicitation", ns,
			[]string{"ff02::1:ffc8:1946", "2606:2800:220:1:248:1893:25c8:1946"}},
		{"truncated arp", arp[:20], nil},
		{"truncated ipv4", v4[:20], nil},
		{"runt", []byte{1, 2, 3}, nil},
	} {
		got := frameDsts(tc.frame)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i, w := range tc.want {
			if got[i] != netip.MustParseAddr(w) {
				t.Errorf("%s: address %d is %v, want %s", tc.name, i, got[i], w)
			}
		}
	}
}
