package conn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
)

var (
	mdns6Group = ap("[ff02::fb]:5353")
	v6A        = netip.MustParseAddr("fd7a:115c:a1e0::1")
	v6B        = netip.MustParseAddr("fd7a:115c:a1e0::2")
	v6C        = netip.MustParseAddr("fd7a:115c:a1e0::3")
	llA, llB   = linkLocal(v6A), linkLocal(v6B)
	llC        = linkLocal(v6C)
)

func mdns6From(src netip.Addr) []byte { return udpPacket(netip.AddrPortFrom(src, 5353), mdns6Group) }

func TestALinkLocalIsTheOverlayAddresssLowHalf(t *testing.T) {
	if got, want := linkLocal(netip.MustParseAddr("fd12:3456:789a:bcde:1:2:3:4")), netip.MustParseAddr("fe80::1:2:3:4"); got != want {
		t.Errorf("linkLocal = %v, want %v", got, want)
	}
	if linkLocal(addrA).IsValid() {
		t.Error("an IPv4 address gave a link-local one")
	}
}

func TestAGroupDatagram6UnwrapsAsSent(t *testing.T) {
	for _, src := range []netip.Addr{llB, v6B} {
		inner := mdns6From(src)
		inner[7] = 255
		got, ok := unwrapGroup6(wrapGroup6(v6B, v6A, inner), v6B, llB, v6A)
		if !ok || !bytes.Equal(got, inner) {
			t.Fatalf("from %v: unwrapped %x, %v; want %x", src, got, ok, inner)
		}
	}
	if outer := parsed(wrapGroup6(v6B, v6A, mdns6From(llB))); outer.IPProto != ipv6Encap || outer.Src.Addr() != v6B || outer.Dst.Addr() != v6A {
		t.Fatalf("wrapped as %v", outer)
	}
}

// udp6With is a UDP datagram from src to dst behind a header of type next,
// as an extension header puts it.
func udp6With(next byte, src, dst netip.AddrPort) []byte {
	b := udpPacket(src, dst)
	ext := []byte{byte(ipproto.UDP), 0, 0, 0, 0, 0, 0, 0}
	out := slices.Concat(b[:40], ext, b[40:])
	out[6] = next
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	return out
}

func TestOnlyAMembersOwnGroupDatagram6Unwraps(t *testing.T) {
	flowLabel := wrapGroup6(v6B, v6A, mdns6From(llB))
	flowLabel[3] = 1
	for name, b := range map[string][]byte{
		"another member's link-local":     wrapGroup6(v6B, v6A, mdns6From(llC)),
		"another member's address":        wrapGroup6(v6B, v6A, mdns6From(v6C)),
		"a LAN host's link-local":         wrapGroup6(v6B, v6A, mdns6From(netip.MustParseAddr("fe80::1234"))),
		"to a group of global scope":      wrapGroup6(v6B, v6A, udpPacket(netip.AddrPortFrom(llB, 5353), ap("[ff0e::fb]:5353"))),
		"to a group of interface scope":   wrapGroup6(v6B, v6A, udpPacket(netip.AddrPortFrom(llB, 5353), ap("[ff01::fb]:5353"))),
		"to a unicast address":            wrapGroup6(v6B, v6A, udpPacket(netip.AddrPortFrom(llB, 5353), netip.AddrPortFrom(llA, 5353))),
		"TCP to a group":                  wrapGroup6(v6B, v6A, tcpPacket(netip.AddrPortFrom(llB, 5353), mdns6Group, tcpSyn)),
		"MLD":                             wrapGroup6(v6B, v6A, ipPacket(ipproto.ICMPv6, llB, netip.MustParseAddr("ff02::16"), make([]byte, 8))),
		"a DHCPv6 solicit":                wrapGroup6(v6B, v6A, udpPacket(netip.AddrPortFrom(llB, 546), ap("[ff02::1:2]:547"))),
		"to the site's DHCPv6 servers":    wrapGroup6(v6B, v6A, udpPacket(netip.AddrPortFrom(llB, 547), ap("[ff05::1:3]:547"))),
		"to a group's DHCPv6 client port": wrapGroup6(v6B, v6A, udpPacket(netip.AddrPortFrom(llB, 547), ap("[ff02::1]:546"))),
		"a UDP header cut short":          wrapGroup6(v6B, v6A, ipPacket(ipproto.UDP, llB, netip.MustParseAddr("ff02::fb"), []byte{0x14, 0xe9})),
		"a fragment header":               wrapGroup6(v6B, v6A, udp6With(44, netip.AddrPortFrom(llB, 5353), mdns6Group)),
		"a hop-by-hop header":             wrapGroup6(v6B, v6A, udp6With(0, netip.AddrPortFrom(llB, 5353), mdns6Group)),
		"IPv4 inside":                     wrapGroup6(v6B, v6A, mdnsFrom(addrB)),
		"a flow label":                    flowLabel,
		"for another node":                wrapGroup6(v6B, v6C, mdns6From(llB)),
		"from another node":               wrapGroup6(v6C, v6A, mdns6From(llB)),
		"cut short":                       wrapGroup6(v6B, v6A, mdns6From(llB))[:60],
		"longer than its datagram":        append(wrapGroup6(v6B, v6A, mdns6From(llB)), 0),
		"IPv4-wrapped":                    wrapGroup(addrB, addrA, mdns6From(llB)),
		"an IPv4 wrapping of an IPv6 one": wrapGroup(addrB, addrA, wrapGroup6(v6B, v6A, mdns6From(llB))),
	} {
		if _, ok := unwrapGroup6(b, v6B, llB, v6A); ok {
			t.Errorf("%s unwrapped", name)
		}
	}
	if _, ok := unwrapGroup6(wrapGroup6(v6B, v6A, mdns6From(llB)), v6B, netip.Addr{}, v6A); ok {
		t.Error("the link-local of a sender holding none unwrapped")
	}
	if _, ok := unwrapGroup(wrapGroup(addrB, addrA, mdns6From(llB)), addrB, addrA); ok {
		t.Error("IPv6 unwrapped from an IPv4 wrapping")
	}
}

func FuzzUnwrapGroup6(f *testing.F) {
	f.Add(wrapGroup6(v6B, v6A, mdns6From(llB)))
	f.Add(wrapGroup6(v6B, v6A, mdns6From(llC)))
	f.Add(wrapGroup6(v6B, v6A, echo6(llB, allNodes, 128, 7)))
	f.Add(mdns6From(llB))
	f.Fuzz(func(t *testing.T, b []byte) {
		inner, ok := unwrapGroup6(b, v6B, llB, v6A)
		if !ok {
			return
		}
		if src, ok := groupDatagram(inner); !ok || src != v6B && src != llB || inner[0]>>4 != 6 {
			t.Fatalf("unwrapped %x, which is no group datagram of the sender's", inner)
		}
		if !bytes.HasSuffix(b, inner) || len(b) != len(inner)+40 {
			t.Fatalf("unwrapped %x from %x", inner, b)
		}
	})
}

func TestALinkLocalTwoWouldShareIsNeithers(t *testing.T) {
	selfKey := key.NewNode().Public()
	self := withLinkLocal([]netip.Prefix{netip.PrefixFrom(v6A, 128)})
	peer := func(v6 string) Peer {
		return Peer{NodeKey: key.NewNode().Public(), Addrs: []netip.Prefix{netip.MustParsePrefix(v6 + "/128")}}
	}
	unique, twinA, twinB, selfTwin := peer("fd7a:115c:a1e0::2"), peer("fd7a:115c:a1e0:1::5"), peer("fd7a:115c:a1e0:2::5"), peer("fd7a:115c:a1e0:7::1")
	selfEntry := Peer{NodeKey: selfKey, Addrs: []netip.Prefix{netip.PrefixFrom(v6A, 128)}}
	got := withLinkLocals(selfKey, self, []Peer{unique, twinA, twinB, selfTwin, selfEntry})
	want := [][]netip.Prefix{
		{netip.PrefixFrom(v6B, 128), netip.PrefixFrom(llB, 128)},
		twinA.Addrs, twinB.Addrs, selfTwin.Addrs,
		self,
	}
	for i := range got {
		if !slices.Equal(got[i].Addrs, want[i]) {
			t.Errorf("peer %d holds %v, want %v", i, got[i].Addrs, want[i])
		}
	}
	if len(unique.Addrs) != 1 {
		t.Errorf("the caller's peer was changed: %v", unique.Addrs)
	}
}

// This node sends its own IPv6 group datagrams alone, from its overlay or
// link-local address, to groups of link and site scope.
func TestOnlyThisNodesOwnGroupDatagram6sAreSent(t *testing.T) {
	c := &multicaster{sending: make(chan groupSend, 8), sent: rate.NewLimiter(groupRate, groupBurst)}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(v6B, 128)}}}, withLinkLocal([]netip.Prefix{netip.PrefixFrom(v6A, 128)}))
	for name, b := range map[string][]byte{
		"from a LAN host's link-local": mdns6From(netip.MustParseAddr("fe80::1234")),
		"to a group of global scope":   udpPacket(netip.AddrPortFrom(llA, 5353), ap("[ff0e::fb]:5353")),
		"MLD":                          ipPacket(ipproto.ICMPv6, llA, netip.MustParseAddr("ff02::16"), make([]byte, 8)),
		"a DHCPv6 solicit":             udpPacket(netip.AddrPortFrom(llA, 546), ap("[ff02::1:2]:547")),
	} {
		c.out(parsed(b), nil)
		if len(c.sending) != 0 {
			t.Errorf("%s was sent", name)
			<-c.sending
		}
	}
	for _, b := range [][]byte{mdns6From(llA), udpPacket(netip.AddrPortFrom(v6A, 1900), ap("[ff05::c]:1900"))} {
		if c.out(parsed(b), nil); len(c.sending) != 1 {
			t.Fatalf("this node's own group datagram %v was not sent", parsed(b))
		}
		if s := <-c.sending; !bytes.Equal(s.pol.wrap(s.pol.peers[0], s.datagram), wrapGroup6(v6A, v6B, b)) {
			t.Errorf("not wrapped to the peer's overlay address")
		}
	}
}

func isUDPTo(dst netip.Addr) func(*packet.Parsed) bool {
	return func(p *packet.Parsed) bool { return p.IPProto == ipproto.UDP && p.Dst.Addr() == dst }
}

// Through real tunnels, an mDNS query from one member's link-local address
// reaches every other member's host, a LAN host's does not, and an answer
// goes back unicast to the link-local address, as SSDP's does.
func TestAGroupDatagram6ReachesEveryMemberAndIsAnswered(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c, cTUN := groupNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	for _, set := range []struct {
		n     *node
		peers []Peer
	}{{a, []Peer{b.peer(), c.peer()}}, {b, []Peer{a.peer(), c.peer()}}, {c, []Peer{a.peer(), b.peer()}}} {
		if err := set.n.mgr.SetPeers(set.peers); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	lan := netip.MustParseAddr("fe80::1234")
	atA := counting(aTUN, stop, isUDPTo(llA))
	atB := counting(bTUN, stop, groupFrom(llA), groupFrom(lan))
	atC := counting(cTUN, stop, groupFrom(llA), groupFrom(lan))
	sendUntil(t, aTUN, mdns6From(llA), atB[0], atC[0])
	for range 5 {
		aTUN.out <- mdns6From(lan)
	}
	sendUntil(t, bTUN, udpPacket(netip.AddrPortFrom(llB, 1900), netip.AddrPortFrom(llA, 5353)), atA[0])
	time.Sleep(500 * time.Millisecond)
	if n := atB[1].Load() + atC[1].Load(); n != 0 {
		t.Errorf("%d datagrams from a LAN host's link-local crossed", n)
	}
}

// The overlay's guard keeps no link-local address to the tunnel: the LAN's
// own may be one like a member's.
func TestTheGuardTakesNoLinkLocal(t *testing.T) {
	addrs := withLinkLocal([]netip.Prefix{netip.PrefixFrom(addrA, 32), netip.PrefixFrom(v6A, 128)})
	if got := hostAddrs(addrs); !slices.Equal(got, []netip.Addr{addrA, v6A}) {
		t.Errorf("the guard is given %v", got)
	}
}

// A new address of this node's derives the peers' link-locals again, so
// that one a peer shares with it is the peer's no longer.
func TestSetSelfDerivesThePeersLinkLocalsAgain(t *testing.T) {
	a, _ := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, _ := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0:1::7/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	m := a.mgr.(*tsManager)
	if !slices.Contains(m.state.Load().peers[b.nodeKey.Public()].Addrs, netip.PrefixFrom(linkLocal(netip.MustParseAddr("fd7a:115c:a1e0:1::7")), 128)) {
		t.Fatal("the peer holds no link-local")
	}
	moved := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0:2::7/128")}
	if err := m.SetSelf(Self{ID: a.id, NodeKey: a.nodeKey, DiscoKey: a.discoKey, Addrs: moved}); err != nil {
		t.Fatalf("SetSelf: %v", err)
	}
	if got := m.state.Load().peers[b.nodeKey.Public()].Addrs; slices.ContainsFunc(got, func(p netip.Prefix) bool { return p.Addr().IsLinkLocalUnicast() }) {
		t.Errorf("the peer keeps the link-local this node now holds: %v", got)
	}
}

// A peer whose link-local this node held, and holds no longer, has its
// link-local unicast taken: wireguard-go is told of the address again.
func TestAPeerRegainingItsLinkLocalIsReachedAtIt(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0:2::7/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0:1::7/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	llB := linkLocal(netip.MustParseAddr("fd7a:115c:a1e0:1::7"))
	atA := counting(aTUN, stop, isUDPTo(addrA), func(p *packet.Parsed) bool { return p.Src.Addr() == llB })
	sendUntil(t, bTUN, udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:5000")), atA[0])

	a.addrs[1] = netip.MustParsePrefix("fd7a:115c:a1e0::1/128")
	if err := a.mgr.(*tsManager).SetSelf(Self{ID: a.id, NodeKey: a.nodeKey, DiscoKey: a.discoKey, Addrs: a.addrs}); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatal(err)
	}
	sendUntil(t, bTUN, udpPacket(netip.AddrPortFrom(llB, 1900), netip.AddrPortFrom(llA, 5353)), atA[1])
}

var allNodes = netip.MustParseAddr("ff02::1")

// echo6 is an ICMPv6 message of type typ from src to dst, with identifier
// id where an echo.
func echo6(src, dst netip.Addr, typ byte, id uint16) []byte {
	return icmpPacket(src, dst, typ, 0, []byte{byte(id >> 8), byte(id), 0, 1})
}

// An echo request to a group crosses as UDP does; no other ICMPv6 to one
// does, as a router advertisement, neighbour discovery or MLD.
func TestAGroupEchoRequestUnwrapsAndNoOtherICMPv6(t *testing.T) {
	for _, inner := range [][]byte{echo6(llB, allNodes, 128, 7), echo6(v6B, netip.MustParseAddr("ff05::1"), 128, 7)} {
		if got, ok := unwrapGroup6(wrapGroup6(v6B, v6A, inner), v6B, llB, v6A); !ok || !bytes.Equal(got, inner) {
			t.Fatalf("an echo request %v did not unwrap", parsed(inner))
		}
	}
	coded := echo6(llB, allNodes, 128, 7)
	coded[41] = 1
	for name, inner := range map[string][]byte{
		"a router advertisement":     ipPacket(ipproto.ICMPv6, llB, allNodes, append([]byte{134, 0, 0, 0}, make([]byte, 12)...)),
		"a router solicitation":      ipPacket(ipproto.ICMPv6, llB, netip.MustParseAddr("ff02::2"), append([]byte{133, 0, 0, 0}, make([]byte, 4)...)),
		"a neighbour solicitation":   ipPacket(ipproto.ICMPv6, llB, netip.MustParseAddr("ff02::1:ff00:1"), append([]byte{135, 0, 0, 0}, make([]byte, 20)...)),
		"a neighbour advertisement":  ipPacket(ipproto.ICMPv6, llB, allNodes, append([]byte{136, 0, 0, 0}, make([]byte, 20)...)),
		"an MLD report":              ipPacket(ipproto.ICMPv6, llB, netip.MustParseAddr("ff02::16"), append([]byte{143, 0, 0, 0}, make([]byte, 4)...)),
		"an echo reply to a group":   echo6(llB, allNodes, 129, 7),
		"an echo request of code 1":  coded,
		"an echo request cut short":  ipPacket(ipproto.ICMPv6, llB, allNodes, []byte{128, 0, 0, 0}),
		"an echo request to ff0e::1": echo6(llB, netip.MustParseAddr("ff0e::1"), 128, 7),
	} {
		if _, ok := unwrapGroup6(wrapGroup6(v6B, v6A, inner), v6B, llB, v6A); ok {
			t.Errorf("%s unwrapped", name)
		}
		if _, ok := groupDatagram(inner); ok {
			t.Errorf("%s is taken for a group datagram", name)
		}
	}
}

// Through real tunnels, a ping to ff02::1 reaches every member's host and
// each answer goes back; under an access, one that passes groups by UDP
// alone passes no ping, one that passes ICMP its pings and their answers by
// identifier.
func TestAGroupPingReachesEveryMemberAndIsAnswered(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c, cTUN := groupNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	restricted := func(n *node, acc Access) Peer { p := n.peer(); p.Access = &acc; return p }
	ping := []Ports{{Proto: ipproto.UDP}, {Proto: ipproto.ICMPv4}, {Proto: ipproto.ICMPv6}}
	for _, set := range []struct {
		n     *node
		peers []Peer
	}{
		{a, []Peer{restricted(b, Access{GroupsTo: ping}), restricted(c, Access{GroupsTo: []Ports{{Proto: ipproto.UDP}}})}},
		{b, []Peer{restricted(a, Access{GroupsFrom: ping})}},
		{c, []Peer{a.peer()}},
	} {
		if err := set.n.mgr.SetPeers(set.peers); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	echoes := func(src, dst netip.Addr, typ byte, id uint16) func(*packet.Parsed) bool {
		return func(p *packet.Parsed) bool {
			b := p.Buffer()
			return p.IPProto == ipproto.ICMPv6 && p.Src.Addr() == src && p.Dst.Addr() == dst && len(b) >= 46 &&
				b[40] == typ && binary.BigEndian.Uint16(b[44:46]) == id
		}
	}
	atA := counting(aTUN, stop, echoes(llB, llA, 129, 7), echoes(llB, llA, 129, 8))
	atB := counting(bTUN, stop, echoes(llA, allNodes, 128, 7))
	atC := counting(cTUN, stop, echoes(llA, allNodes, 128, 7), groupFrom(llA))
	// c, which a passes groups by UDP alone, is reached by those.
	sendUntil(t, aTUN, mdns6From(llA), atC[1])
	sendUntil(t, aTUN, echo6(llA, allNodes, 128, 7), atB[0])
	sendUntil(t, bTUN, echo6(llB, llA, 129, 7), atA[0])
	for range 5 {
		bTUN.out <- echo6(llB, llA, 129, 8)
	}
	time.Sleep(time.Second)
	if n := atC[0].Load(); n != 0 {
		t.Errorf("c, which a passes groups by UDP alone, got %d pings", n)
	}
	if n := atA[1].Load(); n != 0 {
		t.Errorf("%d echo replies to no ping a sent were delivered", n)
	}
}
