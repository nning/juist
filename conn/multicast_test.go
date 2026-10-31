package conn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

var (
	mdnsGroup = ap("224.0.0.251:5353")
	addrA     = netip.MustParseAddr("100.64.0.1")
	addrB     = netip.MustParseAddr("100.64.0.2")
	addrC     = netip.MustParseAddr("100.64.0.3")
)

func mdnsFrom(src netip.Addr) []byte { return udpPacket(netip.AddrPortFrom(src, 5353), mdnsGroup) }

func TestAGroupDatagramUnwrapsAsSent(t *testing.T) {
	inner := mdnsFrom(addrB)
	inner[8] = 255 // mDNS's TTL, left as sent
	got, ok := unwrapGroup(wrapGroup(addrB, addrA, inner), addrB, addrA)
	if !ok || !bytes.Equal(got, inner) {
		t.Fatalf("unwrapped %x, %v; want %x", got, ok, inner)
	}
	if outer := parsed(wrapGroup(addrB, addrA, inner)); outer.IPProto != ipip || outer.Src.Addr() != addrB || outer.Dst.Addr() != addrA {
		t.Fatalf("wrapped as %v", outer)
	}
	if h := wrapGroup(addrB, addrA, inner)[:20]; headerChecksum(h) != 0 {
		t.Fatalf("the outer header's checksum does not add up")
	}
}

func TestOnlyAMembersOwnGroupDatagramUnwraps(t *testing.T) {
	fragmented := wrapGroup(addrB, addrA, mdnsFrom(addrB))
	binary.BigEndian.PutUint16(fragmented[6:8], 0x2000)
	optioned := wrapGroup(addrB, addrA, mdnsFrom(addrB))
	optioned[0] = 4<<4 | 6
	innerOptions := mdnsFrom(addrB)
	innerOptions = slices.Concat(innerOptions[:20], []byte{1, 1, 1, 0}, innerOptions[20:])
	innerOptions[0] = 4<<4 | 6
	binary.BigEndian.PutUint16(innerOptions[2:4], uint16(len(innerOptions)))
	for name, b := range map[string][]byte{
		"another member's source":  wrapGroup(addrB, addrA, mdnsFrom(addrC)),
		"a LAN source":             wrapGroup(addrB, addrA, mdnsFrom(netip.MustParseAddr("192.168.1.20"))),
		"to a unicast address":     wrapGroup(addrB, addrA, udpPacket(ap("100.64.0.2:5353"), ap("100.64.0.1:5353"))),
		"TCP to a group":           wrapGroup(addrB, addrA, tcpPacket(ap("100.64.0.2:5353"), mdnsGroup, tcpSyn)),
		"IGMP":                     wrapGroup(addrB, addrA, ipPacket(ipproto.IGMP, addrB, netip.MustParseAddr("224.0.0.22"), make([]byte, 8))),
		"IPv6 inside":              wrapGroup(addrB, addrA, udpPacket(ap("[fd7a:115c:a1e0::2]:5353"), ap("[ff02::fb]:5353"))),
		"for another node":         wrapGroup(addrB, addrC, mdnsFrom(addrB)),
		"from another node":        wrapGroup(addrC, addrA, mdnsFrom(addrB)),
		"fragmented":               fragmented,
		"with options":             optioned,
		"with options inside":      wrapGroup(addrB, addrA, innerOptions),
		"cut short":                wrapGroup(addrB, addrA, mdnsFrom(addrB))[:30],
		"longer than its datagram": append(wrapGroup(addrB, addrA, mdnsFrom(addrB)), 0),
	} {
		if _, ok := unwrapGroup(b, addrB, addrA); ok {
			t.Errorf("%s unwrapped", name)
		}
	}
}

func FuzzUnwrapGroup(f *testing.F) {
	f.Add(wrapGroup(addrB, addrA, mdnsFrom(addrB)))
	f.Add(wrapGroup(addrB, addrA, mdnsFrom(addrC)))
	f.Add(mdnsFrom(addrB))
	f.Fuzz(func(t *testing.T, b []byte) {
		inner, ok := unwrapGroup(b, addrB, addrA)
		if !ok {
			return
		}
		if src, ok := groupDatagram(inner); !ok || src != addrB {
			t.Fatalf("unwrapped %x, which is no group datagram of the sender's", inner)
		}
		if !bytes.HasSuffix(b, inner) || len(b) != len(inner)+20 {
			t.Fatalf("unwrapped %x from %x", inner, b)
		}
	})
}

func TestTheMulticasterCallsTheEnginesHooks(t *testing.T) {
	var calls int
	next := func(*packet.Parsed, *tstun.Wrapper) filter.Response { calls++; return filter.DropSilently }
	c := &multicaster{nextIn: next, nextOut: next}
	c.set(nil, []netip.Prefix{netip.PrefixFrom(addrA, 32)})
	unicast := parsed(udpPacket(ap("100.64.0.1:5353"), ap("100.64.0.2:5353")))
	if got := c.in(unicast, nil); got != filter.DropSilently {
		t.Errorf("in: %v, want the engine's verdict", got)
	}
	if got := c.out(unicast, nil); got != filter.DropSilently {
		t.Errorf("out: %v, want the engine's verdict", got)
	}
	if calls != 2 {
		t.Errorf("the engine's hooks ran %d times", calls)
	}
}

// This node sends its own group datagrams alone: none the host forwards
// from the LAN, and no IGMP; the filter drops them all, as before.
func TestOnlyThisNodesOwnGroupDatagramsAreSent(t *testing.T) {
	c := &multicaster{sending: make(chan groupSend, 4), sent: rate.NewLimiter(groupRate, groupBurst)}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(addrB, 32)}}}, []netip.Prefix{netip.PrefixFrom(addrA, 32)})
	for name, b := range map[string][]byte{
		"from the LAN": mdnsFrom(netip.MustParseAddr("192.168.1.20")),
		"IGMP":         ipPacket(ipproto.IGMP, addrA, netip.MustParseAddr("224.0.0.22"), make([]byte, 8)),
	} {
		c.out(parsed(b), nil)
		if len(c.sending) != 0 {
			t.Errorf("%s was sent", name)
			<-c.sending
		}
	}
	if c.out(parsed(mdnsFrom(addrA)), nil); len(c.sending) != 1 {
		t.Errorf("this node's own group datagram was not sent")
	}
}

// groupNode starts a node carrying multicast on a pipe device.
func groupNode(t *testing.T, id uint64, v4, v6 string) (*node, *pipeTUN) {
	d := newPipeTUN()
	n := startNode(t, id, v4, v6, func(o *Options) { o.Tun, o.RespondToPing, o.Multicast = d, false, true })
	return n, d
}

// counting counts what d delivers, by each of match, until stop is closed.
func counting(d *pipeTUN, stop chan struct{}, match ...func(*packet.Parsed) bool) []*atomic.Int64 {
	counts := make([]*atomic.Int64, len(match))
	for i := range counts {
		counts[i] = new(atomic.Int64)
	}
	go func() {
		for {
			select {
			case b := <-d.delivered:
				p := parsed(b)
				for i, m := range match {
					if m(p) {
						counts[i].Add(1)
					}
				}
			case <-stop:
				return
			}
		}
	}()
	return counts
}

// groupFrom matches a group datagram from src.
func groupFrom(src netip.Addr) func(*packet.Parsed) bool {
	return func(p *packet.Parsed) bool {
		got, ok := groupDatagram(p.Buffer())
		return ok && got == src
	}
}

func isIGMP(p *packet.Parsed) bool { return p.IPProto == ipproto.IGMP }

// sendUntil has d send pkt, every 200ms, until each count is above zero.
func sendUntil(t *testing.T, d *pipeTUN, pkt []byte, counts ...*atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		all := true
		for _, c := range counts {
			all = all && c.Load() > 0
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the group datagram did not reach every member")
		}
		d.out <- pkt
		time.Sleep(200 * time.Millisecond)
	}
}

// Through real tunnels, an mDNS query one member's host sends reaches every
// other member's host, with the sender's overlay address as its source; one
// a host forwards from the LAN, or IGMP, reaches none.
func TestAGroupDatagramReachesEveryMember(t *testing.T) {
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
	lan := netip.MustParseAddr("192.168.1.20")
	atB := counting(bTUN, stop, groupFrom(addrA), groupFrom(lan), isIGMP)
	atC := counting(cTUN, stop, groupFrom(addrA), groupFrom(lan), isIGMP)
	sendUntil(t, aTUN, mdnsFrom(addrA), atB[0], atC[0])
	for range 5 {
		aTUN.out <- mdnsFrom(lan)
		aTUN.out <- ipPacket(ipproto.IGMP, addrA, netip.MustParseAddr("224.0.0.251"), make([]byte, 8))
	}
	time.Sleep(500 * time.Millisecond)
	for _, n := range []*atomic.Int64{atB[1], atC[1]} {
		if n.Load() != 0 {
			t.Errorf("%d datagrams from the LAN crossed", n.Load())
		}
	}
	if n := atB[2].Load() + atC[2].Load(); n != 0 {
		t.Errorf("%d IGMP messages crossed", n)
	}
}

// A member whose daemon wraps another member's datagram, or sends past the
// limit, is cut at the receiver.
func TestAReceiverHoldsASenderToItsOwnAndToTheLimit(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	if err := a.mgr.SetPeers([]Peer{b.peer(), c.peer()}); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	at := counting(aTUN, stop, groupFrom(addrB), groupFrom(addrC))
	fromB, fromC := at[0], at[1]
	// B's host writes what a patched daemon would send; the filter takes
	// any protocol between members.
	sendUntil(t, bTUN, wrapGroup(addrB, addrA, mdnsFrom(addrB)), fromB)
	for range 20 {
		bTUN.out <- wrapGroup(addrB, addrA, mdnsFrom(addrC))
	}
	time.Sleep(500 * time.Millisecond)
	if n := fromC.Load(); n != 0 {
		t.Errorf("%d datagrams with another member's source were delivered", n)
	}

	time.Sleep(time.Duration(groupBurst/groupRate) * time.Second) // the bucket full again
	start, before := time.Now(), fromB.Load()
	const sent = 4 * groupBurst
	for range sent {
		bTUN.out <- wrapGroup(addrB, addrA, mdnsFrom(addrB))
	}
	time.Sleep(500 * time.Millisecond)
	got, most := fromB.Load()-before, int64(groupBurst+groupRate*time.Since(start).Seconds()+1)
	if got == 0 || got > most {
		t.Errorf("%d of %d delivered, want at most %d", got, sent, most)
	}
}

// A peer kept to an [Access] neither gets this node's group datagrams nor
// has its own delivered.
func TestARestrictedPeerTakesNoPartInGroups(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	confined := b.peer()
	confined.Access = &Access{Open: []Ports{{}}, Sends: []Ports{{}}}
	if err := a.mgr.SetPeers([]Peer{confined}); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	atA := counting(aTUN, stop, groupFrom(addrB), func(p *packet.Parsed) bool { return p.Dst.Addr() == addrA })
	atB := counting(bTUN, stop, groupFrom(addrA))
	// The tunnel is up once a unicast datagram gets through.
	sendUntil(t, bTUN, udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:5000")), atA[1])
	for range 5 {
		aTUN.out <- mdnsFrom(addrA)
		bTUN.out <- mdnsFrom(addrB)
		bTUN.out <- wrapGroup(addrB, addrA, mdnsFrom(addrB))
	}
	time.Sleep(time.Second)
	if n := atB[0].Load(); n != 0 {
		t.Errorf("the restricted peer got %d group datagrams", n)
	}
	if n := atA[0].Load(); n != 0 {
		t.Errorf("%d of the restricted peer's group datagrams were delivered", n)
	}
}

// Under an access, a group datagram goes to a peer whose access passes its
// port alone, and is taken from one whose access passes it; the peer's
// unicast answer to it passes for answerWindow, other unicast not, and a
// wrapped packet from a peer passed no group is dropped.
func TestAccessPassesGroupsAndTheirAnswersAlone(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c, cTUN := groupNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	ssdp := []Ports{{Proto: ipproto.UDP, First: 1900, Last: 1900}}
	restricted := func(n *node, acc Access) Peer { p := n.peer(); p.Access = &acc; return p }
	for _, set := range []struct {
		n     *node
		peers []Peer
	}{
		{a, []Peer{restricted(b, Access{GroupsTo: ssdp}), restricted(c, Access{Sends: []Ports{{}}, Open: []Ports{{}}})}},
		// b holds a to nothing, as a patched daemon would: a decides alone.
		{b, []Peer{a.peer()}},
		{c, []Peer{restricted(a, Access{GroupsFrom: []Ports{{}}, Open: []Ports{{}}, Sends: []Ports{{}}})}},
	} {
		if err := set.n.mgr.SetPeers(set.peers); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	ssdpGroup := ap("239.255.255.250:1900")
	toPort := func(port uint16) func(*packet.Parsed) bool {
		return func(p *packet.Parsed) bool { return p.IPProto == ipproto.UDP && p.Dst.Port() == port }
	}
	atA := counting(aTUN, stop, toPort(5000), toPort(6000), toPort(7000), groupFrom(addrC), toPort(5353))
	atB := counting(bTUN, stop, toPort(1900), toPort(5353))
	atC := counting(cTUN, stop, groupFrom(addrA), toPort(7000))
	// The tunnel to c is up once its unicast arrives.
	sendUntil(t, cTUN, udpPacket(ap("100.64.0.3:7000"), ap("100.64.0.1:7000")), atA[2])
	sendUntil(t, aTUN, udpPacket(ap("100.64.0.1:5000"), ssdpGroup), atB[0])
	for range 5 {
		aTUN.out <- mdnsFrom(addrA)
	}
	sendUntil(t, bTUN, udpPacket(ap("100.64.0.2:1900"), ap("100.64.0.1:5000")), atA[0])
	for range 5 {
		bTUN.out <- udpPacket(ap("100.64.0.2:1900"), ap("100.64.0.1:6000"))
		bTUN.out <- udpPacket(ap("100.64.0.2:1900"), ap("100.64.0.1:5353"))
		cTUN.out <- wrapGroup(addrC, addrA, mdnsFrom(addrC))
	}
	time.Sleep(time.Second)
	if n := atC[0].Load(); n != 0 {
		t.Errorf("c, which no access passes a group to, got %d", n)
	}
	if n := atB[1].Load(); n != 0 {
		t.Errorf("b got %d mDNS datagrams, which its access does not pass", n)
	}
	if n := atA[1].Load(); n != 0 {
		t.Errorf("%d of b's datagrams to a port no group datagram left from were delivered", n)
	}
	if n := atA[3].Load(); n != 0 {
		t.Errorf("%d group datagrams of c, which no access passes, were delivered", n)
	}
	if n := atA[4].Load(); n != 0 {
		t.Errorf("%d of b's datagrams to the port of a group datagram b was not sent were delivered", n)
	}
}

// An answer passes for answerWindow after its question, from the peer
// asked alone, and no longer.
func TestAnAnswerPassesForItsWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &multicaster{now: func() time.Time { return now }}
	b := &groupMember{v4: addrB, v6: v6B, ll: llB}
	c.ask(udpPacket(ap("100.64.0.1:5000"), ap("239.255.255.250:1900")), b)
	c.ask(fragment4(addrA, netip.MustParseAddr("239.255.255.250"), 64), b)
	c.ask(mdns6From(llA), b)
	if !c.answers(addrB, ap("100.64.0.1:5000")) || !c.answers(llB, netip.AddrPortFrom(llA, 5353)) {
		t.Fatal("no answer passes")
	}
	if c.answers(addrB, ap("100.64.0.1:5001")) || c.answers(addrB, ap("100.64.0.2:5000")) ||
		c.answers(addrC, ap("100.64.0.1:5000")) {
		t.Error("an answer to another port or address, or from another peer, passes")
	}
	now = now.Add(answerWindow + time.Second)
	if c.answers(addrB, ap("100.64.0.1:5000")) {
		t.Error("an answer passes past its window")
	}
}

// An access decides each way alone: a peer this node may send to is no
// sender for that, one it takes from no target, and a port the access does
// not pass is not sent.
func TestAnAccessDecidesEachWayAlone(t *testing.T) {
	c := &multicaster{}
	ssdp := []Ports{{Proto: ipproto.UDP, First: 1900, Last: 1900}}
	peer := func(a netip.Addr, acc *Access) Peer {
		return Peer{Addrs: []netip.Prefix{netip.PrefixFrom(a, 32)}, Access: acc}
	}
	c.set([]Peer{peer(addrB, &Access{GroupsTo: ssdp}), peer(addrC, &Access{GroupsFrom: ssdp}),
		peer(netip.MustParseAddr("100.64.0.4"), &Access{Open: []Ports{{}}})}, []netip.Prefix{netip.PrefixFrom(addrA, 32)})
	pol := c.policy.Load()
	if len(pol.peers) != 1 || pol.peers[0].v4 != addrB {
		t.Errorf("sent to %+v, want b alone", pol.peers)
	}
	if pol.sender(addrB) != nil || pol.sender(addrC) == nil || pol.sender(netip.MustParseAddr("100.64.0.4")) != nil {
		t.Error("taken from others than c")
	}
	if pol.wrap(pol.peers[0], mdnsFrom(addrA)) != nil {
		t.Error("mDNS was wrapped for a peer passed SSDP alone")
	}
	if pol.wrap(pol.peers[0], udpPacket(ap("100.64.0.1:5000"), ap("239.255.255.250:1900"))) == nil {
		t.Error("SSDP was not wrapped for a peer passed it")
	}
	if passesGroup(pol.sender(addrC).from, mdnsFrom(addrC)) {
		t.Error("mDNS was taken from a peer passed SSDP alone")
	}
}

// A flow the access passes keeps its replies where its first datagram goes
// to a port a group datagram came from too.
func TestAnAnswerLeavesAFlowItsReplies(t *testing.T) {
	a, aTUN := groupNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b, bTUN := groupNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	mdnsPort := []Ports{{Proto: ipproto.UDP, First: 5353, Last: 5353}}
	pa, pb := b.peer(), a.peer()
	pa.Access = &Access{Sends: mdnsPort, GroupsFrom: []Ports{{Proto: ipproto.UDP}}}
	pb.Access = &Access{Open: mdnsPort, GroupsTo: []Ports{{Proto: ipproto.UDP}}}
	if err := a.mgr.SetPeers([]Peer{pa}); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.SetPeers([]Peer{pb}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	toPort := func(port uint16) func(*packet.Parsed) bool {
		return func(p *packet.Parsed) bool { return p.IPProto == ipproto.UDP && p.Dst.Port() == port }
	}
	atA, atB := counting(aTUN, stop, groupFrom(addrB), toPort(40001)), counting(bTUN, stop, toPort(5353))
	sendUntil(t, bTUN, mdnsFrom(addrB), atA[0])
	sendUntil(t, aTUN, udpPacket(ap("100.64.0.1:40001"), ap("100.64.0.2:5353")), atB[0])
	sendUntil(t, bTUN, udpPacket(ap("100.64.0.2:5353"), ap("100.64.0.1:40001")), atA[1])
}

// A peer's sources fill its own share of what answers are kept for alone.
func TestOnePeersQuestionsCrowdOutNoOthers(t *testing.T) {
	c := &multicaster{}
	x, y := &groupMember{v4: addrB}, &groupMember{v4: addrC}
	for i := range 5000 {
		c.ask(udpPacket(netip.AddrPortFrom(addrB, uint16(i+1)), ap("239.255.255.250:1900")), x)
	}
	c.ask(udpPacket(ap("100.64.0.1:5000"), ap("239.255.255.250:1900")), y)
	if !c.answers(addrC, ap("100.64.0.1:5000")) {
		t.Error("one peer's flood kept another's answer out")
	}
	if !c.answers(addrB, netip.AddrPortFrom(addrB, 5000)) || c.answers(addrB, netip.AddrPortFrom(addrB, 1)) {
		t.Error("the flooding peer keeps other than its latest")
	}
}

// A port set passing every UDP port passes a later fragment, which holds
// no port.
func TestEveryPortPassesFragments(t *testing.T) {
	c := &multicaster{}
	for _, all := range [][]Ports{{{Proto: ipproto.UDP}}, {{}}} {
		c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(addrB, 32)}, Access: &Access{GroupsFrom: all}}},
			[]netip.Prefix{netip.PrefixFrom(addrA, 32)})
		if !passesGroup(c.policy.Load().sender(addrB).from, fragment4(addrB, netip.MustParseAddr("239.1.1.1"), 64)) {
			t.Errorf("%v drops a later fragment", all)
		}
	}
}

// An answer passes to this node's own address alone, and from it alone.
func TestAnAnswerIsThisNodesAlone(t *testing.T) {
	g := &multicaster{}
	g.ask(udpPacket(ap("100.64.0.2:5353"), ap("224.0.0.251:5353")), &groupMember{v4: addrB})
	c := &confiner{groups: g}
	all := []Ports{{Proto: ipproto.UDP}}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(addrB, 32)}, Access: &Access{GroupsFrom: all, GroupsTo: all}}},
		[]netip.Prefix{netip.PrefixFrom(addrA, 32)})
	if got := c.out(parsed(udpPacket(ap("100.64.0.1:40000"), ap("100.64.0.2:5353"))), nil); got != filter.Accept {
		t.Errorf("this node's answer: %v", got)
	}
	if got := c.out(parsed(udpPacket(ap("192.168.1.9:40000"), ap("100.64.0.2:5353"))), nil); got == filter.Accept {
		t.Error("a forwarded host's datagram passed as an answer")
	}
	if got := c.in(parsed(udpPacket(ap("100.64.0.2:40000"), ap("100.64.0.2:5353"))), nil); got == filter.Accept {
		t.Error("the peer's datagram to its own address passed as an answer")
	}
}

// A resting peer, as a phone saving battery, is sent no group datagram.
func TestARestingPeerIsSentNoGroups(t *testing.T) {
	c := &multicaster{}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(addrB, 32)}, Rests: true}, {Addrs: []netip.Prefix{netip.PrefixFrom(addrC, 32)}}},
		[]netip.Prefix{netip.PrefixFrom(addrA, 32)})
	if pol := c.policy.Load(); len(pol.peers) != 1 || pol.peers[0].v4 != addrC {
		t.Errorf("sent to %+v, want c alone", pol.peers)
	}
}

// What is wrapped for this node never reaches the host where no multicaster
// takes it, as with multicast off; what is wrapped for what it routes does.
func TestNothingWrappedForThisNodeReachesTheHost(t *testing.T) {
	c := &confiner{}
	c.set(nil, []netip.Prefix{netip.PrefixFrom(addrA, 32), netip.PrefixFrom(v6A, 128)})
	for _, b := range [][]byte{wrapGroup(addrB, addrA, mdnsFrom(addrB)), wrapGroup6(v6B, v6A, mdns6From(llB))} {
		if got := c.in(parsed(b), nil); got != filter.Drop {
			t.Errorf("%v: %v", parsed(b), got)
		}
	}
	if got := c.in(parsed(wrapGroup(addrB, netip.MustParseAddr("192.168.1.9"), mdnsFrom(addrB))), nil); got != filter.Accept {
		t.Errorf("a packet wrapped for a routed host: %v", got)
	}
}
