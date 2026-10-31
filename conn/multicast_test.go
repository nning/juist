package conn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
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
