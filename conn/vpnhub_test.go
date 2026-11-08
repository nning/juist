package conn

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
	"tailscale.com/wgengine/router"
)

func udp(src, dst string, sport, dport uint16) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	if s.Is4() {
		return packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{Src: s, Dst: d, IPID: 7}, SrcPort: sport, DstPort: dport}, []byte("hello"))
	}
	return packet.Generate(packet.UDP6Header{IP6Header: packet.IP6Header{Src: s, Dst: d}, SrcPort: sport, DstPort: dport}, []byte("hello"))
}

func echo(src, dst string, reply bool) []byte {
	typ := packet.ICMP4EchoRequest
	if reply {
		typ = packet.ICMP4EchoReply
	}
	return packet.Generate(packet.ICMP4Header{IP4Header: packet.IP4Header{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst)}, Type: typ},
		[]byte{0, 9, 0, 1, 'p', 'i', 'n', 'g'})
}

// A hubNet is one network on a hub in a test: its device, router and what
// its engine reads.
type hubNet struct {
	dev  tun.Device
	rtr  router.Router
	read chan []byte
}

func joinHub(t *testing.T, h *VPNHub, slot int, cover []netip.Prefix, self ...string) *hubNet {
	t.Helper()
	p := h.Plumber(slot, func() []netip.Prefix { return cover }).(*vpnPlumber)
	dev, rtr := newVPNPlumbed(p, "juist0", 1280, t.Logf)
	t.Cleanup(func() { dev.Close() })
	n := &hubNet{dev: dev, rtr: rtr, read: readPacket(t, dev)}
	var addrs []netip.Prefix
	for _, a := range self {
		ip := netip.MustParseAddr(a)
		addrs = append(addrs, netip.PrefixFrom(ip, ip.BitLen()))
	}
	if err := rtr.Set(&router.Config{LocalAddrs: addrs}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *hubNet) expect(t *testing.T, want []byte, what string) {
	t.Helper()
	select {
	case got := <-n.read:
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the network read\n%x, want\n%x", what, got, want)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("%s: the network read nothing", what)
	}
}

func (n *hubNet) expectNone(t *testing.T, what string) {
	t.Helper()
	select {
	case got := <-n.read:
		t.Errorf("%s: the network read %x", what, got)
	case <-time.After(100 * time.Millisecond):
	}
}

func (n *hubNet) send(t *testing.T, pkt []byte) {
	t.Helper()
	if _, err := n.dev.Write([][]byte{append(make([]byte, 16), pkt...)}, 16); err != nil {
		t.Fatal(err)
	}
}

// hostReads is what the host reads off the device last established.
func hostReads(t *testing.T, v *fakeVPN) chan []byte {
	t.Helper()
	got := make(chan []byte, 8)
	v.mu.Lock()
	far := v.far[len(v.far)-1]
	v.mu.Unlock()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := far.Read(buf)
			if err != nil {
				return
			}
			got <- slices.Clone(buf[:n])
		}
	}()
	return got
}

func hostSends(t *testing.T, v *fakeVPN, pkt []byte) {
	t.Helper()
	v.mu.Lock()
	far := v.far[len(v.far)-1]
	v.mu.Unlock()
	if _, err := far.Write(pkt); err != nil {
		t.Fatal(err)
	}
}

func expectHost(t *testing.T, got chan []byte, want []byte, what string) {
	t.Helper()
	select {
	case b := <-got:
		if want == nil {
			t.Errorf("%s: the host read %x", what, b)
		} else if !bytes.Equal(b, want) {
			t.Errorf("%s: the host read\n%x, want\n%x", what, b, want)
		}
	case <-time.After(150 * time.Millisecond):
		if want != nil {
			t.Errorf("%s: the host read nothing", what)
		}
	}
}

var (
	netA = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/22"), netip.MustParsePrefix("fd00:a::/48")}
	netB = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/22"), netip.MustParsePrefix("fd00:b::/48")}
)

func TestAHubEstablishesOneDeviceForEveryNetwork(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2", "fd00:a::2")
	joinHub(t, h, 1, netB, "10.1.0.2", "fd00:b::2")
	c := v.given[len(v.given)-1]
	if want := sortedPrefixes(append(slices.Clone(netA), netB...)); !slices.Equal(c.Routes, want) {
		t.Errorf("routes %v, want %v", c.Routes, want)
	}
	if len(c.Addrs) != 4 {
		t.Errorf("addresses %v, want both networks'", c.Addrs)
	}
	for slot, want := range []string{"10.0.0.2", "10.1.0.2"} {
		if got, ok := h.source(slot, true); !ok || got.String() != want {
			t.Errorf("network %d dials from %v, want %s", slot, got, want)
		}
	}
}

// Each packet reaches the network its destination is in, from that
// network's own address, and the answer the address it left from.
func TestAHubHandsEachPacketToItsNetworkFromItsOwnAddress(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	a := joinHub(t, h, 0, netA, "10.0.0.2", "fd00:a::2")
	b := joinHub(t, h, 1, netB, "10.1.0.2", "fd00:b::2")
	host := hostReads(t, v)

	hostSends(t, v, udp("10.0.0.2", "10.0.0.7", 4000, 53))
	a.expect(t, udp("10.0.0.2", "10.0.0.7", 4000, 53), "into its own network")
	b.expectNone(t, "into the other network")

	// Android sends from the first address whatever the destination.
	hostSends(t, v, udp("10.0.0.2", "10.1.0.7", 4001, 80))
	b.expect(t, udp("10.1.0.2", "10.1.0.7", 4001, 80), "from the other network's address")
	a.expectNone(t, "a packet for the other network")
	b.send(t, udp("10.1.0.7", "10.1.0.2", 80, 4001))
	expectHost(t, host, udp("10.1.0.7", "10.0.0.2", 80, 4001), "the answer")
	b.send(t, udp("10.1.0.7", "10.1.0.2", 80, 4999))
	expectHost(t, host, udp("10.1.0.7", "10.1.0.2", 80, 4999), "what answers nothing translated")

	hostSends(t, v, udp("fd00:b::2", "fd00:a::9", 5000, 443))
	a.expect(t, udp("fd00:a::2", "fd00:a::9", 5000, 443), "over IPv6")
	a.send(t, udp("fd00:a::9", "fd00:a::2", 443, 5000))
	expectHost(t, host, udp("fd00:a::9", "fd00:b::2", 443, 5000), "the answer over IPv6")

	hostSends(t, v, echo("10.0.0.2", "10.1.0.7", false))
	b.expect(t, echo("10.1.0.2", "10.1.0.7", false), "an echo")
	b.send(t, echo("10.1.0.7", "10.1.0.2", true))
	expectHost(t, host, echo("10.1.0.7", "10.0.0.2", true), "its answer")

	hostSends(t, v, udp("10.0.0.2", "192.0.2.1", 4002, 80))
	a.expectNone(t, "an address no network routes")
	b.expectNone(t, "an address no network routes")
}

// No network writes to another's addresses on the host, which would let a
// member of one reach the other through the phone.
func TestAHubKeepsEachNetworkFromTheOthersAddresses(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	a := joinHub(t, h, 0, netA, "10.0.0.2", "fd00:a::2")
	b := joinHub(t, h, 1, netB, "10.1.0.2", "fd00:b::2")
	host := hostReads(t, v)
	b.send(t, udp("10.1.0.7", "10.0.0.2", 80, 4000))
	expectHost(t, host, nil, "to the other network's IPv4")
	b.send(t, udp("fd00:b::7", "fd00:a::2", 80, 4000))
	expectHost(t, host, nil, "to the other network's IPv6")
	a.send(t, udp("10.0.0.7", "10.1.0.2", 80, 4000))
	expectHost(t, host, nil, "back the other way")
	a.send(t, udp("10.0.0.7", "10.9.9.9", 80, 4000))
	expectHost(t, host, nil, "to an address the host does not have")
	a.send(t, []byte("not a packet"))
	expectHost(t, host, nil, "what is no packet")
	a.send(t, udp("10.0.0.7", "224.0.0.251", 5353, 5353))
	expectHost(t, host, udp("10.0.0.7", "224.0.0.251", 5353, 5353), "a multicast group")
	a.send(t, udp("10.0.0.7", "10.0.0.2", 80, 4000))
	expectHost(t, host, udp("10.0.0.7", "10.0.0.2", 80, 4000), "to its own address")
}

func TestAHubSendsTheInternetToTheExitNodesNetworkAndItsLookups(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	a := joinHub(t, h, 0, netA, "10.0.0.2", "fd00:a::2")
	b := joinHub(t, h, 1, netB, "10.1.0.2", "fd00:b::2")
	ra, rb := netip.MustParseAddr("fd00:a::53"), netip.MustParseAddr("fd00:b::53")
	if err := h.Plumber(0, nil).SetDNS("juist0", []netip.Addr{ra}, []string{"a.juist"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Plumber(1, nil).SetDNS("juist0", []netip.Addr{rb}, []string{"b.juist"}); err != nil {
		t.Fatal(err)
	}
	last := func() VPNConfig { return v.given[len(v.given)-1] }
	if c := last(); !slices.Equal(c.DNS, []netip.Addr{ra}) || !slices.Equal(c.Search, []string{"a.juist", "b.juist"}) {
		t.Errorf("DNS %v searching %v, want the lowest network's resolver searching both", c.DNS, c.Search)
	}
	if err := b.rtr.(exitRouter).setEgress(EgressTunnel, tunnelled{}); err != nil {
		t.Fatal(err)
	}
	if c := last(); !slices.Equal(c.DNS, []netip.Addr{rb}) || !routes(c.Routes, "8.8.8.8") || routes(c.Routes, "192.168.1.1") {
		t.Errorf("with an exit node: DNS %v, routes %v", c.DNS, c.Routes)
	}
	hostSends(t, v, udp("10.0.0.2", "8.8.8.8", 4000, 53))
	b.expect(t, udp("10.1.0.2", "8.8.8.8", 4000, 53), "the internet")
	a.expectNone(t, "the internet")
	hostSends(t, v, udp("10.0.0.2", "10.0.0.5", 4000, 53))
	a.expect(t, udp("10.0.0.2", "10.0.0.5", 4000, 53), "a network's own beside the exit node")
}

// Where two networks route the same subnet, the lower one carries it, as
// the lower instance's table wins on Linux.
func TestAHubGivesASubnetBothRouteToTheLowerNetwork(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	subnet := netip.MustParsePrefix("192.168.5.0/24")
	b := joinHub(t, h, 1, netB, "10.1.0.2")
	a := joinHub(t, h, 0, netA, "10.0.0.2")
	for _, n := range []*hubNet{a, b} {
		self := netip.MustParsePrefix("10.0.0.2/32")
		if n == b {
			self = netip.MustParsePrefix("10.1.0.2/32")
		}
		if err := n.rtr.Set(&router.Config{LocalAddrs: []netip.Prefix{self}, Routes: []netip.Prefix{subnet}}); err != nil {
			t.Fatal(err)
		}
	}
	hostSends(t, v, udp("10.1.0.2", "192.168.5.9", 4000, 80))
	a.expect(t, udp("10.0.0.2", "192.168.5.9", 4000, 80), "the subnet")
	b.expectNone(t, "the subnet")
}

// A network's mesh restarting keeps the device as it was, and a network gone
// takes its routes along.
func TestAHubKeepsTheDeviceWhileAMeshRestarts(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	a := joinHub(t, h, 0, netA, "10.0.0.2")
	joinHub(t, h, 1, netB, "10.1.0.2")
	n := v.established()
	a.dev.Close()
	a2 := joinHub(t, h, 0, netA, "10.0.0.2")
	if v.established() != n {
		t.Errorf("a mesh restarting established the device %d times more", v.established()-n)
	}
	hostSends(t, v, udp("10.0.0.2", "10.0.0.5", 4000, 53))
	a2.expect(t, udp("10.0.0.2", "10.0.0.5", 4000, 53), "the network's next mesh")

	h.Remove(1)
	if c := v.given[len(v.given)-1]; routes(c.Routes, "10.1.0.5") || len(c.Addrs) != 1 {
		t.Errorf("after the network left: routes %v, addresses %v", c.Routes, c.Addrs)
	}
	m := h.members[0]
	a2.dev.Close()
	h.dropStale(0, m.part)
	if h.file() != nil {
		t.Error("the device stayed up with no network left")
	}
}

// A packet answering a flow that left translated still reaches the host
// after the hub saw other traffic for a while, and one long idle not.
func TestAHubForgetsAnIdleTranslation(t *testing.T) {
	var nat hubNAT
	now := time.Now()
	k := natKey{proto: 17, local: netip.MustParseAddrPort("10.1.0.2:4000"), remote: netip.MustParseAddrPort("10.1.0.7:53")}
	orig := netip.MustParseAddr("10.0.0.2")
	nat.put(k, orig, now)
	if got, ok := nat.get(k, now.Add(natIdle-time.Second)); !ok || got != orig {
		t.Fatalf("a fresh translation: %v, %v", got, ok)
	}
	if _, ok := nat.get(k, now.Add(2*natIdle)); ok {
		t.Error("a translation idle past its time was kept")
	}
	nat.put(k, orig, now)
	nat.put(natKey{proto: 17, local: netip.MustParseAddrPort("10.1.0.2:4001")}, orig, now.Add(natIdle+natSweep+time.Second))
	if _, ok := nat.m[k]; ok {
		t.Error("the sweep kept an expired translation")
	}
}

// An ICMP error about a translated flow, as a packet too big, reaches the
// address the flow left from, quoting it, with its checksums right.
func TestAHubTranslatesAnErrorAboutATranslatedFlow(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2", "fd00:a::2")
	b := joinHub(t, h, 1, netB, "10.1.0.2", "fd00:b::2")
	host := hostReads(t, v)
	for _, c := range []struct{ from, to, translated, router string }{
		{"10.0.0.2", "10.1.0.7", "10.1.0.2", "10.1.0.9"},
		{"fd00:a::2", "fd00:b::7", "fd00:b::2", "fd00:b::9"},
	} {
		hostSends(t, v, udp(c.from, c.to, 4000, 53))
		sent := <-b.read
		router, translated := netip.MustParseAddr(c.router), netip.MustParseAddr(c.translated)
		quote := append([]byte{0, 0, 5, 0}, sent[:min(len(sent), 48)]...)
		var e []byte
		if translated.Is4() {
			e = packet.Generate(packet.ICMP4Header{IP4Header: packet.IP4Header{Src: router, Dst: translated}, Type: packet.ICMP4Unreachable, Code: 3}, quote)
		} else {
			e = packet.Generate(packet.ICMP6Header{IP6Header: packet.IP6Header{Src: router, Dst: translated}, Type: packet.ICMP6PacketTooBig}, quote)
		}
		b.send(t, e)
		var got []byte
		select {
		case got = <-host:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the error did not reach the host", c.from)
		}
		var q packet.Parsed
		q.Decode(got)
		icmp := q.Transport()
		inner, ok := quotedKey(icmp[8:], q.IPVersion)
		from := netip.MustParseAddr(c.from)
		if !ok || q.Dst.Addr() != from || inner.local != netip.AddrPortFrom(from, 4000) {
			t.Errorf("%s: the error went to %v quoting %v", c.from, q.Dst, inner.local)
		}
		var sum uint32
		if from.Is4() {
			sum = onesSum(0, icmp)
			if ih := onesSum(0, icmp[8:28]); ih != 0xffff {
				t.Errorf("the quoted header's checksum is off: %#x", ih)
			}
		} else {
			var pseudo [40]byte
			copy(pseudo[:32], got[8:40])
			pseudo[34], pseudo[35], pseudo[39] = byte(len(icmp)>>8), byte(len(icmp)), 58
			sum = onesSum(onesSum(0, pseudo[:]), icmp)
		}
		if sum != 0xffff {
			t.Errorf("%s: the error's checksum is off: %#x", c.from, sum)
		}
	}
}

// A flow the host sends from a network's own address drops what a
// translation left on its tuple.
func TestAHubForgetsATranslationOnceTheHostOwnsItsTuple(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2")
	b := joinHub(t, h, 1, netB, "10.1.0.2")
	host := hostReads(t, v)
	hostSends(t, v, udp("10.0.0.2", "10.1.0.7", 4000, 53))
	<-b.read
	hostSends(t, v, udp("10.1.0.2", "10.1.0.7", 4000, 53))
	<-b.read
	b.send(t, udp("10.1.0.7", "10.1.0.2", 53, 4000))
	expectHost(t, host, udp("10.1.0.7", "10.1.0.2", 53, 4000), "an answer to the host's own flow")
}

// frag4 is an IPv4 fragment from src to dst of the datagram id, at offset
// eight-byte units in, with more to come where more, carrying payload.
func frag4(src, dst string, id, offset uint16, more bool, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0], b[8], b[9] = 0x45, 64, 17
	n := len(b)
	b[2], b[3] = byte(n>>8), byte(n)
	b[4], b[5] = byte(id>>8), byte(id)
	flags := offset
	if more {
		flags |= 0x2000
	}
	b[6], b[7] = byte(flags>>8), byte(flags)
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	sum := ^uint16(onesSum(0, b[:20]))
	b[10], b[11] = byte(sum>>8), byte(sum)
	copy(b[20:], payload)
	return b
}

// A datagram in fragments leaves translated whole, and one coming back in
// fragments reaches the address it answers, every fragment of it.
func TestAHubTranslatesFragments(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2")
	b := joinHub(t, h, 1, netB, "10.1.0.2")
	host := hostReads(t, v)

	whole := udp("10.0.0.2", "10.1.0.7", 4000, 53)
	first := frag4("10.0.0.2", "10.1.0.7", 9, 0, true, whole[20:28])
	hostSends(t, v, first)
	got := <-b.read
	if src := netip.AddrFrom4([4]byte(got[12:16])); src.String() != "10.1.0.2" || onesSum(0, got[:20]) != 0xffff {
		t.Errorf("the first fragment left from %v, header sum %#x", src, onesSum(0, got[:20]))
	}
	hostSends(t, v, frag4("10.0.0.2", "10.1.0.7", 9, 160, false, []byte("hello")))
	b.expect(t, frag4("10.1.0.2", "10.1.0.7", 9, 160, false, []byte("hello")), "a later fragment")

	answer := udp("10.1.0.7", "10.1.0.2", 53, 4000)
	b.send(t, frag4("10.1.0.7", "10.1.0.2", 77, 0, true, answer[20:28]))
	select {
	case got := <-host:
		if dst := netip.AddrFrom4([4]byte(got[16:20])); dst.String() != "10.0.0.2" || onesSum(0, got[:20]) != 0xffff {
			t.Errorf("the answer's first fragment went to %v", dst)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the answer's first fragment did not reach the host")
	}
	b.send(t, frag4("10.1.0.7", "10.1.0.2", 77, 160, false, []byte("world")))
	expectHost(t, host, frag4("10.1.0.7", "10.0.0.2", 77, 160, false, []byte("world")), "the answer's later fragment")
	b.send(t, frag4("10.1.0.7", "10.1.0.2", 78, 160, false, []byte("other")))
	expectHost(t, host, frag4("10.1.0.7", "10.1.0.2", 78, 160, false, []byte("other")), "a fragment of no translated datagram")
}

// A network whose mesh stops before it routed anything leaves the hub at
// once, so that the one left takes every packet as before.
func TestAHubDropsANetworkThatNeverRouted(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2")
	dev, _ := newVPNPlumbed(h.Plumber(1, nil).(*vpnPlumber), "juist0", 1280, t.Logf)
	dev.Close()
	if tb := h.table.Load(); tb == nil || !tb.only {
		t.Error("a network gone before it routed anything kept the hub from its one network's way")
	}
}

// tcp4 is a TCP segment from src to dst with flags, its checksum right.
func tcp4(src, dst string, sport, dport uint16, flags byte) []byte {
	b := make([]byte, 40)
	b[0], b[8], b[9] = 0x45, 64, 6
	b[3] = 40
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	sum := ^uint16(onesSum(0, b[:20]))
	b[10], b[11] = byte(sum>>8), byte(sum)
	t := b[20:]
	t[0], t[1], t[2], t[3] = byte(sport>>8), byte(sport), byte(dport>>8), byte(dport)
	t[12], t[13] = 5<<4, flags
	pseudo := append(append(append([]byte{}, b[12:20]...), 0, 6), 0, 20)
	sum = ^uint16(onesSum(onesSum(0, pseudo), t))
	t[16], t[17] = byte(sum>>8), byte(sum)
	return b
}

// A packet from where another network's routes lead never reaches the
// host through this one, even to this one's own address.
func TestAHubTakesNoPacketFromAnotherNetworksAddresses(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2", "fd00:a::2")
	b := joinHub(t, h, 1, netB, "10.1.0.2", "fd00:b::2")
	host := hostReads(t, v)
	b.send(t, udp("10.0.0.7", "10.1.0.2", 53, 4000))
	expectHost(t, host, nil, "from the other network's IPv4")
	b.send(t, udp("fd00:a::7", "fd00:b::2", 53, 4000))
	expectHost(t, host, nil, "from the other network's IPv6")
	b.send(t, udp("192.0.2.9", "10.1.0.2", 53, 4000))
	expectHost(t, host, udp("192.0.2.9", "10.1.0.2", 53, 4000), "from where no network's routes lead")
}

// A translation goes with the network it was made for, and a network
// that comes after it at the same address is answered as itself.
func TestAHubDropsTheTranslationsOfANetworkGone(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2")
	b := joinHub(t, h, 1, netB, "10.1.0.2")
	hostSends(t, v, udp("10.0.0.2", "10.1.0.7", 4000, 53))
	<-b.read
	h.Remove(1)
	c := joinHub(t, h, 2, netB, "10.1.0.2")
	host := hostReads(t, v)
	c.send(t, udp("10.1.0.7", "10.1.0.2", 53, 4000))
	expectHost(t, host, udp("10.1.0.7", "10.1.0.2", 53, 4000), "the next network at the same address")
}

// A TCP segment the host sends from its own address on a translated
// flow's tuple, but for a SYN, keeps the translation.
func TestAHubKeepsATranslationButForANativeSYN(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2")
	b := joinHub(t, h, 1, netB, "10.1.0.2")
	host := hostReads(t, v)
	hostSends(t, v, tcp4("10.0.0.2", "10.1.0.7", 4000, 80, 0x02))
	<-b.read
	hostSends(t, v, tcp4("10.1.0.2", "10.1.0.7", 4000, 80, 0x10))
	<-b.read
	b.send(t, tcp4("10.1.0.7", "10.1.0.2", 80, 4000, 0x12))
	expectHost(t, host, tcp4("10.1.0.7", "10.0.0.2", 80, 4000, 0x12), "the translated flow's answer")
	hostSends(t, v, tcp4("10.1.0.2", "10.1.0.7", 4000, 80, 0x02))
	<-b.read
	b.send(t, tcp4("10.1.0.7", "10.1.0.2", 80, 4000, 0x12))
	expectHost(t, host, tcp4("10.1.0.7", "10.1.0.2", 80, 4000, 0x12), "a native flow's answer on the same tuple")
}

// A datagram that reuses a translated one's fragment ID keeps its later
// fragments where its first went.
func TestAHubFollowsEachDatagramsFirstFragment(t *testing.T) {
	v := &fakeVPN{t: t}
	h := NewVPNHub(v, t.Logf)
	defer h.Close()
	joinHub(t, h, 0, netA, "10.0.0.2")
	b := joinHub(t, h, 1, netB, "10.1.0.2")
	host := hostReads(t, v)
	hostSends(t, v, udp("10.0.0.2", "10.1.0.7", 4000, 53))
	<-b.read
	answer := udp("10.1.0.7", "10.1.0.2", 53, 4000)
	b.send(t, frag4("10.1.0.7", "10.1.0.2", 5, 0, true, answer[20:28]))
	<-host
	native := udp("10.1.0.7", "10.1.0.2", 53, 5000)
	b.send(t, frag4("10.1.0.7", "10.1.0.2", 5, 0, true, native[20:28]))
	<-host
	b.send(t, frag4("10.1.0.7", "10.1.0.2", 5, 160, false, []byte("later")))
	expectHost(t, host, frag4("10.1.0.7", "10.1.0.2", 5, 160, false, []byte("later")), "the native datagram's later fragment")
}
