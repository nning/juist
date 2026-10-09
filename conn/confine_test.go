package conn

import (
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

const (
	tcpSyn = 0x02
	tcpAck = 0x10
)

// tcpPacket is a TCP segment with flags from src to dst, its checksum unset.
func tcpPacket(src, dst netip.AddrPort, flags byte) []byte {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:], src.Port())
	binary.BigEndian.PutUint16(payload[2:], dst.Port())
	payload[12] = 5 << 4
	payload[13] = flags
	return ipPacket(ipproto.TCP, src.Addr(), dst.Addr(), payload)
}

// udpPacket is a UDP datagram from src to dst.
func udpPacket(src, dst netip.AddrPort) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload[0:], src.Port())
	binary.BigEndian.PutUint16(payload[2:], dst.Port())
	binary.BigEndian.PutUint16(payload[4:], 8)
	return ipPacket(ipproto.UDP, src.Addr(), dst.Addr(), payload)
}

func ipPacket(proto ipproto.Proto, src, dst netip.Addr, payload []byte) []byte {
	if src.Is4() {
		return packet.Generate(packet.IP4Header{IPProto: proto, Src: src, Dst: dst}, payload)
	}
	return packet.Generate(packet.IP6Header{IPProto: proto, Src: src, Dst: dst}, payload)
}

func parsed(b []byte) *packet.Parsed {
	var p packet.Parsed
	p.Decode(b)
	return &p
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// An ingress sends TCP to this node's own addresses on the ports it may
// open, and replies to what this node opened; nothing else, whatever its
// flags, to whatever this node serves. Other members are the filter's.
func TestTheConfinerKeepsAnIngressToItsPorts(t *testing.T) {
	c := &confiner{}
	c.maxFlowsPerAddr = 4
	ingress, member := netip.MustParsePrefix("100.64.0.2/32"), netip.MustParsePrefix("100.64.0.3/32")
	service := netip.MustParsePrefix("100.64.0.4/32")
	c.set([]Peer{{Addrs: []netip.Prefix{ingress}, Access: ingressAccess([]uint16{41641, 443}, []uint16{443})},
		{Addrs: []netip.Prefix{member}}, {Addrs: []netip.Prefix{service}, Access: serviceAccess()}},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	verdicts := []struct {
		what string
		pkt  []byte
		want filter.Response
	}{
		{"a SYN to a published port", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:443"), tcpSyn), filter.Accept},
		{"the rest of that connection", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:443"), tcpAck), filter.Accept},
		{"log sync", tcpPacket(ap("100.64.0.2:5001"), ap("100.64.0.1:41641"), tcpSyn), filter.Accept},
		{"a SYN to another port", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpSyn), filter.Drop},
		{"an ACK to another port", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpAck), filter.Drop},
		{"UDP to a port published by TLS, for QUIC", udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:443")), filter.Accept},
		{"UDP to log sync's port", udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:41641")), filter.Drop},
		{"UDP to another port", udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:53")), filter.Drop},
		{"UDP to what this node routes", udpPacket(ap("100.64.0.2:5000"), ap("192.168.1.5:443")), filter.Drop},
		{"TCP to what this node routes", tcpPacket(ap("100.64.0.2:5000"), ap("192.168.1.5:443"), tcpAck), filter.Drop},
		{"ICMP", ipPacket(ipproto.ICMPv4, netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"),
			[]byte{3, 3, 0, 0, 0, 0, 0, 0}), filter.Drop},
		{"a member's ACK to any port", tcpPacket(ap("100.64.0.3:5000"), ap("100.64.0.1:22"), tcpAck), filter.Accept},
		{"a service member's SYN to a published port", tcpPacket(ap("100.64.0.4:5000"), ap("100.64.0.1:443"), tcpSyn), filter.Drop},
		{"a service member's SYN to log sync", tcpPacket(ap("100.64.0.4:5000"), ap("100.64.0.1:41641"), tcpSyn), filter.Drop},
		{"a service member's UDP", udpPacket(ap("100.64.0.4:5000"), ap("100.64.0.1:53")), filter.Drop},
	}
	for _, v := range verdicts {
		if got := c.in(parsed(v.pkt), nil); got != v.want {
			t.Errorf("%s: %v, want %v", v.what, got, v.want)
		}
	}

	opened := tcpPacket(ap("100.64.0.1:40000"), ap("100.64.0.2:8080"), tcpSyn)
	reply := tcpPacket(ap("100.64.0.2:8080"), ap("100.64.0.1:40000"), tcpSyn|tcpAck)
	if got := c.in(parsed(reply), nil); got != filter.Drop {
		t.Fatalf("a reply to nothing opened: %v", got)
	}
	c.out(parsed(opened), nil)
	if got := c.in(parsed(reply), nil); got != filter.Accept {
		t.Errorf("a reply to what this node opened: %v", got)
	}
	// A reply this node sends opens nothing for the ingress.
	c.out(parsed(tcpPacket(ap("100.64.0.1:22"), ap("100.64.0.2:6000"), tcpSyn|tcpAck)), nil)
	if got := c.in(parsed(tcpPacket(ap("100.64.0.2:6000"), ap("100.64.0.1:22"), tcpAck)), nil); got != filter.Drop {
		t.Errorf("a reply opened a way in: %v", got)
	}
	c.out(parsed(tcpPacket(ap("100.64.0.1:40002"), ap("100.64.0.4:443"), tcpSyn)), nil)
	if got := c.in(parsed(tcpPacket(ap("100.64.0.4:443"), ap("100.64.0.1:40002"), tcpSyn|tcpAck)), nil); got != filter.Accept {
		t.Errorf("a service member's reply: %v", got)
	}
	c.out(parsed(udpPacket(ap("100.64.0.1:40001"), ap("100.64.0.2:53"))), nil)
	if got := c.in(parsed(udpPacket(ap("100.64.0.2:53"), ap("100.64.0.1:40001"))), nil); got != filter.Accept {
		t.Errorf("a UDP reply: %v", got)
	}

	// The oldest flow goes once the bound is reached, and refreshed ones stay.
	for port := uint16(1); port <= 4; port++ {
		c.out(parsed(tcpPacket(netip.AddrPortFrom(netip.MustParseAddr("100.64.0.1"), 50000+port), ap("100.64.0.2:9"), tcpSyn)), nil)
		c.out(parsed(opened), nil)
	}
	if got := c.in(parsed(reply), nil); got != filter.Accept {
		t.Errorf("a flow in use was evicted: %v", got)
	}
	if got := c.in(parsed(tcpPacket(ap("100.64.0.2:9"), ap("100.64.0.1:50001"), tcpAck)), nil); got != filter.Drop {
		t.Errorf("past the bound, the oldest flow is kept: %v", got)
	}
}

// The engine's own hooks still run, after the confiner's.
func TestTheConfinerCallsTheEnginesHooks(t *testing.T) {
	var calls int
	next := func(*packet.Parsed, *tstun.Wrapper) filter.Response { calls++; return filter.DropSilently }
	c := &confiner{nextIn: next, nextOut: next}
	c.set(nil, nil)
	pkt := parsed(tcpPacket(ap("100.64.0.3:5000"), ap("100.64.0.1:22"), tcpAck))
	if got := c.in(pkt, nil); got != filter.DropSilently {
		t.Errorf("in: %v, want the engine's verdict", got)
	}
	if got := c.out(pkt, nil); got != filter.DropSilently {
		t.Errorf("out: %v, want the engine's verdict", got)
	}
	if calls != 2 {
		t.Errorf("the engine's hooks ran %d times", calls)
	}
}

// pipeTUN is a test device: what is injected, the host sends; what the
// engine delivers, it records.
type pipeTUN struct {
	events    chan tun.Event
	out       chan []byte
	delivered chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newPipeTUN() *pipeTUN {
	return &pipeTUN{events: make(chan tun.Event), out: make(chan []byte, 64), delivered: make(chan []byte, 256),
		closed: make(chan struct{})}
}

func (d *pipeTUN) File() *os.File           { panic("pipeTUN.File") }
func (d *pipeTUN) MTU() (int, error)        { return 1500, nil }
func (d *pipeTUN) Name() (string, error)    { return "pipeTUN", nil }
func (d *pipeTUN) Events() <-chan tun.Event { return d.events }
func (d *pipeTUN) BatchSize() int           { return 1 }

func (d *pipeTUN) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.events)
	})
	return nil
}

func (d *pipeTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case pkt := <-d.out:
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: copy(slab[tun.ReadPacketSpacing:len(slab)-tun.ReadPacketSpacing], pkt)}
		return 1, nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *pipeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case d.delivered <- append([]byte(nil), b[offset:]...):
		default:
		}
	}
	return len(bufs), nil
}

// Through a real tunnel, a member takes from an ingress what goes to a port
// it publishes, and none of what goes elsewhere.
func TestAnIngressReachesItsPortsAlone(t *testing.T) {
	memberTUN, ingressTUN := newPipeTUN(), newPipeTUN()
	member := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) {
		o.Tun, o.RespondToPing = memberTUN, false
	})
	ingress := startNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128", func(o *Options) {
		o.Tun, o.RespondToPing = ingressTUN, false
	})
	confined := ingress.peer()
	confined.Access = ingressAccess([]uint16{443}, nil)
	if err := member.mgr.SetPeers([]Peer{confined}); err != nil {
		t.Fatal(err)
	}
	if err := ingress.mgr.SetPeers([]Peer{member.peer()}); err != nil {
		t.Fatal(err)
	}
	refused := [][]byte{
		tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpSyn),
		tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpAck),
		udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:443")),
		tcpPacket(ap("[fd7a:115c:a1e0::2]:5000"), ap("[fd7a:115c:a1e0::1]:22"), tcpAck),
	}
	allowed := tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:443"), tcpSyn)
	deadline := time.Now().Add(20 * time.Second)
	for arrived := false; !arrived; {
		if time.Now().After(deadline) {
			t.Fatal("nothing the ingress may send arrived")
		}
		for _, p := range refused {
			ingressTUN.out <- p
		}
		ingressTUN.out <- allowed
		timeout := time.After(500 * time.Millisecond)
	drain:
		for {
			select {
			case got := <-memberTUN.delivered:
				p := parsed(got)
				if p.IPProto == ipproto.TCP && p.Dst.Port() == 443 {
					arrived = true
					continue
				}
				if p.IPProto == ipproto.TCP || p.IPProto == ipproto.UDP {
					t.Fatalf("the member took %v from the ingress", p)
				}
			case <-timeout:
				break drain
			}
		}
	}
}

// icmpPacket is an ICMP message of type and code from src to dst; rest
// follows the type, code and checksum.
func icmpPacket(src, dst netip.Addr, typ, code byte, rest []byte) []byte {
	proto := ipproto.ICMPv4
	if src.Is6() {
		proto = ipproto.ICMPv6
	}
	return ipPacket(proto, src, dst, append([]byte{typ, code, 0, 0}, rest...))
}

// A confined peer answers this node's pings, by their identifier, and its
// errors on what this node sent it pass; it starts no ICMP of its own, and
// vouches for no flow to another member.
func TestAConfinedPeerAnswersPingsAndErrors(t *testing.T) {
	c := &confiner{}
	c.maxFlowsPerAddr = 16
	c.set([]Peer{{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32"),
		netip.MustParsePrefix("fd00::2/128")}, Access: ingressAccess([]uint16{443}, nil)}},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd00::1/128")})
	self4, peer4 := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	self6, peer6 := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	echo := func(id byte) []byte { return []byte{0, id, 0, 1} }
	c.out(parsed(icmpPacket(self4, peer4, 8, 0, echo(7))), nil)
	c.out(parsed(icmpPacket(self6, peer6, 128, 0, echo(7))), nil)
	sent := udpPacket(ap("100.64.0.1:40000"), ap("100.64.0.2:53"))
	c.out(parsed(sent), nil)
	elsewhere := udpPacket(ap("100.64.0.1:40001"), ap("100.64.0.3:53"))
	for _, v := range []struct {
		what string
		pkt  []byte
		want filter.Response
	}{
		{"an echo reply", icmpPacket(peer4, self4, 0, 0, echo(7)), filter.Accept},
		{"an IPv6 echo reply", icmpPacket(peer6, self6, 129, 0, echo(7)), filter.Accept},
		{"an echo reply to no ping", icmpPacket(peer4, self4, 0, 0, echo(8)), filter.Drop},
		{"an echo request", icmpPacket(peer4, self4, 8, 0, echo(7)), filter.Drop},
		{"a port unreachable for what this node sent", icmpPacket(peer4, self4, 3, 3, append(make([]byte, 4), sent...)), filter.Accept},
		{"a port unreachable for nothing sent", icmpPacket(peer4, self4, 3, 3,
			append(make([]byte, 4), udpPacket(ap("100.64.0.1:40009"), ap("100.64.0.2:53"))...)), filter.Drop},
		{"an error for what went to another member", icmpPacket(peer4, self4, 3, 3, append(make([]byte, 4), elsewhere...)), filter.Drop},
	} {
		if got := c.in(parsed(v.pkt), nil); got != v.want {
			t.Errorf("%s: %v, want %v", v.what, got, v.want)
		}
	}
}

// A TCP flow this node opened ends with an RST either way at once, and with
// FINs both ways a grace later, which takes the retransmissions and last ACK.
func TestAConfinedFlowEndsWithItsConnection(t *testing.T) {
	const fin, rst = 0x01, 0x04
	now := time.Unix(1000, 0)
	c := &confiner{now: func() time.Time { return now }}
	c.maxFlowsPerAddr = 16
	c.set([]Peer{{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Access: serviceAccess()}},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	conn := func(port uint16) (out, in func(flags byte) filter.Response) {
		self := netip.AddrPortFrom(netip.MustParseAddr("100.64.0.1"), port)
		peer := ap("100.64.0.2:8080")
		return func(flags byte) filter.Response { return c.out(parsed(tcpPacket(self, peer, flags)), nil) },
			func(flags byte) filter.Response { return c.in(parsed(tcpPacket(peer, self, flags)), nil) }
	}
	open := func(port uint16) (out, in func(flags byte) filter.Response) {
		out, in = conn(port)
		out(tcpSyn)
		if got := in(tcpSyn | tcpAck); got != filter.Accept {
			t.Fatalf("the reply to a SYN: %v", got)
		}
		return out, in
	}
	out, in := open(40001)
	out(rst)
	if got := in(tcpAck); got != filter.Drop {
		t.Errorf("after this node's RST: %v", got)
	}
	_, in = open(40002)
	in(rst)
	if got := in(tcpAck); got != filter.Drop {
		t.Errorf("after the peer's RST: %v", got)
	}

	out, in = open(40003)
	out(fin | tcpAck)
	in(fin | tcpAck)
	out2, in2 := open(40004)
	in2(fin | tcpAck)
	out2(fin | tcpAck)
	for _, check := range []func(byte) filter.Response{in, in2} {
		if got := check(tcpAck); got != filter.Accept {
			t.Errorf("within the grace after FINs both ways: %v", got)
		}
	}
	now = now.Add(closedGrace + time.Second)
	for _, check := range []func(byte) filter.Response{in, in2} {
		if got := check(tcpAck); got != filter.Drop {
			t.Errorf("past the grace after FINs both ways: %v", got)
		}
	}

	// A port taken again by a SYN outlives the grace of its last connection.
	out, in = open(40005)
	out(fin | tcpAck)
	in(fin | tcpAck)
	out(tcpSyn)
	now = now.Add(closedGrace + time.Second)
	if got := in(tcpSyn | tcpAck); got != filter.Accept {
		t.Errorf("a connection on a port taken again: %v", got)
	}
}

// One confined peer's churn evicts its own flows, never another's.
func TestOnePeersFlowsEvictNoOthers(t *testing.T) {
	c := &confiner{maxFlows: 8, maxFlowsPerAddr: 4}
	c.set([]Peer{
		{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Access: serviceAccess()},
		{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}, Access: serviceAccess()},
	}, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	self := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("100.64.0.1"), port) }
	quiet, busy := ap("100.64.0.2:53"), ap("100.64.0.3:53")
	c.out(parsed(udpPacket(self(40000), quiet)), nil)
	for port := range uint16(100) {
		c.out(parsed(udpPacket(self(41000+port), busy)), nil)
	}
	if got := c.in(parsed(udpPacket(quiet, self(40000))), nil); got != filter.Accept {
		t.Errorf("the quiet peer's reply after the other's churn: %v", got)
	}
	if got := c.in(parsed(udpPacket(busy, self(41099))), nil); got != filter.Accept {
		t.Errorf("the busy peer's newest flow: %v", got)
	}
	if got := c.in(parsed(udpPacket(busy, self(41000))), nil); got != filter.Drop {
		t.Errorf("the busy peer's oldest flow, past its bound: %v", got)
	}

	// Past the whole bound, the address holding most gives way.
	c.set([]Peer{
		{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Access: serviceAccess()},
		{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32"), netip.MustParsePrefix("100.64.0.5/32")}, Access: serviceAccess()},
	}, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	for port := range uint16(4) {
		c.out(parsed(udpPacket(self(42000+port), ap("100.64.0.5:53"))), nil)
	}
	n := 0
	for _, fc := range c.flows {
		n += fc.Len()
	}
	if n > 8 {
		t.Errorf("%d flows held, past the bound of 8", n)
	}
	if got := c.in(parsed(udpPacket(quiet, self(40000))), nil); got != filter.Accept {
		t.Errorf("the quiet peer's reply past the whole bound: %v", got)
	}

	// A peer no longer confined leaves no flows behind.
	c.set(nil, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	if len(c.flows) != 0 {
		t.Errorf("flows kept for %d addresses no longer confined", len(c.flows))
	}
}

// fragment4 is a fragment of a UDP datagram from src to dst other than the
// first, offset bytes in.
func fragment4(src, dst netip.Addr, offset int) []byte {
	b := ipPacket(ipproto.UDP, src, dst, make([]byte, 64))
	binary.BigEndian.PutUint16(b[6:8], uint16(offset/8)) // no more fragments, at offset
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:20]))
	return b
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// A datagram larger than the tunnel takes, as a browser's QUIC Initial, comes
// in fragments: those after the first, which carry no port, pass from a
// confined peer to this node's own addresses, as the filter passes them, the
// first having been checked; to what this node routes, or inside a transport
// header, not.
func TestFragmentsOfAConfinedPeersDatagramPass(t *testing.T) {
	c := &confiner{}
	self, ingress := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(ingress, 32)}, Access: ingressAccess(nil, []uint16{443})}},
		[]netip.Prefix{netip.PrefixFrom(self, 32)})
	if p := parsed(fragment4(ingress, self, 1232)); p.IPProto != ipproto.Fragment {
		t.Fatalf("the packet is no fragment: %v", p.IPProto)
	}
	for _, v := range []struct {
		what string
		pkt  []byte
		want filter.Response
	}{
		{"a later fragment to this node", fragment4(ingress, self, 1232), filter.Accept},
		{"a later fragment to what this node routes", fragment4(ingress, netip.MustParseAddr("192.168.1.5"), 1232), filter.Drop},
		{"a fragment inside a transport header", fragment4(ingress, self, 8), filter.Drop},
	} {
		if got := c.in(parsed(v.pkt), nil); got != v.want {
			t.Errorf("%s: %v, want %v", v.what, got, v.want)
		}
	}
}

// A reply from a port an ingress may send UDP to opens nothing: once the
// port is no longer its, the ingress reaches it no more.
func TestAQUICReplyOpensNothing(t *testing.T) {
	c := &confiner{}
	self, ingress := netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("100.64.0.2/32")
	peers := []Peer{{Addrs: []netip.Prefix{ingress}, Access: ingressAccess(nil, []uint16{443})}}
	c.set(peers, []netip.Prefix{self})
	in := udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:443"))
	if got := c.in(parsed(in), nil); got != filter.Accept {
		t.Fatalf("UDP to a port QUIC is served on: %v", got)
	}
	c.out(parsed(udpPacket(ap("100.64.0.1:443"), ap("100.64.0.2:5000"))), nil)
	peers[0].Access = ingressAccess(nil, nil)
	c.set(peers, []netip.Prefix{self})
	if got := c.in(parsed(in), nil); got != filter.Drop {
		t.Errorf("UDP to a port no longer served: %v", got)
	}
}

// ingressAccess is what an ingress may open: TCP and UDP to these ports of
// this node's own addresses.
func ingressAccess(tcp, udp []uint16) *Access {
	a := &Access{Sends: []Ports{{}}}
	for _, p := range tcp {
		a.Open = append(a.Open, Ports{Proto: ipproto.TCP, First: p, Last: p})
	}
	for _, p := range udp {
		a.Open = append(a.Open, Ports{Proto: ipproto.UDP, First: p, Last: p})
	}
	return a
}

// serviceAccess is a service member's: replies alone.
func serviceAccess() *Access { return &Access{Sends: []Ports{{}}} }
