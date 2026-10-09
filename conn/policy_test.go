package conn

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// A restricted peer opens what its access passes on this node and through
// it, by protocol and port, whatever its flags; this node opens on it what
// its access sends, and answers what it opened.
func TestAPeerIsKeptToItsAccess(t *testing.T) {
	c := &confiner{}
	acc := &Access{
		Open:    []Ports{{Proto: ipproto.TCP, First: 22, Last: 22}, {Proto: ipproto.UDP, First: 53, Last: 53}},
		Through: []Through{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Ports: []Ports{{Proto: ipproto.TCP, First: 443, Last: 443}}}},
		Sends:   []Ports{{Proto: ipproto.TCP, First: 80, Last: 80}},
	}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Access: acc}},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	for _, v := range []struct {
		what string
		pkt  []byte
		want filter.Response
	}{
		{"a SYN to a port it may open", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpSyn), filter.Accept},
		{"the rest of that connection", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpAck), filter.Accept},
		{"a SYN to another port", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:80"), tcpSyn), filter.Drop},
		{"an ACK to another port", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:80"), tcpAck), filter.Drop},
		{"UDP to a port it may open", udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:53")), filter.Accept},
		{"TCP to that port", tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:53"), tcpSyn), filter.Drop},
		{"a ping, which no rule passes", icmpPacket(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"), 8, 0,
			[]byte{0, 1, 0, 1}), filter.Drop},
		{"the internet on a port it may use", tcpPacket(ap("100.64.0.2:5000"), ap("1.1.1.1:443"), tcpSyn), filter.Accept},
		{"the internet on another port", tcpPacket(ap("100.64.0.2:5000"), ap("1.1.1.1:80"), tcpAck), filter.Drop},
		{"UDP to the internet", udpPacket(ap("100.64.0.2:5000"), ap("1.1.1.1:443")), filter.Drop},
	} {
		if got := c.in(parsed(v.pkt), nil); got != v.want {
			t.Errorf("%s: %v, want %v", v.what, got, v.want)
		}
	}

	for _, v := range []struct {
		what string
		pkt  []byte
		want filter.Response
	}{
		{"opening a port it sends", tcpPacket(ap("100.64.0.1:40000"), ap("100.64.0.2:80"), tcpSyn), filter.Accept},
		{"opening another", tcpPacket(ap("100.64.0.1:40001"), ap("100.64.0.2:22"), tcpSyn), filter.Drop},
		{"UDP to the peer", udpPacket(ap("100.64.0.1:40002"), ap("100.64.0.2:53")), filter.Drop},
		{"a ping", icmpPacket(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), 8, 0, []byte{0, 1, 0, 1}), filter.Drop},
		{"answering its SYN", tcpPacket(ap("100.64.0.1:22"), ap("100.64.0.2:5000"), tcpSyn|tcpAck), filter.Accept},
		{"answering its datagram", udpPacket(ap("100.64.0.1:53"), ap("100.64.0.2:5000")), filter.Accept},
		{"answering for the internet", udpPacket(ap("1.1.1.1:443"), ap("100.64.0.2:5000")), filter.Drop},
	} {
		if got := c.out(parsed(v.pkt), nil); got != v.want {
			t.Errorf("sending %s: %v, want %v", v.what, got, v.want)
		}
	}
	if got := c.in(parsed(tcpPacket(ap("100.64.0.2:80"), ap("100.64.0.1:40000"), tcpSyn|tcpAck)), nil); got != filter.Accept {
		t.Errorf("the answer to what this node opened: %v", got)
	}
	if got := c.in(parsed(udpPacket(ap("100.64.0.2:6000"), ap("100.64.0.1:53"))), nil); got != filter.Accept {
		t.Errorf("UDP it may open, after this node answered its own: %v", got)
	}
	if got := c.in(parsed(udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:40003"))), nil); got != filter.Drop {
		t.Errorf("an answer to this node's answer opened a way in: %v", got)
	}

	ping := &Access{Open: []Ports{{Proto: ipproto.ICMPv4}}, Sends: []Ports{{Proto: ipproto.ICMPv4}}}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Access: ping}},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	if got := c.in(parsed(icmpPacket(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"), 8, 0,
		[]byte{0, 1, 0, 1})), nil); got != filter.Accept {
		t.Errorf("a ping ICMP is passed for: %v", got)
	}
}

// Through a real tunnel, a member takes from a peer what that peer's access
// passes and nothing else, though the peer sends whatever it likes: its own
// side restricts nothing. As an exit node, it forwards that peer nothing
// until its access passes the internet.
func TestTheReceiverEnforcesWhateverTheSenderSends(t *testing.T) {
	bTUN, aTUN := newPipeTUN(), newPipeTUN()
	b := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) {
		o.Tun, o.RespondToPing = bTUN, false
	})
	a := startNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128", func(o *Options) {
		o.Tun, o.RespondToPing = aTUN, false
	})
	m := b.mgr.(*tsManager)
	m.serve = Serve{Routes: Internet(true, true, nil)}
	restricted := a.peer()
	restricted.Access = &Access{Open: []Ports{{Proto: ipproto.TCP, First: 22, Last: 22}}, Sends: []Ports{{}}}
	if err := b.mgr.SetPeers([]Peer{restricted}); err != nil {
		t.Fatal(err)
	}
	// A takes b for the internet's way out, and restricts nothing.
	via := b.peer()
	via.Routes = Internet(true, true, nil)
	if err := a.mgr.SetPeers([]Peer{via}); err != nil {
		t.Fatal(err)
	}
	refused := [][]byte{
		tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:80"), tcpSyn),
		tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:80"), tcpAck),
		udpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:53")),
		icmpPacket(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"), 8, 0, []byte{0, 1, 0, 1}),
		tcpPacket(ap("[fd7a:115c:a1e0::2]:5000"), ap("[fd7a:115c:a1e0::1]:80"), tcpAck),
		tcpPacket(ap("100.64.0.2:5000"), ap("8.8.8.8:443"), tcpSyn),
		tcpPacket(ap("100.64.0.2:5000"), ap("8.8.8.8:443"), tcpAck),
		udpPacket(ap("100.64.0.2:5000"), ap("8.8.8.8:53")),
	}
	takes := func(want func(p []byte) bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for arrived := false; !arrived; {
			if time.Now().After(deadline) {
				t.Fatal("nothing the peer may send arrived")
			}
			for _, p := range refused {
				aTUN.out <- p
			}
			aTUN.out <- tcpPacket(ap("100.64.0.2:5000"), ap("100.64.0.1:22"), tcpSyn)
			timeout := time.After(500 * time.Millisecond)
		drain:
			for {
				select {
				case got := <-bTUN.delivered:
					if want(got) {
						arrived = true
						continue
					}
					if p := parsed(got); p.IPProto != ipproto.ICMPv6 {
						t.Fatalf("the receiver took %v", p)
					}
				case <-timeout:
					break drain
				}
			}
		}
	}
	isSSH := func(got []byte) bool { p := parsed(got); return p.IPProto == ipproto.TCP && p.Dst.Port() == 22 }
	takes(isSSH)

	restricted.Access.Through = []Through{{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Ports: []Ports{{Proto: ipproto.UDP, First: 53, Last: 53}}}}
	if err := b.mgr.SetPeers([]Peer{restricted}); err != nil {
		t.Fatal(err)
	}
	refused = refused[:len(refused)-1]
	aTUN.out <- udpPacket(ap("100.64.0.2:5000"), ap("8.8.8.8:53"))
	takes(func(got []byte) bool {
		p := parsed(got)
		return isSSH(got) || p.IPProto == ipproto.UDP && p.Dst == ap("8.8.8.8:53")
	})
}

// Through an exit node or subnet router, a restricted peer's later fragments
// pass where its first could, and the router's own ICMP errors about what
// this node sent through it reach this node; errors about what it sent
// elsewhere do not.
func TestWhatPassesThroughARouter(t *testing.T) {
	c := &confiner{}
	self, client, exit := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.3")
	c.set([]Peer{
		{Addrs: []netip.Prefix{netip.PrefixFrom(client, 32)}, Access: &Access{
			Through: []Through{{Prefix: netip.MustParsePrefix("8.8.0.0/16"), Ports: []Ports{{Proto: ipproto.UDP}}}}}},
		{Addrs: []netip.Prefix{netip.PrefixFrom(exit, 32)}, Routes: Internet(true, false, nil),
			Access: &Access{Sends: []Ports{{}}}},
	}, []netip.Prefix{netip.PrefixFrom(self, 32)})
	if got := c.in(parsed(fragment4(client, netip.MustParseAddr("8.8.8.8"), 1232)), nil); got != filter.Accept {
		t.Errorf("a later fragment through this node: %v", got)
	}
	if got := c.in(parsed(fragment4(client, netip.MustParseAddr("9.9.9.9"), 1232)), nil); got != filter.Drop {
		t.Errorf("a later fragment to what the peer may not reach: %v", got)
	}
	quoting := func(dst string) []byte {
		quoted := udpPacket(netip.AddrPortFrom(self, 5000), ap(dst))
		return icmpPacket(exit, self, 3, 4, append([]byte{0, 0, 5, 0xdc}, quoted[:28]...))
	}
	if got := c.in(parsed(quoting("8.8.8.8:53")), nil); got != filter.Accept {
		t.Errorf("the exit node's error about what this node sent through it: %v", got)
	}
	if got := c.in(parsed(quoting("100.64.0.2:53")), nil); got != filter.Drop {
		t.Errorf("the exit node's error about what this node sent another peer: %v", got)
	}
}

// What a restricted router sends from the addresses it carries reaches this
// node alone, where answers to what this node sent through it go; an error
// it sends about what this node sent through it reaches this node alone.
func TestARoutersOtherSourcesReachThisNodeAlone(t *testing.T) {
	c := &confiner{}
	self, router := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.3")
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(router, 32)}, Subnets: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")},
		Access: &Access{}}}, []netip.Prefix{netip.PrefixFrom(self, 32)})
	for _, v := range []struct {
		what string
		pkt  []byte
		want filter.Response
	}{
		{"an answer from its subnet to this node", tcpPacket(ap("10.2.0.5:22"), ap("100.64.0.1:40000"), tcpAck), filter.Accept},
		{"from its subnet to what this node serves", tcpPacket(ap("10.2.0.5:22"), ap("10.1.0.7:22"), tcpAck), filter.Drop},
		{"its error about what this node sent, to another host", icmpPacket(router, netip.MustParseAddr("10.1.0.7"), 3, 1,
			append([]byte{0, 0, 0, 0}, udpPacket(netip.AddrPortFrom(self, 5000), ap("10.2.0.5:53"))[:28]...)), filter.Drop},
		{"its error about what this node sent, to this node", icmpPacket(router, self, 3, 1,
			append([]byte{0, 0, 0, 0}, udpPacket(netip.AddrPortFrom(self, 5000), ap("10.2.0.5:53"))[:28]...)), filter.Accept},
	} {
		if got := c.in(parsed(v.pkt), nil); got != v.want {
			t.Errorf("%s: %v, want %v", v.what, got, v.want)
		}
	}
}
