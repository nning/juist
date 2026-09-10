package conn

import (
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// TestFilterCarriesAllProtocols pins the v1 packet policy: any member may send
// any traffic to any other member. An empty IPProto does not mean "any" — it
// defaults to TCP, UDP and ICMP — and a mesh VPN that quietly drops ESP or GRE
// is broken in a way no ping test reveals.
func TestFilterCarriesAllProtocols(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatalf("SetPeers: %v", err)
	}
	filt, err := a.mgr.(*tsManager).filter()
	if err != nil {
		t.Fatalf("filter: %v", err)
	}

	src, dst := b.pingAddr(), a.pingAddr()
	for _, proto := range []ipproto.Proto{
		ipproto.ICMPv4,
		ipproto.TCP,
		ipproto.UDP,
		ipproto.SCTP,
		47,  // GRE
		50,  // ESP
		51,  // AH
		89,  // OSPF
		253, // reserved for experimentation; nothing special-cases it
	} {
		var p packet.Parsed
		p.Decode(ipv4Packet(proto, src, dst))
		if got := filt.RunIn(&p, 0); got != filter.Accept {
			t.Errorf("proto %d (%v) from a member: got %v, want Accept", proto, proto, got)
		}
	}
}

// TestFilterRejectsNonMembers is the filter's half of default-deny: it is a
// second gate, independent of the peer lookup that governs whether WireGuard
// will even create a peer.
func TestFilterRejectsNonMembers(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatalf("SetPeers: %v", err)
	}
	filt, err := a.mgr.(*tsManager).filter()
	if err != nil {
		t.Fatalf("filter: %v", err)
	}

	// An overlay address that belongs to no member.
	outsider := netip.MustParseAddr("100.64.0.99")
	var p packet.Parsed
	p.Decode(ipv4Packet(ipproto.UDP, outsider, a.pingAddr()))
	if got := filt.RunIn(&p, 0); got == filter.Accept {
		t.Errorf("filter accepted traffic from non-member %v", outsider)
	}

	// And with no members at all, nothing is accepted.
	if err := a.mgr.SetPeers(nil); err != nil {
		t.Fatalf("SetPeers(nil): %v", err)
	}
	empty, err := a.mgr.(*tsManager).filter()
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	var q packet.Parsed
	q.Decode(ipv4Packet(ipproto.UDP, b.pingAddr(), a.pingAddr()))
	if got := empty.RunIn(&q, 0); got == filter.Accept {
		t.Errorf("filter accepted traffic with an empty member set")
	}
}

// ipv4Packet builds a minimal IPv4 packet carrying the given protocol number.
// The payload is 20 bytes because the decoder reports a truncated transport
// header as an unknown protocol, which the filter would then judge for the
// wrong reason.
func ipv4Packet(proto ipproto.Proto, src, dst netip.Addr) []byte {
	payload := make([]byte, 20)
	if proto == ipproto.TCP {
		payload[12] = 5 << 4 // data offset: five words
		payload[13] = 0x02   // SYN, so the filter evaluates rules
	}
	return packet.Generate(packet.IP4Header{IPProto: proto, Src: src, Dst: dst}, payload)
}
