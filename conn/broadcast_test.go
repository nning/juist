package conn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

func TestBroadcastUnwrapsOnlyFromItsMember(t *testing.T) {
	packet := udpPacket(ap("100.64.0.2:5000"), ap("255.255.255.255:1716"))
	if _, ok := unwrapGroup(wrapGroup(addrB, addrA, packet), addrB, addrA); !ok {
		t.Fatal("broadcast was refused")
	}
	for _, port := range []uint16{67, 68} {
		for _, offset := range []int{20, 22} {
			b := append([]byte(nil), packet...)
			binary.BigEndian.PutUint16(b[offset:], port)
			if _, ok := unwrapGroup(wrapGroup(addrB, addrA, b), addrB, addrA); ok {
				t.Errorf("blocked port %d at offset %d passed", port, offset)
			}
		}
	}
	for _, dst := range []string{"10.77.0.255", "100.64.0.1"} {
		b := udpPacket(ap("100.64.0.2:5000"), netip.AddrPortFrom(netip.MustParseAddr(dst), 1716))
		if _, ok := unwrapGroup(wrapGroup(addrB, addrA, b), addrB, addrA); ok {
			t.Errorf("destination %s passed", dst)
		}
	}
	for _, src := range []netip.Addr{addrC, netip.MustParseAddr("192.0.2.1")} {
		b := udpPacket(netip.AddrPortFrom(src, 5000), ap("255.255.255.255:1716"))
		if _, ok := unwrapGroup(wrapGroup(addrB, addrA, b), addrB, addrA); ok {
			t.Errorf("source %s passed", src)
		}
	}
	for _, bits := range []uint16{0x2000, 1} {
		b := append([]byte(nil), packet...)
		binary.BigEndian.PutUint16(b[6:8], bits)
		if _, ok := unwrapGroup(wrapGroup(addrB, addrA, b), addrB, addrA); ok {
			t.Errorf("fragment %x passed", bits)
		}
	}
}

func TestBroadcastFollowsTheGroupAccess(t *testing.T) {
	c := &multicaster{}
	acc := &Access{GroupsTo: []Ports{{Proto: ipproto.UDP, First: 1716, Last: 1716}}}
	c.set([]Peer{{Addrs: []netip.Prefix{netip.PrefixFrom(addrB, 32)}, Access: acc}}, []netip.Prefix{netip.PrefixFrom(addrA, 32)})
	pol := c.policy.Load()
	for _, port := range []uint16{1716, 27036} {
		b := udpPacket(ap("100.64.0.1:5000"), netip.AddrPortFrom(netip.MustParseAddr("255.255.255.255"), port))
		if got := pol.wrap(pol.peers[0], b); (got != nil) != (port == 1716) {
			t.Errorf("port %d: wrapped %x", port, got)
		}
	}
}

func TestRefusedBroadcastNeverReachesTheEngine(t *testing.T) {
	calls := 0
	c := &multicaster{nextOut: func(*packet.Parsed, *tstun.Wrapper) filter.Response { calls++; return filter.Accept }}
	for _, port := range []uint16{67, 68} {
		b := udpPacket(ap("100.64.0.1:5000"), netip.AddrPortFrom(netip.MustParseAddr("255.255.255.255"), port))
		if got := c.out(parsed(b), nil); got != filter.DropSilently {
			t.Errorf("port %d fell through: %v", port, got)
		}
	}
	if calls != 0 {
		t.Errorf("the engine saw %d refused broadcasts", calls)
	}
}

func TestBroadcastCarriesOrdinaryUDPPorts(t *testing.T) {
	payload := []byte("192.0.2.7:137 names stay unchanged")
	for _, port := range []uint16{137, 138} {
		for _, ports := range [][2]uint16{{port, 5000}, {5000, port}, {port, port}} {
			b := packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{Src: addrB, Dst: netip.MustParseAddr("255.255.255.255")}, SrcPort: ports[0], DstPort: ports[1]}, payload)
			got, ok := unwrapGroup(wrapGroup(addrB, addrA, b), addrB, addrA)
			if !ok {
				t.Errorf("UDP %d -> %d was refused", ports[0], ports[1])
				continue
			}
			if !bytes.Equal(got, b) {
				t.Errorf("UDP %d -> %d was changed", ports[0], ports[1])
			}
		}
	}
}
