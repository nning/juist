package conn

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ipv6Packet is an IPv6 packet of proto from src to dst carrying seg, its
// checksum at at left as macOS leaves one it sends itself.
func ipv6Packet(proto byte, src, dst netip.Addr, seg []byte, at int) []byte {
	p := make([]byte, 40+len(seg))
	p[0] = 6 << 4
	binary.BigEndian.PutUint16(p[4:], uint16(len(seg)))
	p[6], p[7] = proto, 64
	s, d := src.As16(), dst.As16()
	copy(p[8:], s[:])
	copy(p[24:], d[:])
	copy(p[40:], seg)
	binary.BigEndian.PutUint16(p[40+at:], 0x3d5e)
	return p
}

// valid is whether p's transport checksum is right, by gVisor's sums.
func valid(p []byte) bool {
	src := tcpip.AddrFrom16Slice(p[8:24])
	dst := tcpip.AddrFrom16Slice(p[24:40])
	seg := p[40:]
	sum := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(p[6]), src, dst, uint16(len(seg)))
	return checksum.Checksum(seg, sum) == 0xffff
}

// What a Mac sends its own IPv6 address through the device carries an
// unfinished checksum, which the reflected copy must not: a lookup at the
// device's resolver and a connection to its log sync went unanswered.
func TestSelfAddressedIPv6GetsItsChecksum(t *testing.T) {
	own := netip.MustParseAddr("fd72:15d7:4377:2564:75bf:143:8237:a926")
	other := netip.MustParseAddr("fd72:15d7:4377:21b5:5b16:87e8:3d08:c174")
	udp := []byte{0xec, 0xb8, 0, 53, 0, 13, 0, 0, 'q', 'u', 'e', 'r', 'y'}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 49191)
	binary.BigEndian.PutUint16(tcp[2:], 41644)
	tcp[12], tcp[13] = 5<<4, 0x02
	for name, p := range map[string][]byte{
		"udp": ipv6Packet(17, own, own, udp, 6),
		"tcp": ipv6Packet(6, own, own, tcp, 16),
	} {
		if valid(p) {
			t.Fatalf("%s: the unfinished checksum is valid already", name)
		}
		completeSelfChecksum(p)
		if !valid(p) {
			t.Errorf("%s to itself: checksum still wrong", name)
		}
	}
	// Another host's packets keep theirs: they are the sender's to get right.
	p := ipv6Packet(17, own, other, udp, 6)
	before := string(p)
	completeSelfChecksum(p)
	if string(p) != before {
		t.Error("a packet to another address was changed")
	}
	// What is short or not TCP or UDP is left alone.
	for _, p := range [][]byte{ipv6Packet(58, own, own, udp, 2), ipv6Packet(17, own, own, udp, 6)[:44], {0x45, 0}} {
		before := string(p)
		completeSelfChecksum(p)
		if string(p) != before {
			t.Errorf("changed % x", p)
		}
	}
}
