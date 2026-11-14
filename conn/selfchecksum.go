package conn

import "encoding/binary"

// completeSelfChecksum fills in the TCP or UDP checksum of p, an IPv6 packet
// the host sends to itself through the device: macOS leaves it unfinished,
// as for loopback, and drops the copy the engine reflects back.
func completeSelfChecksum(p []byte) {
	if len(p) < 40 || p[0]>>4 != 6 || string(p[8:24]) != string(p[24:40]) {
		return
	}
	n := int(binary.BigEndian.Uint16(p[4:6]))
	if 40+n > len(p) {
		return
	}
	var at int
	switch p[6] {
	case 6:
		at = 16
	case 17:
		at = 6
	default:
		return
	}
	seg := p[40 : 40+n]
	if len(seg) < at+2 {
		return
	}
	seg[at], seg[at+1] = 0, 0
	sum := uint32(p[6]) + uint32(n)
	for _, b := range [][]byte{p[8:40], seg} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	if c == 0 && p[6] == 17 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(seg[at:], c)
}
