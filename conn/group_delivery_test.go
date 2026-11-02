package conn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

func TestALocalGroupCopyNeedsUnicastAccess(t *testing.T) {
	group := netip.MustParseAddr("224.0.2.60")
	c := &multicaster{localGroups: []netip.Addr{group}}
	pol := &groupPolicy{self: &groupMember{v4: addrA}}
	b := packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{Src: addrB, Dst: group}, SrcPort: 5000, DstPort: 4445}, []byte("world"))
	b[8] = 1
	binary.BigEndian.PutUint16(b[10:12], 0)
	binary.BigEndian.PutUint16(b[10:12], headerChecksum(b[:20]))
	original := bytes.Clone(b)
	for _, tc := range []struct {
		name string
		open []Ports
		want bool
	}{
		{"multicast alone", nil, false},
		{"a different port", []Ports{{Proto: ipproto.UDP, First: 4446, Last: 4446}}, false},
		{"TCP", []Ports{{Proto: ipproto.TCP}}, false},
		{"UDP", []Ports{{Proto: ipproto.UDP, First: 4445, Last: 4445}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.localGroup(b, pol, &groupMember{open: tc.open})
			if (got != nil) != tc.want {
				t.Fatalf("copy %x, want %v", got, tc.want)
			}
			if got != nil {
				p := parsed(got)
				if p.Src != ap("100.64.0.2:5000") || p.Dst != ap("100.64.0.1:4445") || got[8] != 1 || !bytes.Equal(got[28:], []byte("world")) || headerChecksum(got[:20]) != 0 {
					t.Fatalf("bad local copy: %x", got)
				}
			}
			if !bytes.Equal(b, original) {
				t.Fatal("original changed")
			}
		})
	}
	c.localGroups = nil
	if c.localGroup(b, pol, &groupMember{open: []Ports{{}}}) != nil {
		t.Fatal("an unselected group was copied")
	}
	c.autoGroups = true
	if c.localGroup(b, pol, &groupMember{open: []Ports{{}}}) == nil {
		t.Fatal("automatic mode still needs a selected group")
	}
	if c.localGroup(b, pol, &groupMember{}) != nil {
		t.Fatal("automatic mode bypassed unicast access")
	}
	c.autoGroups = false
	c.localGroups = []netip.Addr{group}
	for _, bits := range []uint16{1, 0x2000} {
		fragment := bytes.Clone(b)
		binary.BigEndian.PutUint16(fragment[6:8], bits)
		if c.localGroup(fragment, pol, &groupMember{open: []Ports{{}}}) != nil {
			t.Fatal("a fragment was copied")
		}
	}
}
