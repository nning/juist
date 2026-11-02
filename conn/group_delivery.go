package conn

import (
	"encoding/binary"
	"net/netip"
	"slices"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// localGroup also reaches sockets that joined the group only on the LAN.
// A unicast copy needs the peer's ordinary unicast permission for its port.
func (c *multicaster) localGroup(b []byte, pol *groupPolicy, sender *groupMember) []byte {
	if len(b) < 28 || b[0] != 0x45 || b[9] != byte(ipproto.UDP) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 ||
		int(binary.BigEndian.Uint16(b[24:26])) != len(b)-20 || !pol.self.v4.IsValid() {
		return nil
	}
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	port := binary.BigEndian.Uint16(b[22:24])
	if !dst.IsMulticast() || (!c.autoGroups && !slices.Contains(c.localGroups, dst)) || !passes(sender.open, ipproto.UDP, port) {
		return nil
	}
	h := packet.UDP4Header{IP4Header: packet.IP4Header{Src: netip.AddrFrom4([4]byte(b[12:16])), Dst: pol.self.v4},
		SrcPort: binary.BigEndian.Uint16(b[20:22]), DstPort: port}
	local := packet.Generate(h, b[28:])
	copy(local[:20], b[:20])
	addr := pol.self.v4.As4()
	copy(local[16:20], addr[:])
	binary.BigEndian.PutUint16(local[10:12], 0)
	binary.BigEndian.PutUint16(local[10:12], headerChecksum(local[:20]))
	return local
}
