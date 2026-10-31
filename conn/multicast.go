package conn

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// groupRate and groupBurst bound the group datagrams one member sends, in
// packets a second: this node holds itself to them, and every sender too.
const (
	groupRate  = 100
	groupBurst = 200
)

// ipip is IPv4 encapsulated in IPv4, which carries a group datagram to one
// member, so that its outer address picks the peer.
const ipip ipproto.Proto = 4

// A multicaster carries the group datagrams this node's device sends to
// every unrestricted member, each wrapped and addressed to the member, and
// delivers theirs. Only IPv4 UDP to a multicast group passes, with the
// sender's own overlay address as its source.
type multicaster struct {
	policy atomic.Pointer[groupPolicy]
	sent   *rate.Limiter
	// sending holds what the host sent, for a goroutine of its own to wrap
	// and inject: InjectOutbound blocks the hook, which runs on the
	// goroutine that drains what it injects.
	sending chan groupSend

	// The engine's own hooks, run after these.
	nextIn, nextOut tstun.FilterFunc
}

type groupSend struct {
	datagram []byte
	pol      *groupPolicy
}

// groupPolicy is one immutable snapshot of who takes part.
type groupPolicy struct {
	self    netip.Addr                   // this node's overlay IPv4 address
	peers   []netip.Addr                 // the members a group datagram goes to
	senders map[netip.Addr]*rate.Limiter // the same, with what each may still send
}

// relayGroups installs a multicaster around w's engine hook and inbound
// hook, sending until done is closed. It must run before w starts, since the
// hooks are plain fields the packet path reads, and after [confine], which it
// runs ahead of.
func relayGroups(w *tstun.Wrapper, done <-chan struct{}, running *sync.WaitGroup) *multicaster {
	c := &multicaster{
		sent:    rate.NewLimiter(groupRate, groupBurst),
		sending: make(chan groupSend, groupBurst),
		nextIn:  w.PreFilterPacketInboundFromWireGuard,
		nextOut: w.PreFilterPacketOutboundToWireGuardEngineIntercept,
	}
	w.PreFilterPacketInboundFromWireGuard = c.in
	w.PreFilterPacketOutboundToWireGuardEngineIntercept = c.out
	running.Add(1)
	go func() {
		defer running.Done()
		for {
			select {
			case s := <-c.sending:
				for _, peer := range s.pol.peers {
					w.InjectOutbound(wrapGroup(s.pol.self, peer, s.datagram))
				}
			case <-done:
				return
			}
		}
	}()
	return c
}

// set replaces who takes part: the peers without an [Access], and this
// node's addresses. A nil c does nothing.
func (c *multicaster) set(peers []Peer, self []netip.Prefix) {
	if c == nil {
		return
	}
	prev := c.policy.Load()
	p := &groupPolicy{self: firstIPv4(self), senders: map[netip.Addr]*rate.Limiter{}}
	for _, peer := range peers {
		a := firstIPv4(peer.Addrs)
		if peer.Access != nil || !a.IsValid() {
			continue
		}
		p.peers = append(p.peers, a)
		if prev != nil && prev.senders[a] != nil {
			p.senders[a] = prev.senders[a]
		} else {
			p.senders[a] = rate.NewLimiter(groupRate, groupBurst)
		}
	}
	c.policy.Store(p)
}

func firstIPv4(addrs []netip.Prefix) netip.Addr {
	for _, a := range addrs {
		if a.Addr().Is4() {
			return a.Addr()
		}
	}
	return netip.Addr{}
}

// out takes a group datagram the host sends, ahead of the filter, which
// drops every multicast destination, and sends a wrapped copy to each
// member.
func (c *multicaster) out(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if src, ok := groupDatagram(p.Buffer()); ok {
		pol := c.policy.Load()
		if pol != nil && pol.self.IsValid() && src == pol.self && len(pol.peers) > 0 && c.sent.Allow() {
			select {
			case c.sending <- groupSend{datagram: append([]byte(nil), p.Buffer()...), pol: pol}:
			default:
			}
		}
		return filter.DropSilently
	}
	if c.nextOut != nil {
		return c.nextOut(p, w)
	}
	return filter.Accept
}

// in delivers a member's group datagram, unwrapped, and drops anything else
// wrapped for this node.
func (c *multicaster) in(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if pol := c.policy.Load(); pol != nil && pol.self.IsValid() && p.IPVersion == 4 && p.IPProto == ipip && p.Dst.Addr() == pol.self {
		inner, ok := unwrapGroup(p.Buffer(), p.Src.Addr(), pol.self)
		if lim := pol.senders[p.Src.Addr()]; !ok || lim == nil || !lim.Allow() {
			return filter.Drop
		}
		w.InjectInboundCopy(inner)
		return filter.DropSilently
	}
	if c.nextIn != nil {
		return c.nextIn(p, w)
	}
	return filter.Accept
}

// groupDatagram reports whether b is a whole IPv4 packet carrying UDP, or a
// fragment of it, to a multicast group, and its source.
func groupDatagram(b []byte) (netip.Addr, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) || len(b) < ihl {
		return netip.Addr{}, false
	}
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	if !dst.IsMulticast() || ipproto.Proto(b[9]) != ipproto.UDP {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(b[12:16])), true
}

// wrapGroup is inner addressed from src to dst, inside an IPv4 header of
// its own.
func wrapGroup(src, dst netip.Addr, inner []byte) []byte {
	b := make([]byte, 20+len(inner))
	b[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = byte(ipip)
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], headerChecksum(b[:20]))
	copy(b[20:], inner)
	return b
}

// unwrapGroup is the group datagram b carries from sender to self, or false
// where b is not exactly what [wrapGroup] makes of one: unfragmented, without
// options, and the datagram's own source the sender's.
func unwrapGroup(b []byte, sender, self netip.Addr) ([]byte, bool) {
	if len(b) < 20 || b[0] != 4<<4|5 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) ||
		binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 || ipproto.Proto(b[9]) != ipip ||
		netip.AddrFrom4([4]byte(b[12:16])) != sender || netip.AddrFrom4([4]byte(b[16:20])) != self {
		return nil, false
	}
	inner := b[20:]
	if src, ok := groupDatagram(inner); !ok || src != sender {
		return nil, false
	}
	return inner, true
}

func headerChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
