package conn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/time/rate"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

// groupRate and groupBurst bound the group datagrams one member sends, in
// packets a second: this node holds itself to them, and every sender too.
const (
	groupRate  = 100
	groupBurst = 200
)

// ipip and ipv6Encap are IPv4 in IPv4 and IPv6 in IPv6, which carry a
// group datagram to one member, so that its outer address picks the peer.
const (
	ipip      ipproto.Proto = 4
	ipv6Encap ipproto.Proto = 41
)

// A multicaster carries the group datagrams this node's device sends to
// every member its access lets it, each wrapped and addressed to the member,
// and delivers theirs. Only UDP to a multicast group passes, IPv6 only to a
// group of link or site scope, with the sender's own overlay address as its
// source, or over IPv6 its link-local address.
type multicaster struct {
	policy atomic.Pointer[groupPolicy]
	sent   *rate.Limiter

	// asked are the sources of the group datagrams sent and delivered
	// lately, by the address of the peer that may answer them, which its
	// unicast answers pass; at most maxAsked a peer.
	askedMu sync.Mutex
	asked   map[netip.Addr]map[netip.AddrPort]time.Time
	now     func() time.Time
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
	self    *groupMember
	peers   []*groupMember              // those this node sends to
	senders map[netip.Addr]*groupMember // those it takes from, by their overlay addresses
	members map[netip.Addr]*groupMember // both, for their limiters
}

// A groupMember is a member's overlay addresses, its link-local address
// where it holds one, and what it may still send. to and from are the UDP
// ports a group datagram may go to it on and come from it on, any where nil.
type groupMember struct {
	v4, v6, ll netip.Addr
	lim        *rate.Limiter
	to, from   []Ports
}

// answerWindow is how long a unicast answer to a group datagram passes
// a restricted peer's access: SSDP's longest wait, and more.
const answerWindow = 10 * time.Second

// maxAsked bounds the sources answers are kept for, a peer: one fills only
// its own.
const maxAsked = 256

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
					if b := s.pol.wrap(peer, s.datagram); b != nil {
						c.ask(s.datagram, peer)
						w.InjectOutbound(b)
					}
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
	p := &groupPolicy{self: memberOf(self), senders: map[netip.Addr]*groupMember{}, members: map[netip.Addr]*groupMember{}}
	for _, peer := range peers {
		acc := peer.Access
		sends, takes := acc == nil, acc == nil
		m := memberOf(peer.Addrs)
		if acc != nil && !acc.Nothing {
			sends, takes = len(acc.GroupsTo) > 0, len(acc.GroupsFrom) > 0
			m.to, m.from = anyPort(acc.GroupsTo), anyPort(acc.GroupsFrom)
		}
		sends = sends && !peer.Rests
		if !sends && !takes {
			continue
		}
		for _, a := range []netip.Addr{m.v6, m.v4} {
			if was := prev.member(a); m.lim == nil && was != nil {
				m.lim = was.lim
			}
		}
		if m.lim == nil {
			m.lim = rate.NewLimiter(groupRate, groupBurst)
		}
		if sends {
			p.peers = append(p.peers, m)
		}
		for _, a := range []netip.Addr{m.v4, m.v6} {
			if !a.IsValid() {
				continue
			}
			p.members[a] = m
			if takes {
				p.senders[a] = m
			}
		}
	}
	c.policy.Store(p)
}

func (p *groupPolicy) member(a netip.Addr) *groupMember {
	if p == nil || !a.IsValid() {
		return nil
	}
	return p.members[a]
}

func (p *groupPolicy) sender(a netip.Addr) *groupMember {
	if p == nil || !a.IsValid() {
		return nil
	}
	return p.senders[a]
}

// anyPort is ports, nil where they pass every UDP port, so that a later
// fragment, which holds none, passes too.
func anyPort(ports []Ports) []Ports {
	if slices.ContainsFunc(ports, func(p Ports) bool { return (p.Proto == 0 || p.Proto == ipproto.UDP) && p.First == 0 }) {
		return nil
	}
	return ports
}

// passes reports whether ports pass datagram, any where nil; one whose port
// is not in it, as a later fragment, passes where nil alone.
func passesGroup(ports []Ports, datagram []byte) bool {
	if ports == nil {
		return true
	}
	_, dst, ok := groupPorts(datagram)
	return ok && passes(ports, ipproto.UDP, dst.Port())
}

// groupPorts is a group datagram's source and destination with their UDP
// ports, false where it does not hold them, as a later fragment does not.
func groupPorts(b []byte) (src, dst netip.AddrPort, ok bool) {
	switch {
	case len(b) >= 48 && b[0]>>4 == 6:
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), binary.BigEndian.Uint16(b[40:42])),
			netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[24:40])), binary.BigEndian.Uint16(b[42:44])), true
	case len(b) >= 28 && b[0]>>4 == 4 && binary.BigEndian.Uint16(b[6:8])&0x1fff == 0:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[12:16])), binary.BigEndian.Uint16(b[20:22])),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[16:20])), binary.BigEndian.Uint16(b[22:24])), true
	}
	return netip.AddrPort{}, netip.AddrPort{}, false
}

// ask records that peer may answer datagram for answerWindow, at its
// addresses of the datagram's family.
func (c *multicaster) ask(datagram []byte, peer *groupMember) {
	src, _, ok := groupPorts(datagram)
	if !ok {
		return
	}
	if src.Addr().Is4() {
		c.record(peer.v4, src)
		return
	}
	c.record(peer.v6, src)
	c.record(peer.ll, src)
}

// record keeps src for peer, in place of what peer holds longest where it
// holds maxAsked.
func (c *multicaster) record(peer netip.Addr, src netip.AddrPort) {
	if !peer.IsValid() {
		return
	}
	now := c.clock()
	c.askedMu.Lock()
	defer c.askedMu.Unlock()
	if c.asked == nil {
		c.asked = map[netip.Addr]map[netip.AddrPort]time.Time{}
	}
	held := c.asked[peer]
	if held == nil {
		held = map[netip.AddrPort]time.Time{}
		c.asked[peer] = held
	}
	if _, ok := held[src]; !ok && len(held) >= maxAsked {
		var oldest netip.AddrPort
		for k, at := range held {
			if !oldest.IsValid() || at.Before(held[oldest]) {
				oldest = k
			}
		}
		delete(held, oldest)
	}
	held[src] = now
}

// answers reports whether peer may answer a group datagram that left from
// src lately: one this node sent it, or it sent this node.
func (c *multicaster) answers(peer netip.Addr, src netip.AddrPort) bool {
	c.askedMu.Lock()
	at, ok := c.asked[peer][src]
	c.askedMu.Unlock()
	return ok && c.clock().Sub(at) <= answerWindow
}

func (c *multicaster) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func memberOf(addrs []netip.Prefix) *groupMember {
	m := &groupMember{}
	for _, pfx := range addrs {
		switch a := pfx.Addr(); {
		case a.Is4() && !m.v4.IsValid():
			m.v4 = a
		case a.Is6() && a.IsLinkLocalUnicast() && !m.ll.IsValid():
			m.ll = a
		case a.Is6() && !a.IsLinkLocalUnicast() && !m.v6.IsValid():
			m.v6 = a
		}
	}
	return m
}

// owns reports whether src is one of m's addresses a datagram of its own
// may come from.
func (m *groupMember) owns(src netip.Addr) bool {
	return src.IsValid() && (src == m.v4 || src == m.v6 || src == m.ll)
}

// wrap is datagram wrapped from this node to peer, nil where either lacks
// an address of its family.
func (p *groupPolicy) wrap(peer *groupMember, datagram []byte) []byte {
	if !passesGroup(peer.to, datagram) {
		return nil
	}
	if datagram[0]>>4 == 4 {
		if !p.self.v4.IsValid() || !peer.v4.IsValid() {
			return nil
		}
		return wrapGroup(p.self.v4, peer.v4, datagram)
	}
	if !p.self.v6.IsValid() || !peer.v6.IsValid() {
		return nil
	}
	return wrapGroup6(p.self.v6, peer.v6, datagram)
}

// out takes a group datagram the host sends, ahead of the filter, which
// drops every multicast destination, and sends a wrapped copy to each
// member.
func (c *multicaster) out(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if src, ok := groupDatagram(p.Buffer()); ok {
		pol := c.policy.Load()
		if pol != nil && pol.self.owns(src) && len(pol.peers) > 0 && c.sent.Allow() {
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
	pol := c.policy.Load()
	wrapped := pol != nil && (p.IPVersion == 4 && p.IPProto == ipip && pol.self.v4.IsValid() && p.Dst.Addr() == pol.self.v4 ||
		p.IPVersion == 6 && p.IPProto == ipv6Encap && pol.self.v6.IsValid() && p.Dst.Addr() == pol.self.v6)
	if wrapped {
		sender := pol.sender(p.Src.Addr())
		if sender == nil {
			return filter.Drop
		}
		var inner []byte
		var ok bool
		if p.IPVersion == 4 {
			inner, ok = unwrapGroup(p.Buffer(), sender.v4, pol.self.v4)
		} else {
			inner, ok = unwrapGroup6(p.Buffer(), sender.v6, sender.ll, pol.self.v6)
		}
		if !ok || !passesGroup(sender.from, inner) || !sender.lim.Allow() {
			return filter.Drop
		}
		c.ask(inner, sender)
		w.InjectInboundCopy(inner)
		return filter.DropSilently
	}
	if c.nextIn != nil {
		return c.nextIn(p, w)
	}
	return filter.Accept
}

// groupDatagram reports whether b is a whole IP packet carrying UDP to a
// multicast group, without IPv4 options or IPv6 extension headers, over IPv4
// a fragment of one too, over IPv6 to a group of link or site scope; and its
// source.
func groupDatagram(b []byte) (netip.Addr, bool) {
	if len(b) >= 40 && b[0]>>4 == 6 {
		scope := b[25] & 0x0f
		if int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) || ipproto.Proto(b[6]) != ipproto.UDP ||
			b[24] != 0xff || scope != 2 && scope != 5 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(b[8:24])), true
	}
	if len(b) < 20 || b[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	if b[0]&0x0f != 5 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
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

// wrapGroup6 is inner addressed from src to dst, inside an IPv6 header of
// its own.
func wrapGroup6(src, dst netip.Addr, inner []byte) []byte {
	b := make([]byte, 40+len(inner))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(inner)))
	b[6] = byte(ipv6Encap)
	b[7] = 64
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], inner)
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
	if src, ok := groupDatagram(inner); !ok || src != sender || inner[0]>>4 != 4 {
		return nil, false
	}
	return inner, true
}

// unwrapGroup6 is [unwrapGroup] for what [wrapGroup6] makes: the datagram's
// own source is the sender's overlay address or its link-local one, ll,
// where valid.
func unwrapGroup6(b []byte, sender, ll, self netip.Addr) ([]byte, bool) {
	if len(b) < 40 || binary.BigEndian.Uint32(b[0:4]) != 6<<28 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) ||
		ipproto.Proto(b[6]) != ipv6Encap ||
		netip.AddrFrom16([16]byte(b[8:24])) != sender || netip.AddrFrom16([16]byte(b[24:40])) != self {
		return nil, false
	}
	inner := b[40:]
	if src, ok := groupDatagram(inner); !ok || inner[0]>>4 != 6 || src != sender && (!ll.IsValid() || src != ll) {
		return nil, false
	}
	return inner, true
}

// linkLocal is the link-local address of a member whose overlay IPv6
// address is a: fe80::/64 and a's low 64 bits.
func linkLocal(a netip.Addr) netip.Addr {
	if !a.Is6() {
		return netip.Addr{}
	}
	ll := [16]byte{0xfe, 0x80}
	b := a.As16()
	copy(ll[8:], b[8:])
	return netip.AddrFrom16(ll)
}

// withLinkLocal is addrs and the link-local address their overlay IPv6
// address gives, where it has one.
func withLinkLocal(addrs []netip.Prefix) []netip.Prefix {
	ll := linkLocal(memberOf(addrs).v6)
	if !ll.IsValid() || slices.Contains(addrs, netip.PrefixFrom(ll, 128)) {
		return addrs
	}
	return append(slices.Clip(addrs), netip.PrefixFrom(ll, 128))
}

// withoutLinkLocals is peers without the link-local addresses
// [withLinkLocals] gave them.
func withoutLinkLocals(peers []Peer) []Peer {
	out := slices.Clone(peers)
	for i := range out {
		out[i].Addrs = slices.DeleteFunc(slices.Clone(out[i].Addrs), func(p netip.Prefix) bool { return p.Addr().IsLinkLocalUnicast() })
	}
	return out
}

// withLinkLocals is peers, each with its link-local address where no other
// peer, and not self, would share it; the entry whose key is selfKey with
// self's.
func withLinkLocals(selfKey key.NodePublic, self []netip.Prefix, peers []Peer) []Peer {
	selfLL := memberOf(self).ll
	count := map[netip.Addr]int{}
	for _, p := range peers {
		if p.NodeKey != selfKey {
			count[linkLocal(memberOf(p.Addrs).v6)]++
		}
	}
	out := slices.Clone(peers)
	for i, p := range out {
		ll := linkLocal(memberOf(p.Addrs).v6)
		switch {
		case p.NodeKey == selfKey && selfLL.IsValid():
			ll = selfLL
		case p.NodeKey == selfKey, !ll.IsValid(), count[ll] != 1, ll == selfLL:
			continue
		}
		if !slices.Contains(p.Addrs, netip.PrefixFrom(ll, 128)) {
			out[i].Addrs = append(slices.Clip(p.Addrs), netip.PrefixFrom(ll, 128))
		}
	}
	return out
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

// checkGroups refuses [Options.Groups] the node cannot route.
func checkGroups(opts Options) error {
	if len(opts.Groups) == 0 {
		return nil
	}
	if !opts.Multicast || opts.TunName == "" || opts.Tun != nil || opts.Plumber != nil || runtime.GOOS != "linux" {
		return errors.New("conn: groups are routed into a device of Linux's own, with multicast")
	}
	for _, g := range opts.Groups {
		if !g.Is4() || !g.IsMulticast() {
			return fmt.Errorf("conn: %v is no IPv4 multicast group", g)
		}
	}
	return nil
}

// joinGroups joins groups on dev, which holds them while the socket returned
// is open; it binds no port a group's datagrams go to.
func joinGroups(dev string, groups []netip.Addr) (io.Closer, error) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	p := ipv4.NewPacketConn(c)
	for _, g := range groups {
		if err := p.JoinGroup(ifi, &net.UDPAddr{IP: g.AsSlice()}); err != nil {
			c.Close()
			return nil, fmt.Errorf("joining %v: %w", g, err)
		}
	}
	return c, nil
}
