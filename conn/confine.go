package conn

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// Confinement is what a member may send this node, decided by its role.
type Confinement uint8

const (
	// ConfineNone leaves a peer to the filter, which takes anything from a
	// member.
	ConfineNone Confinement = iota

	// ConfineIngress takes from a peer replies to what this node opened, and
	// TCP to this node's own addresses on the ports [Manager.SetIngressPorts]
	// names.
	ConfineIngress

	// ConfineService takes from a peer replies to what this node opened
	// alone: a service member opens nothing.
	ConfineService
)

// maxConfinedFlows bounds the flows this node opened to confined peers, and
// maxFlowsPerAddr those to one of their addresses, so that one peer's churn
// evicts its own flows. One evicted ends that connection, so both are generous.
const (
	maxConfinedFlows = 16384
	maxFlowsPerAddr  = 4096
)

// A confiner keeps confined peers to what their [Confinement] allows. The
// filter cannot: it takes TCP without SYN, ICMP errors and TSMP from any
// member, to any address this node serves.
type confiner struct {
	policy atomic.Pointer[confinePolicy]

	mu      sync.Mutex
	flows   map[netip.Addr]*flowtrack.Cache[flowState] // opened by this node, as it sent them, by the peer's address
	closing []closingFlow                              // TCP flows closed both ways, oldest first
	now     func() time.Time

	// Zero is maxConfinedFlows and maxFlowsPerAddr.
	maxFlows, maxFlowsPerAddr int

	// The engine's own hooks, run after these.
	nextIn, nextOut tstun.FilterFunc
}

// flowState is how far a TCP flow has closed: FIN sent each way, and both.
type flowState struct {
	finOut, finIn, closed bool
}

type closingFlow struct {
	t  flowtrack.Tuple
	at time.Time
}

// closedGrace is how long a TCP flow closed both ways still takes the
// peer's retransmissions and last ACK.
const closedGrace = time.Minute

// confinePolicy is one immutable snapshot of who is confined and to what.
type confinePolicy struct {
	peers map[netip.Addr]Confinement // confined peers' overlay addresses
	self  []netip.Addr               // this node's own overlay addresses
	ports []uint16                   // TCP ports an ingress may open
}

// confine installs c around w's filter. It must run before w starts, since
// the hooks are plain fields the packet path reads.
func confine(w *tstun.Wrapper) *confiner {
	c := &confiner{nextIn: w.PreFilterPacketInboundFromWireGuard, nextOut: w.PostFilterPacketOutboundToWireGuard}
	w.PreFilterPacketInboundFromWireGuard = c.in
	w.PostFilterPacketOutboundToWireGuard = c.out
	return c
}

// set replaces the policy: peers by kind, this node's addresses and the ports
// an ingress may open.
func (c *confiner) set(peers []Peer, self []netip.Prefix, ports []uint16) {
	p := &confinePolicy{peers: map[netip.Addr]Confinement{}, ports: slices.Clone(ports)}
	for _, peer := range peers {
		if peer.Confined == ConfineNone {
			continue
		}
		for _, a := range peer.Addrs {
			p.peers[a.Addr()] = peer.Confined
		}
	}
	for _, a := range self {
		p.self = append(p.self, a.Addr())
	}
	c.policy.Store(p)
	c.mu.Lock()
	for a := range c.flows {
		if _, ok := p.peers[a]; !ok {
			delete(c.flows, a)
		}
	}
	c.mu.Unlock()
}

func (c *confiner) in(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if pol := c.policy.Load(); pol != nil {
		if kind, ok := pol.peers[p.Src.Addr()]; ok && !c.admits(pol, kind, p) {
			return filter.Drop
		}
	}
	if c.nextIn != nil {
		return c.nextIn(p, w)
	}
	return filter.Accept
}

// admits reports whether a confined peer of kind may send p.
func (c *confiner) admits(pol *confinePolicy, kind Confinement, p *packet.Parsed) bool {
	if isICMP(p.IPProto) && p.IsError() {
		t, ok := erredFlow(p)
		c.mu.Lock()
		defer c.mu.Unlock()
		_, opened := c.getLocked(t)
		return ok && opened
	}
	if isICMP(p.IPProto) && !p.IsEchoResponse() {
		return false
	}
	t := flowKey(p, false)
	c.mu.Lock()
	c.expireLocked()
	f, opened := c.getLocked(t)
	if opened && p.IPProto == ipproto.TCP {
		switch {
		case p.TCPFlags&packet.TCPRst != 0:
			c.removeLocked(t)
		case p.TCPFlags&packet.TCPFin != 0:
			f.finIn = true
			c.closeLocked(t, f)
		}
	}
	c.mu.Unlock()
	if opened {
		return true
	}
	return kind == ConfineIngress && p.IPProto == ipproto.TCP &&
		slices.Contains(pol.self, p.Dst.Addr()) && slices.Contains(pol.ports, p.Dst.Port())
}

func (c *confiner) out(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if pol := c.policy.Load(); pol != nil {
		if _, ok := pol.peers[p.Dst.Addr()]; ok {
			t := flowKey(p, true)
			c.mu.Lock()
			c.expireLocked()
			f, known := c.getLocked(t)
			switch {
			// A reply opens nothing: only what this node starts is its own.
			case !known && (p.IPProto == ipproto.UDP || p.IsTCPSyn() || isICMP(p.IPProto) && p.IsEchoRequest()):
				c.addLocked(t)
			case known && p.IsTCPSyn():
				*f = flowState{} // the port taken again
			case known && p.IPProto == ipproto.TCP && p.TCPFlags&packet.TCPRst != 0:
				c.removeLocked(t)
			case known && p.IPProto == ipproto.TCP && p.TCPFlags&packet.TCPFin != 0:
				f.finOut = true
				c.closeLocked(t, f)
			}
			c.mu.Unlock()
		}
	}
	if c.nextOut != nil {
		return c.nextOut(p, w)
	}
	return filter.Accept
}

// closeLocked queues a flow closed both ways to go after closedGrace.
func (c *confiner) closeLocked(t flowtrack.Tuple, f *flowState) {
	if f.finIn && f.finOut && !f.closed {
		f.closed = true
		c.closing = append(c.closing, closingFlow{t, c.clock()})
	}
}

// expireLocked removes the flows closed longer than closedGrace ago that no
// SYN took again since.
func (c *confiner) expireLocked() {
	now := c.clock()
	for len(c.closing) > 0 && now.Sub(c.closing[0].at) > closedGrace {
		if f, ok := c.getLocked(c.closing[0].t); ok && f.closed {
			c.removeLocked(c.closing[0].t)
		}
		c.closing = c.closing[1:]
	}
}

func (c *confiner) getLocked(t flowtrack.Tuple) (*flowState, bool) {
	if fc := c.flows[t.DstAddr()]; fc != nil {
		return fc.Get(t)
	}
	return nil, false
}

func (c *confiner) removeLocked(t flowtrack.Tuple) {
	if fc := c.flows[t.DstAddr()]; fc != nil {
		fc.Remove(t)
		if fc.Len() == 0 {
			delete(c.flows, t.DstAddr())
		}
	}
}

// addLocked records a flow, evicting the oldest of its address's past their
// bound, and past the whole bound the oldest of the address holding most.
func (c *confiner) addLocked(t flowtrack.Tuple) {
	perAddr, total := cmp.Or(c.maxFlowsPerAddr, maxFlowsPerAddr), cmp.Or(c.maxFlows, maxConfinedFlows)
	if c.flows == nil {
		c.flows = map[netip.Addr]*flowtrack.Cache[flowState]{}
	}
	fc := c.flows[t.DstAddr()]
	if fc == nil {
		fc = &flowtrack.Cache[flowState]{MaxEntries: perAddr}
		c.flows[t.DstAddr()] = fc
	}
	fc.Add(t, flowState{})
	n, most := 0, fc
	for _, other := range c.flows {
		n += other.Len()
		if other.Len() > most.Len() {
			most = other
		}
	}
	if n > total {
		most.RemoveOldest()
	}
}

func (c *confiner) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func isICMP(p ipproto.Proto) bool { return p == ipproto.ICMPv4 || p == ipproto.ICMPv6 }

// flowKey is p's flow as this node sent it, outbound or not: an ICMP echo's
// by its identifier, which takes the port's place on this node's side.
func flowKey(p *packet.Parsed, outbound bool) flowtrack.Tuple {
	self, peer := p.Src, p.Dst
	if !outbound {
		self, peer = p.Dst, p.Src
	}
	if isICMP(p.IPProto) {
		var id uint16
		if b := p.Payload(); len(b) >= 2 {
			id = binary.BigEndian.Uint16(b)
		}
		self = netip.AddrPortFrom(self.Addr(), id)
	}
	return flowtrack.MakeTuple(p.IPProto, self, peer)
}

// erredFlow is the flow an ICMP error from a peer is about: the packet it
// quotes, which this node sent to that peer, or false where it is none.
func erredFlow(p *packet.Parsed) (flowtrack.Tuple, bool) {
	b := p.Payload()
	if len(b) < 4 {
		return flowtrack.Tuple{}, false
	}
	b = b[4:] // the unused word, or a needed MTU
	var proto ipproto.Proto
	var src, dst netip.Addr
	var l4 []byte
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+4 {
			return flowtrack.Tuple{}, false
		}
		proto, src, dst, l4 = ipproto.Proto(b[9]), netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[ihl:]
	case len(b) >= 44 && b[0]>>4 == 6:
		proto, src, dst, l4 = ipproto.Proto(b[6]), netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), b[40:]
	default:
		return flowtrack.Tuple{}, false
	}
	if (proto != ipproto.TCP && proto != ipproto.UDP) || dst != p.Src.Addr() || src != p.Dst.Addr() {
		return flowtrack.Tuple{}, false
	}
	sp, dp := binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
	return flowtrack.MakeTuple(proto, netip.AddrPortFrom(src, sp), netip.AddrPortFrom(dst, dp)), true
}
