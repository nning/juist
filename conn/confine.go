package conn

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// An Access is what a restricted peer may open on this node, and through it,
// and what this node may open on the peer. Anything else the peer sends is
// dropped but replies to what this node opened; anything else this node
// would open on it, too. Without one a peer is left to the filter, which
// takes anything from a member.
type Access struct {
	// Open is what the peer may open on this node's own addresses.
	Open []Ports

	// Through is what it may open on what this node serves: the internet, as
	// an exit node, or its subnets; each prefix holding a destination adds
	// its ports.
	Through []Through

	// Sends is what this node may open on the peer's own addresses.
	Sends []Ports
}

// Ports are a protocol, zero for every one, and its ports First to Last,
// both zero for every port.
type Ports struct {
	Proto       ipproto.Proto
	First, Last uint16
}

// Through is ports on a prefix this node serves.
type Through struct {
	Prefix netip.Prefix
	Ports  []Ports
}

// Clone returns a deep copy, nil for nil.
func (a *Access) Clone() *Access {
	if a == nil {
		return nil
	}
	out := &Access{Open: slices.Clone(a.Open), Through: slices.Clone(a.Through), Sends: slices.Clone(a.Sends)}
	for i := range out.Through {
		out.Through[i].Ports = slices.Clone(out.Through[i].Ports)
	}
	return out
}

// passes reports whether ports pass a packet of proto to port, or an echo
// request, which has none, where the protocol is passed at all.
func passes(ports []Ports, proto ipproto.Proto, port uint16) bool {
	for _, p := range ports {
		if p.Proto == 0 || p.Proto == proto && (p.First == 0 || p.First <= port && port <= p.Last) {
			return true
		}
	}
	return false
}

// maxConfinedFlows bounds the flows this node opened to confined peers, and
// maxFlowsPerAddr those to one of their addresses, so that one peer's churn
// evicts its own flows. One evicted ends that connection, so both are generous.
const (
	maxConfinedFlows = 16384
	maxFlowsPerAddr  = 4096
)

// A confiner keeps restricted peers to their [Access]. The filter cannot: it
// takes TCP without SYN, ICMP errors and TSMP from any member, to any
// address this node serves.
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

// confinePolicy is one immutable snapshot of who is restricted and to what.
type confinePolicy struct {
	peers  map[netip.Addr]*Access        // restricted peers' overlay addresses
	routes map[netip.Addr][]netip.Prefix // what this node routes through each
	routed *netipx.IPSet                 // all of those
	self   []netip.Addr                  // this node's own overlay addresses
}

// confine installs c around w's filter. It must run before w starts, since
// the hooks are plain fields the packet path reads.
func confine(w *tstun.Wrapper) *confiner {
	c := &confiner{nextIn: w.PreFilterPacketInboundFromWireGuard, nextOut: w.PostFilterPacketOutboundToWireGuard}
	w.PreFilterPacketInboundFromWireGuard = c.in
	w.PostFilterPacketOutboundToWireGuard = c.out
	return c
}

// set replaces the policy: the restricted peers' access, and this node's
// addresses.
func (c *confiner) set(peers []Peer, self []netip.Prefix) {
	p := &confinePolicy{peers: map[netip.Addr]*Access{}, routes: map[netip.Addr][]netip.Prefix{}}
	var routed netipx.IPSetBuilder
	for _, peer := range peers {
		if peer.Access == nil {
			continue
		}
		for _, r := range slices.Concat(peer.Routes, peer.Subnets) {
			routed.AddPrefix(r)
		}
		for _, a := range peer.Addrs {
			p.peers[a.Addr()] = peer.Access
			p.routes[a.Addr()] = slices.Concat(peer.Routes, peer.Subnets)
		}
	}
	p.routed, _ = routed.IPSet()
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
		if acc, ok := pol.peers[p.Src.Addr()]; ok && !c.admits(pol, acc, p) {
			return filter.Drop
		}
		// From an address a restricted router carries, as an exit node's
		// answers: for this node alone, which the filter keeps to answers.
		if pol.routed != nil && pol.routed.Contains(p.Src.Addr()) && !slices.Contains(pol.self, p.Dst.Addr()) {
			return filter.Drop
		}
	}
	if c.nextIn != nil {
		return c.nextIn(p, w)
	}
	return filter.Accept
}

// opens reports whether acc lets its peer open proto to dst, on this node or
// through it.
func (pol *confinePolicy) opens(acc *Access, proto ipproto.Proto, dst netip.AddrPort) bool {
	if slices.Contains(pol.self, dst.Addr()) {
		return passes(acc.Open, proto, dst.Port())
	}
	return slices.ContainsFunc(acc.Through, func(t Through) bool {
		return t.Prefix.Contains(dst.Addr()) && passes(t.Ports, proto, dst.Port())
	})
}

// admits reports whether a restricted peer may send p.
func (c *confiner) admits(pol *confinePolicy, acc *Access, p *packet.Parsed) bool {
	// A fragment after the first carries no port: it passes where the peer
	// may send something, the first having been checked, and the host it is
	// for drops what has no first.
	if p.IPProto == ipproto.Fragment {
		return slices.Contains(pol.self, p.Dst.Addr()) ||
			slices.ContainsFunc(acc.Through, func(t Through) bool { return t.Prefix.Contains(p.Dst.Addr()) })
	}
	if isICMP(p.IPProto) && p.IsError() {
		// The peer's own error about what this node sent through it, as an
		// exit node's that the path is too narrow.
		if _, src, dst, _, ok := quoted(p); ok && src == p.Dst.Addr() && slices.Contains(pol.self, src) &&
			slices.ContainsFunc(pol.routes[p.Src.Addr()], func(r netip.Prefix) bool { return r.Contains(dst) }) {
			return true
		}
		t, ok := erredFlow(p)
		c.mu.Lock()
		defer c.mu.Unlock()
		_, opened := c.getLocked(t)
		return ok && opened
	}
	if isICMP(p.IPProto) && p.IsEchoRequest() {
		return pol.opens(acc, p.IPProto, p.Dst)
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
	return !isICMP(p.IPProto) && pol.opens(acc, p.IPProto, p.Dst)
}

func (c *confiner) out(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if pol := c.policy.Load(); pol != nil {
		if acc, ok := pol.peers[p.Dst.Addr()]; ok && !c.sends(pol, acc, p) {
			return filter.Drop
		}
	}
	if c.nextOut != nil {
		return c.nextOut(p, w)
	}
	return filter.Accept
}

// sends tracks what this node opens on a restricted peer, and reports
// whether it may: a reply, or a new flow its access passes.
func (c *confiner) sends(pol *confinePolicy, acc *Access, p *packet.Parsed) bool {
	t := flowKey(p, true)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	f, known := c.getLocked(t)
	switch {
	// A reply opens nothing: only what this node starts is its own.
	case !known && p.IPProto == ipproto.UDP && pol.opens(acc, p.IPProto, p.Src):
	case !known && (p.IPProto == ipproto.UDP || p.IsTCPSyn() || isICMP(p.IPProto) && p.IsEchoRequest()):
		if !passes(acc.Sends, p.IPProto, p.Dst.Port()) {
			return false
		}
		c.addLocked(t)
	case known && p.IsTCPSyn():
		*f = flowState{} // the port taken again
	case known && p.IPProto == ipproto.TCP && p.TCPFlags&packet.TCPRst != 0:
		c.removeLocked(t)
	case known && p.IPProto == ipproto.TCP && p.TCPFlags&packet.TCPFin != 0:
		f.finOut = true
		c.closeLocked(t, f)
	}
	return true
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
	proto, src, dst, l4, ok := quoted(p)
	if !ok || (proto != ipproto.TCP && proto != ipproto.UDP) || dst != p.Src.Addr() || src != p.Dst.Addr() {
		return flowtrack.Tuple{}, false
	}
	sp, dp := binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
	return flowtrack.MakeTuple(proto, netip.AddrPortFrom(src, sp), netip.AddrPortFrom(dst, dp)), true
}

// quoted is the packet an ICMP error quotes: its protocol, addresses and
// the start of its transport header.
func quoted(p *packet.Parsed) (proto ipproto.Proto, src, dst netip.Addr, l4 []byte, ok bool) {
	b := p.Payload()
	if len(b) < 4 {
		return 0, src, dst, nil, false
	}
	b = b[4:] // the unused word, or a needed MTU
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+4 {
			return 0, src, dst, nil, false
		}
		return ipproto.Proto(b[9]), netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[ihl:], true
	case len(b) >= 44 && b[0]>>4 == 6:
		return ipproto.Proto(b[6]), netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), b[40:], true
	}
	return 0, src, dst, nil, false
}
