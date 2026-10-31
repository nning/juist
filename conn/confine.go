package conn

import (
	"cmp"
	"encoding/binary"
	"maps"
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

	// Nothing passes nothing either way, replies and errors included.
	Nothing bool

	// GroupsFrom are the UDP ports the peer may send this node group
	// datagrams on, GroupsTo those this node may send it on; none where
	// nil. Each passes the unicast answers to a group datagram too.
	GroupsFrom, GroupsTo []Ports
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
	out := &Access{Open: slices.Clone(a.Open), Through: slices.Clone(a.Through), Sends: slices.Clone(a.Sends), Nothing: a.Nothing,
		GroupsFrom: slices.Clone(a.GroupsFrom), GroupsTo: slices.Clone(a.GroupsTo)}
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

	// flows are those this node opened, as it sent them, by the peer's
	// address; replaced whole under flowsMu, read without it.
	flows   atomic.Pointer[map[netip.Addr]*flowSet]
	flowsMu sync.Mutex
	held    atomic.Int64  // flows in all sets
	gen     atomic.Uint64 // advanced by each flow added, which use stamps
	now     func() time.Time

	baseOnce sync.Once
	base     time.Time

	// Zero is maxConfinedFlows and maxFlowsPerAddr.
	maxFlows, maxFlowsPerAddr int

	// The engine's own hooks, run after these.
	nextIn, nextOut tstun.FilterFunc

	// groups knows the group datagrams sent and delivered, which a
	// restricted peer's answers follow; nil without multicast.
	groups *multicaster
}

// A flowSet is the flows to one peer address. A packet of a flow takes its
// lock for reading; one that opens, closes or ends a flow, for writing.
type flowSet struct {
	mu      sync.RWMutex
	flows   map[flowtrack.Tuple]*flow
	closing []closingFlow // TCP flows closed both ways, oldest first
	gone    bool          // its address is no longer confined
}

type flow struct {
	used     atomic.Uint64 // the gen when last used
	closedAt atomic.Int64  // when closed both ways, as [confiner.since]; zero while open
	state    flowState     // under the set's mu
}

// flowState is how far a TCP flow has closed: FIN sent each way.
type flowState struct {
	finOut, finIn bool
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
	none   *netipx.IPSet                 // what peers passing nothing route
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
	var routed, none netipx.IPSetBuilder
	for _, peer := range peers {
		if peer.Access == nil {
			continue
		}
		for _, r := range slices.Concat(peer.Routes, peer.Subnets) {
			routed.AddPrefix(r)
			if peer.Access.Nothing {
				none.AddPrefix(r)
			}
		}
		for _, a := range peer.Addrs {
			p.peers[a.Addr()] = peer.Access
			p.routes[a.Addr()] = slices.Concat(peer.Routes, peer.Subnets)
		}
	}
	p.routed, _ = routed.IPSet()
	p.none, _ = none.IPSet()
	for _, a := range self {
		p.self = append(p.self, a.Addr())
	}
	c.policy.Store(p)
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()
	if c.flows.Load() == nil {
		return
	}
	next := maps.Clone(*c.flows.Load())
	for a, fs := range next {
		if _, ok := p.peers[a]; !ok {
			fs.mu.Lock()
			c.held.Add(-int64(len(fs.flows)))
			fs.flows, fs.gone = nil, true
			fs.mu.Unlock()
			delete(next, a)
		}
	}
	c.flows.Store(&next)
}

func (c *confiner) in(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if pol := c.policy.Load(); pol != nil {
		// What is wrapped for this node is the multicaster's, which takes it
		// ahead of this where it runs; the host's own tunnels never see it.
		if (p.IPProto == ipip || p.IPProto == ipv6Encap) && slices.Contains(pol.self, p.Dst.Addr()) {
			return filter.Drop
		}
		if acc, ok := pol.peers[p.Src.Addr()]; ok && (acc.Nothing || !c.admits(pol, acc, p) && !(slices.Contains(pol.self, p.Dst.Addr()) && c.answer(acc.GroupsTo, p.IPProto, p.Src.Addr(), p.Dst))) ||
			pol.none != nil && pol.none.Contains(p.Src.Addr()) {
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

// answer reports whether a UDP datagram of peer's to dst answers a group
// datagram that left from dst lately, one peer was sent or sent; groups are
// its access's, which pass none where empty.
func (c *confiner) answer(groups []Ports, proto ipproto.Proto, peer netip.Addr, dst netip.AddrPort) bool {
	return c.groups != nil && len(groups) > 0 && proto == ipproto.UDP && c.groups.answers(peer, dst)
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
		return ok && c.opened(t)
	}
	if isICMP(p.IPProto) && p.IsEchoRequest() {
		return pol.opens(acc, p.IPProto, p.Dst)
	}
	if isICMP(p.IPProto) && !p.IsEchoResponse() {
		return false
	}
	t := flowKey(p, false)
	opened := c.opened(t)
	if opened && p.IPProto == ipproto.TCP && p.TCPFlags&(packet.TCPRst|packet.TCPFin) != 0 {
		c.change(t, func(fs *flowSet, f *flow) {
			switch {
			case f == nil:
			case p.TCPFlags&packet.TCPRst != 0:
				c.removeLocked(fs, t)
			default:
				f.state.finIn = true
				c.closeLocked(fs, t, f)
			}
		})
	}
	if opened {
		return true
	}
	return !isICMP(p.IPProto) && pol.opens(acc, p.IPProto, p.Dst)
}

func (c *confiner) out(p *packet.Parsed, w *tstun.Wrapper) filter.Response {
	if pol := c.policy.Load(); pol != nil {
		if acc, ok := pol.peers[p.Dst.Addr()]; ok && (acc.Nothing || !c.sends(pol, acc, p) && !(slices.Contains(pol.self, p.Src.Addr()) && c.answer(acc.GroupsFrom, p.IPProto, p.Dst.Addr(), p.Dst))) ||
			pol.none != nil && pol.none.Contains(p.Dst.Addr()) {
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
	known := c.opened(t)
	tcpFlags := p.IPProto == ipproto.TCP && p.TCPFlags&(packet.TCPSyn|packet.TCPRst|packet.TCPFin) != 0
	switch {
	case known && !tcpFlags:
		return true
	// A reply opens nothing: only what this node starts is its own.
	case !known && p.IPProto == ipproto.UDP && pol.opens(acc, p.IPProto, p.Src):
		return true
	case !known && (p.IPProto == ipproto.UDP || p.IsTCPSyn() || isICMP(p.IPProto) && p.IsEchoRequest()):
		if !passes(acc.Sends, p.IPProto, p.Dst.Port()) {
			return false
		}
		c.add(t)
		return true
	case !known:
		return true
	}
	c.change(t, func(fs *flowSet, f *flow) {
		switch {
		case f == nil:
		case p.IsTCPSyn():
			// The port taken again.
			f.state = flowState{}
			f.closedAt.Store(0)
		case p.TCPFlags&packet.TCPRst != 0:
			c.removeLocked(fs, t)
		case p.TCPFlags&packet.TCPFin != 0:
			f.state.finOut = true
			c.closeLocked(fs, t, f)
		}
	})
	return true
}

// opened reports whether this node opened t and it has not ended, marking
// it used.
func (c *confiner) opened(t flowtrack.Tuple) bool {
	fs := c.flowSet(t.DstAddr())
	if fs == nil {
		return false
	}
	fs.mu.RLock()
	f := fs.flows[t]
	fs.mu.RUnlock()
	if f == nil {
		return false
	}
	if at := f.closedAt.Load(); at != 0 && c.since()-at > int64(closedGrace) {
		return false
	}
	if g := c.gen.Load(); f.used.Load() != g {
		f.used.Store(g)
	}
	return true
}

func (c *confiner) flowSet(a netip.Addr) *flowSet {
	if m := c.flows.Load(); m != nil {
		return (*m)[a]
	}
	return nil
}

// change runs fn on t's set, and t if held, under the set's lock, after
// removing the flows closed longer than closedGrace ago.
func (c *confiner) change(t flowtrack.Tuple, fn func(*flowSet, *flow)) {
	fs := c.flowSet(t.DstAddr())
	if fs == nil {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	c.expireLocked(fs)
	fn(fs, fs.flows[t])
}

// closeLocked queues a flow closed both ways to go after closedGrace.
func (c *confiner) closeLocked(fs *flowSet, t flowtrack.Tuple, f *flow) {
	if f.state.finIn && f.state.finOut && f.closedAt.Load() == 0 {
		f.closedAt.Store(c.since())
		fs.closing = append(fs.closing, closingFlow{t, c.clock()})
	}
}

// expireLocked removes the flows of fs closed longer than closedGrace ago
// that no SYN took again since.
func (c *confiner) expireLocked(fs *flowSet) {
	now := c.clock()
	for len(fs.closing) > 0 && now.Sub(fs.closing[0].at) > closedGrace {
		if f := fs.flows[fs.closing[0].t]; f != nil && f.closedAt.Load() != 0 {
			c.removeLocked(fs, fs.closing[0].t)
		}
		fs.closing = fs.closing[1:]
	}
}

func (c *confiner) removeLocked(fs *flowSet, t flowtrack.Tuple) {
	if _, ok := fs.flows[t]; ok {
		delete(fs.flows, t)
		c.held.Add(-1)
	}
}

// add records a flow, evicting the least used of its address's past their
// bound, and past the whole bound that of the address holding most.
func (c *confiner) add(t flowtrack.Tuple) {
	perAddr, total := cmp.Or(c.maxFlowsPerAddr, maxFlowsPerAddr), cmp.Or(c.maxFlows, maxConfinedFlows)
	fs := c.flowSet(t.DstAddr())
	if fs == nil {
		c.flowsMu.Lock()
		next := map[netip.Addr]*flowSet{}
		if m := c.flows.Load(); m != nil {
			next = maps.Clone(*m)
		}
		if fs = next[t.DstAddr()]; fs == nil {
			fs = &flowSet{flows: map[flowtrack.Tuple]*flow{}}
			next[t.DstAddr()] = fs
			c.flows.Store(&next)
		}
		c.flowsMu.Unlock()
	}
	fs.mu.Lock()
	if fs.gone {
		fs.mu.Unlock()
		return
	}
	c.expireLocked(fs)
	if f, ok := fs.flows[t]; ok {
		// Closed past its grace, and not expired yet: open again.
		f.state = flowState{}
		f.closedAt.Store(0)
		f.used.Store(c.gen.Add(1))
	} else {
		f := &flow{}
		f.used.Store(c.gen.Add(1))
		fs.flows[t] = f
		c.held.Add(1)
	}
	if len(fs.flows) > perAddr {
		c.evictLocked(fs)
	}
	fs.mu.Unlock()
	if c.held.Load() > int64(total) {
		c.evictFromLargest()
	}
}

// evictLocked removes the flow of fs used least lately.
func (c *confiner) evictLocked(fs *flowSet) {
	var oldest flowtrack.Tuple
	var at uint64
	found := false
	for t, f := range fs.flows {
		if u := f.used.Load(); !found || u < at {
			oldest, at, found = t, u, true
		}
	}
	if found {
		c.removeLocked(fs, oldest)
	}
}

// evictFromLargest has the address holding most flows give one up.
func (c *confiner) evictFromLargest() {
	m := c.flows.Load()
	if m == nil {
		return
	}
	var most *flowSet
	n := 0
	for _, fs := range *m {
		fs.mu.RLock()
		if l := len(fs.flows); l > n {
			most, n = fs, l
		}
		fs.mu.RUnlock()
	}
	if most != nil {
		most.mu.Lock()
		c.evictLocked(most)
		most.mu.Unlock()
	}
}

// since is nanoseconds since the confiner first asked, by the monotonic
// clock where it reads the system's; never zero.
func (c *confiner) since() int64 {
	c.baseOnce.Do(func() { c.base = c.clock() })
	return max(int64(c.clock().Sub(c.base)), 1)
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
