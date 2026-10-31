package conn

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/nning/juist/types"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/wgcfg"
)

// peerState is one immutable peer-set snapshot.
type peerState struct {
	peers   map[key.NodePublic]Peer             // keyed by WireGuard public key
	byIP    map[netip.Addr]key.NodePublic       // overlay address -> owner
	nodes   map[key.NodePublic]tailcfg.NodeView // prebuilt views for peerForIP
	allowed map[key.NodePublic][]netip.Prefix   // each peer's addresses and routes
	routes  []routeEntry                        // every peer's routes, by first address
}

// A selfLookup is this node's addresses and view, as one.
type selfLookup struct {
	addrs []netip.Prefix
	node  tailcfg.NodeView
}

// A routeEntry is one peer's route as a range of addresses.
type routeEntry struct {
	r  netipx.IPRange
	nk key.NodePublic
}

// byRoute finds the peer whose routes hold ip. Routes do not overlap, so the
// one starting at or below ip is the only candidate.
func (st *peerState) byRoute(ip netip.Addr) (key.NodePublic, netip.Prefix, bool) {
	i, _ := slices.BinarySearchFunc(st.routes, ip, func(e routeEntry, ip netip.Addr) int {
		return e.r.From().Compare(ip)
	})
	switch {
	case i < len(st.routes) && st.routes[i].r.From() == ip:
	case i > 0:
		i--
	default:
		return key.NodePublic{}, netip.Prefix{}, false
	}
	if e := st.routes[i]; e.r.Contains(ip) {
		p, _ := e.r.Prefix()
		return e.nk, p, true
	}
	return key.NodePublic{}, netip.Prefix{}, false
}

// selfNode renders s exactly like a peer, minus endpoints: nothing discovers
// us through our own node view. Only TCP 443 also keeps the engine from using
// peer relays, which speak UDP.
func (m *tsManager) selfNode(s Self) tailcfg.NodeView {
	self := peerNode(Peer{
		ID:       s.ID,
		NodeKey:  s.NodeKey.Public(),
		DiscoKey: s.DiscoKey.Public(),
		Addrs:    s.Addrs,
	}, 0).AsStruct()
	if m.httpsOnly {
		self.CapMap = tailcfg.NodeCapMap{nodecap.OnlyTCP443: nil}
	}
	return self.View()
}

// checkSelf refuses a Self the data plane cannot run as.
func checkSelf(s Self) error {
	if s.NodeKey.IsZero() {
		return errors.New("conn: Self.NodeKey is required")
	}
	// A zero disco key makes magicsock generate an ephemeral one that no peer
	// can match against the log, failing every exchange with no symptom but
	// pings that get no pong.
	if s.DiscoKey.IsZero() {
		return errors.New("conn: Self.DiscoKey is required")
	}
	if err := checkNodeID(s.ID); err != nil {
		return fmt.Errorf("conn: Self.ID: %w", err)
	}
	if len(s.Addrs) == 0 {
		return errors.New("conn: Self.Addrs must not be empty")
	}
	for _, pfx := range s.Addrs {
		if err := checkHostPrefix(pfx); err != nil {
			return fmt.Errorf("conn: Self address: %w", err)
		}
	}
	return nil
}

// peerConfig answers the data plane's live per-peer config lookup.
func (m *tsManager) peerConfig(nk key.NodePublic) (wgcfg.PeerConfig, bool) {
	if e := m.evicting.Load(); e != nil && *e == nk {
		return wgcfg.PeerConfig{}, false
	}
	st := m.state.Load()
	a, ok := st.allowed[nk]
	return wgcfg.PeerConfig{AllowedIPs: a, PresharedKey: st.peers[nk].PSK}, ok
}

// peerByIP routes every outbound packet to a peer, so it stays lock-free:
// one atomic load and one map read.
func (m *tsManager) peerByIP(ip netip.Addr) (key.NodePublic, bool) {
	st := m.state.Load()
	if nk, ok := st.byIP[ip]; ok {
		return nk, true
	}
	nk, _, ok := st.byRoute(ip)
	return nk, ok
}

// sendTo is the peer what is sent to ip goes to: none while it is unproven.
func (m *tsManager) sendTo(ip netip.Addr) (key.NodePublic, bool) {
	nk, ok := m.peerByIP(ip)
	if ok && m.isUnproven(nk) {
		return key.NodePublic{}, false
	}
	return nk, ok
}

// unprovenWait bounds how long a peer waits for a path to be proven: past
// the last of [warmSchedule]'s pings, whose delays follow one another.
var unprovenWait = func() time.Duration {
	d := 500 * time.Millisecond
	for _, w := range warmSchedule {
		d += w
	}
	return d
}()

// heldUnproven reports whether what is sent to p waits for disco to prove a
// path: where it has an address to try and no relay to fall back on.
func heldUnproven(p Peer, haveRelays bool) bool {
	return (p.HomeRelay == 0 || !haveRelays) && len(p.Endpoints) > 0
}

func (m *tsManager) isUnproven(nk key.NodePublic) bool {
	until, ok := m.unproven.Load(nk)
	if !ok {
		return false
	}
	if time.Now().Before(until.(time.Time)) {
		return true
	}
	m.unproven.CompareAndDelete(nk, until)
	return false
}

func (m *tsManager) peerForIP(ip netip.Addr) (wgengine.PeerForIP, bool) {
	self := m.selfOnPath.Load()
	for _, p := range self.addrs {
		if p.Addr() == ip {
			return wgengine.PeerForIP{Node: self.node, IsSelf: true, Route: p}, true
		}
	}
	st := m.state.Load()
	if nk, ok := st.byIP[ip]; ok {
		return wgengine.PeerForIP{Node: st.nodes[nk], Route: netip.PrefixFrom(ip, ip.BitLen())}, true
	}
	if nk, r, ok := st.byRoute(ip); ok {
		return wgengine.PeerForIP{Node: st.nodes[nk], Route: r}, true
	}
	return wgengine.PeerForIP{}, false
}

func (m *tsManager) SetPeers(peers []Peer) error {
	// Copies are validated and stored, so the caller's slices can neither
	// bypass the validation later nor race the lock-free lookups.
	peers = clonePeers(peers)

	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return errors.New("conn: manager is closed")
	}
	if m.groups != nil {
		peers = withLinkLocals(m.self.NodeKey.Public(), m.self.Addrs, peers)
	}
	// Before touching any state, so a rejected peer set leaves the data plane
	// as it was.
	if err := validatePeers(m.self, peers); err != nil {
		return err
	}
	m.holdHomes(peers, time.Now())
	next, nodeList := newPeerState(m.self.NodeKey.Public(), peers, m.sendHome)

	prev := m.state.Load().peers
	resets := peerDelta(prev, next.peers)
	fresh := newPaths(prev, next.peers)
	m.noteKeying(prev, next.peers)
	m.unproven.Range(func(k, _ any) bool {
		if _, ok := next.peers[k.(key.NodePublic)]; !ok {
			m.unproven.Delete(k)
		}
		return true
	})
	for _, nk := range fresh {
		if heldUnproven(next.peers[nk], len(m.relays) > 0) {
			m.unproven.Store(nk, time.Now().Add(unprovenWait))
		}
	}

	// Order matters: the snapshot is swapped in before the data plane is
	// told to resync, so a removed peer's lookup already fails by the time
	// wireguard-go asks. A newly confined peer is confined first, and one
	// newly keyed passes nothing until no session without its key is left.
	m.setPolicy(m.keptConfined(peers), m.self.Addrs)
	m.state.Store(next)

	// Session keys are discarded outright rather than left to expire, for a
	// removed peer and for one whose disco key changed — that means it
	// restarted, so its old sessions are dead. Both are re-created lazily.
	for _, nk := range resets {
		m.evicting.Store(&nk)
		m.eng.SyncDevicePeer(nk)
	}
	m.evicting.Store(nil)
	// Every kept peer, not just changed ones: wireguard-go's lazy peer
	// creation reads the config lookup unordered against this call, so a
	// concurrently created peer can hold the previous snapshot's AllowedIPs.
	for nk := range next.peers {
		m.eng.SyncDevicePeer(nk)
	}
	m.magic.SetNetworkMap(m.selfNV, nodeList)
	// Warm regardless of the reconfig result: the next SetPeers diffs against
	// the snapshot already stored above, so a peer skipped here would never be
	// warmed at all.
	err := m.reconfig()
	// Best effort: the peers are installed, and the SetEgress each reconcile
	// follows with tries again and reports.
	if t := m.tunnelledBy(next.peers); m.exits != nil && m.egress != EgressDirect && !t.equal(m.tunnelled) {
		if gerr := m.exits.setEgress(m.egress, t); gerr != nil {
			m.logf("conn: guarding what the peers carry: %v", gerr)
		} else {
			m.tunnelled = t
		}
	}
	m.warmPaths(fresh)
	if walledMoved(prev, next.peers) {
		m.meetSoon()
	}
	return err
}

func (m *tsManager) SetSelf(s Self) error {
	s.Addrs = slices.Clone(s.Addrs)
	if m.groups != nil {
		s.Addrs = withLinkLocal(s.Addrs)
	}
	if err := checkSelf(s); err != nil {
		return err
	}
	m.apply.Lock()
	defer m.apply.Unlock()
	switch {
	case m.closed:
		return errors.New("conn: manager is closed")
	case s.ID != m.self.ID || !s.DiscoKey.Equal(m.self.DiscoKey):
		return errors.New("conn: SetSelf changes only the node key and the addresses")
	}
	peers := slices.Collect(maps.Values(m.state.Load().peers))
	if m.groups != nil {
		// Derived again: a peer's may be the new one of this node's.
		peers = withLinkLocals(s.NodeKey.Public(), s.Addrs, withoutLinkLocals(peers))
	}
	if err := validatePeers(s, peers); err != nil {
		return err
	}
	if err := m.guardAhead(m.self.Addrs, s.Addrs); err != nil {
		return err
	}
	// The new addresses are ours before the router puts them on the device,
	// so the filter and the confiner never drop what arrives for them.
	m.self = s
	m.selfNV = m.selfNode(s)
	m.selfOnPath.Store(&selfLookup{addrs: s.Addrs, node: m.selfNV})
	m.eng.SetSelfNode(m.selfNV)
	next, nodeList := newPeerState(s.NodeKey.Public(), peers, m.sendHome)
	m.setPolicy(m.keptConfined(peers), s.Addrs)
	if m.groups != nil {
		// A peer's link-local may come or go: its AllowedIPs with it.
		m.state.Store(next)
		for nk := range next.peers {
			m.eng.SyncDevicePeer(nk)
		}
	}
	m.magic.SetNetworkMap(m.selfNV, nodeList)
	return m.reconfig()
}

// setPolicy tells the confiner and the multicaster who the peers are, and
// this node's addresses.
func (m *tsManager) setPolicy(peers []Peer, self []netip.Prefix) {
	m.confiner.set(peers, self)
	m.groups.set(peers, self)
}

// keptConfined is peers with each one newly keyed passing nothing, for as
// long as a session without its key may still carry traffic. The caller
// holds m.apply.
func (m *tsManager) keptConfined(peers []Peer) []Peer {
	var out []Peer
	for i, p := range peers {
		if _, ok := m.keying[p.NodeKey]; ok {
			if out == nil {
				out = slices.Clone(peers)
			}
			out[i].Access = &Access{Nothing: true}
		}
	}
	if out == nil {
		return peers
	}
	return out
}

// clonePeers copies peers and the slices they hold.
func clonePeers(peers []Peer) []Peer {
	out := slices.Clone(peers)
	for i := range out {
		out[i].Addrs = slices.Clone(out[i].Addrs)
		out[i].Routes = slices.Clone(out[i].Routes)
		out[i].Subnets = slices.Clone(out[i].Subnets)
		out[i].Endpoints = slices.Clone(out[i].Endpoints)
		out[i].Access = out[i].Access.Clone()
	}
	return out
}

// validatePeers reports whether peers is a set the data plane can hold
// beside self. The log is supposed to make every refusal impossible, so one
// means a bug upstream. An entry carrying self's node key must agree with
// self, and is otherwise ignored.
func validatePeers(self Self, peers []Peer) error {
	selfKey, selfDisco := self.NodeKey.Public(), self.DiscoKey.Public()
	seen := make(map[key.NodePublic]bool, len(peers))
	byID := make(map[uint64]key.NodePublic, len(peers))
	byDisco := make(map[key.DiscoPublic]key.NodePublic, len(peers))
	byIP := make(map[netip.Addr]key.NodePublic, len(peers))
	for _, p := range peers {
		if p.NodeKey.IsZero() {
			return errors.New("conn: peer has zero node key")
		}
		if p.NodeKey == selfKey {
			// A matching self entry is expected; a disagreeing one means the
			// log and the data plane hold different ideas of who we are.
			if p.ID != self.ID || p.DiscoKey != selfDisco || !samePrefixSet(p.Addrs, self.Addrs) {
				return fmt.Errorf("conn: peer entry %v carries our node key but diverges from Self (ID %d, disco %v, addrs %v; Self has ID %d, disco %v, addrs %v)",
					p.NodeKey.ShortString(), p.ID, p.DiscoKey.ShortString(), p.Addrs,
					self.ID, selfDisco.ShortString(), self.Addrs)
			}
			continue
		}
		if err := checkNodeID(p.ID); err != nil {
			return fmt.Errorf("conn: peer %v: %w", p.NodeKey.ShortString(), err)
		}
		if p.ID == self.ID {
			return fmt.Errorf("conn: peer %v shares our node ID %d", p.NodeKey.ShortString(), p.ID)
		}
		// magicsock keys its peer state by node ID, so a shared ID would make
		// one peer silently clobber the other.
		if other, dup := byID[p.ID]; dup {
			return fmt.Errorf("conn: peers %v and %v share ID %d",
				other.ShortString(), p.NodeKey.ShortString(), p.ID)
		}
		if seen[p.NodeKey] {
			return fmt.Errorf("conn: peer %v appears twice", p.NodeKey.ShortString())
		}
		if p.DiscoKey.IsZero() {
			return fmt.Errorf("conn: peer %v has no disco key", p.NodeKey.ShortString())
		}
		// Disco keys must be distinct: the NAT-traversal layer keys path state
		// by them, and this is the one field a peer chooses, so without the
		// check a member could copy another's and cut its connectivity.
		if other, dup := byDisco[p.DiscoKey]; dup {
			return fmt.Errorf("conn: peers %v and %v announce the same disco key %v",
				other.ShortString(), p.NodeKey.ShortString(), p.DiscoKey.ShortString())
		}
		if p.DiscoKey == selfDisco {
			return fmt.Errorf("conn: peer %v announces this node's own disco key",
				p.NodeKey.ShortString())
		}
		if len(p.Addrs) == 0 {
			return fmt.Errorf("conn: peer %v has no overlay address", p.NodeKey.ShortString())
		}
		for _, pfx := range p.Addrs {
			if err := checkHostPrefix(pfx); err != nil {
				return fmt.Errorf("conn: peer %v address: %w", p.NodeKey.ShortString(), err)
			}
			if owner, taken := byIP[pfx.Addr()]; taken {
				return fmt.Errorf("conn: address %v claimed by both %v and %v",
					pfx.Addr(), owner.ShortString(), p.NodeKey.ShortString())
			}
			if tsaddr.PrefixesContainsIP(self.Addrs, pfx.Addr()) {
				return fmt.Errorf("conn: peer %v claims our own address %v",
					p.NodeKey.ShortString(), pfx.Addr())
			}
			byIP[pfx.Addr()] = p.NodeKey
		}
		seen[p.NodeKey] = true
		byID[p.ID] = p.NodeKey
		byDisco[p.DiscoKey] = p.NodeKey
	}
	return validateRoutes(self, peers)
}

// validateRoutes holds routes to their contract: canonical prefixes outside
// every address of this node's and its peers', and no two overlapping, so
// that every address a route holds has one peer.
func validateRoutes(self Self, peers []Peer) error {
	var addrs, routes netipx.IPSetBuilder
	for _, p := range self.Addrs {
		addrs.AddPrefix(p)
	}
	for _, p := range peers {
		for _, a := range p.Addrs {
			addrs.AddPrefix(a)
		}
	}
	held, err := addrs.IPSet()
	if err != nil {
		return fmt.Errorf("conn: %w", err)
	}
	for _, p := range peers {
		for _, r := range p.carried() {
			switch {
			case !r.IsValid() || r.Masked() != r || r.Addr().Is4In6() || r.Addr().Zone() != "":
				return fmt.Errorf("conn: peer %v route %v is not a canonical prefix", p.NodeKey.ShortString(), r)
			case held.OverlapsPrefix(r):
				return fmt.Errorf("conn: peer %v route %v holds an overlay address", p.NodeKey.ShortString(), r)
			}
			carried, err := routes.IPSet()
			if err != nil {
				return fmt.Errorf("conn: %w", err)
			}
			if carried.OverlapsPrefix(r) {
				return fmt.Errorf("conn: route %v is carried twice", r)
			}
			routes.AddPrefix(r)
		}
	}
	return nil
}

// newPeerState indexes a validated peer set, leaving out the entry for
// selfKey; sendHome maps a peer's home to the region sent to.
func newPeerState(selfKey key.NodePublic, peers []Peer, sendHome func(int) int) (*peerState, []tailcfg.NodeView) {
	st := &peerState{
		peers:   make(map[key.NodePublic]Peer, len(peers)),
		byIP:    make(map[netip.Addr]key.NodePublic, len(peers)),
		nodes:   make(map[key.NodePublic]tailcfg.NodeView, len(peers)),
		allowed: make(map[key.NodePublic][]netip.Prefix, len(peers)),
	}
	nodes := make([]tailcfg.NodeView, 0, len(peers))
	for _, p := range peers {
		if p.NodeKey == selfKey {
			continue
		}
		nv := peerNode(p, sendHome(p.HomeRelay))
		st.peers[p.NodeKey] = p
		st.nodes[p.NodeKey] = nv
		st.allowed[p.NodeKey] = slices.Concat(p.Addrs, p.carried())
		for _, pfx := range p.Addrs {
			st.byIP[pfx.Addr()] = p.NodeKey
		}
		for _, r := range p.carried() {
			st.routes = append(st.routes, routeEntry{r: netipx.RangeOfPrefix(r), nk: p.NodeKey})
		}
		nodes = append(nodes, nv)
	}
	slices.SortFunc(st.routes, func(x, y routeEntry) int { return x.r.From().Compare(y.r.From()) })
	return st, nodes
}

// samePrefixSet reports whether a and b hold the same prefixes, ignoring
// order.
func samePrefixSet(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := slices.Clone(a), slices.Clone(b)
	slices.SortFunc(as, types.ComparePrefix)
	slices.SortFunc(bs, types.ComparePrefix)
	return slices.Equal(as, bs)
}

// checkHostPrefix enforces the contract shared by [Self.Addrs] and
// [Peer.Addrs]: a single host address in canonical form. Addrs become
// AllowedIPs, which also authorize the source addresses a peer may originate,
// so a wider prefix lets it impersonate other members. A v4-mapped v6 prefix
// is refused because it aliases the plain v4 address while comparing unequal
// to it, slipping past the duplicate checks while matching no packet.
func checkHostPrefix(pfx netip.Prefix) error {
	if !pfx.IsSingleIP() {
		return fmt.Errorf("%v is not a single-IP prefix", pfx)
	}
	if pfx.Addr().Is4In6() {
		return fmt.Errorf("%v is a v4-mapped v6 prefix; use the plain v4 form", pfx)
	}
	return nil
}

// checkNodeID reports whether id is usable as a tailcfg.NodeID, which is a
// signed 64-bit value that magicsock requires to be non-zero.
func checkNodeID(id uint64) error {
	if id == 0 {
		return errors.New("ID must be non-zero")
	}
	if id > math.MaxInt64 {
		return fmt.Errorf("ID %d overflows tailcfg.NodeID", id)
	}
	return nil
}

// walledMoved reports whether a peer became walled or stopped being so, or
// a walled one moved home, from prev to next: what the meeting loop is
// kicked for, not every reconcile, as each kick pings every walled peer.
func walledMoved(prev, next map[key.NodePublic]Peer) bool {
	homes := func(peers map[key.NodePublic]Peer) map[key.NodePublic]int {
		out := map[key.NodePublic]int{}
		for nk, p := range peers {
			if p.Walled {
				out[nk] = p.HomeRelay
			}
		}
		return out
	}
	return !maps.Equal(homes(prev), homes(next))
}

// carried is everything outside the overlay p carries for this node.
func (p Peer) carried() []netip.Prefix { return slices.Concat(p.Routes, p.Subnets) }

// peerNode is p as the data plane takes it, sent to at home.
func peerNode(p Peer, home int) tailcfg.NodeView {
	return (&tailcfg.Node{
		ID:         tailcfg.NodeID(p.ID),
		StableID:   tailcfg.StableNodeID(fmt.Sprintf("n%d", p.ID)),
		Name:       fmt.Sprintf("n%d", p.ID),
		Key:        p.NodeKey,
		DiscoKey:   p.DiscoKey,
		Addresses:  p.Addrs,
		AllowedIPs: slices.Concat(p.Addrs, p.carried()),
		Endpoints:  p.Endpoints,
		HomeDERP:   tailcfg.DERPRegionID(home),
		Cap:        tailcfg.CurrentCapabilityVersion,
	}).View()
}

// homeHeld is how long a peer that says it has no home is still sent to at
// the one it had: restarting, a device is homeless for a while before it
// takes the same home again, and a peer installed with none is sent nothing
// by relay, not even the answer to what it sends.
const homeHeld = 2 * time.Minute

// A heldHome is the home a peer last said it had, and when.
type heldHome struct {
	region int
	at     time.Time
}

// holdHomes gives each of peers that says it has no home the home it had
// within [homeHeld] before now, and notes the homes the others say. The
// caller holds m.apply.
func (m *tsManager) holdHomes(peers []Peer, now time.Time) {
	held := make(map[key.NodePublic]heldHome, len(peers))
	for i := range peers {
		p := &peers[i]
		if p.HomeRelay != 0 {
			held[p.NodeKey] = heldHome{p.HomeRelay, now}
			continue
		}
		if h, ok := m.homes[p.NodeKey]; ok && now.Sub(h.at) < homeHeld {
			p.HomeRelay = h.region
			held[p.NodeKey] = h
		}
	}
	m.homes = held
}
