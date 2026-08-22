package conn

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// Options configures a Tailscale-backed [Manager].
type Options struct {
	// Self is the local node's identity and overlay addresses.
	Self Self

	// ListenPort is the UDP port to bind. Zero picks one.
	ListenPort uint16

	// Logf receives engine logs. Nil discards them.
	Logf logger.Logf

	// Tun is the OS TUN device. If nil, a no-op fake device is used: the
	// tunnel is real, but nothing is plumbed into the host network stack and
	// no privileges are needed. Used by tests and by RespondToPing demos.
	//
	// A real device does not change that by itself: the engine is built
	// without a router (wgengine.Config.Router defaults to a fake), so
	// overlay addresses and routes are never programmed into the OS either
	// way. That plumbing arrives with the M2 netns harness.
	Tun tun.Device

	// RespondToPing makes the engine answer overlay ICMP echo requests
	// internally, without a TUN device. Test and demo use only.
	RespondToPing bool

	// Debug enables magicsock's verbose NAT-traversal logging.
	Debug bool
}

// tsManager implements [Manager] on top of Tailscale's wgengine and magicsock.
//
// It is the adapter described in docs/04-architecture.md: the only place in
// this project that touches Tailscale's types. Notably it does not use
// controlclient, tsnet, or ipn — all of which assume a coordination server.
// Peer state arrives only through SetPeers.
type tsManager struct {
	logf   logger.Logf
	eng    wgengine.Engine
	magic  *magicsock.Conn
	bus    *eventbus.Bus
	self   Self
	selfNV tailcfg.NodeView

	// apply serializes whole reconfigurations, and shutdown. magicsock
	// requires the caller to serialize SetNetworkMap calls relative to one
	// another, the state snapshot below must not be overtaken by a later
	// caller between being written and being pushed to the data plane —
	// otherwise the data plane keeps one peer set while the lookups answer
	// from another, and the two never reconverge until the next call — and
	// Close must not tear the engine down under a SetPeers in flight.
	apply  sync.Mutex
	closed bool // guarded by apply: Close has run, the engine is gone

	// state is the peer set the data plane answers from. It is read
	// lock-free on the per-packet paths and replaced wholesale, under
	// apply, by SetPeers. The maps inside a snapshot are never mutated
	// after it is stored.
	state atomic.Pointer[peerState]
}

// peerState is one immutable peer-set snapshot.
type peerState struct {
	peers map[key.NodePublic]Peer             // keyed by WireGuard public key
	byIP  map[netip.Addr]key.NodePublic       // overlay address -> owner
	nodes map[key.NodePublic]tailcfg.NodeView // prebuilt views for peerForIP
}

var _ Manager = (*tsManager)(nil)

// New starts a Tailscale-backed connectivity manager.
//
// No DERP map is installed, so the manager is direct-only: it makes no
// connection to any relay or STUN server. Relays enter later, from
// member-volunteered roles in the membership log.
func New(opts Options) (Manager, error) {
	if opts.Self.NodeKey.IsZero() {
		return nil, errors.New("conn: Self.NodeKey is required")
	}
	// A zero disco key would make magicsock generate an ephemeral one, which
	// no peer could match against the key recorded for us in the log: every
	// disco exchange would fail and the only symptom would be pings that
	// never get a pong.
	if opts.Self.DiscoKey.IsZero() {
		return nil, errors.New("conn: Self.DiscoKey is required")
	}
	if err := checkNodeID(opts.Self.ID); err != nil {
		return nil, fmt.Errorf("conn: Self.ID: %w", err)
	}
	if len(opts.Self.Addrs) == 0 {
		return nil, errors.New("conn: Self.Addrs must not be empty")
	}
	for _, pfx := range opts.Self.Addrs {
		if err := checkHostPrefix(pfx); err != nil {
			return nil, fmt.Errorf("conn: Self address: %w", err)
		}
	}
	logf := opts.Logf
	if logf == nil {
		logf = logger.Discard
	}
	// The caller keeps ownership of its slice; the addresses are read
	// lock-free on packet paths, so they must not be mutable from outside.
	opts.Self.Addrs = slices.Clone(opts.Self.Addrs)

	bus := eventbus.New()
	m := &tsManager{
		logf: logf,
		bus:  bus,
		self: opts.Self,
	}
	m.state.Store(&peerState{})

	var tundev *tstun.Wrapper
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           opts.Tun,
		ListenPort:    opts.ListenPort,
		RespondToPing: opts.RespondToPing,
		EventBus:      bus,
		Metrics:       new(usermetric.Registry),
		HealthTracker: new(health.Tracker),
		ForceDiscoKey: opts.Self.DiscoKey,
		SetSubsystem: func(s any) {
			switch v := s.(type) {
			case *magicsock.Conn:
				m.magic = v
			case *tstun.Wrapper:
				tundev = v
			}
		},
	})
	if err != nil {
		bus.Close()
		return nil, fmt.Errorf("conn: starting engine: %w", err)
	}
	if m.magic == nil || tundev == nil {
		eng.Close()
		bus.Close()
		return nil, errors.New("conn: engine did not surface its magicsock conn or TUN wrapper")
	}
	m.eng = eng

	// Self is rendered exactly like a peer, minus endpoints: nothing
	// discovers us through our own node view.
	m.selfNV = peerNode(Peer{
		ID:       opts.Self.ID,
		NodeKey:  opts.Self.NodeKey.Public(),
		DiscoKey: opts.Self.DiscoKey.Public(),
		Addrs:    opts.Self.Addrs,
	})
	eng.SetSelfNode(m.selfNV)

	// The data plane learns its peer set only from these two lookups, both
	// backed by the snapshot that SetPeers stores. A key absent from that
	// snapshot has no WireGuard peer and no allowed IPs, so it cannot
	// complete a handshake: this is where default-deny lives.
	eng.SetPeerConfigFunc(m.allowedIPs)
	eng.SetPeerByIPPacketFunc(m.peerByIP)
	eng.SetPeerForIPFunc(m.peerForIP)

	m.apply.Lock()
	err = m.reconfig()
	m.apply.Unlock()
	if err != nil {
		eng.Close()
		bus.Close()
		return nil, err
	}

	// The TUN wrapper blocks every read until Start is called; Tailscale
	// calls it from ipnlocal once its subsystems are wired. We are the
	// equivalent wiring point, and everything the wrapper depends on — the
	// peer lookups, the filter, the initial config — is installed above.
	tundev.Start()
	if opts.Debug {
		m.magic.SetDebugLoggingEnabled(true)
	}
	return m, nil
}

// allowedIPs answers the data plane's live per-peer config lookup.
func (m *tsManager) allowedIPs(nk key.NodePublic) ([]netip.Prefix, bool) {
	p, ok := m.state.Load().peers[nk]
	if !ok {
		return nil, false
	}
	return p.Addrs, true
}

// peerByIP routes every outbound packet to a peer, so it stays lock-free:
// one atomic load and one map read.
func (m *tsManager) peerByIP(ip netip.Addr) (key.NodePublic, bool) {
	nk, ok := m.state.Load().byIP[ip]
	return nk, ok
}

func (m *tsManager) peerForIP(ip netip.Addr) (wgengine.PeerForIP, bool) {
	for _, p := range m.self.Addrs {
		if p.Addr() == ip {
			return wgengine.PeerForIP{Node: m.selfNV, IsSelf: true, Route: p}, true
		}
	}
	st := m.state.Load()
	nk, ok := st.byIP[ip]
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	return wgengine.PeerForIP{Node: st.nodes[nk], Route: netip.PrefixFrom(ip, ip.BitLen())}, true
}

func (m *tsManager) SetPeers(peers []Peer) error {
	selfKey := m.self.NodeKey.Public()
	nodeList := make([]tailcfg.NodeView, 0, len(peers))
	next := &peerState{
		peers: make(map[key.NodePublic]Peer, len(peers)),
		byIP:  make(map[netip.Addr]key.NodePublic, len(peers)),
		nodes: make(map[key.NodePublic]tailcfg.NodeView, len(peers)),
	}
	byID := make(map[uint64]key.NodePublic, len(peers))

	// Validate everything before touching any state, so a rejected peer set
	// leaves the data plane exactly as it was. These are all conditions the
	// membership log is supposed to make impossible, so reaching one means a
	// bug upstream — refuse loudly rather than let the data plane act on it.
	for _, p := range peers {
		if p.NodeKey.IsZero() {
			return errors.New("conn: peer has zero node key")
		}
		if p.NodeKey == selfKey {
			// The reconciler passes the full authorized set, which includes
			// this node, so a matching self entry is expected. But one that
			// disagrees with Options.Self means the log and the data plane
			// hold different ideas of who we are — an upstream bug nothing
			// else would ever surface, so it too is refused loudly. The disco
			// key matters most: peers reach us with the logged one, so a
			// divergence there is every inbound disco exchange failing with
			// no symptom beyond pings that never get a pong.
			if p.ID != m.self.ID || p.DiscoKey != m.self.DiscoKey.Public() || !samePrefixSet(p.Addrs, m.self.Addrs) {
				return fmt.Errorf("conn: peer entry %v carries our node key but diverges from Self (ID %d, disco %v, addrs %v; Self has ID %d, disco %v, addrs %v)",
					p.NodeKey.ShortString(), p.ID, p.DiscoKey.ShortString(), p.Addrs,
					m.self.ID, m.self.DiscoKey.Public().ShortString(), m.self.Addrs)
			}
			continue
		}
		if err := checkNodeID(p.ID); err != nil {
			return fmt.Errorf("conn: peer %v: %w", p.NodeKey.ShortString(), err)
		}
		if p.ID == m.self.ID {
			return fmt.Errorf("conn: peer %v shares our node ID %d", p.NodeKey.ShortString(), p.ID)
		}
		// magicsock keys its peer state by node ID, so a shared ID would make
		// one peer silently clobber the other.
		if other, dup := byID[p.ID]; dup {
			return fmt.Errorf("conn: peers %v and %v share ID %d",
				other.ShortString(), p.NodeKey.ShortString(), p.ID)
		}
		if _, dup := next.peers[p.NodeKey]; dup {
			return fmt.Errorf("conn: peer %v appears twice", p.NodeKey.ShortString())
		}
		if p.DiscoKey.IsZero() {
			return fmt.Errorf("conn: peer %v has no disco key", p.NodeKey.ShortString())
		}
		if len(p.Addrs) == 0 {
			return fmt.Errorf("conn: peer %v has no overlay address", p.NodeKey.ShortString())
		}
		for _, pfx := range p.Addrs {
			if err := checkHostPrefix(pfx); err != nil {
				return fmt.Errorf("conn: peer %v address: %w", p.NodeKey.ShortString(), err)
			}
			if owner, taken := next.byIP[pfx.Addr()]; taken {
				return fmt.Errorf("conn: address %v claimed by both %v and %v",
					pfx.Addr(), owner.ShortString(), p.NodeKey.ShortString())
			}
			if tsaddr.PrefixesContainsIP(m.self.Addrs, pfx.Addr()) {
				return fmt.Errorf("conn: peer %v claims our own address %v",
					p.NodeKey.ShortString(), pfx.Addr())
			}
			next.byIP[pfx.Addr()] = p.NodeKey
		}
		byID[p.ID] = p.NodeKey
		// The caller keeps ownership of its slices; clone them so a later
		// mutation can neither bypass the validation above nor race the
		// lock-free lookups reading the stored snapshot.
		p.Addrs = slices.Clone(p.Addrs)
		p.Endpoints = slices.Clone(p.Endpoints)
		nv := peerNode(p)
		next.peers[p.NodeKey] = p
		next.nodes[p.NodeKey] = nv
		nodeList = append(nodeList, nv)
	}

	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return errors.New("conn: manager is closed")
	}

	resets := peerDelta(m.state.Load().peers, next.peers)

	// Order matters: the snapshot is swapped in before the data plane is
	// told to resync, so a removed peer's lookup already fails by the time
	// wireguard-go asks.
	m.state.Store(next)

	// A removed peer's session key material is discarded outright rather
	// than left to expire. So is a retained peer's whose disco key changed:
	// that means the peer restarted and its old sessions are dead —
	// ipnlocal performs exactly this reset after SetNetworkMap, and with no
	// ipnlocal here the job is ours. Either kind is re-created lazily on
	// demand, with current state.
	for _, nk := range resets {
		m.eng.ResetDevicePeer(nk)
	}
	// Every kept peer is re-synced, not just those whose addresses changed:
	// wireguard-go's lazy peer creation reads the config lookup with no
	// ordering against this call, so a peer created concurrently can be
	// inserted holding the *previous* snapshot's AllowedIPs. This sweep
	// bounds that staleness at one reconcile round, the same self-healing
	// the old sync-everything loop provided; only an upstream re-validation
	// after insert could close the window entirely. The sweep is cheap:
	// SyncDevicePeer is a no-op for peers not active in the device, and
	// re-applying an unchanged AllowedIPs list is a no-op below it.
	for nk := range next.peers {
		m.eng.SyncDevicePeer(nk)
	}
	m.magic.SetNetworkMap(m.selfNV, nodeList)
	return m.reconfig()
}

// peerDelta compares two peer sets and reports which device peers must be
// reset — removed from the device, discarding session keys. That covers peers
// that left the set and peers whose disco key rotated: a rotation means the
// peer restarted, so its old sessions are dead either way, and waiting out
// WireGuard's rekey timers would blackhole traffic to it for minutes.
func peerDelta(prev, next map[key.NodePublic]Peer) (resets []key.NodePublic) {
	for nk, old := range prev {
		if cur, still := next[nk]; !still || cur.DiscoKey != old.DiscoKey {
			resets = append(resets, nk)
		}
	}
	return resets
}

// samePrefixSet reports whether a and b hold the same prefixes, ignoring
// order.
func samePrefixSet(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := slices.Clone(a), slices.Clone(b)
	cmp := func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return x.Bits() - y.Bits()
	}
	slices.SortFunc(as, cmp)
	slices.SortFunc(bs, cmp)
	return slices.Equal(as, bs)
}

// checkHostPrefix enforces the address contract shared by [Self.Addrs] and
// [Peer.Addrs]: a single host address in canonical form.
//
// Addrs become the peer's WireGuard AllowedIPs, and wireguard-go checks every
// decrypted packet's *source* address against them (AllowedPeerSourceIP). A
// prefix wider than one host would therefore authorize its peer to originate
// traffic as any address inside it — impersonating other members straight
// past the packet filter, which sees a member source and accepts. v1 binds
// host addresses only; routes arrive in M7 through a deliberate,
// quorum-granted widening, never implicitly here.
//
// A v4-mapped v6 prefix (::ffff:a.b.c.d) is refused for a related reason: it
// aliases the plain v4 address while comparing unequal to it as a netip.Addr,
// so it would slip past the duplicate-address and claims-our-address checks —
// and could never match a packet anyway, since parsed packet addresses are
// never v4-mapped.
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

// reconfig applies the local node's own WireGuard config and the packet
// filter. Peers are not part of it: wireguard-go pulls those from the lookups
// installed in New.
//
// The caller must hold m.apply.
func (m *tsManager) reconfig() error {
	filt, err := m.filter()
	if err != nil {
		return fmt.Errorf("conn: building filter: %w", err)
	}
	m.eng.SetFilter(filt)
	err = m.eng.Reconfig(
		&wgcfg.Config{
			PrivateKey: m.self.NodeKey,
			Addresses:  m.self.Addrs,
		},
		&router.Config{LocalAddrs: m.self.Addrs},
		&dns.Config{},
	)
	if err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		return fmt.Errorf("conn: reconfig: %w", err)
	}
	return nil
}

// filter builds the v1 packet policy: any member may send anything to any
// other member. Fine-grained ACLs are a post-v1 item (docs/01-requirements.md),
// but the filter is installed explicitly rather than left nil, because a nil
// filter drops every inbound packet.
//
// The Match values are built directly rather than routed through
// tailcfg.FilterRule and its parser: that string layer is a control-plane
// wire format, and round-tripping prefixes this package just validated
// through it added parse failure modes that had no honest handling. The only
// error left is the IPSet build, and it is propagated — a filter that could
// not be built must fail the reconfig loudly, not fall back to dropping
// member traffic while SetPeers reports success.
func (m *tsManager) filter() (*filter.Filter, error) {
	st := m.state.Load()
	srcs := make([]netip.Prefix, 0, len(st.peers))
	for _, p := range st.peers {
		srcs = append(srcs, p.Addrs...)
	}

	var localNets netipx.IPSetBuilder
	dsts := make([]filtertype.NetPortRange, 0, len(m.self.Addrs))
	for _, pfx := range m.self.Addrs {
		localNets.AddPrefix(pfx)
		dsts = append(dsts, filtertype.NetPortRange{Net: pfx, Ports: filtertype.AllPorts})
	}
	ls, err := localNets.IPSet()
	if err != nil {
		return nil, fmt.Errorf("building local net set: %w", err)
	}
	if len(srcs) == 0 {
		return filter.NewAllowNone(m.logf, ls), nil
	}
	matches := []filter.Match{{
		IPProto: allIPProtos,
		Srcs:    srcs,
		Dsts:    dsts,
	}}
	// Sharing state with the previous filter carries the flow-tracking
	// cache across rebuilds, so a membership change does not send every
	// established UDP flow back through the slow path (ipnlocal does the
	// same). GetFilter is nil on the first build, which means fresh state.
	return filter.New(matches, nil, ls, ls, m.eng.GetFilter(), m.logf), nil
}

// allIPProtos enumerates every IP protocol number, which is the only way to
// express "any protocol" here: Match.IPProto is a membership test with no
// wildcard form, and one that silently rejects anything absent. Leaving any
// value out would drop ESP, AH, GRE, SCTP, OSPF or whatever else a member
// sends — a full mesh with no per-port ACLs (docs/01-requirements.md) has to
// carry all of it.
//
// The cost is a linear scan of up to 256 entries, paid only on the filter's
// slow paths (TCP SYN, uncached UDP, ICMP, other protocols) and not on
// established flows. Performance is priority 3; silently dropping protocols
// is not a trade we get to make.
var allIPProtos = func() views.Slice[ipproto.Proto] {
	p := make([]ipproto.Proto, 256)
	for i := range p {
		p[i] = ipproto.Proto(i)
	}
	return views.SliceOf(p)
}()

func (m *tsManager) LocalPort() uint16 { return m.magic.LocalPort() }

func (m *tsManager) Ping(ip netip.Addr, cb func(PingResult)) {
	m.eng.Ping(ip, tailcfg.PingICMP, 0, func(r *ipnstate.PingResult) {
		res := PingResult{Err: r.Err}
		if r.LatencySeconds > 0 {
			res.Latency = time.Duration(r.LatencySeconds * float64(time.Second))
		}
		cb(res)
	})
}

func (m *tsManager) Close() error {
	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.eng.Close()
	m.bus.Close()
	return nil
}

func peerNode(p Peer) tailcfg.NodeView {
	return (&tailcfg.Node{
		ID:         tailcfg.NodeID(p.ID),
		StableID:   tailcfg.StableNodeID(fmt.Sprintf("n%d", p.ID)),
		Name:       fmt.Sprintf("n%d", p.ID),
		Key:        p.NodeKey,
		DiscoKey:   p.DiscoKey,
		Addresses:  p.Addrs,
		AllowedIPs: p.Addrs,
		Endpoints:  p.Endpoints,
		Cap:        tailcfg.CurrentCapabilityVersion,
	}).View()
}
