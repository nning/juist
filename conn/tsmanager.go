package conn

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
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

	// STUN are public STUN servers, as host:port, that tell this node its
	// reflexive address where no member relay is there to. They carry no
	// traffic and relay nothing — the data plane never dials a STUN-only
	// node — and what they learn is that this address speaks STUN. Empty asks
	// nobody outside the network.
	STUN []string

	// Logf receives engine logs. Nil discards them.
	Logf logger.Logf

	// Tun is a caller-supplied TUN device, for tests. With both Tun and
	// TunName unset the engine gets a fake device and a fake router: the
	// tunnel is real, but nothing is plumbed into the host.
	Tun tun.Device

	// TunName, when set and Tun is nil, names an OS TUN device to create. New
	// then also builds a real router, so this node's addresses and its peers'
	// routes reach the host stack. Needs /dev/net/tun and CAP_NET_ADMIN, and
	// fails rather than falling back to a device nothing can reach.
	TunName string

	// RespondToPing makes the engine answer overlay ICMP echo requests
	// internally, without a TUN device. Test and demo use only.
	RespondToPing bool

	// Debug enables magicsock's verbose NAT-traversal logging.
	Debug bool

	// OnConnectivityChange is called, possibly from another goroutine, when
	// [Manager.HomeRelay] or [Manager.LocalEndpoints] changes. Both belong in
	// this node's announcement, so the caller re-announces and pushes.
	OnConnectivityChange func()
}

// tsManager implements [Manager] on top of Tailscale's wgengine and magicsock.
// It is the only place in this project that touches Tailscale's types, and it
// uses no controlclient, tsnet or ipn: all three assume a coordination server.
type tsManager struct {
	logf   logger.Logf
	eng    wgengine.Engine
	magic  *magicsock.Conn
	bus    *eventbus.Bus
	self   Self
	selfNV tailcfg.NodeView

	// netMon is shared with the engine on the real-device path, nil on the
	// fake one. The engine never closes a monitor it was handed, so Close does.
	netMon *netmon.Monitor

	health *health.Tracker

	// apply serializes whole reconfigurations and shutdown: magicsock requires
	// SetNetworkMap calls to be serialized, a snapshot must not be overtaken
	// between being stored and being pushed to the data plane, and Close must
	// not tear the engine down under a SetPeers in flight.
	apply  sync.Mutex
	closed bool // guarded by apply: Close has run, the engine is gone

	// routerStale records that the last reconfiguration failed, so the OS may
	// not match what the engine believes it programmed. Guarded by apply.
	routerStale bool

	// stun are the public STUN servers, and stunRegions the regions they
	// hold in the map last installed.
	stun        []string
	stunRegions atomic.Pointer[map[int]bool]

	// relays is the relay set last installed, kept so an unchanged one does
	// not restart the latency probes. Guarded by apply.
	relays []Relay

	// onChange is called when the home relay or the local endpoint set moves.
	onChange func()

	// homeRelay is the region the data plane picked, and localEps the
	// addresses it believes this node is reachable at. Both are written from
	// the engine's callbacks and read by the announcement.
	homeRelay atomic.Int64
	epsMu     sync.Mutex
	localEps  []netip.AddrPort

	// done is closed by Close, and warm tracks the path warm-up goroutines
	// so that none of them can touch the engine after it is torn down.
	done chan struct{}
	warm sync.WaitGroup

	// state is the peer set the data plane answers from: read lock-free on the
	// per-packet paths, replaced wholesale under apply, never mutated once
	// stored.
	state atomic.Pointer[peerState]
}

// peerState is one immutable peer-set snapshot.
type peerState struct {
	peers map[key.NodePublic]Peer             // keyed by WireGuard public key
	byIP  map[netip.Addr]key.NodePublic       // overlay address -> owner
	nodes map[key.NodePublic]tailcfg.NodeView // prebuilt views for peerForIP
}

var _ Manager = (*tsManager)(nil)

// New starts a Tailscale-backed connectivity manager. No DERP map is
// installed, so it is direct-only: no connection to any relay or STUN server.
func New(opts Options) (_ Manager, err error) {
	if err := checkOptions(&opts); err != nil {
		return nil, err
	}
	logf := opts.Logf
	if logf == nil {
		logf = logger.Discard
	}
	// The caller keeps ownership of its slice; the addresses are read
	// lock-free on packet paths, so they must not be mutable from outside.
	opts.Self.Addrs = slices.Clone(opts.Self.Addrs)

	// What a failed New must release, in reverse order.
	var undo cleanups
	defer func() {
		if err != nil {
			undo.run()
		}
	}()
	bus := eventbus.New()
	undo.push(bus.Close)
	m := &tsManager{
		logf:     logf,
		bus:      bus,
		self:     opts.Self,
		done:     make(chan struct{}),
		onChange: opts.OnConnectivityChange,
		stun:     slices.Clone(opts.STUN),
	}
	m.state.Store(&peerState{})
	m.stunRegions.Store(&map[int]bool{})
	if opts.Logf != nil && len(opts.STUN) > 0 {
		logf = m.withoutSTUNHomeNoise(logf)
		m.logf = logf
	}

	// Shared with the OS router on the real-device path. Marked as in a map
	// poll for good: magicsock keeps the first home relay it picks unless it
	// believes it can tell peers of a change, which announcements do here, so
	// otherwise a relay granted after start would never be used.
	healthTracker := new(health.Tracker)
	healthTracker.GotStreamedMapResponse()
	m.health = healthTracker

	var tundev *tstun.Wrapper
	cfg := wgengine.Config{
		Tun:           opts.Tun,
		ListenPort:    opts.ListenPort,
		RespondToPing: opts.RespondToPing,
		EventBus:      bus,
		Metrics:       new(usermetric.Registry),
		HealthTracker: healthTracker,
		ForceDiscoKey: opts.Self.DiscoKey,
		SetSubsystem: func(s any) {
			switch v := s.(type) {
			case *magicsock.Conn:
				m.magic = v
			case *tstun.Wrapper:
				tundev = v
			}
		},
	}

	// newOSRouter wants the device and the engine wants the router, fixing the
	// order: netmon, TUN, router, engine. The MTU must be DefaultTUNMTU() —
	// 1280, the IPv6 minimum; lower and the kernel drops IPv6 silently.
	if opts.Tun == nil && opts.TunName != "" {
		mon, err := netmon.New(bus, logf)
		if err != nil {
			return nil, fmt.Errorf("conn: starting the network monitor: %w", err)
		}
		// The engine never closes a monitor it was handed.
		undo.push(func() { mon.Close() })
		dev, err := tun.CreateTUN(opts.TunName, int(tstun.DefaultTUNMTU()))
		if err != nil {
			// Lists what creation needs; does not claim to be the cause,
			// since a name already in use comes back as EBUSY.
			return nil, fmt.Errorf("conn: creating TUN device %q: %w "+
				"(needs /dev/net/tun and CAP_NET_ADMIN, and the name must be free)",
				opts.TunName, err)
		}
		undo.push(func() { dev.Close() })
		osRtr, err := newOSRouter(logf, dev, mon, healthTracker, bus)
		if err != nil {
			return nil, fmt.Errorf("conn: creating the OS router: %w", err)
		}
		// The engine's own cleanup closes the device, and neither closes the
		// router on failure; the router may already hold the policy rules its
		// Up installed.
		undo.pop()
		undo.push(func() { closeUnstartedRouter(osRtr) })
		// One monitor for both, rather than letting the engine start a second.
		cfg.Tun = dev
		cfg.Router = osRtr
		cfg.NetMon = mon
		m.netMon = mon
	}

	eng, err := wgengine.NewUserspaceEngine(logf, cfg)
	if err != nil {
		return nil, fmt.Errorf("conn: starting engine: %w", err)
	}
	// Past here eng.Close() closes the router; the monitor is still ours.
	if cfg.Router != nil {
		undo.pop()
	}
	undo.push(eng.Close)
	if m.magic == nil || tundev == nil {
		return nil, errors.New("conn: engine did not surface its magicsock conn or TUN wrapper")
	}
	// magicsock treats ListenPort as a preference: a port it cannot bind
	// silently becomes an OS-assigned one, and nothing downstream repairs
	// that, since our endpoints come from an interface scan. Only the initial
	// bind is checked — magicsock may rebind, so callers keep reading
	// LocalPort.
	if opts.ListenPort != 0 {
		if got := m.magic.LocalPort(); got != opts.ListenPort {
			return nil, fmt.Errorf(
				"conn: could not bind UDP port %d; the engine fell back to %d. "+
					"Something else holds it, or pass 0 to let the OS choose: %w",
				opts.ListenPort, got, ErrPortTaken)
		}
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

	// The data plane learns its peer set only from these lookups, backed by
	// the snapshot SetPeers stores. A key absent from it has no peer entry and
	// no allowed IPs, so it cannot handshake: default-deny lives here.
	eng.SetPeerConfigFunc(m.allowedIPs)
	eng.SetPeerByIPPacketFunc(m.peerByIP)
	eng.SetPeerForIPFunc(m.peerForIP)

	// Where reflexive addresses come from. Without a relay the engine reports
	// none — its endpoint set needs a STUN result or a DERP map — so this is
	// silent until SetRelays installs one, which is the whole reason the
	// announcement is still built from an interface scan as well.
	eng.SetStatusCallback(m.onStatus)
	// The region the engine picked for itself. Peers cannot guess it: relays
	// are not meshed, so a packet sent to any other region is dropped.
	m.magic.SetNetInfoCallback(m.onNetInfo)
	if len(m.stun) > 0 {
		m.installDERPMap(nil)
	}

	m.apply.Lock()
	err = m.reconfig()
	m.apply.Unlock()
	if err != nil {
		return nil, err
	}

	// The wrapper blocks every read until Start is called, and everything it
	// depends on — lookups, filter, initial config — is installed above.
	tundev.Start()
	if opts.Debug {
		m.magic.SetDebugLoggingEnabled(true)
	}
	return m, nil
}

// checkOptions refuses options New cannot start from.
func checkOptions(opts *Options) error {
	if opts.Self.NodeKey.IsZero() {
		return errors.New("conn: Self.NodeKey is required")
	}
	for _, s := range opts.STUN {
		if _, err := parseSTUNServer(s); err != nil {
			return err
		}
	}
	// A zero disco key makes magicsock generate an ephemeral one that no peer
	// can match against the log, failing every exchange with no symptom but
	// pings that get no pong.
	if opts.Self.DiscoKey.IsZero() {
		return errors.New("conn: Self.DiscoKey is required")
	}
	if err := checkNodeID(opts.Self.ID); err != nil {
		return fmt.Errorf("conn: Self.ID: %w", err)
	}
	if len(opts.Self.Addrs) == 0 {
		return errors.New("conn: Self.Addrs must not be empty")
	}
	for _, pfx := range opts.Self.Addrs {
		if err := checkHostPrefix(pfx); err != nil {
			return fmt.Errorf("conn: Self address: %w", err)
		}
	}
	if opts.Tun == nil && opts.TunName != "" {
		if err := checkTunName(opts.TunName); err != nil {
			return fmt.Errorf("conn: TunName: %w", err)
		}
	}
	return nil
}

// cleanups is a stack of releases, run last first.
type cleanups []func()

func (c *cleanups) push(f func()) { *c = append(*c, f) }

// pop drops the newest release: what it released has changed hands.
func (c *cleanups) pop() { *c = (*c)[:len(*c)-1] }

func (c cleanups) run() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
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
	// Copies are validated and stored, so the caller's slices can neither
	// bypass the validation later nor race the lock-free lookups.
	peers = clonePeers(peers)
	// Before touching any state, so a rejected peer set leaves the data plane
	// as it was.
	if err := validatePeers(m.self, peers); err != nil {
		return err
	}
	next, nodeList := newPeerState(m.self.NodeKey.Public(), peers)

	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return errors.New("conn: manager is closed")
	}

	prev := m.state.Load().peers
	resets := peerDelta(prev, next.peers)
	fresh := newPaths(prev, next.peers)

	// Order matters: the snapshot is swapped in before the data plane is
	// told to resync, so a removed peer's lookup already fails by the time
	// wireguard-go asks.
	m.state.Store(next)

	// Session keys are discarded outright rather than left to expire, for a
	// removed peer and for one whose disco key changed — that means it
	// restarted, so its old sessions are dead. Both are re-created lazily.
	for _, nk := range resets {
		m.eng.ResetDevicePeer(nk)
	}
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
	m.warmPaths(fresh)
	return err
}

// clonePeers copies peers and the slices they hold.
func clonePeers(peers []Peer) []Peer {
	out := slices.Clone(peers)
	for i := range out {
		out[i].Addrs = slices.Clone(out[i].Addrs)
		out[i].Endpoints = slices.Clone(out[i].Endpoints)
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
	return nil
}

// newPeerState indexes a validated peer set, leaving out the entry for
// selfKey.
func newPeerState(selfKey key.NodePublic, peers []Peer) (*peerState, []tailcfg.NodeView) {
	st := &peerState{
		peers: make(map[key.NodePublic]Peer, len(peers)),
		byIP:  make(map[netip.Addr]key.NodePublic, len(peers)),
		nodes: make(map[key.NodePublic]tailcfg.NodeView, len(peers)),
	}
	nodes := make([]tailcfg.NodeView, 0, len(peers))
	for _, p := range peers {
		if p.NodeKey == selfKey {
			continue
		}
		nv := peerNode(p)
		st.peers[p.NodeKey] = p
		st.nodes[p.NodeKey] = nv
		for _, pfx := range p.Addrs {
			st.byIP[pfx.Addr()] = p.NodeKey
		}
		nodes = append(nodes, nv)
	}
	return st, nodes
}

// warmPaths starts NAT-traversal discovery towards new peers before anything
// sends to them: without it the first handshake has no path, is dropped, and
// WireGuard's five-second retry dominates in both directions. Probes repeat on
// [warmSchedule], since a disco ping to a peer not yet told about us is
// discarded. Failures are ignored. The caller must hold m.apply, which is what
// makes the WaitGroup handshake with Close safe.
func (m *tsManager) warmPaths(fresh []key.NodePublic) {
	if len(fresh) == 0 || m.closed {
		return
	}
	m.warm.Add(1)
	go func() {
		defer m.warm.Done()
		for i, delay := range warmSchedule {
			if i > 0 {
				select {
				case <-m.done:
					return
				case <-time.After(delay):
				}
			}
			// Re-read the snapshot each round: a peer removed in the
			// meantime is gone from it, and must not be probed.
			st := m.state.Load()
			for _, nk := range fresh {
				nv, ok := st.nodes[nk]
				if !ok {
					continue
				}
				m.magic.Ping(nv, new(ipnstate.PingResult), 0, func(*ipnstate.PingResult) {})
			}
		}
	}()
}

// warmSchedule is when warm-up probes are sent, measured from the reconcile
// that introduced the peer. Over within a few seconds: past that WireGuard's
// own retry has taken over.
var warmSchedule = []time.Duration{0, 250 * time.Millisecond, 1 * time.Second, 3 * time.Second}

// newPaths reports the peers that need a path established: those that were not
// in the set before, and those whose disco key changed, which means the peer
// restarted and whatever path was known to it is stale.
func newPaths(prev, next map[key.NodePublic]Peer) (fresh []key.NodePublic) {
	for nk, cur := range next {
		if old, had := prev[nk]; !had || old.DiscoKey != cur.DiscoKey {
			fresh = append(fresh, nk)
		}
	}
	return fresh
}

// peerDelta reports which device peers must be reset, discarding session keys:
// those that left the set, and those whose disco key rotated, since that means
// a restart and waiting out the rekey timers would blackhole traffic.
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
	slices.SortFunc(as, comparePrefix)
	slices.SortFunc(bs, comparePrefix)
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

// maxTunNameLen is IFNAMSIZ-1, the longest name Linux and the BSDs accept.
const maxTunNameLen = 15

// checkTunName rejects device names the OS would mishandle, which TUNSETIFF
// reports as a bare EINVAL. '%' matters most: the kernel treats it as a
// template, so "juist%d" creates a device the caller never named.
func checkTunName(name string) error {
	if name == "" {
		return errors.New("must not be empty")
	}
	if len(name) > maxTunNameLen {
		return fmt.Errorf("%q is %d bytes; the OS accepts at most %d", name, len(name), maxTunNameLen)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%q is not a usable interface name", name)
	}
	if strings.ContainsAny(name, "%") {
		return fmt.Errorf("%q contains %%, which the kernel expands to a different name", name)
	}
	if strings.ContainsAny(name, "/: \t\n") {
		return fmt.Errorf("%q contains a character an interface name may not hold", name)
	}
	return nil
}

// reconfig applies this node's own WireGuard config and the packet filter;
// wireguard-go pulls peers from the lookups installed in New. The caller must
// hold m.apply.
func (m *tsManager) reconfig() error {
	filt, err := m.filter()
	if err != nil {
		return fmt.Errorf("conn: building filter: %w", err)
	}
	m.eng.SetFilter(filt)
	wg := &wgcfg.Config{
		PrivateKey: m.self.NodeKey,
		Addresses:  m.self.Addrs,
	}
	// LocalAddrs puts our addresses on the interface; Routes is what sends
	// a peer's address into the tunnel. NetfilterOff is stated rather
	// than left to the zero value: the systemd unit's
	// ProtectKernelTunables depends on this daemon writing no sysctls.
	rt := &router.Config{
		LocalAddrs:    m.self.Addrs,
		Routes:        m.peerRoutes(),
		NetfilterMode: preftype.NetfilterOff,
	}
	if m.routerStale {
		// The engine records a router config before it programs it, so after
		// a failure it never hands that config to the router again: it
		// reports ErrNoChanges, or nil where anything else in the call moved,
		// as the listen port of an engine given none always does. A config
		// that differs in between makes the retry real. Our addresses are off
		// the device for one call, and only where the router is known broken;
		// whether that call succeeds does not matter.
		_ = m.eng.Reconfig(wg, &router.Config{NetfilterMode: preftype.NetfilterOff}, &dns.Config{})
	}
	err = m.eng.Reconfig(wg, rt, &dns.Config{})
	if err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		m.routerStale = true
		return fmt.Errorf("conn: reconfig: %w", err)
	}
	m.routerStale = false
	return nil
}

// peerRoutes is one prefix per peer overlay address: what the host must route
// into the tunnel. Sorted, so an unchanged peer set yields an identical slice
// and Reconfig recognises the no-op instead of reprogramming the OS.
func (m *tsManager) peerRoutes() []netip.Prefix {
	st := m.state.Load()
	routes := make([]netip.Prefix, 0, len(st.peers))
	for _, p := range st.peers {
		routes = append(routes, p.Addrs...)
	}
	slices.SortFunc(routes, comparePrefix)
	return routes
}

// comparePrefix orders prefixes by address, then bits.
func comparePrefix(x, y netip.Prefix) int {
	if c := x.Addr().Compare(y.Addr()); c != 0 {
		return c
	}
	return x.Bits() - y.Bits()
}

// filter builds the packet policy: any member may send anything to any other
// member. It is installed explicitly, because a nil filter drops every inbound
// packet, and built from Match values directly rather than through
// tailcfg.FilterRule's parser, which only adds failure modes.
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
	// Sharing state with the previous filter carries the flow-tracking cache
	// across rebuilds, so a membership change does not send every established
	// UDP flow back through the slow path. Nil on the first build.
	return filter.New(matches, nil, ls, ls, m.eng.GetFilter(), m.logf), nil
}

// allIPProtos enumerates every IP protocol number, the only way to say "any
// protocol": Match.IPProto is a membership test with no wildcard.
var allIPProtos = func() views.Slice[ipproto.Proto] {
	p := make([]ipproto.Proto, 256)
	for i := range p {
		p[i] = ipproto.Proto(i)
	}
	return views.SliceOf(p)
}()

// SetRelays installs the relay set. It is separate from SetPeers because the
// two change for different reasons: a relay set moves when a role is granted
// or a relay restarts, and installing it re-runs the data plane's latency
// probes, which an unchanged set must not.
func (m *tsManager) SetRelays(relays []Relay) error {
	if err := validateRelays(relays); err != nil {
		return err
	}
	relays = slices.Clone(relays)
	for i := range relays {
		relays[i].Addrs = slices.Clone(relays[i].Addrs)
	}
	slices.SortFunc(relays, func(a, b Relay) int { return a.Region - b.Region })

	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return errors.New("conn: manager is closed")
	}
	if sameRelays(m.relays, relays) {
		return nil
	}
	m.relays = relays
	m.installDERPMap(relays)
	if len(relays) == 0 {
		// Nothing will report a home region again, and a stale one would be
		// announced to peers as a path that no longer exists.
		if m.homeRelay.Swap(0) != 0 {
			m.notifyChange()
		}
	}
	return nil
}

func (m *tsManager) HomeRelay() int { return int(m.homeRelay.Load()) }

// withoutSTUNHomeNoise drops what the engine logs about a STUN server it took
// as its home. With no member relay the nearest region is always a STUN
// server's, since netcheck picks a home among every region it measured, and
// the engine then tries to connect to it every few seconds. Each try fails
// before anything is sent — a STUN-only node carries no relay — and peers are
// told of no home (see onNetInfo), so what is left is log lines saying a relay
// is down that never existed. The alternative, SetHomeless, would also stop
// the periodic STUN that keeps this node's public address current.
func (m *tsManager) withoutSTUNHomeNoise(logf logger.Logf) logger.Logf {
	stunRetry := func(args []any) bool {
		name, _ := args[0].(string)
		region, err := strconv.Atoi(strings.TrimPrefix(name, "derp-"))
		return err == nil && (*m.stunRegions.Load())[region]
	}
	return func(format string, args ...any) {
		switch {
		case strings.HasSuffix(format, "[v1] backoff: %d msec") && len(args) == 2 && stunRetry(args):
			return
		case strings.Contains(fmt.Sprintf(format, args...), "no non-STUNOnly nodes"):
			return
		}
		logf(format, args...)
	}
}

// installDERPMap renders the relays and the STUN servers as one map. The STUN
// regions are recorded first, so a report naming one is never mistaken for a
// relay to be reached through.
func (m *tsManager) installDERPMap(relays []Relay) {
	dm, stunRegions := derpMap(relays, m.stun)
	m.stunRegions.Store(&stunRegions)
	m.magic.SetDERPMap(dm)
}

func (m *tsManager) LocalEndpoints() []netip.AddrPort {
	m.epsMu.Lock()
	defer m.epsMu.Unlock()
	return slices.Clone(m.localEps)
}

// onStatus records the endpoint set the data plane believes this node is
// reachable at. Without a relay it is empty: magicsock reports no endpoints of
// its own with neither a STUN result nor a DERP map, which is why the
// announcement is built from an interface scan as well and these are added to
// it rather than substituted for it.
func (m *tsManager) onStatus(st *wgengine.Status, err error) {
	if err != nil || st == nil {
		return
	}
	eps := make([]netip.AddrPort, 0, len(st.LocalAddrs))
	for _, e := range st.LocalAddrs {
		ap := e.Addr
		if !ap.IsValid() || ap.Port() == 0 {
			continue
		}
		eps = append(eps, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	slices.SortFunc(eps, func(a, b netip.AddrPort) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return int(a.Port()) - int(b.Port())
	})
	eps = slices.Compact(eps)

	m.epsMu.Lock()
	changed := !slices.Equal(m.localEps, eps)
	m.localEps = eps
	m.epsMu.Unlock()
	if changed {
		m.notifyChange()
	}
}

// onNetInfo records the relay region the data plane chose for itself.
func (m *tsManager) onNetInfo(ni *tailcfg.NetInfo) {
	if ni == nil {
		return
	}
	home := ni.PreferredDERP
	if (*m.stunRegions.Load())[home] {
		// Nearest, but nothing to be reached through.
		home = 0
	}
	if m.homeRelay.Swap(int64(home)) != int64(home) {
		m.notifyChange()
	}
}

// notifyChange tells the caller that something in this node's announcement
// moved. It runs on the engine's goroutines, so it must not block: the
// callback's contract is that it returns promptly.
func (m *tsManager) notifyChange() {
	if m.onChange != nil {
		m.onChange()
	}
}

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

func (m *tsManager) Tunnels() map[uint64]Tunnel {
	if m.isClosed() {
		return nil
	}
	sb := &ipnstate.StatusBuilder{WantPeers: true}
	m.eng.UpdateStatus(sb)
	peers := m.state.Load().peers
	st := sb.Status()
	out := make(map[uint64]Tunnel, len(st.Peer))
	for nk, ps := range st.Peer {
		if p, ok := peers[nk]; ok {
			t := Tunnel{LastHandshake: ps.LastHandshake}
			if ap, err := netip.ParseAddrPort(ps.CurAddr); err == nil {
				t.Direct = ap
			}
			out[p.ID] = t
		}
	}
	return out
}

// Probe uses a TSMP ping, which the peer's TUN wrapper answers before its
// packet filter and host stack see it.
func (m *tsManager) Probe(ip netip.Addr, timeout time.Duration, cb func(bool)) {
	if m.isClosed() {
		cb(false)
		return
	}
	var once sync.Once
	answer := func(ok bool) { once.Do(func() { cb(ok) }) }
	t := time.AfterFunc(timeout, func() { answer(false) })
	m.eng.Ping(ip, tailcfg.PingTSMP, 0, func(r *ipnstate.PingResult) {
		t.Stop()
		answer(r.Err == "")
	})
}

func (m *tsManager) isClosed() bool {
	m.apply.Lock()
	defer m.apply.Unlock()
	return m.closed
}

func (m *tsManager) Close() error {
	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	// Stop and drain the warm-up goroutines before the engine goes: they
	// call into magicsock, which does not survive its engine.
	close(m.done)
	m.warm.Wait()
	m.eng.Close()
	// The engine closes the router it was given but not the monitor, since it
	// did not create it. Do that here, after the engine has finished using it
	// on the way down.
	if m.netMon != nil {
		m.netMon.Close()
	}
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
		HomeDERP:   p.HomeRelay,
		Cap:        tailcfg.CurrentCapabilityVersion,
	}).View()
}
