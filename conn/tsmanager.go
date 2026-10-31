package conn

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/types"
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

	// Plumber, where set, creates the device TunName names and routes it,
	// for a node that may not itself, as on FreeBSD; one from [NewVPNPlumber]
	// establishes it as Android's VpnService does.
	Plumber Plumber

	// Instance numbers this node among the juist nodes on the host, from 0
	// to instance.Max. The real router keeps each instance's routes in a
	// table of its own, behind policy rules of its own, so stopping one
	// leaves the others' in place.
	Instance int

	// RespondToPing makes the engine answer overlay ICMP echo requests
	// internally, without a TUN device. Test and demo use only.
	RespondToPing bool

	// Debug enables magicsock's verbose NAT-traversal logging.
	Debug bool

	// OnConnectivityChange is called, possibly from another goroutine, when
	// [Manager.HomeRelay] or [Manager.LocalEndpoints] changes. Both belong in
	// this node's announcement, so the caller re-announces and pushes.
	OnConnectivityChange func()

	// OnHostRoutesChange is called, possibly from another goroutine, when
	// what [Manager.HostRoutes] says may have changed.
	OnHostRoutesChange func()

	// OnInterfacesChange is called, possibly from another goroutine, when
	// the host's interfaces or their addresses change, on a device of its
	// own.
	OnInterfacesChange func()

	// HTTPSOnly sends nothing but TLS to 443/tcp of relays' names: no UDP
	// and no peer relay, and STUN is ignored. Every packet then goes through
	// a relay.
	HTTPSOnly bool

	// Proxy, with HTTPSOnly, is the HTTP proxy a connection to a relay's
	// name goes through, by CONNECT, or nil for none.
	Proxy func(host string) (*url.URL, error)

	// Local, where set, is a device whose other end is a stack in this
	// process holding LocalAddrs: what this node's device sends to them is
	// taken there before the engine and its filter, and what the stack sends
	// is delivered to the device. Close closes it, as a New that fails does.
	Local      tun.Device
	LocalAddrs []netip.Addr

	// Multicast carries the UDP this node's device sends to a multicast
	// group to every member without an [Access], and delivers theirs. Each
	// member then holds a link-local address of its overlay IPv6 one's, the
	// only one on this node's device.
	Multicast bool

	// Groups are IPv4 multicast groups routed into the device and joined on
	// it, with Multicast, so that an app sending and listening on the host's
	// default interface reaches the members instead of the LAN. Linux alone.
	Groups []netip.Addr
}

// tsManager implements [Manager] on top of Tailscale's wgengine and magicsock.
// It is the only place in this project that touches Tailscale's types, and it
// uses no controlclient, tsnet or ipn: all three assume a coordination server.
type tsManager struct {
	logf  logger.Logf
	eng   wgengine.Engine
	magic *magicsock.Conn
	bus   *eventbus.Bus

	// self and selfNV change under apply; selfOnPath is both for the lookups
	// the engine makes on packet paths.
	self       Self
	selfNV     tailcfg.NodeView
	selfOnPath atomic.Pointer[selfLookup]

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

	// unproven are peers installed with no relay to fall back on, each until
	// when nothing is sent to it before disco proves a path: a first
	// handshake sent on none is lost, and its retry waits five seconds.
	unproven sync.Map // key.NodePublic → time.Time

	// keying are the peers newly given a preshared key, and since when:
	// each passes nothing until its reset is repeated, as a peer the engine
	// created concurrently may hold the key it had. Guarded by apply.
	keying map[key.NodePublic]time.Time

	// routerStale records that the last reconfiguration failed, so the OS may
	// not match what the engine believes it programmed, and osRouter is the
	// router a retry goes to directly.
	// Guarded by apply.
	routerStale bool
	osRouter    router.Router

	// exits is the OS router's side of egress and serving, nil without a
	// device of this node's own; egress and serve are what it was last given.
	// Guarded by apply.
	exits exitRouter
	// hostRouter is the OS router's reading of the host's own routes.
	hostRouter hostRouter
	// inGuard keeps the overlay's addresses to the tunnel where the OS
	// router can.
	inGuard overlayGuard
	// tunnelled is what the router was last told the peers carry, and
	// isolate whether answers go in too.
	tunnelled tunnelled
	isolate   bool
	egress    Egress
	serve     Serve
	tunName   string

	// confiner keeps restricted peers to their access, and groups carries
	// multicast, nil without [Options.Multicast].
	confiner *confiner
	groups   *multicaster
	// routed are [Options.Groups], and joined holds them on the device.
	routed []netip.Prefix
	joined io.Closer

	// stun are the public STUN servers, and stunRegions the regions they
	// hold in the map last installed.
	stun        []string
	stunRegions atomic.Pointer[map[tailcfg.DERPRegionID]bool]
	// relayRegions are the member relays' regions in that map.
	relayRegions atomic.Pointer[map[tailcfg.DERPRegionID]bool]
	// pinged are the relays netcheck reached by ICMP alone.
	pinged pinged
	// homes are the homes peers last said they had. Guarded by apply.
	homes map[key.NodePublic]heldHome
	// homeless is whether the engine is told it has no home: the map last
	// installed holds STUN servers alone (stunOnly), or the last report
	// measured no member relay (relayMissing); homeMu orders the telling.
	// tun is the wrapper whose idleness paces STUN then.
	homeless, stunOnly, relayMissing atomic.Bool
	relayLost                        atomic.Int64  // relayMissing set anew, which starts the retries over
	homed                            chan struct{} // the engine was told it has a home again
	homeMu                           sync.Mutex
	tun                              *tstun.Wrapper
	// saving is [tsManager.SetSaving]'s; silentMu orders it with a quiet
	// probe's silent disco.
	saving   atomic.Bool
	silentMu sync.Mutex

	// relays is the relay set last installed, kept so an unchanged one does
	// not restart the latency probes, and dm the map installed. Guarded by
	// apply.
	relays []Relay
	dm     *tailcfg.DERPMap
	// stunDrop is whether a dropSTUNConn is due, stunDropped when the last
	// ran, in Unix nanoseconds, and unreadLine says once that magicsock's
	// line naming a new connection no longer reads as conn expects.
	stunDrop    atomic.Bool
	stunDropped atomic.Int64
	unreadLine  sync.Once

	// httpsOnly and proxy are [Options.HTTPSOnly] and [Options.Proxy], and
	// named the names of the relays installed, those dropped since kept.
	httpsOnly bool
	proxy     func(host string) (*url.URL, error)
	named     atomic.Pointer[[]string]

	// local are this host's networks, which a relay's addresses on come
	// first in the map, and skip the device it leaves out of them.
	local atomic.Pointer[Networks]
	skip  string

	// onChange is called when the home relay or the local endpoint set moves.
	onChange func()

	// homeRelay is the region the data plane picked, and localEps the
	// addresses it believes this node is reachable at. Both are written from
	// the engine's callbacks and read by the announcement.
	homeRelay atomic.Int64
	epsMu     sync.Mutex
	localEps  []netip.AddrPort
	// publicSeen is when each public address among them was last reported.
	publicSeen map[netip.Addr]time.Time

	// done is closed by Close, and warm tracks the path warm-up goroutines
	// so that none of them can touch the engine after it is torn down.
	done chan struct{}
	warm sync.WaitGroup

	// state is the peer set the data plane answers from: read lock-free on the
	// per-packet paths, replaced wholesale under apply, never mutated once
	// stored.
	state atomic.Pointer[peerState]

	// evicting is the peer peerConfig disowns while it is taken out of the
	// device, the engine's only way to drop a peer's sessions. Set under apply.
	evicting atomic.Pointer[key.NodePublic]

	// stack is [Options.Local].
	stack tun.Device

	// walled is [Manager.Walled], walls what makes it so.
	walled atomic.Bool
	walls  walls
}

var _ Manager = (*tsManager)(nil)

// New starts a Tailscale-backed connectivity manager. No DERP map is
// installed, so it is direct-only: no connection to any relay or STUN server.
func New(opts Options) (_ Manager, err error) {
	if opts.Local != nil {
		defer func() {
			if err != nil {
				opts.Local.Close()
			}
		}()
	}
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
	if opts.Multicast {
		opts.Self.Addrs = withLinkLocal(opts.Self.Addrs)
	}
	if err := checkGroups(opts); err != nil {
		return nil, err
	}

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
		logf:      logf,
		bus:       bus,
		self:      opts.Self,
		done:      make(chan struct{}),
		onChange:  opts.OnConnectivityChange,
		stun:      slices.Clone(opts.STUN),
		httpsOnly: opts.HTTPSOnly,
		proxy:     opts.Proxy,
	}
	if m.httpsOnly {
		m.stun = nil
	}
	m.state.Store(&peerState{})
	m.stunRegions.Store(&map[tailcfg.DERPRegionID]bool{})
	m.relayRegions.Store(&map[tailcfg.DERPRegionID]bool{})
	m.named.Store(&[]string{})
	m.skip = opts.TunName
	m.publicSeen = map[netip.Addr]time.Time{}
	m.local.Store(&Networks{Prefixes: hostNetworks(m.skip)})
	if len(m.stun) > 0 {
		m.homed = make(chan struct{}, 1)
	}
	m.walls.kick = make(chan struct{}, 1)
	m.walls.keepKey = key.NewNode().Public()
	logf = m.watchEngine(logf)
	m.logf = logf

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

	if opts.Tun == nil && opts.TunName != "" {
		if err := m.openDevice(opts, &cfg, &undo, logf); err != nil {
			return nil, err
		}
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
	m.confiner = confine(tundev)
	if opts.Multicast {
		m.groups = relayGroups(tundev, m.done, &m.warm)
		m.confiner.groups = m.groups
		undo.push(func() { close(m.done) })
		for _, g := range opts.Groups {
			m.routed = append(m.routed, netip.PrefixFrom(g, 32))
		}
	}
	m.tun = tundev
	if opts.Local != nil {
		m.stack = opts.Local
		takeLocal(tundev, opts.Local, slices.Clone(opts.LocalAddrs), &m.warm)
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
	if m.httpsOnly {
		// Before any map: netcheck and the first endpoint update read it.
		m.magic.SetOnlyTCP443(true)
		registerProxied(m)
		undo.push(func() { unregisterProxied(m) })
	}

	m.selfNV = m.selfNode(opts.Self)
	m.selfOnPath.Store(&selfLookup{addrs: opts.Self.Addrs, node: m.selfNV})
	eng.SetSelfNode(m.selfNV)

	// The data plane learns its peer set only from these lookups, backed by
	// the snapshot SetPeers stores. A key absent from it has no peer entry and
	// no allowed IPs, so it cannot handshake: default-deny lives here.
	eng.SetPeerConfigFunc(m.peerConfig)
	eng.SetPeerByIPPacketFunc(m.sendTo)
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
		m.warm.Add(1)
		go m.stunWhileHomeless()
	}

	m.apply.Lock()
	err = m.reconfig()
	m.apply.Unlock()
	if err != nil {
		return nil, err
	}
	if len(m.routed) > 0 {
		if m.joined, err = joinGroups(opts.TunName, opts.Groups); err != nil {
			return nil, fmt.Errorf("conn: joining the groups routed into %s: %w", opts.TunName, err)
		}
		undo.push(func() { m.joined.Close() })
	}
	go m.meetLoop()

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
	for _, s := range opts.STUN {
		if _, err := parseSTUNServer(s); err != nil {
			return err
		}
	}
	if err := checkSelf(opts.Self); err != nil {
		return err
	}
	if opts.Tun == nil && opts.TunName != "" {
		if err := checkTunName(opts.TunName); err != nil {
			return fmt.Errorf("conn: TunName: %w", err)
		}
	}
	if opts.Instance < 0 || opts.Instance > instance.Max {
		return fmt.Errorf("conn: Instance %d is not between 0 and %d", opts.Instance, instance.Max)
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
		Routes:        slices.Concat(m.peerRoutes(), m.routed),
		NetfilterMode: preftype.NetfilterOff,
	}
	err = m.eng.Reconfig(wg, rt, &dns.Config{})
	if err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		m.routerStale = true
		return fmt.Errorf("conn: reconfig: %w", err)
	}
	if m.routerStale && m.osRouter != nil {
		// The engine records a router config before it programs it, so it
		// never hands a config that failed to the router again: the retry
		// goes to the router itself, which redoes only what failed.
		if err := m.osRouter.Set(rt); err != nil {
			return fmt.Errorf("conn: reconfig: %w", err)
		}
	}
	m.routerStale = false
	if m.inGuard != nil {
		return m.inGuard.guardOverlay(hostAddrs(m.self.Addrs), m.peerAddrs())
	}
	return nil
}

// peerAddrs is every peer's overlay addresses, sorted.
func (m *tsManager) peerAddrs() []netip.Addr {
	var addrs []netip.Addr
	for _, p := range m.state.Load().peers {
		addrs = append(addrs, hostAddrs(p.Addrs)...)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

// guardAhead keeps to the tunnel the addresses next adds to prev before
// the router puts them on the device, where they are reached by any
// device until the guard names them. The caller holds m.apply.
func (m *tsManager) guardAhead(prev, next []netip.Prefix) error {
	if m.inGuard == nil {
		return nil
	}
	both := slices.Clone(prev)
	for _, p := range next {
		if !slices.Contains(both, p) {
			both = append(both, p)
		}
	}
	if len(both) == len(prev) {
		return nil
	}
	return m.inGuard.guardOverlay(hostAddrs(both), m.peerAddrs())
}

// hostAddrs is the addresses of single-address prefixes.
func hostAddrs(ps []netip.Prefix) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(ps))
	for _, p := range ps {
		// A link-local address is the device's alone by its scope, and the
		// LAN's own may be one like it.
		if !p.Addr().IsLinkLocalUnicast() {
			addrs = append(addrs, p.Addr())
		}
	}
	return addrs
}

// peerRoutes is one prefix per peer overlay address, and each subnet a peer
// routes: what the host must route into the tunnel. Sorted, so an unchanged
// peer set yields an identical slice and Reconfig recognises the no-op
// instead of reprogramming the OS.
func (m *tsManager) peerRoutes() []netip.Prefix {
	st := m.state.Load()
	routes := make([]netip.Prefix, 0, len(st.peers))
	for _, p := range st.peers {
		routes = append(routes, p.Addrs...)
		routes = append(routes, p.Subnets...)
	}
	slices.SortFunc(routes, types.ComparePrefix)
	return routes
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

// NetworkChanged has the network monitor look at the host's interfaces now,
// as Android, whose monitor only polls every few minutes, has to say.
func (m *tsManager) NetworkChanged() {
	if m.netMon != nil {
		m.netMon.InjectEvent()
	}
}

func (m *tsManager) Echo(ip netip.Addr, cb func(PingResult)) {
	if m.isClosed() {
		cb(PingResult{Err: "the data plane is closed"})
		return
	}
	m.eng.Ping(ip, tailcfg.PingTSMP, 0, func(r *ipnstate.PingResult) {
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

// ProbeQuietly is [tsManager.Probe] by a disco ping alone, sent with silent
// disco on: magicsock starts its heartbeat towards a peer, pinging it every
// 3 s until 45 s after the last packet, on whatever it sends it but a disco
// ping sent so, and its pong starts none on the far end. It does count as
// such a last packet: one sooner than 45 s after another keeps a heartbeat
// already going. Silent disco is the whole conn's: another peer's heartbeat
// that ticks in that instant stops until its next packet.
func (m *tsManager) ProbeQuietly(ip netip.Addr, timeout time.Duration, cb func(bool)) {
	if m.isClosed() {
		cb(false)
		return
	}
	var once sync.Once
	answer := func(ok bool) { once.Do(func() { cb(ok) }) }
	t := time.AfterFunc(timeout, func() { answer(false) })
	m.silentMu.Lock()
	defer m.silentMu.Unlock()
	// Engine.Ping reaches magicsock, which decides on the heartbeat, before
	// it returns.
	if !m.saving.Load() {
		m.magic.SetSilentDisco(true)
		defer m.magic.SetSilentDisco(false)
	}
	m.eng.Ping(ip, tailcfg.PingDisco, 0, func(r *ipnstate.PingResult) {
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
	unregisterProxied(m)
	// Stop and drain the warm-up goroutines before the engine goes: they
	// call into magicsock, which does not survive its engine.
	close(m.done)
	if m.stack != nil {
		m.stack.Close()
	}
	if m.joined != nil {
		m.joined.Close()
	}
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

func (m *tsManager) HostRoutes() []netip.Prefix {
	if m.hostRouter != nil {
		return m.hostRouter.hostRoutes()
	}
	nets, _ := attached(m.tunName)
	return nets
}
