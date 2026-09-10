// Package daemon holds the membership log, the sync layer and the data plane
// together: it renders log state into a WireGuard peer set, runs anti-entropy
// and blinded LAN discovery, and serves the CLI over a unix socket.
//
// [log.Authority] is not safe for concurrent use and every gossip session
// touches it, so the authority and its store sit behind one mutex, never held
// across a call into the data plane.
package daemon

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

const (
	// DefaultSyncInterval is the periodic anti-entropy round with one random
	// member. It is the backstop; a change reaches reachable members by push.
	DefaultSyncInterval = 2 * time.Minute

	// DefaultReconcileInterval re-derives the peer set for what changes
	// without an event, such as a membership expiring.
	DefaultReconcileInterval = 15 * time.Second
)

// Options configures a [Daemon].
type Options struct {
	// Authority is the open membership log. The daemon takes ownership: it is
	// not safe for concurrent use, and nothing else may touch it afterwards.
	Authority *log.Authority

	// Storage is the same store the authority was opened over, read directly
	// to answer which records this node holds.
	Storage log.Storage

	// Identity is this device's node identity key, which signs its endpoint
	// announcements. It is not an admin key and cannot authorize anything.
	Identity types.PrivateIdentity

	// Recipient is this device's HPKE key material, needed to open its wrap
	// of each epoch group secret.
	Recipient *secrets.PrivateKeys

	// WireGuard is this device's WireGuard static private key, as recorded
	// in the log by its public half.
	WireGuard [32]byte

	// ListenPort is the UDP port the data plane binds. Zero picks one.
	ListenPort uint16

	// TunName is the OS TUN device the data plane creates, which needs
	// /dev/net/tun and CAP_NET_ADMIN. Empty means no host device.
	TunName string

	// RelayPort is the TCP port this device's relay serves DERP on, and the
	// UDP port it answers STUN on. Zero picks one; the port travels in the
	// signed announcement either way.
	RelayPort uint16

	// DisableRelay keeps this device from relaying even where the log grants
	// it the role: the operator's veto over their own machine's bandwidth.
	DisableRelay bool

	// Connect builds the data plane. Nil uses [conn.New].
	Connect func(conn.Options) (conn.Manager, error)

	// GossipListener accepts inbound anti-entropy sessions. Nil listens on
	// GossipPort.
	GossipListener net.Listener

	// GossipPort is the TCP port to accept sessions on when GossipListener is
	// nil. Zero picks one: the port travels in the signed announcement.
	GossipPort uint16

	// Discovery configures LAN discovery; the daemon fills in the keyring and
	// the callbacks. Nil uses the real multicast group.
	Discovery *mdns.Options

	// DisableDiscovery turns LAN discovery off.
	DisableDiscovery bool

	// DisableDHT turns the public-DHT rendezvous off. It is how a node
	// finds a member that is on no LAN it can see and at no address it has
	// cached; a network that only ever runs on one segment loses nothing by
	// switching it off, and stops touching the public DHT at all.
	DisableDHT bool

	// DHTBootstrap overrides the public DHT routers a fresh node starts from.
	DHTBootstrap []string

	// SocketPath is where the IPC socket is created. Empty disables IPC.
	SocketPath string

	// EndpointCachePath is where last-known peer addresses are persisted, so
	// a restarted device knows where its peers were before it hears from
	// anyone. Empty keeps the cache in memory only.
	EndpointCachePath string

	// SyncInterval and ReconcileInterval override the defaults above.
	SyncInterval      time.Duration
	ReconcileInterval time.Duration

	// Clock overrides time.Now, for tests.
	Clock func() time.Time

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// A Daemon is one member's running node.
type Daemon struct {
	// authMu guards the authority and its store, and is never held across a
	// call into the connectivity layer. reconcileMu serializes whole
	// reconciles — state read through SetPeers — so two cannot install their
	// peer sets in the opposite order to their state reads; it nests outside
	// authMu and nothing else takes it.
	reconcileMu sync.Mutex
	authMu      sync.Mutex
	authority   *log.Authority
	storage     log.Storage
	identity    types.PrivateIdentity
	recipient   *secrets.PrivateKeys
	self        types.Identity
	ula         netip.Prefix

	manager   conn.Manager
	gossip    *gossip.Node
	beacon    *mdns.Beacon
	dht       *dht.Node
	ipc       *ipcServer
	endpoints *gossip.Cache
	keyring   *secrets.Keyring

	relayPort uint16
	noRelay   bool
	cachePath string

	discoPrivate [32]byte
	discoPublic  gossip.DiscoKey
	wgPublic     types.WGKey
	gossipPort   uint16

	syncEvery      time.Duration
	reconcileEvery time.Duration
	clock          func() time.Time
	logf           func(string, ...any)

	// dirty coalesces "something changed, reconcile and push". Buffered to
	// one: a second signal arriving before the loop wakes is the same work.
	dirty chan struct{}

	// syncing holds a token while an anti-entropy round runs, so rounds do not
	// overlap; pushDeferred records one asked for while it was running.
	syncing chan struct{}

	// closing guards the wait set: an Add that takes the counter off zero
	// must not race a Wait, which Run and Close would otherwise do.
	closeOnce sync.Once
	closed    chan struct{}
	trackMu   sync.Mutex
	closing   bool
	wg        sync.WaitGroup

	// mu guards everything below: the local peer-ID assignment, the cached
	// announcement, and the status snapshot.
	mu      sync.Mutex
	peerIDs map[types.Identity]uint64

	// everMember records every identity seen as a live member, so a cached
	// announcement can be told from a former member's.
	everMember map[types.Identity]bool

	// logged deduplicates the persistent-condition log lines; see
	// [Daemon.logOnce].
	logged       map[string]bool
	pushDeferred bool
	nextPeerID   uint64
	announced    *gossip.Endpoint

	// cachedEndpoints is the last encoding written to the endpoint cache, so
	// an unchanged set does not rewrite the file on every reconcile.
	cachedEndpoints []byte

	// relay is this device's own relay while the log grants it the role, and
	// relayMembers is the WireGuard key set it admits, refreshed by every
	// reconcile so that a DERP connection never has to reach the authority.
	relay        *relay.Server
	relayMembers map[types.WGKey]bool

	// addrs caches the last interface scan; see [Daemon.underlayEndpoints].
	addrs      []netip.AddrPort
	addrsPort  uint16
	addrsUntil time.Time
	seq        uint64
	status     Status
}

// Status is what the daemon reports about itself, over IPC and to tests. Times
// are Unix seconds: canonical CBOR admits one spelling per value, and
// time.Time carries a monotonic reading and a location.
type Status struct {
	// Self is this node's identity, and Addrs its overlay addresses.
	Self  types.Identity `cbor:"1,keyasint"`
	Addrs []netip.Prefix `cbor:"2,keyasint,omitempty"`

	// Network is the genesis hash and NetworkName the human-readable name.
	Network     types.Hash `cbor:"3,keyasint"`
	NetworkName string     `cbor:"4,keyasint,omitempty"`

	// Head and Epoch are where this node's chain is: the same beacon it
	// puts on every gossip frame.
	Head  types.Hash `cbor:"5,keyasint"`
	Epoch uint64     `cbor:"6,keyasint"`

	// Members is how many the log carries, Peers how many are installed in the
	// data plane, Unreachable how many have no announcement yet, and Expired
	// how many are past their expiry and treated as former members.
	Members     int `cbor:"7,keyasint"`
	Peers       int `cbor:"8,keyasint"`
	Unreachable int `cbor:"9,keyasint"`
	Expired     int `cbor:"15,keyasint,omitempty"`

	// Relays is how many member-run relays this node has installed,
	// RelayCapable how many members the log grants the role, and Relaying
	// reports whether this device is serving one itself. The three differ:
	// a grant with no announcement behind it is a relay nobody can reach.
	Relays       int  `cbor:"21,keyasint,omitempty"`
	Relaying     bool `cbor:"22,keyasint,omitempty"`
	RelayCapable int  `cbor:"23,keyasint,omitempty"`

	// Conflicted is how many members were denied a peer entry for announcing a
	// NAT-traversal key another member or this device already uses. Dropping
	// only those keeps one announcement from costing everyone their data plane.
	Conflicted int `cbor:"18,keyasint,omitempty"`

	// Alarm is the fork alarm's text while one is raised, and empty
	// otherwise. While it is set the data plane holds no peers at all.
	Alarm string `cbor:"10,keyasint,omitempty"`

	// EpochError is set when this node could not open its wrap of the
	// current group secret, which costs it discovery and gossip but not the
	// data plane.
	EpochError string `cbor:"11,keyasint,omitempty"`

	// SchemaAlarm is set when a quorum has moved the network to a record
	// schema this build does not implement. The state below the upgrade is
	// still held and still acted on — see [log.SchemaTooNewError] — but
	// nothing after it will apply until the binary is newer.
	SchemaAlarm string `cbor:"20,keyasint,omitempty"`

	// NotMember is set when this device is no longer in the member set. The
	// daemon has torn its own data plane down.
	NotMember bool `cbor:"16,keyasint,omitempty"`

	// StaleKeys is set when the log names different keys for this device than
	// the daemon was started with: a rotation was applied while it ran, and
	// tunnels and the group secret fail until it restarts over the new keys.
	StaleKeys bool `cbor:"17,keyasint,omitempty"`

	// DataPlaneError is set when the peer set was derived but the data plane
	// refused it: the host may be routed for an older peer set than the log
	// names. The daemon retries on every reconcile.
	DataPlaneError string `cbor:"19,keyasint,omitempty"`

	// LastReconcile is when the peer set was last derived, in Unix seconds.
	LastReconcile int64 `cbor:"12,keyasint,omitempty"`

	// ListenPort is the data plane's UDP port and GossipPort the sync
	// layer's TCP port.
	ListenPort uint16 `cbor:"13,keyasint,omitempty"`
	GossipPort uint16 `cbor:"14,keyasint,omitempty"`
}

// New starts a daemon. The caller runs [Daemon.Run].
func New(opts Options) (*Daemon, error) {
	switch {
	case opts.Authority == nil:
		return nil, errors.New("daemon: Authority is required")
	case opts.Storage == nil:
		return nil, errors.New("daemon: Storage is required")
	case opts.Identity.IsZero():
		return nil, errors.New("daemon: Identity is required")
	case opts.Recipient == nil:
		return nil, errors.New("daemon: Recipient keys are required")
	case opts.WireGuard == [32]byte{}:
		return nil, errors.New("daemon: WireGuard key is required")
	}

	// Unguarded by TrustedState: what is read here is fixed at genesis and
	// identical on every branch of a fork. The rest goes through Reconcile.
	state := opts.Authority.State()
	self := opts.Identity.Public()
	if !state.IsMember(self) {
		return nil, fmt.Errorf(
			"daemon: %v is not a member of network %q; this device has a log but was never enrolled in it",
			self.ShortString(), state.Network())
	}

	d := &Daemon{
		authority:      opts.Authority,
		storage:        opts.Storage,
		identity:       opts.Identity,
		recipient:      opts.Recipient,
		self:           self,
		ula:            state.ULA(),
		endpoints:      gossip.NewCache(),
		keyring:        secrets.NewKeyring(),
		syncEvery:      cmpOr(opts.SyncInterval, DefaultSyncInterval),
		reconcileEvery: cmpOr(opts.ReconcileInterval, DefaultReconcileInterval),
		clock:          opts.Clock,
		logf:           opts.Logf,
		dirty:          make(chan struct{}, 1),
		syncing:        make(chan struct{}, 1),
		closed:         make(chan struct{}),
		peerIDs:        map[types.Identity]uint64{},
		everMember:     map[types.Identity]bool{},
		cachePath:      opts.EndpointCachePath,
		relayPort:      opts.RelayPort,
		noRelay:        opts.DisableRelay,
		relayMembers:   map[types.WGKey]bool{},
	}
	if d.logf == nil {
		d.logf = func(string, ...any) {}
	}

	wgPub, err := wgPublicOf(opts.WireGuard)
	if err != nil {
		return nil, err
	}
	d.wgPublic = wgPub

	// Fresh every start and never persisted: it is connectivity material, and
	// a peer seeing a new one is meant to read it as a restart.
	discoPriv, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		return nil, err
	}
	d.discoPrivate = discoPriv
	d.discoPublic = gossip.DiscoKey(discoPub)

	connect := opts.Connect
	if connect == nil {
		connect = conn.New
	}
	mgr, err := connect(conn.Options{
		Self: conn.Self{
			ID:       d.peerID(self),
			NodeKey:  conn.NodeKeyFromRaw32(opts.WireGuard),
			DiscoKey: conn.DiscoKeyFromRaw32(discoPriv),
			Addrs:    state.Addrs(self),
		},
		ListenPort: opts.ListenPort,
		TunName:    opts.TunName,
		Logf:       d.logf,
		// The home relay and the reflexive addresses both belong in this
		// node's announcement, and both are learned asynchronously once
		// there is a relay to learn them from.
		OnConnectivityChange: d.onConnectivityChange,
	})
	if err != nil {
		return nil, fmt.Errorf("daemon: starting the data plane: %w", err)
	}
	d.manager = mgr

	ln := opts.GossipListener
	if ln == nil {
		ln, err = net.Listen("tcp", fmt.Sprintf(":%d", opts.GossipPort))
		if err != nil {
			mgr.Close()
			return nil, fmt.Errorf("daemon: listening for gossip: %w", err)
		}
	}
	d.gossipPort = uint16(portOf(ln.Addr()))

	d.gossip, err = gossip.New(gossip.Options{
		Self:         self,
		Log:          (*logAdapter)(d),
		Keyring:      d.keyring,
		Endpoints:    d.endpoints,
		Announce:     d.announcement,
		Listener:     ln,
		OverlayAddrs: d.overlayGossipAddrs,
		OnRecords:    d.MarkDirty,
		Logf:         d.logf,
	})
	if err != nil {
		ln.Close()
		mgr.Close()
		return nil, err
	}

	if !opts.DisableDiscovery {
		mopts := mdns.Options{}
		if opts.Discovery != nil {
			mopts = *opts.Discovery
		}
		mopts.Keyring = d.keyring
		mopts.Announce = d.announcement
		mopts.OnPeer = d.onDiscovered
		mopts.NeedsPeers = d.needsPeers
		mopts.Logf = d.logf
		// Discovery is an underlay function, so it must not use the overlay
		// device this daemon just created.
		mopts.SkipInterface = opts.TunName
		d.beacon, err = mdns.New(mopts)
		if err != nil {
			d.gossip.Close()
			mgr.Close()
			return nil, err
		}
	}

	if !opts.DisableDHT {
		d.dht, err = dht.New(dht.Options{
			Self:      self,
			Keyring:   d.keyring,
			Announce:  d.announcement,
			Wanted:    d.unheard,
			OnPeer:    d.onFoundInDHT,
			Bootstrap: opts.DHTBootstrap,
			Logf:      d.logf,
		})
		if err != nil {
			if d.beacon != nil {
				d.beacon.Close()
			}
			d.gossip.Close()
			mgr.Close()
			return nil, err
		}
	}

	if opts.SocketPath != "" {
		d.ipc, err = newIPCServer(d, opts.SocketPath)
		if err != nil {
			if d.dht != nil {
				d.dht.Close()
			}
			if d.beacon != nil {
				d.beacon.Close()
			}
			d.gossip.Close()
			mgr.Close()
			return nil, err
		}
	}

	// Before the loop starts, so the first reconcile already has somewhere to
	// reach the peers this device knew about when it stopped.
	d.loadEndpointCache(d.cachePath)

	d.setStatus(func(s *Status) {
		s.Self = self
		s.Addrs = state.Addrs(self)
		// Known the moment the log is opened, so a status read before the
		// first reconcile still names the network.
		s.Network = state.GenesisHash()
		s.NetworkName = state.Network()
		s.ListenPort = mgr.LocalPort()
		s.GossipPort = d.gossipPort
	})
	return d, nil
}

// wgPublicOf derives the public half of a WireGuard static key, as the log
// records it.
func wgPublicOf(priv [32]byte) (types.WGKey, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return types.WGKey{}, fmt.Errorf("daemon: deriving the WireGuard public key: %w", err)
	}
	var out types.WGKey
	copy(out[:], k.PublicKey().Bytes())
	return out, nil
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
}

func portOf(a net.Addr) int {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.Port
	}
	return 0
}

// Run drives the daemon until ctx is cancelled or [Daemon.Close] is called.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !d.track() {
		return nil // closed before it ever ran
	}
	go func() {
		defer d.wg.Done()
		d.gossip.Serve()
	}()
	if d.beacon != nil && d.track() {
		go func() {
			defer d.wg.Done()
			d.beacon.Run(ctx)
		}()
	}
	if d.ipc != nil && d.track() {
		go func() {
			defer d.wg.Done()
			d.ipc.serve()
		}()
	}
	if d.dht != nil && d.track() {
		go func() {
			defer d.wg.Done()
			d.dht.Run(ctx)
		}()
	}

	// Before the first session: a node that speaks only its newest epoch can
	// neither reach a peer that is behind nor be reached by one.
	d.backfillEpochs()

	// So the data plane reflects the log from the first instant.
	if err := d.Reconcile(); err != nil {
		d.logf("daemon: initial reconcile: %v", err)
	}
	d.MarkDirty() // and sync with whoever is already known

	syncTick := time.NewTicker(d.syncEvery)
	defer syncTick.Stop()
	reconcileTick := time.NewTicker(d.reconcileEvery)
	defer reconcileTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.closed:
			return nil
		case <-d.dirty:
			if err := d.Reconcile(); err != nil {
				d.logf("daemon: reconcile: %v", err)
			}
			d.inBackground(ctx, d.pushAll)
		case <-reconcileTick.C:
			if err := d.Reconcile(); err != nil {
				d.logf("daemon: reconcile: %v", err)
			}
		case <-syncTick.C:
			d.inBackground(ctx, d.syncOne)
		}
	}
}

// inBackground runs one anti-entropy round off the loop's goroutine, at most
// one at a time: a round can take tens of seconds against an unreachable
// member, and the loop must stay free to service d.dirty. A round asked for
// while one runs is deferred, not dropped — dropping it would break the
// epidemic relay a revocation depends on.
func (d *Daemon) inBackground(ctx context.Context, round func(context.Context)) {
	select {
	case d.syncing <- struct{}{}:
	default:
		d.mu.Lock()
		d.pushDeferred = true
		d.mu.Unlock()
		return
	}
	if !d.track() {
		<-d.syncing
		return
	}
	go func() {
		defer d.wg.Done()
		defer func() {
			<-d.syncing
			d.mu.Lock()
			deferred := d.pushDeferred
			d.pushDeferred = false
			d.mu.Unlock()
			if deferred {
				// Terminates: the round it triggers raises no signal of its
				// own unless something was genuinely new.
				d.MarkDirty()
			}
		}()
		round(ctx)
	}()
}

// track admits a goroutine to the wait set, or reports that the daemon is
// shutting down and it must not start.
func (d *Daemon) track() bool {
	d.trackMu.Lock()
	defer d.trackMu.Unlock()
	if d.closing {
		return false
	}
	d.wg.Add(1)
	return true
}

// MarkDirty asks the loop to reconcile and push. It never blocks, so it is
// safe from a gossip session or an IPC handler.
func (d *Daemon) MarkDirty() {
	select {
	case d.dirty <- struct{}{}:
	default:
	}
}

// Inform applies records an admin quorum authorized and pushes them out, so a
// change converges in a round trip rather than at the anti-entropy interval.
// The log decides whether they are authorized; this decides who hears.
func (d *Daemon) Inform(records []types.AUM) error {
	if len(records) == 0 {
		return nil
	}
	d.authMu.Lock()
	err := d.authority.Inform(records...)
	d.authMu.Unlock()
	if err != nil {
		return err
	}
	if err := d.Reconcile(); err != nil {
		d.logf("daemon: reconcile after Inform: %v", err)
	}
	d.MarkDirty()
	return nil
}

// PushFanout is how many members one push round reaches. Push is epidemic, not
// broadcast: a member that learns something new pushes in turn, so a change
// reaches everyone in O(log n) rounds rather than costing O(n²) sessions.
const PushFanout = 8

// pushAll runs one anti-entropy round with up to [PushFanout] members. It
// terminates because OnRecords fires only when something was actually new.
func (d *Daemon) pushAll(ctx context.Context) {
	peers := d.memberList()
	if len(peers) == 0 {
		return
	}
	if len(peers) > PushFanout {
		// Shuffle rather than take a prefix: a fixed slice would leave the
		// rest reachable only through whoever happened to be in it.
		rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
		peers = peers[:PushFanout]
	}
	d.gossip.Sync(ctx, peers)
}

// syncOne is the periodic backstop: anti-entropy with one member chosen at
// random, which is what makes convergence robust to a push that was dropped.
func (d *Daemon) syncOne(ctx context.Context) {
	peers := d.memberList()
	if len(peers) == 0 {
		return
	}
	pick := peers[rand.IntN(len(peers))]
	d.gossip.Sync(ctx, []types.Identity{pick})
}

// memberList returns the members to gossip with: everyone the log carries
// except this node. It reads TrustedState, so a node under a fork alarm
// gossips with nobody.
func (d *Daemon) memberList() []types.Identity {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil
	}
	now := d.now().Unix()
	// A device that is no longer a member goes quiet: members exclude it from
	// their own lists, so dialling them anyway can only read as probing.
	if self, ok := state.Node(d.self); !ok || self.Expired(now) {
		return nil
	}
	nodes := state.Nodes()
	out := make([]types.Identity, 0, len(nodes))
	for i := range nodes {
		// Excluded for the same reason they get no peer entry: expiry must
		// mean the same thing in every layer.
		if nodes[i].Identity != d.self && !nodes[i].Expired(now) {
			out = append(out, nodes[i].Identity)
		}
	}
	return out
}

// onDiscovered takes an announcement learned from the LAN, already verified by
// mdns. Caching is unconditional — one routinely arrives before the record that
// admits its subject — but waking and logging are gated on the subject being a
// member: an epoch-secret holder can mint identities without limit, and
// ungated that is a reconcile and a push per packet, mesh-wide.
func (d *Daemon) onDiscovered(e gossip.Endpoint) { d.discovered(e, "on the LAN") }

// onFoundInDHT is [Daemon.onDiscovered] for the rendezvous path. The record
// arrives verified either way; where it came from decides nothing but the log
// line, since an announcement's authority is its signature.
func (d *Daemon) onFoundInDHT(e gossip.Endpoint) { d.discovered(e, "through the DHT") }

func (d *Daemon) discovered(e gossip.Endpoint, where string) {
	if e.Identity == d.self {
		return
	}
	if !d.endpoints.Add(e) {
		return
	}
	if !d.actionableSubject(e.Identity) {
		return
	}
	d.logf("daemon: discovered %v %s at %v", e.Identity.ShortString(), where, e.Addrs)
	d.MarkDirty()
}

// overlayGossipAddrs is where a member can be reached for anti-entropy once
// its tunnel is up. Two members behind NAT can open no TCP session to each
// other on the underlay, so without this they sync only through whichever
// member both can reach.
func (d *Daemon) overlayGossipAddrs(id types.Identity) []netip.AddrPort {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil
	}
	e, held := d.endpoints.Get(id)
	if !held || e.GossipPort == 0 {
		return nil
	}
	addrs := state.Addrs(id)
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, pfx := range addrs {
		out = append(out, netip.AddrPortFrom(pfx.Addr(), e.GossipPort))
	}
	return out
}

// unheard returns the live members this node holds no announcement for: the
// only ones worth a rendezvous lookup, since asking after a member already
// known would spend privacy — a query is visible to whoever answers it — on
// nothing.
func (d *Daemon) unheard() []types.Identity {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil
	}
	now := d.now().Unix()
	nodes := state.Nodes()
	out := make([]types.Identity, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if n.Identity == d.self || n.Expired(now) {
			continue
		}
		if _, held := d.endpoints.Get(n.Identity); !held {
			out = append(out, n.Identity)
		}
	}
	return out
}

// actionableSubject reports whether an announcement's subject is one the
// reconciler could act on: a current member, or anyone before the first
// reconcile, so a node coming up alongside its peers reaches them at once.
// That window closes for good after the first reconcile.
func (d *Daemon) actionableSubject(id types.Identity) bool {
	if d.endpoints.IsMember(id) {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status.LastReconcile == 0
}

// logOnce logs a message once and suppresses repeats: the conditions it serves
// persist across reconcile rounds.
func (d *Daemon) logOnce(msg string) {
	d.mu.Lock()
	seen := d.logged[msg]
	if !seen {
		if d.logged == nil {
			d.logged = map[string]bool{}
		}
		d.logged[msg] = true
	}
	d.mu.Unlock()
	if !seen {
		d.logf("%s", msg)
	}
}

// needsPeers reports whether the log carries a member this node has no
// announcement for, which is what makes a LAN query worth sending.
func (d *Daemon) needsPeers() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Before the first reconcile there is no answer yet, and this is when the
	// node knows least.
	return d.status.LastReconcile == 0 || d.status.Unreachable > 0
}

// Status returns a snapshot of what the daemon knows about itself.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.status
	s.Addrs = append([]netip.Prefix(nil), d.status.Addrs...)
	return s
}

func (d *Daemon) setStatus(f func(*Status)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(&d.status)
}

// onConnectivityChange is called by the data plane when the relay region it
// chose, or the set of addresses it believes it is reachable at, has moved.
// Both are in this node's announcement, so it is rebuilt and pushed.
func (d *Daemon) onConnectivityChange() {
	d.mu.Lock()
	d.announced = nil
	d.mu.Unlock()
	d.MarkDirty()
}

// Endpoints exposes the announcement cache, for tests and diagnostics.
func (d *Daemon) Endpoints() *gossip.Cache { return d.endpoints }

// Manager exposes the data plane, for tests and diagnostics.
func (d *Daemon) Manager() conn.Manager { return d.manager }

// GossipPort reports the TCP port anti-entropy sessions are accepted on.
func (d *Daemon) GossipPort() uint16 { return d.gossipPort }

// Learn injects an announcement directly, for when LAN discovery is off.
func (d *Daemon) Learn(e gossip.Endpoint) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if e.Identity == d.self {
		// This node is the authority on its own announcement; a copy fed back
		// in must not shadow it.
		return nil
	}
	if d.endpoints.Add(e) {
		d.MarkDirty()
	}
	return nil
}

// Announcement returns this node's current signed endpoint record.
func (d *Daemon) Announcement() (gossip.Endpoint, bool) { return d.announcement() }

// Close shuts everything down. It is idempotent.
func (d *Daemon) Close() error {
	var err error
	d.closeOnce.Do(func() {
		d.trackMu.Lock()
		d.closing = true
		d.trackMu.Unlock()
		close(d.closed)
		if d.ipc != nil {
			d.ipc.close()
		}
		if d.dht != nil {
			d.dht.Close()
		}
		if d.beacon != nil {
			d.beacon.Close()
		}
		d.gossip.Close()
		d.closeRelay()
		err = d.manager.Close()
		d.wg.Wait()
	})
	return err
}

// --- the gossip.Log adapter ------------------------------------------------

// logAdapter presents the authority and its store as a [gossip.Log]. A
// distinct type over the same struct, so gossip can reach those three methods
// and nothing else.
type logAdapter Daemon

var _ gossip.Log = (*logAdapter)(nil)

func (a *logAdapter) daemon() *Daemon { return (*Daemon)(a) }

func (a *logAdapter) View() (gossip.View, error) {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	state := d.authority.State()
	have, err := d.storage.Hashes()
	if err != nil {
		return gossip.View{}, err
	}
	return gossip.View{
		Network: state.GenesisHash(),
		Head:    state.Head(),
		Epoch:   state.Epoch(),
		Anchor:  d.authority.Anchor(),
		Have:    have,
	}, nil
}

// Missing returns records the peer lacks and can accept, parents first. The
// walk starts at the *peer's* anchor: after a compaction a record below it is
// one the peer's log refuses, and Inform is atomic, so one refused record
// poisons the whole batch. Children are visited in hash order, so two nodes
// holding the same store offer the same batch; losing fork branches are
// included, since a peer must see a fork in full to alarm on it.
func (a *logAdapter) Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error) {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if _, err := d.storage.AUM(anchor); err != nil {
		if errors.Is(err, log.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	held := make(map[types.Hash]bool, len(have))
	for _, h := range have {
		held[h] = true
	}
	out := make([]types.AUM, 0, gossip.MaxRecordsPerFrame)
	queue := []types.Hash{anchor}
	visited := map[types.Hash]bool{anchor: true}
	for len(queue) > 0 && len(out) < gossip.MaxRecordsPerFrame {
		h := queue[0]
		queue = queue[1:]
		if !held[h] {
			aum, err := d.storage.AUM(h)
			if err != nil {
				return nil, err
			}
			out = append(out, aum)
		}
		children, err := d.storage.Children(h)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(children, compareHash)
		for _, ch := range children {
			if !visited[ch] {
				visited[ch] = true
				queue = append(queue, ch)
			}
		}
	}
	return out, nil
}

func (a *logAdapter) Inform(records []types.AUM) error {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authority.Inform(records...)
}

func compareHash(a, b types.Hash) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
