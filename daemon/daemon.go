// Package daemon is the reconciliation loop: it holds the membership log, the
// sync layer and the data plane together and keeps them agreeing.
//
// It is TCB-adjacent rather than TCB (docs/04-architecture.md's module map).
// Nothing here decides who is a member — trust/log does — but the reconciler
// is what turns that decision into a WireGuard peer set, so its default-deny
// property is in the audit scope even though the package is not: a member set
// this loop fails to shrink is a revoked device that still has access.
//
// # What runs
//
//   - The reconciler ([Daemon.Reconcile]), which renders log state into the
//     connectivity layer's peer set.
//   - Anti-entropy over gossip: a full round with every member at startup and
//     after any local change, and a periodic round with one random member,
//     which is the schedule docs/04-architecture.md sets.
//   - Blinded LAN discovery, which is how a member finds a peer's underlay
//     address with no internet and no coordination server.
//   - A unix-socket IPC server, so the CLI can ask what state the daemon is in
//     and hand it records that an admin quorum has authorized.
//
// # Ordering
//
// [log.Authority] is documented as not safe for concurrent use, and this
// package is where the concurrency is: every inbound gossip session runs on
// its own goroutine and every one of them reads or informs the log. So the
// authority and the store it was opened over sit behind one mutex, taken for
// the duration of each trust-layer call and never held across a call into the
// data plane. What the mutex hands back — a [log.State] — is immutable, so the
// reconciler can work from it after releasing.
//
// The loop on top of that is about *when*, not about safety: a change from
// gossip, from IPC, or from a tick marks the daemon dirty, and one goroutine
// reconciles and then pushes, so a burst of arriving records costs one
// reconcile rather than one each. Reconciling is local and runs on the loop;
// the push that follows is network-bound and runs beside it
// ([Daemon.inBackground]), so that a slow round cannot delay the next
// revocation the loop has to act on.
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
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Default timings.
const (
	// DefaultSyncInterval is the periodic anti-entropy round with one random
	// member, from docs/04-architecture.md ("every 2–5 min"). It is the
	// backstop, not the mechanism: a change reaches reachable members by
	// push, in the time a TCP round trip takes.
	DefaultSyncInterval = 2 * time.Minute

	// DefaultReconcileInterval re-derives the peer set even when nothing
	// arrived. It exists for the things that change without an event —
	// a membership expiring, an interface coming up — and is cheap: at this
	// scale a reconcile is a few map walks and a no-op SetPeers.
	DefaultReconcileInterval = 15 * time.Second
)

// Options configures a [Daemon].
type Options struct {
	// Authority is the open membership log. The daemon takes ownership: it
	// is not safe for concurrent use, and the daemon's loop is the only
	// thing that may touch it afterwards.
	Authority *log.Authority

	// Storage is the same store the authority was opened over. The daemon
	// reads it directly to answer "which records do I hold", which is what
	// anti-entropy exchanges.
	Storage log.Storage

	// Identity is this device's node identity key: what signs its endpoint
	// announcements. It is not an admin key and cannot authorize anything —
	// docs/04-architecture.md keeps admin keys out of the daemon entirely.
	Identity types.PrivateIdentity

	// Recipient is this device's HPKE key material, needed to open its wrap
	// of each epoch group secret.
	Recipient *secrets.PrivateKeys

	// WireGuard is this device's WireGuard static private key, as recorded
	// in the log by its public half.
	WireGuard [32]byte

	// ListenPort is the UDP port the data plane binds. Zero picks one.
	ListenPort uint16

	// Connect builds the data plane. Nil uses [conn.New]. Tests substitute a
	// factory that adds a fake TUN device.
	Connect func(conn.Options) (conn.Manager, error)

	// GossipListener accepts inbound anti-entropy sessions. Nil listens on
	// GossipPort.
	GossipListener net.Listener

	// GossipPort is the TCP port to accept sessions on when GossipListener
	// is nil. Zero picks one, which is fine because the port travels inside
	// the signed announcement rather than being a well-known number.
	GossipPort uint16

	// Discovery configures LAN discovery; the daemon fills in the keyring,
	// the announcement callback and the peer callback. Nil uses the real
	// multicast group.
	Discovery *mdns.Options

	// DisableDiscovery turns LAN discovery off, for a node whose peers are
	// configured some other way.
	DisableDiscovery bool

	// SocketPath is where the IPC socket is created. Empty disables IPC.
	SocketPath string

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
	// authMu serializes access to the authority and its store. Everything
	// that reads or changes the log takes it; nothing holds it while
	// calling into the connectivity layer.
	//
	// reconcileMu serializes whole reconciles — state read through SetPeers —
	// so that two of them cannot install their peer sets in the opposite
	// order to their state reads. It nests outside authMu and is never held
	// by anything else, so gossip sessions still never wait behind a
	// reconfiguration.
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
	ipc       *ipcServer
	endpoints *gossip.Cache
	keyring   *secrets.Keyring

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

	// syncing holds a token for as long as an anti-entropy round is running,
	// so that rounds do not overlap and the loop never blocks on one; see
	// [Daemon.inBackground]. pushDeferred, guarded by d.mu, records that a
	// round was asked for while one was running and must follow it.
	syncing chan struct{}

	// closing guards the wait set, for the reason sync.WaitGroup documents:
	// an Add that takes the counter off zero must not race a Wait, and
	// Run starting its goroutines while Close drains them is exactly that.
	closeOnce sync.Once
	closed    chan struct{}
	trackMu   sync.Mutex
	closing   bool
	wg        sync.WaitGroup

	// mu guards everything below: the local peer-ID assignment, the cached
	// announcement, and the status snapshot.
	mu      sync.Mutex
	peerIDs map[types.Identity]uint64

	// everMember records every identity this node has seen the log carry as
	// a live member, so that a cached announcement can be told apart from a
	// former member's — see [Daemon.pruneEndpoints].
	everMember map[types.Identity]bool

	// logged deduplicates the persistent-condition log lines; see
	// [Daemon.logOnce].
	logged       map[string]bool
	pushDeferred bool
	nextPeerID   uint64
	announced    *gossip.Endpoint

	// addrs caches the last interface scan; see [Daemon.underlayEndpoints].
	addrs      []netip.AddrPort
	addrsPort  uint16
	addrsUntil time.Time
	seq        uint64
	status     Status
}

// Status is what the daemon reports about itself, over IPC and to tests.
//
// Times are Unix seconds rather than time.Time: the IPC encoding is the same
// canonical CBOR discipline the rest of the project uses, and a wire format
// with one spelling per value cannot carry a type with a monotonic clock
// reading and a location attached.
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

	// Members is how many the log carries, Peers how many are installed in
	// the data plane, Unreachable how many are members this node has no
	// announcement for and therefore cannot yet configure, and Expired how
	// many have passed their expiry and are treated as former members.
	Members     int `cbor:"7,keyasint"`
	Peers       int `cbor:"8,keyasint"`
	Unreachable int `cbor:"9,keyasint"`
	Expired     int `cbor:"15,keyasint,omitempty"`

	// Conflicted is how many members were denied a peer entry because their
	// announced NAT-traversal key collides with another member's or with this
	// device's. The connectivity layer requires those keys to be distinct, and
	// dropping just the colliding members is what keeps one member's
	// announcement from costing everyone else their data plane.
	Conflicted int `cbor:"18,keyasint,omitempty"`

	// Alarm is the fork alarm's text while one is raised, and empty
	// otherwise. While it is set the data plane holds no peers at all.
	Alarm string `cbor:"10,keyasint,omitempty"`

	// EpochError is set when this node could not open its wrap of the
	// current group secret, which costs it discovery and gossip but not the
	// data plane.
	EpochError string `cbor:"11,keyasint,omitempty"`

	// NotMember is set when this device is no longer in the member set —
	// removed, or past its expiry. The daemon has torn its own data plane
	// down; whether it complies is not what keeps the network safe (peers
	// enforce membership on their side), but a device that knows it was
	// removed and keeps probing its former peers is malware behaviour, not
	// fail-closed behaviour.
	NotMember bool `cbor:"16,keyasint,omitempty"`

	// StaleKeys is set when the log names different keys for this device
	// than the ones this daemon was started with: a key rotation was applied
	// while it ran. Peers move to the new keys immediately, so tunnels and
	// the group secret both fail until the daemon is restarted over the
	// promoted key file; this is what points at that instead of letting it
	// look like a network problem.
	StaleKeys bool `cbor:"17,keyasint,omitempty"`

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

	// The state is read once here, unguarded by TrustedState, because what
	// is taken from it — the network's identity, its address space, and this
	// node's own address — is fixed at genesis and identical on every branch
	// of any fork. Everything a fork could disagree about goes through
	// Reconcile.
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
	}
	if d.logf == nil {
		d.logf = func(string, ...any) {}
	}

	wgPub, err := wgPublicOf(opts.WireGuard)
	if err != nil {
		return nil, err
	}
	d.wgPublic = wgPub

	// The disco key is fresh every start and never persisted: it is
	// connectivity material, not identity, and a peer seeing a new one is
	// supposed to read it as "that node restarted" (see conn's peerDelta).
	// It reaches peers inside this node's signed announcement.
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
		Logf:       d.logf,
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
		Self:      self,
		Log:       (*logAdapter)(d),
		Keyring:   d.keyring,
		Endpoints: d.endpoints,
		Announce:  d.announcement,
		Listener:  ln,
		OnRecords: d.MarkDirty,
		Logf:      d.logf,
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
		d.beacon, err = mdns.New(mopts)
		if err != nil {
			d.gossip.Close()
			mgr.Close()
			return nil, err
		}
	}

	if opts.SocketPath != "" {
		d.ipc, err = newIPCServer(d, opts.SocketPath)
		if err != nil {
			if d.beacon != nil {
				d.beacon.Close()
			}
			d.gossip.Close()
			mgr.Close()
			return nil, err
		}
	}

	d.setStatus(func(s *Status) {
		s.Self = self
		s.Addrs = state.Addrs(self)
		// The network's identity is fixed at genesis, so it is known the
		// moment the log is opened — before the first reconcile. Without
		// this, a status read between construction and the first reconcile
		// (the daemon's own startup banner does exactly that) names no
		// network at all.
		s.Network = state.GenesisHash()
		s.NetworkName = state.Network()
		s.ListenPort = mgr.LocalPort()
		s.GossipPort = d.gossipPort
	})
	return d, nil
}

// wgPublicOf derives the public half of a WireGuard static key, in the form
// the log records it. Used once at start, and to notice a rotation applied
// while the daemon runs.
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

	// Recover the recent past epochs before the first session runs: a node
	// that speaks only its newest epoch cannot reach a peer that is behind,
	// and cannot be reached by one. See [Daemon.backfillEpochs].
	d.backfillEpochs()

	// Reconcile before anything else, so the data plane reflects the log
	// from the first instant rather than from the first tick.
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
// one at a time.
//
// The rounds are network-bound and the loop must not be. A peer that accepts a
// connection and then says nothing costs a full [gossip.DefaultTimeout], and a
// peer with several announced addresses is tried at each in turn — so a round
// can take tens of seconds against an unreachable member. Doing that inline
// would stop the loop servicing d.dirty, which is how an arriving revocation
// reaches the reconciler: the revoked device would keep its WireGuard entry
// until the round finished, far past the five-second budget
// docs/05-roadmap.md sets. The expiry backstop on reconcileTick would stall
// with it.
//
// A round that arrives while one is running is deferred, not dropped. The two
// would carry the same state, so running them concurrently buys nothing — but
// discarding the request outright would break the property the push exists
// for: epidemic propagation depends on a node that learns something new
// telling others in turn, and a revocation that arrives mid-round would then
// be reconciled locally and never relayed, converging at the anti-entropy
// timer instead of in the five seconds docs/05-roadmap.md budgets. So the
// request is remembered and the daemon is marked dirty again when the round
// ends, which sends the loop straight back here.
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
				// Terminates: the flag is only set by a request this round
				// displaced, and the round it triggers raises no signal of
				// its own unless something was genuinely new.
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

// Inform applies records an admin quorum authorized and pushes them out.
//
// This is what makes a change converge in the time a round trip takes rather
// than at the anti-entropy interval, which is what docs/05-roadmap.md's
// five-second revocation budget needs. The log decides whether the records are
// authorized; this only decides who hears about them.
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

// PushFanout is how many members one push round reaches.
//
// Epidemic push, not broadcast: a member that learns something new pushes in
// turn, because gossip's OnRecords marks the daemon dirty, so a change reaches
// everyone in O(log n) rounds without any single node talking to everyone.
// Broadcasting instead would make one change cost O(n²) sessions across the
// network — invisible at the two to five nodes M2 targets and not at the
// twenty-five to a hundred docs/01-requirements.md does.
//
// Eight is above the target scale, so at M2 sizes a push still reaches
// everyone in one round and the convergence measurements are unaffected.
const PushFanout = 8

// pushAll runs one anti-entropy round with up to [PushFanout] members.
//
// It terminates because a round that teaches nobody anything raises no further
// signal: OnRecords fires only when records or announcements were actually
// new.
func (d *Daemon) pushAll(ctx context.Context) {
	peers := d.memberList()
	if len(peers) == 0 {
		return
	}
	if len(peers) > PushFanout {
		// Shuffle rather than take a prefix: a fixed slice of the member set
		// would leave the rest reachable only through whoever happened to be
		// in it, which is a partition waiting for one of them to be offline.
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
// except this node.
//
// It comes from TrustedState, so a node under a fork alarm gossips with
// nobody. That is the same fail-closed direction the reconciler takes, applied
// to the sync layer: a node that cannot tell who is a member should not be
// handing out its log either.
func (d *Daemon) memberList() []types.Identity {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil
	}
	now := d.now().Unix()
	// A device that is no longer a member goes quiet. Members will not talk
	// to it — their own member lists exclude it — so dialling them anyway is
	// traffic that can only be read as probing. It learned of its removal;
	// the honest next step is re-enrollment, not persistence.
	if self, ok := state.Node(d.self); !ok || self.Expired(now) {
		return nil
	}
	nodes := state.Nodes()
	out := make([]types.Identity, 0, len(nodes))
	for i := range nodes {
		// Expired memberships are excluded for the same reason they get no
		// peer entry: the backstop has to mean the same thing in every layer
		// or it does not mean anything.
		if nodes[i].Identity != d.self && !nodes[i].Expired(now) {
			out = append(out, nodes[i].Identity)
		}
	}
	return out
}

// onDiscovered takes an announcement learned from the LAN.
//
// It is verified before it gets here — mdns decodes through
// [gossip.DecodeEndpoint] — so all that is left is to cache it and, if it is
// worth acting on, wake the loop: a member whose address just became known is a
// peer that can now be configured and gossiped with.
//
// Caching is unconditional, which is the early-join contract [gossip.Cache]
// documents: an announcement routinely arrives before the record that admits
// its subject, and must be waiting when it does. Waking and logging are not.
// The reconciler joins announcements onto the log's member set and ignores
// every subject the log does not carry, so a rising-Seq announcement for an
// invented non-member is inert there — and an epoch-secret holder (a member, or
// a revoked device inside the keyring window) can mint identities without limit
// and sign a fresh, higher Seq for each, which the cache accepts on every
// packet. Left ungated, each such packet drove a full reconcile, an eight-way
// gossip round, and a log line, mesh-wide and for as long as the sender kept
// transmitting: churn and unbounded log growth from one LAN attacker, which
// docs/09-mesh-layer-notes.md's "costs metadata and nothing else" promise for
// that window does not allow. A member's own record admits it over gossip, and
// that arrival — not its beacon — is the wake that installs it.
func (d *Daemon) onDiscovered(e gossip.Endpoint) {
	if e.Identity == d.self {
		return
	}
	if !d.endpoints.Add(e) {
		return
	}
	if !d.actionableSubject(e.Identity) {
		return
	}
	d.logf("daemon: discovered %v on the LAN at %v", e.Identity.ShortString(), e.Addrs)
	d.MarkDirty()
}

// actionableSubject reports whether an announcement's subject is one the
// reconciler could do anything with: a current member, or — before the first
// reconcile has established who the members are — anyone, so that a node coming
// up alongside its peers still reaches them at the ~20 ms the mesh test
// measures rather than waiting for a record it may already hold. The initial
// window closes for good after the first reconcile, so it is not a way in.
func (d *Daemon) actionableSubject(id types.Identity) bool {
	if d.endpoints.IsMember(id) {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status.LastReconcile == 0
}

// logOnce logs a message the first time it is seen and suppresses repeats.
// The conditions it serves persist across reconcile rounds, and a line per
// round buries the log it is supposed to be read in.
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
	// Before the first reconcile there is no answer yet, and asking is the
	// right default: that is exactly when this node knows least.
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

// Endpoints exposes the announcement cache, for tests and diagnostics.
func (d *Daemon) Endpoints() *gossip.Cache { return d.endpoints }

// Manager exposes the data plane, for tests and diagnostics.
func (d *Daemon) Manager() conn.Manager { return d.manager }

// GossipPort reports the TCP port anti-entropy sessions are accepted on.
func (d *Daemon) GossipPort() uint16 { return d.gossipPort }

// Learn injects an announcement directly, bypassing discovery. It is how a
// node is told where a peer is when LAN discovery is off — the configured-
// bootstrap case, and how tests wire a mesh without multicast.
func (d *Daemon) Learn(e gossip.Endpoint) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if e.Identity == d.self {
		// This node is the authority on its own announcement; a copy fed
		// back in must not shadow it. Same rule as [Daemon.onDiscovered].
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
		if d.beacon != nil {
			d.beacon.Close()
		}
		d.gossip.Close()
		err = d.manager.Close()
		d.wg.Wait()
	})
	return err
}

// --- the gossip.Log adapter ------------------------------------------------

// logAdapter presents the authority and its store as a [gossip.Log].
//
// It is a distinct type over the same struct so that the three methods gossip
// may call are exactly the three that exist, rather than gossip holding a
// *Daemon and being able to reach everything.
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

// Missing returns records the peer lacks and can accept, parents first.
//
// The walk starts at the *peer's* anchor, not ours, and that is the point.
// After a compaction the two sides hold different slices of history: a record
// below the peer's anchor is one its log will refuse, and because Inform is
// atomic, a single refused record poisons every acceptable one in the same
// batch. Walking the peer's anchor sends exactly what it can take. A peer
// whose anchor we do not hold gets nothing — either it has more history than
// we do, in which case the other half of this same session is where it sends
// us ours, or it is on a chain we have never seen, which no batch fixes.
//
// Breadth-first over [log.Storage.Children] — the store's own index — so a
// session reads only the records it actually sends, and children are visited
// in hash order so that two nodes holding the same store offer the same batch.
// Branches that lost fork choice are descendants like any other and are
// included: a fork is something the peer must see in full before it can alarm
// on it.
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
