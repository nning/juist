// Package daemon holds the membership log, the sync layer and the data plane
// together: it renders log state into a WireGuard peer set, runs anti-entropy
// and blinded LAN discovery, and serves the CLI over a unix socket.
//
// [log.Authority] is not safe for concurrent use and every gossip session
// touches it, so the authority and its store sit behind one mutex, never held
// across a call into the data plane.
package daemon

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/types/key"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/internal/firewalld"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/netstack"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Default ports, fixed so a firewall rule can name them. Each falls back to
// one the OS chooses where another program holds it (see
// [Options.PortFallback]); 41641 is Tailscale's, which a host may run too.
const (
	DefaultListenPort = 41643 // UDP, the data plane
	DefaultGossipPort = 41644 // TCP, log sync
	DefaultRelayPort  = 41645 // TCP DERP and UDP STUN, on relay-capable members
)

const (
	// DefaultSyncInterval is the periodic anti-entropy round with one random
	// member. It is the backstop; a change reaches reachable members by push.
	DefaultSyncInterval = 2 * time.Minute

	// DefaultReconcileInterval re-derives the peer set where neither an
	// event nor a deadline the log names, such as a membership expiring,
	// has in the meantime: a backstop for what changes unannounced.
	DefaultReconcileInterval = 2 * time.Minute

	// DefaultReachDelay leaves paths time to come up before the first check,
	// which would otherwise report every peer as not answering.
	DefaultReachDelay = 10 * time.Second
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
	// CAP_NET_ADMIN on Linux, or Plumber. Empty means no host device.
	TunName string
	// Plumber creates it and routes it where juistd may not, as on FreeBSD.
	Plumber conn.Plumber

	// Instance numbers this node among the juist nodes on the host, one per
	// network: 0 for the default, up to instance.Max. It chooses the routing
	// table and policy rules the device's routes live in; see
	// conn.Options.Instance.
	Instance int

	// HostHoldings lists what the host's other instances hold; see
	// [conn.InstanceHoldings], which the service uses where the node has a
	// TUN device and this is nil.
	HostHoldings func(self int, own string) ([]conn.Holding, error)

	// LowerStatus asks instance n on the host for its status, which says
	// what its network claims, where it answers; the service asks the
	// sockets beside its own where this is nil. An instance that does not
	// answer is read from HostHoldings instead.
	LowerStatus func(ctx context.Context, n int) (*ipc.Status, error)

	// LowerHome is where instance n on the host keeps its state, which says
	// whether it holds a network while it does not answer; the service
	// derives it from its own home where this is nil.
	LowerHome func(n int) string

	// NoV4 runs the mesh on IPv6 alone: no IPv4 address on this device and
	// none of the members' in the data plane, so none is routed or accepted.
	// The service sets it while a lower instance on the host holds IPv4 this
	// network claims, which the host routes into that instance's network;
	// log sync goes on over IPv6, so a renumbering that ends the conflict
	// still arrives.
	NoV4 bool

	// RelayPort is the TCP port this device's relay serves DERP on, and the
	// UDP port it answers STUN on. Zero picks one; the port travels in the
	// signed announcement either way.
	RelayPort uint16

	// STUN are public STUN servers the data plane may ask for this device's
	// reflexive address; see conn.Options.STUN. Empty asks nobody outside
	// the network, which leaves members behind NAT unable to reach each
	// other without a member relay.
	STUN []string

	// PortFallback lets a port above that another program holds become one
	// the OS chooses, for defaults rather than ports an operator asked for.
	// The ports travel in the signed announcement either way.
	PortFallback bool

	// DisableRelay keeps this device from relaying even where the log grants
	// it the role: the operator's veto over their own machine's bandwidth.
	DisableRelay bool

	// RelayNameByRole is the part of [Prefs.RelayName] the ingress role
	// gave, "" where it is set or the role gives none.
	RelayNameByRole string

	// ACMEDirectory is the CA the relay's name, [Prefs.RelayName], has its
	// certificate from, kept in RelayCertsPath, in memory where empty.
	// ListenHTTPS binds 443 at an address, which needs
	// CAP_NET_BIND_SERVICE or root; nil binds it directly.
	ACMEDirectory  string
	RelayCertsPath string
	ListenHTTPS    func(netip.Addr) (net.Listener, error)

	// HandOffSocket is the Unix socket the ingress here hands the relay's
	// name on at, which the process of IngressUID alone may connect to;
	// "" hands nothing on.
	HandOffSocket string
	IngressUID    uint32

	// Connect builds the data plane. Nil uses [conn.New].
	Connect func(conn.Options) (conn.Manager, error)

	// GossipDial opens outbound log sync sessions. Nil dials TCP; tests
	// replace it to cut a device off as a dropped tunnel would.
	GossipDial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

	// GossipListener accepts inbound anti-entropy sessions. Nil listens on
	// GossipPort.
	GossipListener net.Listener

	// GossipPort is the TCP port to accept sessions on when GossipListener is
	// nil. Zero picks one: the port travels in the signed announcement.
	GossipPort uint16

	// Netstack runs the overlay on a network stack in this process instead
	// of a device of the host's: what reaches the overlay addresses reaches
	// this process alone, which listens there and dials from there. For a
	// service member, which needs no TUN, root or capability.
	Netstack bool

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

	// EndpointCachePath is where last-known peer addresses are persisted, so
	// a restarted device knows where its peers were before it hears from
	// anyone. Empty keeps the cache in memory only.
	EndpointCachePath string

	// PairsPath is where the preshared keys this node holds with its peers
	// are kept across restarts; empty keeps them in memory alone.
	PairsPath string

	// KeyringPath is where the epoch secrets this node holds are kept across
	// a restart. Empty keeps them in memory only.
	KeyringPath string

	// LeasePath is where freshness leases are persisted. Empty keeps them in
	// memory only, so a restart starts stale until an admin device vouches.
	LeasePath string

	// WaitingPath is where the changes waiting for votes this node holds are
	// kept across a restart. Empty keeps them in memory only.
	WaitingPath string

	// Moved is sent to, without waiting, when the log gives this device other
	// overlay addresses than the data plane holds or names other keys than
	// the mesh runs on, each once until the mesh follows, and when the
	// chosen exit node rotated its identity. Give it a buffer.
	Moved chan<- struct{}

	// Prefs are the device's settings; [Daemon.SetPrefs] and
	// [Daemon.SetExitChoice] change them.
	Prefs

	// EgressUser says why juistd's user may use no exit node, "" where it
	// may; nil asks the host, once, of the user juistd runs as.
	EgressUser func() string

	// HostDNS routes the host's DNS through the exit node in use, and
	// ServeDNS answers members' DNS on an exit node: systemd-resolved and
	// [dnsfwd] on TunName where nil, and nothing without it.
	HostDNS  HostDNS
	ServeDNS DNSServer
	// ServeNames answers the host's DNS for the network's names at
	// NamesAddr, an address the device holds on [NamesPort] where zero, on
	// 53 where the host asks juistd alone: [dnsfwd] with a TUN device, and
	// nothing without one. ListenDNS binds 53 where juistd may not.
	ServeNames NamesServer
	NamesAddr  netip.AddrPort
	ListenDNS  func(netip.AddrPort) (net.PacketConn, net.Listener, error)
	// ResolvConf is what the host's programs read their resolvers from,
	// /etc/resolv.conf where empty; it must name resolved's stub for
	// resolved's routing to be theirs.
	ResolvConf string
	// StrictRP6 reports whether the host drops an exit node's IPv6 answers
	// by a strict reverse-path filter: firewalld's ruleset on TunName where
	// nil, and never without it.
	StrictRP6 func() bool

	// FreshnessTTL is how long this node acts on its view of the network
	// after an admin device last vouched for it. Zero uses
	// [DefaultFreshnessTTL].
	FreshnessTTL time.Duration

	// TerminatorWanted, where set, is a file kept while this device needs
	// its terminator, for systemd to start it by, which is then told when
	// it may stop.
	TerminatorWanted string

	// IngressPorts, where set, is a file kept listing the public TCP ports
	// an ingress here takes, for the host's firewall to follow.
	IngressPorts string

	// LeaseInterval is how often this node vouches, if it is an admin
	// device. Zero uses [DefaultLeaseInterval].
	LeaseInterval time.Duration

	// SyncInterval and ReconcileInterval override the defaults above; a
	// reconcile waits a second at least.
	SyncInterval      time.Duration
	ReconcileInterval time.Duration

	// Pace, where set, slows the mesh while it saves battery; it outlives a
	// restart of the mesh.
	Pace *Pace

	// Rests says this device saves battery whenever it can, as a phone does:
	// its announcement says so, where the network's schema has the field,
	// and it joins the public DHT only while no member that does not rest
	// answers it.
	Rests bool

	// ReachDelay is how long after start the tunnels are first checked. Zero
	// uses [DefaultReachDelay].
	ReachDelay time.Duration

	// Clock overrides time.Now, for tests.
	Clock func() time.Time

	// Session is the NAT-traversal key and relay certificate to announce.
	// Nil draws a fresh one; see [Session] for when to pass one again.
	Session *Session

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// A Daemon is one member's running node.
//
// Each field sits under the lock that guards it; those above the first lock
// are set by [New] and not changed after. Locks are taken in this order, and
// none is held across a call into the data plane but reconcileMu, selfMu and
// dns.mu, the last also across the host's resolver (D-Bus) and the DNS
// server's Close, which gossip never waits on and which waits for its
// queries, so a query takes no lock held across D-Bus:
//
//	Service.mu → selfMu → reconcileMu,  selfMu → dns.mu,  selfMu → mu
//	Service.mu → reconcileMu → authMu,  Service.mu → mu → waits' own
//	Service.mu → changes.mu,  reconcileMu → mu,  reconcileMu → changes.saveMu → changes.mu
//	reconcileMu → dns.mu → mu,  dns.mu → sole.mu,  reconcileMu → pub.mu → mu
//	dns.mu → hostRouting.mu → mu
//	probes.mu → mu,  leases.saveMu → leases.mu,  keyringSaveMu → the keyring's own
//	a relay server's lock → mu: its admission callbacks take mu, so mu is
//	never held across a call into the relay
//
// pairs.mu and sole.mu are innermost: nothing is taken under them.
//
// authMu, mu, leases.mu and changes.mu are never held together, and the function
// passed to setStatus runs under mu, so it must take no lock of the daemon's.
type Daemon struct {
	self     types.Identity
	identity types.PrivateIdentity
	own      atomic.Pointer[ownKeys]
	ula      netip.Prefix

	manager   conn.Manager
	gossip    *gossip.Node
	beacon    *mdns.Beacon
	dht       *dht.Node
	endpoints *gossip.Cache
	keyring   *keyring.Keyring

	relayPort    uint16
	portFallback bool
	noRelay      bool

	// httpsOnly, proxy, relayName and the rest are [Options.HTTPSOnly] and
	// its neighbours; relayCerts is nil without a relay name.
	httpsOnly   bool
	proxy       string
	envProxy    func(*url.URL) (*url.URL, error)
	relayName   string
	relayCerts  certSource
	listenHTTPS func(netip.Addr) (net.Listener, error)
	handOffPath string
	ingressUID  uint32
	rvKeys      rendezvousKeys
	nameProofs  relayNameProofs
	whoamiHTTP  *http.Client
	askWhoami   func(context.Context, string) ([32]byte, error)
	noV4        atomic.Bool
	cachePath   string
	moved       chan<- struct{}
	movedSaid   atomic.Bool // a move was said since the mesh last followed one
	// relayNameSaid is whether the relay's name was said to have moved.
	relayNameSaid atomic.Bool
	// announcedWalls is whether the last announcement said this device is
	// walled, by announcing no address. Guarded by mu.
	announcedWalls bool
	keysSaid       atomic.Bool // a rotation was said since the mesh last followed one
	keyringPath    string
	// terminatorWanted is [Options.TerminatorWanted], ingressPorts
	// [Options.IngressPorts].
	terminatorWanted, ingressPorts string

	// relayNameByRole is [Options.RelayNameByRole].
	relayNameByRole string

	session      *Session
	discoPrivate [32]byte
	discoPublic  gossip.DiscoKey
	gossipPort   uint16
	overlayOnly  bool          // log sync through the tunnel alone
	handedOn     types.Hash    // the disable record handOnDisable gave members
	stack        *netstack.Net // the overlay's network stack, nil on a device
	tunName      string
	gossipLn     net.Listener

	// selfMu serializes changes to the data plane's Self, connSelf, whose
	// addresses held follows.
	selfMu   sync.Mutex
	connSelf conn.Self
	held     atomic.Pointer[[]netip.Prefix]

	// pairs are the preshared keys this node holds with its peers; psks
	// what each installed peer was last given, under mu.
	pairs      *pairStore
	psks       map[types.Identity]pskGiven
	pairWanted map[types.Identity]bool // peers an exchange waits on, under mu

	// signingKeys are the members' signing keys the announcement cache holds
	// them to, under mu.
	signingKeys map[types.Identity]types.SigningKey

	// kept are the epoch secrets read from the keyring file at start, before
	// anything could overwrite it: those whose wraps this node can no longer
	// open, after a rotation of its own keys.
	kept map[uint64]secrets.Secret

	pace           *Pace
	saving         savingPace
	rests          bool
	reconcileDue   atomic.Pointer[time.Time] // see [Daemon.noteDue]
	reconcileArmed atomic.Pointer[time.Time] // when the loop's timer fires
	restingSynced  time.Time                 // see [Daemon.syncOne]; guarded by mu
	addrsWaiting   atomic.Bool               // see [Daemon.onConnectivityChange]
	pushRests      atomic.Bool               // the next push reaches members that rest too
	wired          atomic.Bool               // New is done, which the data plane's callbacks may precede
	syncEvery      time.Duration
	reachEvery     time.Duration
	reachDelay     time.Duration
	pathSettle     time.Duration
	firewalled     func(ctx context.Context, iface string, port uint16) (blocked, unsure bool)
	reconcileEvery time.Duration
	ttl            time.Duration
	leaseEvery     time.Duration
	greetAfter     []time.Duration
	clock          func() time.Time
	logf           func(string, ...any)

	// dirty coalesces "something changed, reconcile and push", soon
	// "reconcile", and recheck "check the tunnels soon". Buffered to one: a
	// second signal arriving before the loop wakes is the same work.
	dirty   chan struct{}
	soon    chan struct{}
	rearm   chan struct{} // a deadline sooner than the loop's timer
	recheck chan struct{}

	// syncing holds a token while an anti-entropy round runs, so rounds do not
	// overlap; pushDeferred, under mu, records one asked for meanwhile.
	syncing chan struct{}

	// ctx ends at Close; Run's ends with it too.
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	waits     waitSet

	// reconcileMu serializes whole reconciles — state read through SetPeers —
	// so two cannot install their peer sets in the opposite order to their
	// state reads.
	reconcileMu sync.Mutex

	// authMu guards the authority and its store.
	authMu     sync.Mutex
	authority  *log.Authority
	storage    log.Storage
	compacting compaction

	probes probeState

	leases leaseStore

	// keyringSaveMu serializes writing the keyring out.
	keyringSaveMu sync.Mutex

	changes waitStore

	mu sync.Mutex

	// v4 is the network's overlay IPv4 ranges in use.
	v4 []netip.Prefix

	// peerIDs are the local handles the data plane knows members by.
	peerIDs    map[types.WGKey]uint64
	nextPeerID uint64

	// installed is the peer set last installed in the data plane, by name,
	// and lastPeers that set as installed, routes and access included.
	installed     []namedPeer
	lastPeers     []conn.Peer
	lastIngresses map[key.NodePublic]bool

	// gossipTo is the members log sync may reach, where a policy restricts
	// them; nil for every member.
	gossipTo func(types.Identity) bool

	// sealing is this device's address key, where it seals its addresses,
	// and opened the keys of members' it unwrapped, newest last.
	sealing *sealing
	opened  map[types.Identity][]addrkey.Key

	down        map[types.Identity]*downPeer       // installed members found down
	unheardPlan map[types.Identity]*lookupPlan     // members with no announcement held
	asidePlan   map[types.Identity]*lookupPlan     // members a stale node keeps no tunnel to
	probeNow    map[types.Identity]bool            // members to probe past their backoff
	doubtedOn   map[types.Identity]gossip.DiscoKey // the hint's disco key each doubted member was checked for
	syncRetried map[types.Identity]time.Time       // when a failing sync was last retried
	behind      map[types.Identity]time.Time       // since when live members have announced no epoch, or running ones without a tunnel an older build
	olderBuild  map[types.Identity]time.Time       // since when live members have announced an older schema

	// moving follows a renumbering while one is under way.
	moving *renumbering

	// peerBeacons is what each member's last hello said of its log, and
	// behindSince since when peers answer only from beyond it.
	peerBeacons map[types.Identity]peerBeacon
	behindSince time.Time

	// everMember records every identity seen as a live member, so a cached
	// announcement can be told from a former member's.
	everMember map[types.Identity]bool

	// logged deduplicates the persistent-condition log lines; see
	// [Daemon.logOnce].
	logged       map[string]bool
	pushDeferred bool
	deferredFull bool // a deferred round would have reached members that rest

	// exitChoice and serveConsent are the owner's and the operator's word on
	// exit nodes, servingExit whether this device serves as one now, and
	// exitStatus what the last reconcile made of them.
	exitChoice ExitChoice
	// successorMiss is the identity and head a rotation was last looked
	// for in vain.
	successorMiss struct {
		id   types.Identity
		head types.Hash
	}
	userEgress   string      // why this user may use no exit node, "" where it may
	strictRP6    func() bool // [Options.StrictRP6], nil for never
	serveConsent bool
	servingExit  bool
	exitStatus   ipc.Exit
	// subnetConsent and subnetsOff are the operator's and the owner's word
	// on subnet routes, servingSubnets whether this device routes its own
	// now, and subnetStatus what the last reconcile made of them.
	subnetConsent  bool
	subnetsOff     bool
	servingSubnets bool
	// servingPublished is whether this device serves what is published on
	// it, which its announcement says.
	servingPublished bool
	subnetStatus     ipc.Subnets
	acceptNames      bool // [Options.AcceptNames]
	pub              publishing
	// dnsPort is the port this device answers members' DNS on, zero for
	// none, which its announcement says.
	dnsPort uint16
	// announcedNoV4 is whether the announcement says this device has no
	// IPv4: only where the log routes through it.
	announcedNoV4 bool

	hostDNS    HostDNS
	startDNS   DNSServer
	resolvConf string
	dns        dnsState

	startNames  NamesServer
	namesFixed  netip.AddrPort // [Options.NamesAddr]
	reachable   atomic.Pointer[map[types.Identity]bool]
	zone        atomic.Pointer[names.Zone]
	namesExit   atomic.Pointer[[]netip.AddrPort] // the exit node's resolvers, which names asks
	namesRouted atomic.Bool                      // whether the host's resolver asks names

	dnsOff      atomic.Bool // [Options.DNSOff]
	sole        soleState
	hostRouting hostRoutingState

	announced   *gossip.Endpoint // nil when it is to be rebuilt
	signed      *gossip.Endpoint // the last one signed, which announced renews
	announcedAt time.Time
	seq         uint64

	// cachedEndpoints is the last encoding written to the endpoint cache, so
	// an unchanged set does not rewrite the file on every reconcile.
	cachedEndpoints []byte
	cachedList      []gossip.Endpoint
	cachedKeys      []gossip.AddrKey
	cachedAt        time.Time

	// namedRelays are the relays installed that serve a name on 443.
	namedRelays []conn.Relay
	relays      []conn.Relay // every relay installed, asked for announcements before the DHT
	ownRelay    relayState

	// addrs caches the last interface scan; see [Daemon.underlayEndpoints].
	addrs      []netip.AddrPort
	internal   []netip.Addr
	addrsPort  uint16
	addrsUntil time.Time

	status ipc.Status

	// reachGen counts teardowns, so a tunnel check that began before one
	// does not publish what it found.
	reachGen uint64

	// askingFirewall is set while [Daemon.recheckFirewall] waits for an
	// answer.
	askingFirewall bool
}

// ErrNotMember is returned by [New] for a device the log does not list:
// removed, or never admitted.
var ErrNotMember = errors.New("this device is not a member")

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
		return nil, fmt.Errorf("daemon: %v is not a member of network %q: %w",
			self.ShortString(), state.Network(), ErrNotMember)
	}

	d := &Daemon{
		authority:      opts.Authority,
		storage:        opts.Storage,
		identity:       opts.Identity,
		self:           self,
		ula:            state.ULA(),
		endpoints:      gossip.NewCache(),
		keyring:        keyring.New(),
		pace:           opts.Pace,
		rests:          opts.Rests,
		saving:         savingPace{reach: savingReachEvery, sync: savingSyncEvery, reconcile: savingReconcileEvery},
		syncEvery:      cmp.Or(opts.SyncInterval, DefaultSyncInterval),
		reachEvery:     reachEvery,
		greetAfter:     defaultGreetAfter,
		reachDelay:     cmp.Or(opts.ReachDelay, DefaultReachDelay),
		pathSettle:     pathSettle,
		firewalled:     firewalld.Blocks,
		reconcileEvery: cmp.Or(opts.ReconcileInterval, DefaultReconcileInterval),
		clock:          opts.Clock,
		logf:           opts.Logf,
		dirty:          make(chan struct{}, 1),
		soon:           make(chan struct{}, 1),
		rearm:          make(chan struct{}, 1),
		recheck:        make(chan struct{}, 1),
		syncing:        make(chan struct{}, 1),
		peerIDs:        map[types.WGKey]uint64{},
		everMember:     map[types.Identity]bool{},
		peerBeacons:    map[types.Identity]peerBeacon{},
		cachePath:      opts.EndpointCachePath,
		relayPort:      opts.RelayPort,
		portFallback:   opts.PortFallback,
		noRelay:        opts.DisableRelay,
		httpsOnly:      opts.HTTPSOnly,
		proxy:          opts.Proxy,
		envProxy:       envProxyFunc(),
		relayName:      opts.RelayName,
		listenHTTPS:    opts.ListenHTTPS,
		handOffPath:    opts.HandOffSocket,
		ingressUID:     opts.IngressUID,
		ownRelay: relayState{
			https443: map[netip.Addr]net.Listener{},
			members:  map[types.WGKey]bool{},
			hosts:    map[types.Identity]bool{},
		},
		leases:           newLeaseStore(opts.LeasePath),
		moved:            opts.Moved,
		exitChoice:       opts.Exit,
		serveConsent:     opts.ServeExit,
		subnetConsent:    opts.ServeSubnets,
		subnetsOff:       opts.SubnetsOff,
		acceptNames:      opts.AcceptNames,
		userEgress:       egressUserOf(opts.EgressUser),
		changes:          waitStore{path: opts.WaitingPath, held: map[types.Hash]heldChange{}},
		keyringPath:      opts.KeyringPath,
		terminatorWanted: opts.TerminatorWanted,
		ingressPorts:     opts.IngressPorts,
		ttl:              cmp.Or(opts.FreshnessTTL, DefaultFreshnessTTL),
		leaseEvery:       cmp.Or(opts.LeaseInterval, DefaultLeaseInterval),
	}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.noV4.Store(opts.NoV4)
	d.endpoints.SetClock(d.now)
	d.pub.consent, d.pub.to, d.pub.members = opts.ServePublished, maps.Clone(opts.ServeTo), maps.Clone(opts.ServeMembers)
	if d.listenHTTPS == nil {
		d.listenHTTPS = defaultListenHTTPS
	}
	d.nameProofs.wanted = make(chan struct{}, 1)
	d.whoamiHTTP = d.whoamiClient()
	d.askWhoami = d.defaultAskWhoami
	// The addresses are those of this moment: past a renumbering's deadline
	// they change, and the service restarts the mesh on them.
	now := d.now().Unix()
	selfAddrs := d.overlayAddrs(state, self, now)
	d.v4 = state.V4RangesAt(now)
	d.kept = d.loadKeyring()
	d.pairs = loadPairStore(opts.PairsPath, d.logf)
	if d.logf == nil {
		d.logf = func(string, ...any) {}
	}
	d.pub.mu.Lock()
	d.flagTerminatorLocked()
	d.pub.mu.Unlock()

	wgPub, err := wgPublicOf(opts.WireGuard)
	if err != nil {
		return nil, err
	}
	d.own.Store(&ownKeys{recipient: opts.Recipient, wg: wgPub})

	// Never persisted: it is connectivity material, and a peer seeing a new
	// one is meant to read it as a restart of the process.
	d.session = opts.Session
	if d.session == nil {
		if d.session, err = NewSession(); err != nil {
			return nil, err
		}
	}
	d.discoPrivate, d.discoPublic = d.session.discoPrivate, d.session.discoPublic

	var undo cleanup
	defer undo.run()

	if opts.HTTPSOnly && opts.TunName == "" && !opts.Netstack {
		return nil, errors.New("daemon: HTTPS alone needs a device or the netstack, since log sync runs in the tunnel")
	}
	d.relayNameByRole = opts.RelayNameByRole
	if opts.RelayName != "" {
		if d.relayCerts, err = newRelayCertificates(opts.RelayName, opts.ACMEDirectory, opts.RelayCertsPath, &d.waits); err != nil {
			return nil, fmt.Errorf("daemon: the relay's certificates: %w", err)
		}
	}

	connect := opts.Connect
	if connect == nil {
		connect = conn.New
	}
	if opts.Netstack {
		connect = d.onNetstack(connect)
	}
	connOpts := conn.Options{
		Self: conn.Self{
			ID:       d.peerID(wgPub),
			NodeKey:  conn.NodeKeyFromRaw32(opts.WireGuard),
			DiscoKey: conn.DiscoKeyFromRaw32(d.discoPrivate),
			Addrs:    selfAddrs,
		},
		TunName:   opts.TunName,
		Plumber:   opts.Plumber,
		Instance:  opts.Instance,
		STUN:      opts.STUN,
		HTTPSOnly: opts.HTTPSOnly,
		Proxy:     d.proxyFor,
		Logf:      d.logf,
		// The home relay and the reflexive addresses both belong in this
		// node's announcement, and both are learned asynchronously once
		// there is a relay to learn them from.
		OnConnectivityChange: d.onConnectivityChange,
		OnInterfacesChange:   d.interfacesChanged,
		// A subnet a route of the host's now holds is given back at once.
		OnHostRoutesChange: d.MarkDirty,
	}
	mgr, err := onPortOrAny(d, opts.ListenPort, conn.ErrPortTaken, "UDP", func(port uint16) (conn.Manager, error) {
		o := connOpts
		o.ListenPort = port
		return connect(o)
	})
	if err != nil {
		return nil, fmt.Errorf("daemon: starting the data plane: %w", err)
	}
	d.manager, d.connSelf = mgr, connOpts.Self
	undo.push(func() { mgr.Close() })

	// With a TUN device, log sync runs through the tunnel alone: the port is
	// bound to the overlay addresses and reachable from no other network.
	// Without one there is no overlay to bind, as in tests and the one-machine
	// demo, and it listens on the underlay.
	d.overlayOnly, d.tunName = opts.TunName != "" || opts.Netstack, opts.TunName
	d.hostDNS, d.startDNS, d.resolvConf = opts.HostDNS, opts.ServeDNS, opts.ResolvConf
	d.strictRP6 = opts.StrictRP6
	if opts.Plumber != nil && d.hostDNS == nil {
		d.hostDNS = resolvconfDNS{plumbedDNS{p: opts.Plumber, dev: opts.TunName}}
	}
	if opts.TunName != "" {
		if d.strictRP6 == nil {
			d.strictRP6 = d.loggedStrictRP6(conn.StrictRP6)
		}
		if d.hostDNS == nil && opts.Instance == 0 && resolvConfIsOwn(cmp.Or(opts.ResolvConf, "/etc/resolv.conf")) {
			d.hostDNS = fileDNS{own: OwnResolvConf, saved: SavedResolvConf, redirect: conn.RedirectLocalDNS}
		}
		if d.hostDNS == nil {
			d.hostDNS = resolvedDNS{dev: opts.TunName}
		}
		if d.startDNS == nil {
			d.startDNS = d.defaultDNSServer(opts.TunName)
		}
		if opts.ServeNames == nil {
			opts.ServeNames = defaultNamesServer(opts.TunName, opts.ListenDNS)
		}
	}
	d.dnsOff.Store(opts.DNSOff)
	d.startNames, d.namesFixed = opts.ServeNames, opts.NamesAddr
	d.held.Store(&selfAddrs)
	ln, err := d.listenGossip(opts, selfAddrs)
	if err != nil {
		return nil, err
	}
	undo.push(func() { ln.Close() })
	d.gossipLn, d.gossipPort = ln, uint16(portOf(ln.Addr()))

	d.gossip, err = gossip.New(gossip.Options{
		Self:         self,
		Log:          (*logAdapter)(d),
		Keyring:      d.keyring,
		Endpoints:    d.endpoints,
		CatchUp:      &gossip.CatchUpKeys{Identity: opts.Identity, Recipient: opts.Recipient},
		Announce:     d.announcement,
		OwnKey:       d.ownAddrKey,
		Underlay:     d.underlay,
		Listener:     ln,
		Dial:         d.gossipDial(opts.GossipDial),
		OverlayAddrs: d.overlayGossipAddrs,
		OverlayOnly:  d.overlayOnly,
		Overlay:      d.ula,
		OnOwn:        d.ownEchoed,
		OnRecords:    d.relayRecords,
		OnAnnounced:  d.relayAnnounced,
		Leases:       d.leases.encoded,
		OnLeases:     d.offerLeases,
		SeenAlone:    d.seenAlone,
		OnHave:       d.onHave,
		Waiting:      (*waitingAdapter)(d),
		Pair:         d.pairMsg,
		OnPair:       d.onPair,
		Logf:         d.logf,
	})
	if err != nil {
		return nil, err
	}
	undo.push(func() { d.gossip.Close() })

	if !opts.DisableDiscovery && !opts.HTTPSOnly {
		mopts := mdns.Options{}
		if opts.Discovery != nil {
			mopts = *opts.Discovery
		}
		mopts.Keyring = d.keyring
		mopts.Announce = d.announcement
		mopts.OnPeer = d.onDiscovered
		mopts.NeedsPeers = d.needsPeers
		mopts.Quiet = d.pace.Saving
		mopts.Logf = d.logf
		// Discovery is an underlay function, so it must not use the overlay
		// device this daemon just created.
		mopts.SkipInterface = opts.TunName
		if d.beacon, err = mdns.New(mopts); err != nil {
			return nil, err
		}
		undo.push(func() { d.beacon.Close() })
	}

	if !opts.DisableDHT || opts.HTTPSOnly {
		o := dht.Options{
			Self:      self,
			Keyring:   d.keyring,
			Announce:  d.publishedAnnouncement,
			Wanted:    d.wanted,
			OnPeer:    d.onFoundInDHT,
			Bootstrap: opts.DHTBootstrap,
			Logf:      d.logf,
		}
		if opts.HTTPSOnly {
			// The relays on 443 stand in for the DHT, which is UDP.
			o.Items = &relayItems{d: d, hc: d.httpsClient()}
		} else {
			o.Ask, o.Seeks = d.askRelays, d.seeksInDHT
			if opts.Rests {
				o.Joins = d.joinsDHT
			}
			// So they stand in while the network passes 443 alone.
			o.Beside, o.Walled = &relayItems{d: d, hc: d.httpsClient()}, d.manager.Walled
		}
		if d.dht, err = dht.New(o); err != nil {
			return nil, err
		}
	}
	undo.done()
	d.wired.Store(true)

	// Before the loop starts, so the first reconcile already has somewhere to
	// reach the peers this device knew about when it stopped, and knows how
	// fresh its state was. The keys first, so nothing is held unchecked.
	d.setSigning(state)
	d.loadEndpointCache(d.cachePath)
	d.leases.load(d.logf)
	d.loadWaiting()

	d.setStatus(func(s *ipc.Status) {
		s.Self = self
		s.Addrs = selfAddrs
		// Known the moment the log is opened, so a status read before the
		// first reconcile still names the network.
		s.Network = state.GenesisHash()
		s.NetworkName = state.Network()
		s.ListenPort = mgr.LocalPort()
		s.GossipPort = d.gossipPort
		s.SyncInTunnel = d.overlayOnly
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

func portOf(a net.Addr) int {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.Port
	}
	return 0
}

// A cleanup undoes, last first, what a constructor built before it failed.
type cleanup []func()

func (c *cleanup) push(f func()) { *c = append(*c, f) }

// done keeps what was built: run then undoes nothing.
func (c *cleanup) done() { *c = nil }

func (c *cleanup) run() {
	for i := len(*c) - 1; i >= 0; i-- {
		(*c)[i]()
	}
}

// onPortOrAny opens on port, and where [Options.PortFallback] allows and open
// fails with taken, on one the OS chooses instead.
func onPortOrAny[T any](d *Daemon, port uint16, taken error, what string, open func(uint16) (T, error)) (T, error) {
	v, err := open(port)
	if err != nil && d.portFallback && port != 0 && errors.Is(err, taken) {
		d.logf("daemon: %s port %d is taken; using one the OS chooses", what, port)
		v, err = open(0)
	}
	return v, err
}

// listenGossip is where log sync accepts sessions: the listener given, the
// overlay addresses where sync runs through the tunnel alone, or the underlay.
func (d *Daemon) listenGossip(opts Options, overlay []netip.Prefix) (net.Listener, error) {
	if opts.GossipListener != nil {
		return opts.GossipListener, nil
	}
	listen := func(port uint16) (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", port)) }
	switch {
	case d.stack != nil:
		listen = func(port uint16) (net.Listener, error) {
			return asListener(listenEach(func(ap netip.AddrPort) (net.Listener, error) { return d.stack.ListenTCPAddrPort(ap) }, overlay, port))
		}
	case d.overlayOnly:
		listen = func(port uint16) (net.Listener, error) { return listenOverlay(overlay, port) }
	}
	ln, err := onPortOrAny(d, opts.GossipPort, syscall.EADDRINUSE, "TCP", listen)
	if err != nil {
		return nil, fmt.Errorf("daemon: listening for gossip: %w", err)
	}
	return ln, nil
}

// Run drives the daemon until ctx is cancelled or [Daemon.Close] is called.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(d.ctx, cancel)()

	if !d.waits.track() {
		return nil // closed before it ever ran
	}
	// Under a policy, sealed from the first announcement on.
	d.decideSealing()
	go func() {
		defer d.waits.done()
		d.gossip.Serve()
	}()
	if d.beacon != nil && d.waits.track() {
		go func() {
			defer d.waits.done()
			d.beacon.Run(ctx)
		}()
	}
	if d.dht != nil && d.waits.track() {
		go func() {
			defer d.waits.done()
			d.dht.Run(ctx)
		}()
	}
	if d.relayCerts != nil && d.waits.track() {
		go func() {
			defer d.waits.done()
			d.keepRelayCertificate(ctx)
		}()
	}
	if d.waits.track() {
		go func() {
			defer d.waits.done()
			d.proveRelayNames(ctx)
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
	d.checkInBackground(ctx)
	d.watchHostDNS(ctx)
	var paced <-chan struct{}
	reconcileAt := time.NewTimer(time.Hour)
	defer reconcileAt.Stop()
	rearm := func() {
		// The change taken before the wait, so that none comes between.
		paced = d.pace.Changed()
		wait := d.reconcileWait()
		armed := d.now().Add(wait)
		d.reconcileArmed.Store(&armed)
		reconcileAt.Reset(wait)
	}
	rearm()

	// While saving, sync ticks come at the normal pace and those due sooner
	// than the saving one are skipped.
	synced := time.Now()
	for {
		select {
		case <-ctx.Done():
			if d.ctx.Err() != nil {
				return nil
			}
			return ctx.Err()
		case <-d.dirty:
			if err := d.Reconcile(); err != nil {
				d.logf("daemon: reconcile: %v", err)
			}
			rearm()
			// Whichever push, it carries an address that waited.
			d.addrsWaiting.Store(false)
			if d.pushRests.Swap(false) {
				d.inBackground(ctx, d.pushAll, true)
			} else {
				d.inBackground(ctx, d.pushAwake, false)
			}
		case <-paced:
			if !d.pace.Saving() && d.addrsWaiting.Swap(false) {
				d.announceSoon()
			}
			rearm()
		case <-d.rearm:
			rearm()
		case <-d.soon:
			if err := d.Reconcile(); err != nil {
				d.logf("daemon: reconcile: %v", err)
			}
			rearm()
		case <-reconcileAt.C:
			if err := d.Reconcile(); err != nil {
				d.logf("daemon: reconcile: %v", err)
			}
			rearm()
			if d.addrsWaiting.Swap(false) {
				d.inBackground(ctx, d.pushAwake, false)
			}
		case <-syncTick.C:
			if !d.due(synced, d.saving.sync) {
				continue
			}
			synced = time.Now()
			d.inBackground(ctx, d.syncOne, true)
		}
	}
}

// inBackground runs one anti-entropy round off the loop's goroutine, at most
// one at a time: a round can take tens of seconds against an unreachable
// member, and the loop must stay free to service d.dirty. A round asked for
// while one runs is deferred, not dropped — dropping it would break the
// epidemic relay a revocation depends on.
// A deferred round reaches members that rest where any round deferred
// would have: full says this one would.
func (d *Daemon) inBackground(ctx context.Context, round func(context.Context), full bool) {
	select {
	case d.syncing <- struct{}{}:
	default:
		d.mu.Lock()
		d.pushDeferred = true
		d.deferredFull = d.deferredFull || full
		d.mu.Unlock()
		return
	}
	if !d.waits.track() {
		<-d.syncing
		return
	}
	go func() {
		defer d.waits.done()
		defer func() {
			<-d.syncing
			d.mu.Lock()
			deferred, full := d.pushDeferred, d.deferredFull
			d.pushDeferred, d.deferredFull = false, false
			d.mu.Unlock()
			// Terminates: the round it triggers raises no signal of its
			// own unless something was genuinely new.
			switch {
			case deferred && full:
				d.MarkDirty()
			case deferred:
				d.announceSoon()
			}
		}()
		round(ctx)
	}()
}

// reconcileSoon asks the loop to reconcile, pushing nothing. It never
// blocks.
func (d *Daemon) reconcileSoon() {
	select {
	case d.soon <- struct{}{}:
	default:
	}
}

// MarkDirty asks the loop to reconcile and push. It never blocks, so it is
// safe from a gossip session or an IPC handler.
func (d *Daemon) MarkDirty() {
	d.pushRests.Store(true)
	d.announceSoon()
}

// announceSoon is [Daemon.MarkDirty] for this device's announcement alone,
// pushed to the members that do not rest: one that rests learns it at its
// next sync, and from disco on the way meanwhile.
func (d *Daemon) announceSoon() {
	select {
	case d.dirty <- struct{}{}:
	default:
	}
}

// seenAlone reports whether the network is at the schema whose hellos say
// what they hold.
func (d *Daemon) seenAlone() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status.Schema >= types.SchemaSeen
}

// relayRecords passes on log records a session brought, to every member:
// a node that rests leaves that to those awake, and reconciles alone.
func (d *Daemon) relayRecords() {
	if d.leavesRelaying() {
		// Records may change its own announcement: its epoch, its pairs'.
		d.announceSoon()
		return
	}
	d.MarkDirty()
}

// relayAnnounced is [Daemon.relayRecords] for another's announcement, an
// address key or a waiting change, passed on to the members awake: one
// that rests has an announcement's news from its author, or at its next
// sync.
func (d *Daemon) relayAnnounced() {
	if d.leavesRelaying() {
		d.reconcileSoon()
		return
	}
	d.announceSoon()
}

// leavesRelaying reports whether this node rests and a member awake relays
// in its stead.
func (d *Daemon) leavesRelaying() bool {
	return d.rests && slices.ContainsFunc(d.memberList(), func(id types.Identity) bool { return !d.peerRests(id) })
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

// boolOrder sorts false before true.
func boolOrder(b bool) int {
	if b {
		return 1
	}
	return 0
}

// restingPushFanout is how many members awake a node that rests pushes to:
// they push it on, and each session wakes the phone.
const restingPushFanout = 2

// pushAll runs one anti-entropy round with up to [PushFanout] members. It
// terminates because OnRecords fires only when something was actually new.
func (d *Daemon) pushAll(ctx context.Context) { d.push(ctx, false) }

// push is [Daemon.pushAll], to the members that do not rest alone where
// awake says so, and to those an exchange of preshared keys waits on.
func (d *Daemon) push(ctx context.Context, awake bool) {
	wanted := d.takePairWanted()
	var up, resting []types.Identity
	for _, id := range d.memberList() {
		if d.peerRests(id) && !wanted[id] {
			resting = append(resting, id)
		} else {
			up = append(up, id)
		}
	}
	fanout := PushFanout
	if d.rests {
		fanout = restingPushFanout
	}
	if len(up) > fanout {
		// Shuffle rather than take a prefix: a fixed slice would leave the
		// rest reachable only through whoever happened to be in it.
		rand.Shuffle(len(up), func(i, j int) { up[i], up[j] = up[j], up[i] })
		slices.SortStableFunc(up, func(a, b types.Identity) int {
			return boolOrder(d.gossip.Failing(a)) - boolOrder(d.gossip.Failing(b))
		})
		// An exchange of preshared keys waits on its peer alone.
		first := slices.DeleteFunc(slices.Clone(up), func(id types.Identity) bool { return !wanted[id] })
		up = append(first, slices.DeleteFunc(up, func(id types.Identity) bool { return wanted[id] })...)
		up = up[:max(fanout, len(first))]
	}
	peers := up
	if !awake {
		// Members that rest relay nothing, so each hears from the author.
		peers = append(peers, resting...)
	}
	if len(peers) == 0 {
		return
	}
	d.gossip.Sync(ctx, peers)
}

// pushAwake is [Daemon.pushAll] to the members that do not rest.
func (d *Daemon) pushAwake(ctx context.Context) { d.push(ctx, true) }

// syncOne is the periodic backstop: anti-entropy with one member chosen at
// random, which is what makes convergence robust to a push that was dropped.
// A member that rests is left to sync by itself, at its own pace, but where
// all do, one is synced with every [savingSyncEvery].
func (d *Daemon) syncOne(ctx context.Context) {
	all := d.memberList()
	peers := slices.DeleteFunc(slices.Clone(all), d.peerRests)
	if len(peers) == 0 {
		// Saving, the loop paces the tick already.
		d.mu.Lock()
		due := d.pace.Saving() || d.now().Sub(d.restingSynced) >= savingSyncEvery
		if due {
			d.restingSynced = d.now()
		}
		d.mu.Unlock()
		if !due {
			return
		}
		peers = all
	}
	if len(peers) == 0 {
		return
	}
	pick := peers[rand.IntN(len(peers))]
	d.gossip.Sync(ctx, []types.Identity{pick})
}

// peerRests reports whether id's announcement, not a hint, says it rests.
func (d *Daemon) peerRests(id types.Identity) bool {
	e, ok := d.endpoints.Get(id)
	return ok && !e.HintAlone() && e.Rests
}

// memberList returns the members to gossip with: everyone the log carries
// except this node. It reads TrustedState, so a node under a fork alarm
// gossips with nobody; a disabled one still hands the members the record
// that disabled it.
func (d *Daemon) memberList() []types.Identity {
	state, err := d.gossipState()
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
	d.mu.Lock()
	to := d.gossipTo
	d.mu.Unlock()
	out := make([]types.Identity, 0, len(nodes))
	for i := range nodes {
		// Excluded for the same reason they get no peer entry: expiry and the
		// policy must mean the same thing in every layer.
		if nodes[i].Identity != d.self && !nodes[i].Expired(now) && (to == nil || to(nodes[i].Identity)) {
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
	change := d.endpoints.Added(e)
	if change == gossip.Unchanged || !d.actionableSubject(e.Identity) {
		return
	}
	d.logf("daemon: discovered %v %s at %v", e.Identity.ShortString(), where, d.underlay(e))
	d.relayAnnounced()
}

// overlayGossipAddrs is where a member can be reached for anti-entropy once
// its tunnel is up. Two members behind NAT can open no TCP session to each
// other on the underlay, so without this they sync only through whichever
// member both can reach.
func (d *Daemon) overlayGossipAddrs(id types.Identity) []netip.AddrPort {
	state, err := d.gossipState()
	if err != nil {
		return nil
	}
	e, held := d.endpoints.Get(id)
	if !held || e.GossipPort == 0 {
		return nil
	}
	addrs := d.overlayAddrs(state, id, d.now().Unix())
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, pfx := range addrs {
		out = append(out, netip.AddrPortFrom(pfx.Addr(), e.GossipPort))
	}
	return out
}

// checkInBackground runs [Daemon.refreshReach] after the reach delay and then
// every [reachEvery] until the daemon stops, off the loop, since a check waits
// for probes.
func (d *Daemon) checkInBackground(ctx context.Context) {
	if !d.waits.track() {
		return
	}
	go func() {
		defer d.waits.done()
		wait := time.NewTimer(d.reachDelay)
		var last time.Time
		defer wait.Stop()
		// Each change taken before the pace is read, so that none comes
		// between.
		paced := d.pace.Changed()
		d.followPace()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wait.C:
			case <-paced:
				paced = d.pace.Changed()
				d.followPace()
				if d.pace.Saving() {
					// The next check comes at the saving pace.
					wait.Stop()
					wait.Reset(max(d.reachEvery, d.saving.reach-time.Since(last)))
					continue
				}
				// Back from saving, the tunnels are checked at once.
				wait.Stop()
				if gap := recheckGap - time.Since(last); gap > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(gap):
					}
				}
			case <-d.recheck:
				wait.Stop()
				// However often announcements ask, checks keep their distance.
				if gap := recheckGap - time.Since(last); gap > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(gap):
					}
				}
			}
			d.refreshReach(ctx)
			last = time.Now()
			wait.Reset(d.pace.every(d.reachEvery, d.saving.reach))
		}
	}()
}

// addrsMoved reports whether the log gives this device other overlay
// addresses than the data plane holds, as a renumbering does when it applies
// and again at its deadline.
func (d *Daemon) addrsMoved() bool {
	state, err := d.TrustedState()
	if err != nil || !state.IsMember(d.self) {
		return false
	}
	return !slices.Equal(d.overlayAddrs(state, d.self, d.now().Unix()), d.heldAddrs())
}

// sayMovesAgain has the next move the log makes said again, as one a
// reconcile said from before the last may have been.
func (d *Daemon) sayMovesAgain() { d.movedSaid.Store(false) }

// heldAddrs is the overlay addresses the data plane holds.
func (d *Daemon) heldAddrs() []netip.Prefix {
	if p := d.held.Load(); p != nil {
		return *p
	}
	return nil
}

// overlayAddrs is [log.State.Addrs] as this mesh uses them: without IPv4
// where it runs without.
func (d *Daemon) overlayAddrs(state *log.State, id types.Identity, now int64) []netip.Prefix {
	addrs := state.Addrs(id, now)
	if d.noV4.Load() {
		addrs = slices.DeleteFunc(addrs, func(p netip.Prefix) bool { return p.Addr().Is4() })
	}
	return addrs
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
func (d *Daemon) Status() ipc.Status {
	held := d.changes.len()
	names := d.namesNow() // before d.mu, which dns.mu is taken before
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.status
	s.Addrs = append([]netip.Prefix(nil), d.status.Addrs...)
	s.Waiting, s.Names = held, names
	return s
}

func (d *Daemon) setStatus(f func(*ipc.Status)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(&d.status)
}

// Disabled returns the record that ended the network, or nil.
func (d *Daemon) Disabled() *log.DisabledError {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authority.Disabled()
}

// gossipState is TrustedState, or once the network is disabled the state it
// ended at: log sync goes on with the members, so the record reaches them.
func (d *Daemon) gossipState() (*log.State, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	state, err := d.authority.TrustedState()
	if errors.As(err, new(*log.DisabledError)) {
		return d.authority.State(), nil
	}
	return state, err
}

// TrustedState returns the membership state, or the alarm that withholds it.
func (d *Daemon) TrustedState() (*log.State, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authority.TrustedState()
}

// Chain returns the active chain's records, anchor first.
func (d *Daemon) Chain() ([]types.AUM, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	hashes, err := d.authority.Chain()
	if err != nil {
		return nil, err
	}
	out := make([]types.AUM, 0, len(hashes))
	for _, h := range hashes {
		aum, err := d.storage.AUM(h)
		if err != nil {
			return nil, err
		}
		out = append(out, aum)
	}
	return out, nil
}

// OfferHints takes what an inviting device sent: announcements, verified
// here like any other, and leases, checked like any other.
func (d *Daemon) OfferHints(endpoints, leases [][]byte) {
	for _, b := range endpoints {
		if e, err := gossip.DecodeEndpoint(b); err == nil {
			_ = d.Learn(e)
		}
	}
	d.offerLeases(leases)
}

// Endpoints exposes the announcement cache, for tests and diagnostics.
func (d *Daemon) Endpoints() *gossip.Cache { return d.endpoints }

// Manager exposes the data plane, for tests and diagnostics.
func (d *Daemon) Manager() conn.Manager { return d.manager }

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
	if d.endpoints.Added(e) != gossip.Unchanged {
		d.relayAnnounced()
	}
	return nil
}

// Announcement returns this node's current signed endpoint record.
func (d *Daemon) Announcement() (gossip.Endpoint, bool) { return d.announcement() }

// Close shuts everything down. It is idempotent.
func (d *Daemon) Close() error {
	var err error
	d.closeOnce.Do(func() {
		d.waits.stop()
		d.cancel()
		if d.dht != nil {
			d.dht.Close()
		}
		if d.beacon != nil {
			d.beacon.Close()
		}
		d.gossip.Close()
		d.closeHTTPS()
		d.closeRelay()
		// Before the device goes, which resolved's routing names.
		d.closeDNS()
		err = d.manager.Close()
		d.waits.wait()
	})
	return err
}

// now is the daemon's clock, overridable in tests.
func (d *Daemon) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}
