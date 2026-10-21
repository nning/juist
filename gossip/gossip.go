// Package gossip is the sync layer: it moves membership-log records and
// connectivity announcements between members over transports it does not
// trust. Records and announcements are self-certifying, so a hostile transport
// or peer can delay, drop, duplicate or reorder them and never change who is a
// member.
//
// One TCP session per anti-entropy round, four frames, strictly alternating so
// neither side can block on a write the other is not reading:
//
//	initiator → hello    what network, where my chain is, what I hold
//	responder → hello    the same, answered
//	initiator → records  what the responder turned out to be missing
//	responder → records  what the initiator turned out to be missing
//
// Every frame carries the sender's (epoch, head) whether or not anything needs
// transferring, and one round makes both sides whole. The "what I hold" set is
// sent outright rather than walked back to a common ancestor, which keeps the
// exchange stateless; where the set is cut short, a record listed stands for
// its ancestors. A node that holds no epoch its peer speaks asks for a
// catch-up first, and runs the same exchange under the key it grants.
//
// Sessions run through the tunnel where the daemon listens on its overlay
// addresses alone, and on the underlay otherwise; [seal] covers the metadata
// the underlay shows.
package gossip

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nning/juist/internal/admit"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// A View is what a peer is told about this node's log in a beacon.
type View struct {
	// Network is the genesis hash, which names the network.
	Network types.Hash

	// Head is the current chain head, and Epoch the current group-secret
	// epoch. Together they are the beacon: a peer compares them against its
	// own to decide whether there is anything to exchange.
	Head  types.Hash
	Epoch uint64

	// Anchor is the record this node's chain is resolved from: its genesis, or
	// the newest checkpoint it compacted to. Peers answer [Log.Missing]
	// relative to it, since records below it are ones this log refuses.
	Anchor types.Hash

	// Have is every record hash this node resolves from its anchor, including
	// branches that lost fork choice: both sides must see a fork in full to
	// alarm on it. Where there are more than [MaxHashesPerFrame], those
	// nothing hangs from come first, and a peer takes each as standing for its
	// ancestors.
	Have []types.Hash
}

// ErrNothingNew is what [Log.Inform] returns for records that add nothing to
// the log, such as a copy of a record it leaves out: no failure, and no news
// to pass on.
var ErrNothingNew = errors.New("gossip: nothing new")

// A Log is the membership log as gossip needs it. An interface, so the trust
// layer stays usable without a network and the daemon is what joins the two.
type Log interface {
	// View reports this node's beacon and the records it holds.
	View() (View, error)

	// Missing returns records this node holds that the peer lacks and can
	// accept: descendants of the peer's anchor that are neither in have nor
	// ancestors of a record in it, parents first, at most
	// [MaxRecordsPerFrame].
	Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error)

	// Inform hands received records to the log, oldest first. An error is
	// expected in normal operation and is reported, not fatal;
	// [ErrNothingNew] says the log took none of them in.
	Inform(records []types.AUM) error

	// Member returns the record of a current, unexpired member other than
	// this node, which a catch-up is granted to. An error means this node
	// answers no catch-up at all: it is under an alarm, or no member itself.
	Member(id types.Identity) (rec types.NodeRecord, listed bool, err error)

	// SigningKey returns the signing key the log names for id, or nil.
	SigningKey(id types.Identity) *types.SigningKey

	// ListedSigningKey returns the signing key the log's chain last named for
	// member id, listed now or not, or nil for one it never named.
	ListedSigningKey(id types.Identity) *types.SigningKey
}

// Options configures a [Node].
type Options struct {
	// Self is this node's identity, used to ignore announcements about
	// ourselves and to avoid gossiping with ourselves.
	Self types.Identity

	// Log is the membership log this node syncs.
	Log Log

	// Keyring holds the epoch secrets frames are sealed under. A node whose
	// keyring is empty cannot gossip at all: it has not opened its own
	// epoch secret, which means it cannot prove membership to anyone.
	Keyring *keyring.Keyring

	// Endpoints is the announcement cache, shared with the reconciler.
	Endpoints *Cache

	// CatchUp are the keys this node asks for a catch-up with, when no epoch
	// it holds is answered, and signs its answers to one with. Nil does
	// neither.
	CatchUp *CatchUpKeys

	// Announce returns this node's current announcement, or false if it has
	// none yet. Called per session, so it always reflects the live one.
	Announce func() (Endpoint, bool)

	// OwnKey returns this node's address key, or false where its addresses
	// are not sealed. Nil seals nothing.
	OwnKey func() (AddrKey, bool)

	// Underlay returns the addresses an announcement opens to, its sealed
	// ones where this node holds their key. Nil takes [Endpoint.Addrs].
	Underlay func(Endpoint) []netip.AddrPort

	// Listener accepts inbound sessions. Required.
	Listener net.Listener

	// Dial opens an outbound session. Nil uses a plain TCP dialer.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

	// Timeout bounds one session end to end. Zero uses [DefaultTimeout].
	Timeout time.Duration

	// OverlayAddrs returns addresses to try after the ones a peer announced —
	// in practice its overlay addresses, which become reachable once the
	// tunnel is up. It is what lets two members behind NAT sync directly:
	// neither can open a TCP session to the other on the underlay, and the
	// tunnel that carries it is brought up by the connectivity layer rather
	// than by this one. Nil tries only what the announcement carries.
	OverlayAddrs func(types.Identity) []netip.AddrPort

	// OverlayOnly tries only OverlayAddrs, not the announced addresses: log
	// sync through the tunnel alone, where peers listen on no other network.
	OverlayOnly bool

	// Overlay is the network's overlay IPv6 prefix, each address of which
	// one member holds alone; the zero Prefix for none.
	Overlay netip.Prefix

	// OnOwn is handed this node's own announcement as a peer holds it,
	// unverified. Nil ignores it.
	OnOwn func(Endpoint)

	// OnRecords is called after a session accepted log records, so the
	// daemon can reconcile without waiting for its next tick, and
	// OnAnnounced, where set, in its stead after one took no records but
	// new announcements, address keys or waiting changes. Neither may block
	// for long; they run on the session's goroutine.
	OnRecords, OnAnnounced func()

	// Leases returns the encoded freshness leases to send a peer, and
	// OnLeases receives a peer's, after its records have been applied so a
	// lease naming one of them can be checked against it. Both are optional.
	Leases   func() [][]byte
	OnLeases func([][]byte)

	// SeenAlone reports whether a hello says what this node holds rather
	// than carrying it: the network is at [types.SchemaSeen]. Nil never.
	SeenAlone func() bool

	// Waiting is the store of changes waiting for votes, handed between
	// admin devices beside the log. Nil hands none.
	Waiting Waiting

	// Pair returns this node's message to a peer in the exchange of a
	// preshared key, signed, or nil for none; OnPair takes a peer's, which
	// it verifies, before the frame answering it is built. Nil sends and
	// takes none.
	Pair   func(to types.Identity) *pairkey.Msg
	OnPair func(m *pairkey.Msg)

	// OnHave receives the head, the anchor and the record hashes a peer's
	// hello says it holds, under the identity its announcement names. Any
	// member can forge that, so it decides nothing a record is needed for. It
	// runs on the session's goroutine.
	OnHave func(from types.Identity, head, anchor types.Hash, have []types.Hash)

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// DefaultTimeout bounds one anti-entropy session. Generous for a LAN, and
// short enough that a peer that has gone away does not hold a slot until TCP
// gives up on its own.
const DefaultTimeout = 20 * time.Second

// DialTimeout bounds opening one connection, at most a quarter of the session
// timeout: a peer's addresses share one budget, and a SYN into a network that
// drops it must not spend all of it before the address that works is tried.
const DialTimeout = 3 * time.Second

// maxInboundSessions bounds concurrent inbound sessions. Excess connections
// are closed rather than queued: the peer retries on its own timer.
const maxInboundSessions = 16

// maxOutboundSessions bounds how many peers one [Node.Sync] call dials at
// once, so one local change cannot become hundreds of simultaneous dials.
const maxOutboundSessions = 16

// maxUnauthPerSource bounds how many connections from one source, an
// overlay address or else a host (an IPv4 address, an IPv6 /64), may be
// waiting to say anything. Over it, that source's oldest silent connection
// is closed rather than the new one refused: a peer that has authenticated
// is off this budget, so what a busy source displaces past it is its own
// not-yet-authenticated connections, and past [maxUnauth] the largest's.
// Refusing instead would punish members who legitimately share an address —
// behind a NAT, or on one host — for the behaviour of whoever else is on it.
const maxUnauthPerSource = 4

// maxUnauth bounds the silent connections from all sources, so that they
// hold half the inbound slots at most. Past it the oldest of the source
// holding the most within the group and site holding the most is closed, so
// a flood closes its own before a member alone in its site.
const maxUnauth = maxInboundSessions / 2

// helloTimeout bounds how long an unauthenticated connection may hold a slot
// before it has said anything. The rest of the session gets the full timeout;
// this covers only the part where the peer has proved nothing.
const helloTimeout = 5 * time.Second

// A Node runs anti-entropy for one member.
type Node struct {
	opts        Options
	timeout     time.Duration
	dialTimeout time.Duration
	logf        func(string, ...any)

	// slots bounds inbound concurrency; a token is held for a session's
	// lifetime.
	slots chan struct{}

	// closing and the wait set it guards are the shutdown handshake: an Add
	// that takes the counter off zero must not race Wait, so the flag check
	// and the Add happen under one lock.
	closeOnce sync.Once
	closed    chan struct{}
	trackMu   sync.Mutex
	closing   bool
	wg        sync.WaitGroup

	// peerEpoch remembers the epoch each peer last spoke, so a push to a peer
	// that has not caught up is sealed under an epoch it can still open —
	// without it, the push carrying a revocation's epoch bump is unreadable to
	// everyone who has not applied it. The value is the authenticated seal
	// epoch, never the frame's plaintext beacon, and entry is gated by
	// membership so minted identities cannot fill the map.
	mu        sync.Mutex
	peerEpoch map[types.Identity]uint64

	// recipient opens what is sealed to this device: CatchUp's, until
	// SetRecipient.
	recipient atomic.Pointer[secrets.PrivateKeys]

	// failing holds, under mu, why the last outbound round to a peer
	// completed no session. Entered only for peers Sync was asked to reach,
	// which the caller draws from the membership.
	failing map[types.Identity]Failure

	// silent counts the inbound connections that have not yet opened a frame
	// under the group secret, by [Node.silentSource].
	silent *admit.Set[netip.Prefix]
}

// New starts a gossip node. The caller runs [Node.Serve] to accept sessions.
func New(opts Options) (*Node, error) {
	switch {
	case opts.Log == nil:
		return nil, errors.New("gossip: Log is required")
	case opts.Keyring == nil:
		return nil, errors.New("gossip: Keyring is required")
	case opts.Endpoints == nil:
		return nil, errors.New("gossip: Endpoints cache is required")
	case opts.Listener == nil:
		return nil, errors.New("gossip: Listener is required")
	case opts.CatchUp != nil && (opts.CatchUp.Recipient == nil || opts.CatchUp.Identity.Public() != opts.Self):
		return nil, errors.New("gossip: CatchUp must hold this node's own identity and recipient keys")
	}
	n := &Node{
		opts:      opts,
		timeout:   cmp.Or(opts.Timeout, DefaultTimeout),
		logf:      opts.Logf,
		slots:     make(chan struct{}, maxInboundSessions),
		closed:    make(chan struct{}),
		peerEpoch: map[types.Identity]uint64{},
		failing:   map[types.Identity]Failure{},
	}
	n.silent = admit.NewNested(admit.Limits{PerSource: maxUnauthPerSource, OnSource: admit.EvictOldest,
		Total: maxUnauth, OnTotal: admit.EvictLargest}, n.silentWithin)
	n.dialTimeout = min(DialTimeout, n.timeout/4)
	if opts.CatchUp != nil {
		n.recipient.Store(opts.CatchUp.Recipient)
	}
	if n.logf == nil {
		n.logf = func(string, ...any) {}
	}
	if n.opts.Dial == nil {
		n.opts.Dial = dialTCP
	}
	return n, nil
}

func dialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr.String())
}

// Addr reports the address inbound sessions are accepted on.
func (n *Node) Addr() net.Addr { return n.opts.Listener.Addr() }

// track admits a goroutine to the wait set, or reports that the node is
// shutting down and it must not start.
func (n *Node) track() bool {
	n.trackMu.Lock()
	defer n.trackMu.Unlock()
	if n.closing {
		return false
	}
	n.wg.Add(1)
	return true
}

// admitSilent counts a connection as not yet having said anything; see
// [maxUnauthPerSource]. Closing an evicted one unblocks its read, so its
// session ends and its slot comes back.
func (n *Node) admitSilent(c net.Conn) *admit.Ticket[netip.Prefix] {
	t, _ := n.silent.Admit(n.silentSource(admit.Source(c.RemoteAddr())), func() {
		n.logf("gossip: closing a silent connection from %v: past %d from its source or %d in all",
			c.RemoteAddr(), maxUnauthPerSource, maxUnauth)
		c.Close()
	})
	return t
}

// silentSource is whose budget a silent connection from a takes: an overlay
// address its own, as one member holds it alone and its /64 may hold
// another's, and any other address its host's.
func (n *Node) silentSource(a netip.Addr) netip.Prefix {
	if n.opts.Overlay.Contains(a) {
		return netip.PrefixFrom(a, a.BitLen())
	}
	return admit.Host(a)
}

// silentWithin is the site and group a silent source is within: an overlay
// address, held by one member, is both alone.
func (n *Node) silentWithin(src netip.Prefix) []netip.Prefix {
	if a := src.Addr(); !n.opts.Overlay.Contains(a) {
		return []netip.Prefix{admit.Site(a), admit.Group(a)}
	}
	return []netip.Prefix{src, src}
}

// Serve accepts inbound sessions until [Node.Close]. It blocks.
func (n *Node) Serve() {
	for {
		c, err := n.opts.Listener.Accept()
		if err != nil {
			select {
			case <-n.closed:
				return
			default:
			}
			// A transient accept error must not end the loop: a node that
			// stops accepting silently drops out of the mesh.
			n.logf("gossip: accept: %v", err)
			select {
			case <-n.closed:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		select {
		case n.slots <- struct{}{}:
		default:
			n.logf("gossip: refusing a session from %v: %d already in flight",
				c.RemoteAddr(), maxInboundSessions)
			c.Close()
			continue
		}
		if !n.track() {
			<-n.slots
			c.Close()
			return
		}
		silent := n.admitSilent(c)
		go func() {
			defer n.wg.Done()
			defer func() { <-n.slots }()
			defer silent.Release()
			defer c.Close()
			if _, err := n.session(c, sessionOpts{authed: silent.Release}); err != nil {
				n.logf("gossip: inbound session from %v: %v", c.RemoteAddr(), err)
			}
		}()
	}
}

// Close stops accepting and waits for sessions in flight.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.trackMu.Lock()
		n.closing = true
		n.trackMu.Unlock()
		close(n.closed)
		n.opts.Listener.Close()
	})
	n.wg.Wait()
	return nil
}

// SetRecipient has the node open what is sealed to this device with r from
// now on, as after a rotation of its keys.
func (n *Node) SetRecipient(r *secrets.PrivateKeys) { n.recipient.Store(r) }
