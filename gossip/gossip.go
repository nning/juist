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
// exchange stateless up to [MaxHashesPerFrame]. A node that holds no epoch
// its peer speaks asks for a catch-up first, and runs the same exchange under
// the key it grants.
//
// Gossip runs on the underlay, since reaching a peer over the overlay needs
// the tunnel gossip brings up; [seal] covers the metadata that costs.
package gossip

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/nning/juist/internal/admit"
	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/keyring"
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

	// Have is every record hash this node holds, including branches that lost
	// fork choice: both sides must see a fork in full to alarm on it.
	Have []types.Hash
}

// A Log is the membership log as gossip needs it. An interface, so the trust
// layer stays usable without a network and the daemon is what joins the two.
type Log interface {
	// View reports this node's beacon and the records it holds.
	View() (View, error)

	// Missing returns records this node holds that the peer lacks and can
	// accept: descendants of the peer's anchor absent from have, parents
	// first, at most [MaxRecordsPerFrame]. A peer whose anchor this node does
	// not hold gets nothing.
	Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error)

	// Inform hands received records to the log, oldest first. An error is
	// expected in normal operation and is reported, not fatal.
	Inform(records []types.AUM) error

	// Member returns the record of a current, unexpired member other than
	// this node, which a catch-up is granted to. An error means this node
	// answers no catch-up at all: it is under an alarm, or no member itself.
	Member(id types.Identity) (rec types.NodeRecord, listed bool, err error)
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

	// OnRecords is called after a session accepted log records, so the
	// daemon can reconcile without waiting for its next tick. It must not
	// block for long; it runs on the session's goroutine.
	OnRecords func()

	// Leases returns the encoded freshness leases to send a peer, and
	// OnLeases receives a peer's, after its records have been applied so a
	// lease naming one of them can be checked against it. Both are optional.
	Leases   func() [][]byte
	OnLeases func([][]byte)

	// Waiting is the store of changes waiting for votes, handed between
	// admin devices beside the log. Nil hands none.
	Waiting Waiting

	// OnHave receives the record hashes a peer's hello says it holds, under
	// the identity its announcement names. Any member can forge that, so it
	// is for display only. It runs on the session's goroutine.
	OnHave func(from types.Identity, have []types.Hash)

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

// maxUnauthPerSource bounds how many connections from one address may be
// waiting to say anything. Over it, that address's oldest silent connection is
// closed rather than the new one refused: a peer that has authenticated is
// off this budget, so what a busy address displaces is only its own
// not-yet-authenticated connections. Refusing instead would punish members
// who legitimately share an address — behind a NAT, or on one host — for the
// behaviour of whoever else is on it.
const maxUnauthPerSource = 4

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

	// failing holds the peers whose last outbound round reached none of
	// their addresses, and refused those of them whose catch-up refused this
	// node, both under mu. Entered only for peers Sync was asked to reach,
	// which the caller draws from the membership.
	failing map[types.Identity]bool
	refused map[types.Identity]bool

	// silent counts the inbound connections that have not yet opened a frame
	// under the group secret.
	silent *admit.Set[netip.Addr]
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
		failing:   map[types.Identity]bool{},
		refused:   map[types.Identity]bool{},
		silent:    admit.New[netip.Addr](admit.Limits{PerSource: maxUnauthPerSource, OnSource: admit.EvictOldest}),
	}
	n.dialTimeout = min(DialTimeout, n.timeout/4)
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
func (n *Node) admitSilent(c net.Conn) *admit.Ticket[netip.Addr] {
	t, _ := n.silent.Admit(admit.Source(c.RemoteAddr()), func() {
		n.logf("gossip: closing a silent connection from %v: %d from that address are "+
			"already waiting to speak", c.RemoteAddr(), maxUnauthPerSource)
		c.Close()
	})
	return t
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

// SyncWith runs one anti-entropy session against a peer. peerID may be zero
// when the peer is not known yet, in which case the frame is sealed under this
// node's own epoch.
//
// A peer that hangs up on the hello without answering is one that cannot
// open it: behind by an epoch this node has not sealed to it before, as after
// this node rotated its own keys and restarted, when nothing remembers the
// peer's epoch. The session is then tried again under each older epoch this
// node still holds, newest first, and the one that works is remembered. Both
// sides behind a change would otherwise wait for each other forever. When no
// epoch is answered, it asks for a catch-up.
func (n *Node) SyncWith(ctx context.Context, addr netip.AddrPort, peerID types.Identity) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	var force uint64
	for {
		used, err := n.syncOnce(ctx, addr, sessionOpts{initiator: true, peerID: peerID, force: force})
		if err == nil {
			return nil
		}
		if errors.Is(err, errNoEpochHeld) {
			return n.catchUpWith(ctx, addr, peerID, err)
		}
		if !errors.Is(err, errNoHelloBack) {
			return err
		}
		lower, ok := n.olderEpoch(used)
		if !ok {
			return n.catchUpWith(ctx, addr, peerID, err)
		}
		force = lower
	}
}

// PushTo runs one session with a member that hands it, after what it lacks of
// this node's log, records this node holds but has not applied: the change
// ending its membership, while it still has a tunnel to hear it through.
func (n *Node) PushTo(ctx context.Context, id types.Identity, records [][]byte) error {
	e, held := n.opts.Endpoints.Get(id)
	if !held {
		return fmt.Errorf("gossip: no announcement of %v to reach it at", id.ShortString())
	}
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	addrs := e.GossipAddrs()
	if n.opts.OverlayOnly {
		addrs = nil
	}
	if n.opts.OverlayAddrs != nil {
		addrs = append(addrs, n.opts.OverlayAddrs(id)...)
	}
	err := fmt.Errorf("gossip: no address to reach %v at", id.ShortString())
	for _, addr := range addrs {
		if ctx.Err() != nil {
			break
		}
		if _, err = n.syncOnce(ctx, addr, sessionOpts{initiator: true, peerID: id, extra: records}); err == nil {
			return nil
		}
	}
	return err
}

// withExtra appends records to a records frame, after those already in it,
// within the frame's byte budget: all of them, or an error.
func withExtra(f *frame, extra [][]byte) error {
	used := 0
	for _, b := range f.Records {
		used += len(b)
	}
	for _, b := range extra {
		used += len(b)
	}
	if len(f.Records)+len(extra) > MaxRecordsPerFrame || used > maxRecordBytesPerFrame {
		return fmt.Errorf("gossip: %d records to hand over do not fit one frame", len(extra))
	}
	f.Records = append(f.Records, extra...)
	return nil
}

// CatchUpWith runs one catch-up session against a peer, whatever epochs this
// node holds.
func (n *Node) CatchUpWith(ctx context.Context, addr netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	return n.catchUpWith(ctx, addr, types.Identity{}, nil)
}

func (n *Node) catchUpWith(ctx context.Context, addr netip.AddrPort, peerID types.Identity, unanswered error) error {
	if n.opts.CatchUp == nil {
		if unanswered == nil {
			return errors.New("gossip: this node holds no keys to ask for a catch-up with")
		}
		return unanswered
	}
	_, err := n.syncOnce(ctx, addr, sessionOpts{initiator: true, peerID: peerID, catchUp: true})
	if err != nil && unanswered != nil && errors.Is(err, errNoCatchUp) {
		return fmt.Errorf("%w, nor a catch-up", unanswered)
	}
	return err
}

// errNoEpochHeld is a node whose keyring is empty, which only a catch-up
// helps.
var errNoEpochHeld = errors.New("this node holds no epoch secret, so it cannot gossip; " +
	"it is not a member of the epoch its log resolves to")

// errNoHelloBack is a peer that closed after this node's hello, unanswered.
var errNoHelloBack = errors.New("the peer did not answer the hello")

func (n *Node) syncOnce(ctx context.Context, addr netip.AddrPort, so sessionOpts) (uint64, error) {
	dctx, cancel := context.WithTimeout(ctx, n.dialTimeout)
	c, err := n.opts.Dial(dctx, addr)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("gossip: dialing %v: %w", addr, err)
	}
	defer c.Close()
	// Unblock the session's blocking reads and writes when the context ends;
	// a peer that accepts a connection and then says nothing must not hold
	// this goroutine past the timeout.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	used, err := n.session(c, so)
	if err != nil {
		return used, fmt.Errorf("gossip: session with %v: %w", addr, err)
	}
	return used, nil
}

// olderEpoch returns the newest epoch this node holds below e.
func (n *Node) olderEpoch(e uint64) (uint64, bool) {
	held := n.opts.Keyring.Epochs()
	for i := len(held) - 1; i >= 0; i-- {
		if held[i] < e {
			return held[i], true
		}
	}
	return 0, false
}

// Sync runs one round against every peer it can reach, concurrently, and
// returns how many sessions succeeded. Failures are logged, not returned: a
// peer being asleep is the common case.
func (n *Node) Sync(ctx context.Context, peers []types.Identity) int {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ok    int
		slots = make(chan struct{}, maxOutboundSessions)
	)
	for _, id := range peers {
		if id == n.opts.Self {
			continue
		}
		e, held := n.opts.Endpoints.Get(id)
		if !held {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			// One session's worth of time across all a peer's addresses.
			// Without the budget, an announcement of unreachable addresses
			// costs every member a full timeout each — a connection flood
			// aimed wherever the announcer likes.
			pctx, cancel := context.WithTimeout(ctx, n.timeout)
			defer cancel()
			// Announced addresses are tried in order and the round stops at
			// the first that completes: they are alternative paths to one
			// peer, not several peers.
			addrs := e.GossipAddrs()
			if n.opts.OverlayOnly {
				addrs = nil
			}
			if n.opts.OverlayAddrs != nil {
				// Last, not first: a peer's overlay address is only routable
				// once the tunnel is up, and a TCP connect into a tunnel that
				// is not would spend the whole per-peer budget waiting rather
				// than failing.
				addrs = append(addrs, n.opts.OverlayAddrs(id)...)
			}
			reached, refused := false, false
			defer func() { n.noteRound(id, reached, refused) }()
			for _, addr := range addrs {
				if pctx.Err() != nil {
					return
				}
				if err := n.SyncWith(pctx, addr, id); err != nil {
					n.logf("%v", err)
					if errors.Is(err, ErrCatchUpRefused) {
						// Its log's answer, whichever address it came by.
						refused = true
						return
					}
					continue
				}
				reached = true
				mu.Lock()
				ok++
				mu.Unlock()
				return
			}
		}()
	}
	wg.Wait()
	return ok
}

func (n *Node) noteRound(id types.Identity, reached, refused bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case reached:
		delete(n.failing, id)
		delete(n.refused, id)
	case refused:
		n.failing[id] = true
		n.refused[id] = true
	default:
		n.failing[id] = true
		delete(n.refused, id)
	}
}

// Failing reports whether the last round Sync ran against the peer reached
// none of its addresses.
func (n *Node) Failing(id types.Identity) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.failing[id]
}

// Refused reports whether the last round Sync ran against the peer ended in
// its log refusing this node a catch-up. Such a peer is also [Node.Failing].
func (n *Node) Refused(id types.Identity) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.refused[id]
}

// sessionOpts are one session's parameters. An initiator seals under force
// when it is set, and asks for a catch-up instead of sealing under an epoch
// when catchUp is; authed is called once an inbound peer has proved it may
// speak.
type sessionOpts struct {
	initiator bool
	peerID    types.Identity
	authed    func()
	force     uint64
	catchUp   bool
	// extra are records this node holds but has not applied, sent after
	// what the peer lacks of its log; see [Node.PushTo].
	extra [][]byte
}

// A sessionSeal is what one session's frames are sealed under: the epoch the
// first frame named, or for a catch-up the key its grant carried, under
// [catchUpEpoch], and the identity on the other side of it.
type sessionSeal struct {
	epoch   uint64
	catchUp *[secrets.CatchUpKeySize]byte
	with    types.Identity
}

// session runs the four-frame exchange. See the package comment for the
// ordering and why it is strictly alternating.
//
// It returns the epoch the session was sealed under.
func (n *Node) session(c net.Conn, so sessionOpts) (uint64, error) {
	var ss sessionSeal
	err := n.runSession(c, so, &ss)
	return ss.epoch, err
}

func (n *Node) runSession(c net.Conn, so sessionOpts, ss *sessionSeal) error {
	if err := c.SetDeadline(time.Now().Add(n.timeout)); err != nil {
		return err
	}
	view, err := n.opts.Log.View()
	if err != nil {
		return fmt.Errorf("reading local log state: %w", err)
	}
	var peer frame
	if so.initiator {
		peer, err = n.initiatorHello(c, so, ss, &view)
	} else {
		peer, err = n.responderHello(c, so.authed, ss, &view)
	}
	if err != nil {
		return err
	}
	if err := n.checkHello(&peer, &view); err != nil {
		return err
	}
	switch {
	case ss.catchUp == nil:
		n.notePeer(&peer, ss.epoch)
		return n.swapRecords(c, ss, &view, &peer, so.initiator, n.heard(&peer), so.extra)
	case so.initiator:
		return n.finishCatchUp(c, ss, &view, &peer)
	default:
		return n.answerCatchUp(c, ss, &view, &peer)
	}
}

// initiatorHello chooses what the session is sealed under, asking for a
// catch-up where so says to, sends this node's hello and returns the peer's.
func (n *Node) initiatorHello(c net.Conn, so sessionOpts, ss *sessionSeal, view *View) (frame, error) {
	hello := n.hello(view)
	var err error
	switch {
	case so.catchUp:
		if ss.catchUp, ss.with, err = n.askCatchUp(c, view.Network, view.Epoch); err != nil {
			return frame{}, err
		}
		// Nothing about this node or the others until the peer is known to
		// be a member; see catchup.go.
		hello.Self, hello.Endpoints = nil, nil
	case so.force != 0:
		ss.epoch = so.force
	default:
		if ss.epoch, err = n.sealEpoch(so.peerID, view.Epoch); err != nil {
			return frame{}, err
		}
		hello.Waiting = n.heldFor(view.Network, so.peerID)
	}
	if err := n.writeSealed(c, ss, &hello); err != nil {
		return frame{}, err
	}
	peer, err := n.readSealed(c, ss)
	if err != nil && !so.catchUp && (errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
		return frame{}, fmt.Errorf("%w: %w", errNoHelloBack, err)
	}
	return peer, err
}

// responderHello reads the peer's hello, granting a catch-up first where
// that is what it opens with, and answers under the same seal, so a peer
// that is behind stays able to read this node for the whole session. authed
// is called once the peer has proved it may speak.
func (n *Node) responderHello(c net.Conn, authed func(), ss *sessionSeal, view *View) (frame, error) {
	hello := n.hello(view)
	// A connection that has said nothing has proved nothing, so it gets a
	// short deadline, covering a catch-up's proof too; the full one starts
	// once its hello is in.
	if err := c.SetDeadline(time.Now().Add(min(helloTimeout, n.timeout))); err != nil {
		return frame{}, err
	}
	first, err := readBlob(c)
	if err != nil {
		return frame{}, err
	}
	var peer frame
	if isCatchUp(first) {
		if ss.catchUp, ss.with, err = n.grantCatchUp(c, first, view); err != nil {
			return frame{}, err
		}
		if err := n.authenticated(c, authed); err != nil {
			return frame{}, err
		}
		if peer, err = n.readSealed(c, ss); err != nil {
			return frame{}, err
		}
	} else {
		if peer, err = n.openSealed(first, ss); err != nil {
			return frame{}, err
		}
		// The frame opened, so the peer holds a group secret: it is a member
		// or was recently one.
		if err := n.authenticated(c, authed); err != nil {
			return frame{}, err
		}
		if id, ok := n.claimed(&peer); ok && peer.Network == view.Network {
			hello.Waiting = n.heldFor(view.Network, id)
		}
	}
	if err := n.writeSealed(c, ss, &hello); err != nil {
		return frame{}, err
	}
	return peer, nil
}

// authenticated takes an inbound peer off the budget for connections that
// have said nothing, and gives it the full session timeout.
func (n *Node) authenticated(c net.Conn, authed func()) error {
	if authed != nil {
		authed()
	}
	return c.SetDeadline(time.Now().Add(n.timeout))
}

// checkHello refuses a hello the session cannot go on from.
func (n *Node) checkHello(peer *frame, view *View) error {
	if peer.Kind != kindHello {
		return fmt.Errorf("expected a hello, got a %v frame", peer.Kind)
	}
	if peer.Network != view.Network {
		// Two networks on one LAN, or a peer whose genesis differs from
		// ours. Either way nothing it holds can apply here.
		return fmt.Errorf("peer belongs to network %v, this node to %v", peer.Network, view.Network)
	}
	if peer.Self != nil && peer.Self.Identity == n.opts.Self && peer.Self.Verify() == nil {
		// This node, reached through one of its own announced addresses: a
		// bridge address like 172.17.0.1 is identical on every host that has
		// one. The session would "succeed" against ourselves and the real
		// peer would never be synced with, with nothing that looks like a
		// failure in the logs.
		return errors.New("this session reached this node itself; the address is not unique to the peer")
	}
	return nil
}

// swapRecords sends the peer what its hello shows it missing and takes the
// records it sends back, writing first where writeFirst says to and reading
// first otherwise. changed reports that the session already cached a new
// announcement.
func (n *Node) swapRecords(c net.Conn, ss *sessionSeal, view *View, peer *frame, writeFirst, changed bool,
	extra [][]byte) error {
	reply, err := n.records(view, peer, false)
	if err != nil {
		return err
	}
	if len(extra) > 0 {
		if err := withExtra(&reply, extra); err != nil {
			return err
		}
	}
	var sent [][]byte
	if ss.catchUp == nil {
		reply.Waiting, sent = n.waitingFor(view.Network, peer, maxRecordBytesPerFrame-recordBytes(&reply))
	}
	var theirs frame
	if writeFirst {
		if err := n.writeSealed(c, ss, &reply); err != nil {
			return err
		}
		n.handed(peer, sent)
		if theirs, err = n.readRecords(c, ss, view); err != nil {
			return err
		}
	} else {
		if theirs, err = n.readRecords(c, ss, view); err != nil {
			return err
		}
		if err := n.writeSealed(c, ss, &reply); err != nil {
			return err
		}
		n.handed(peer, sent)
	}
	if n.takeEndpoints(theirs.Self, theirs.Endpoints) {
		changed = true
	}
	applied, err := n.take(&theirs)
	// After the records, which may be what a change waits on.
	if ss.catchUp == nil && n.takeWaiting(view.Network, &theirs) {
		changed = true
	}
	if applied || changed {
		n.onRecords()
	}
	return err
}

// recordBytes is what a records frame's records and leases take of its
// budget.
func recordBytes(f *frame) int {
	used := 0
	for _, b := range f.Records {
		used += len(b)
	}
	for _, b := range f.Leases {
		used += len(b)
	}
	return used
}

// answerCatchUp is the responder's side of a catch-up session past the
// hellos: its records go first, so the initiator speaks last, and only while
// the log still lists the initiator.
func (n *Node) answerCatchUp(c net.Conn, ss *sessionSeal, view *View, peer *frame) error {
	changed := n.heard(peer)
	if err := n.stillMember(ss.with); err != nil {
		return err
	}
	return n.swapRecords(c, ss, view, peer, true, changed, nil)
}

// finishCatchUp is the initiator's side of a catch-up session past the
// hellos: the peer's records first, then this node's, only once its log lists
// the peer that granted it.
func (n *Node) finishCatchUp(c net.Conn, ss *sessionSeal, view *View, peer *frame) error {
	theirs, err := n.readRecords(c, ss, view)
	if err != nil {
		return err
	}
	applied, applyErr := n.take(&theirs)
	if err := n.stillMember(ss.with); err != nil {
		if applied {
			n.onRecords()
		}
		return errors.Join(err, applyErr)
	}
	changed := n.heard(peer)
	if n.takeEndpoints(theirs.Self, theirs.Endpoints) {
		changed = true
	}
	if after, err := n.opts.Log.View(); err == nil {
		view = &after
	}
	reply, err := n.records(view, peer, true)
	if err != nil {
		return err
	}
	err = n.writeSealed(c, ss, &reply)
	if applied || changed {
		n.onRecords()
	}
	return errors.Join(err, applyErr)
}

// heard takes what a peer's hello says: which records it holds, for display,
// and its announcements, reporting whether any were new.
func (n *Node) heard(peer *frame) bool {
	if n.opts.OnHave != nil && peer.Self != nil && peer.Self.Identity != n.opts.Self && peer.Self.Verify() == nil {
		n.opts.OnHave(peer.Self.Identity, peer.Have)
	}
	return n.takeEndpoints(peer.Self, peer.Endpoints)
}

// records builds the frame answering a peer's hello: what it is missing, and
// the leases. withAnnouncements adds this node's own and the ones it holds,
// for a peer that has not had them in a hello.
func (n *Node) records(view *View, peer *frame, withAnnouncements bool) (frame, error) {
	// What the peer is missing is computed from the hello it just sent, so
	// this is the same question in both directions.
	records, err := n.opts.Log.Missing(peer.Have, peer.Anchor)
	if err != nil {
		return frame{}, fmt.Errorf("collecting records for the peer: %w", err)
	}
	reply := frame{
		Kind:    kindRecords,
		Network: view.Network,
		Epoch:   view.Epoch,
		Head:    view.Head,
		Anchor:  view.Anchor,
		Records: make([][]byte, 0, len(records)),
	}
	// Bounded by bytes as well as by count. Records are parents-first, so a
	// prefix is still applicable on its own, and the peer's next round asks
	// for the rest — where an over-long frame would fail to encode, fail the
	// same way every round, and wedge that pair's sync for good. A single
	// record always fits: [types.MaxRecordSize] is below the budget.
	budget := maxRecordBytesPerFrame
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return frame{}, fmt.Errorf("encoding record %v: %w", records[i].Hash(), err)
		}
		if len(reply.Records) > 0 && len(b) > budget {
			break
		}
		budget -= len(b)
		reply.Records = append(reply.Records, b)
	}
	if n.opts.Leases != nil {
		reply.Leases = n.opts.Leases()
		if len(reply.Leases) > MaxLeasesPerFrame {
			reply.Leases = reply.Leases[:MaxLeasesPerFrame]
		}
	}
	if withAnnouncements {
		h := n.hello(view)
		reply.Self, reply.Endpoints = h.Self, h.Endpoints
	}
	return reply, nil
}

// readRecords reads the peer's records frame.
func (n *Node) readRecords(c net.Conn, ss *sessionSeal, view *View) (frame, error) {
	theirs, err := n.readSealed(c, ss)
	if err != nil {
		return frame{}, err
	}
	if theirs.Kind != kindRecords {
		return frame{}, fmt.Errorf("expected records, got a %v frame", theirs.Kind)
	}
	if theirs.Network != view.Network {
		return frame{}, fmt.Errorf("peer's records frame names network %v, this node is %v",
			theirs.Network, view.Network)
	}
	return theirs, nil
}

// take applies a records frame's records, then its leases, which may name
// them.
func (n *Node) take(theirs *frame) (bool, error) {
	applied, err := n.apply(theirs.Records)
	if n.opts.OnLeases != nil && len(theirs.Leases) > 0 {
		n.opts.OnLeases(theirs.Leases)
	}
	return applied, err
}

func (n *Node) onRecords() {
	if n.opts.OnRecords != nil {
		n.opts.OnRecords()
	}
}

// apply decodes and offers the peer's records to the log, reporting whether
// anything was accepted. Decoding goes through types.DecodeAUM: a frame is not
// a second way to build a record. A rejected batch is reported and dropped —
// a fork, a replay or a missing ancestor is not this layer's to resolve.
func (n *Node) apply(raw [][]byte) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	if len(raw) > MaxRecordsPerFrame {
		return false, fmt.Errorf("peer sent %d records, over the %d limit", len(raw), MaxRecordsPerFrame)
	}
	// Decoding stops at the first record this build cannot read, and the
	// prefix is still offered. Records arrive parents-first, so a prefix
	// applies on its own — and after a schema upgrade the record that explains
	// why the rest is unreadable is the one immediately before them. Refusing
	// the batch whole would leave a node that only saw sync stop.
	records := make([]types.AUM, 0, len(raw))
	var stopped error
	for _, b := range raw {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			stopped = fmt.Errorf("peer sent a record this build cannot read: %w", err)
			break
		}
		records = append(records, aum)
	}
	if len(records) == 0 {
		return false, stopped
	}
	if err := n.opts.Log.Inform(records); err != nil {
		return false, fmt.Errorf("offering %d records to the log: %w", len(records), err)
	}
	return true, stopped
}

// takeEndpoints verifies and caches announcements, reporting whether any were
// new. One that does not verify is dropped and logged without ending the
// session: the relaying peer is not necessarily its author, and the good ones
// in the same frame are still good.
func (n *Node) takeEndpoints(self *Endpoint, relayed []Endpoint) bool {
	eps := relayed
	if self != nil {
		eps = append([]Endpoint{*self}, relayed...)
	}
	changed := false
	for i := range eps {
		e := eps[i]
		if e.Identity == n.opts.Self {
			// Our own announcement, echoed back. We are the authority on it.
			continue
		}
		if err := e.Verify(); err != nil {
			n.logf("gossip: dropping an announcement: %v", err)
			continue
		}
		if n.opts.Endpoints.Add(e) {
			changed = true
		}
	}
	return changed
}

// hello builds this node's opening frame: its beacon, what it holds, and every
// announcement it knows including its own.
func (n *Node) hello(view *View) frame {
	f := frame{
		Kind:    kindHello,
		Network: view.Network,
		Epoch:   view.Epoch,
		Head:    view.Head,
		Anchor:  view.Anchor,
		Have:    view.Have,
	}
	if len(f.Have) > MaxHashesPerFrame {
		// Which ones survive is arbitrary — the store reports by hash, not by
		// chain position — which costs bandwidth and never correctness: a
		// peer that cannot see we hold a record sends it again.
		f.Have = f.Have[:MaxHashesPerFrame]
	}
	if n.opts.Announce != nil {
		if mine, ok := n.opts.Announce(); ok {
			f.Self = &mine
		}
	}
	eps := n.opts.Endpoints.All()
	if len(eps) > MaxEndpointsPerFrame {
		eps = eps[:MaxEndpointsPerFrame]
	}
	f.Endpoints = eps
	return f
}

// notePeer records the epoch this session ran under against the peer that
// authored the session's Self announcement, so the next push to it is sealed
// under an epoch it can open.
//
// sealEpoch must be the epoch the session was sealed under, which taking part
// authenticated — never the frame's plaintext beacon, which one crafted hello
// could pin at 2^64-1. Only the frame's own Self names the peer, a remembered
// epoch is never lowered, and entry is gated by membership so that minted
// identities cannot fill this bounded map.
func (n *Node) notePeer(peer *frame, sealEpoch uint64) {
	if peer.Self == nil || peer.Self.Identity == n.opts.Self {
		return
	}
	if err := peer.Self.Verify(); err != nil {
		return
	}
	id := peer.Self.Identity
	if n.opts.Endpoints.IsFormer(id) {
		// A device the log has dropped. Its frames still open for the keyring
		// window, but the only thing a remembered epoch buys is a push to it,
		// and this node no longer pushes to a former member.
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, known := n.peerEpoch[id]; !known && len(n.peerEpoch) >= maxRememberedPeers {
		// Full: a member displaces a non-member, as in the announcement cache.
		// Waiting for room costs a non-member nothing — an unknown epoch
		// means a push under this node's own.
		if !n.opts.Endpoints.IsMember(id) || !n.evictNonMemberEpochLocked() {
			return
		}
	}
	if sealEpoch > n.peerEpoch[id] {
		n.peerEpoch[id] = sealEpoch
	}
}

// evictNonMemberEpochLocked drops one non-member's remembered epoch so a
// member can take its slot, reporting whether it freed one. The caller holds
// n.mu. The bound is 2*[types.MaxNodes], so a full map always holds one.
func (n *Node) evictNonMemberEpochLocked() bool {
	for id := range n.peerEpoch {
		if !n.opts.Endpoints.IsMember(id) {
			delete(n.peerEpoch, id)
			return true
		}
	}
	return false
}

// maxRememberedPeers bounds [Node.peerEpoch]. Two per member, matching the
// announcement cache's bound and for the same reason: room for every member of
// a full network plus the ones this node has not yet learned about.
const maxRememberedPeers = 2 * types.MaxNodes

// sealEpoch picks the epoch a frame to a peer is sealed under: the peer's, if
// this node still holds that secret, and otherwise its own.
func (n *Node) sealEpoch(peerID types.Identity, own uint64) (uint64, error) {
	n.mu.Lock()
	theirs, known := n.peerEpoch[peerID]
	n.mu.Unlock()
	if known && theirs < own {
		if _, held := n.opts.Keyring.Secret(theirs); held {
			return theirs, nil
		}
	}
	if _, held := n.opts.Keyring.Secret(own); held {
		return own, nil
	}
	latest, _, ok := n.opts.Keyring.Latest()
	if !ok {
		return 0, errNoEpochHeld
	}
	return latest, nil
}

// --- stream framing --------------------------------------------------------

// Frames on the stream are length-prefixed sealed blobs. The prefix is
// checked against the sealed-size limit before a single byte is buffered, so
// a peer cannot announce a gigabyte and have this node try to hold it.
func (n *Node) writeSealed(c net.Conn, ss *sessionSeal, f *frame) error {
	pt, err := encode(f)
	if err != nil {
		return err
	}
	var blob []byte
	if ss.catchUp != nil {
		blob, err = aead.Seal(*ss.catchUp, catchUpEpoch, pt)
	} else {
		s, ok := n.opts.Keyring.Secret(ss.epoch)
		if !ok {
			return fmt.Errorf("gossip: no secret for epoch %d, which this session is sealed under", ss.epoch)
		}
		blob, err = seal(s, ss.epoch, pt)
	}
	if err != nil {
		return err
	}
	return writeBlob(c, blob, f.Kind.String())
}

func writeBlob(c net.Conn, blob []byte, what string) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := c.Write(hdr[:]); err != nil {
		return fmt.Errorf("gossip: writing a %v frame: %w", what, err)
	}
	if _, err := c.Write(blob); err != nil {
		return fmt.Errorf("gossip: writing a %v frame: %w", what, err)
	}
	return nil
}

// readSealed reads one frame. A session sealed under an epoch takes it from
// its first frame and holds every later one to it, so a session cannot be
// walked from one epoch's key to another's.
func (n *Node) readSealed(c net.Conn, ss *sessionSeal) (frame, error) {
	blob, err := readBlob(c)
	if err != nil {
		return frame{}, err
	}
	return n.openSealed(blob, ss)
}

func (n *Node) openSealed(blob []byte, ss *sessionSeal) (frame, error) {
	if ss.catchUp != nil {
		if len(blob) > maxSealedSize {
			return frame{}, fmt.Errorf("gossip: sealed frame is %d bytes, over the %d limit", len(blob), maxSealedSize)
		}
		if !isCatchUp(blob) {
			return frame{}, errors.New("gossip: a catch-up session's frame is sealed under an epoch")
		}
		pt, err := aead.Open(*ss.catchUp, blob)
		if err != nil {
			return frame{}, fmt.Errorf("gossip: catch-up frame: %w", err)
		}
		return decodeFrame(pt)
	}
	got, pt, err := open(n.opts.Keyring, blob)
	if err != nil {
		return frame{}, err
	}
	if ss.epoch == 0 {
		ss.epoch = got
	} else if got != ss.epoch {
		return frame{}, fmt.Errorf("gossip: session began at epoch %d and this frame is sealed under %d",
			ss.epoch, got)
	}
	return decodeFrame(pt)
}

// readBlob reads one length-prefixed blob off the stream.
func readBlob(c net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, fmt.Errorf("gossip: reading a frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > maxSealedSize {
		return nil, fmt.Errorf("gossip: peer announced a %d-byte frame, over the %d limit",
			size, maxSealedSize)
	}
	// Grown as bytes arrive, never allocated from the announced size: that
	// size is an unauthenticated claim, and trusting it lets a peer hold
	// hundreds of megabytes here by announcing frames it never sends.
	blob, err := readN(c, int(size))
	if err != nil {
		return nil, fmt.Errorf("gossip: reading a frame body: %w", err)
	}
	return blob, nil
}

// readN reads exactly n bytes, growing its buffer as they arrive, so an
// announced size costs nothing until bytes back it.
func readN(r io.Reader, n int) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(min(n, 32<<10))
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
