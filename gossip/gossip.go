// Package gossip is the sync layer: it moves membership-log records and
// connectivity announcements between members over transports it does not
// trust.
//
// Nothing here is trust-critical. Log records carry their own signatures and
// their own hash chain, and endpoint announcements carry a signature by the
// node they describe, so a hostile transport — or a hostile peer — can delay,
// drop, duplicate or reorder what it moves and can never change who is a
// member. That is the property docs/04-architecture.md states as "AUMs are
// self-certifying, so they may arrive over *any* transport", and it is why
// this package sits outside the audit scope while still owning a parser that
// faces attacker input (hence its fuzz targets, docs/06-verification.md §2).
//
// # The protocol
//
// One TCP session per anti-entropy round, four frames, strictly alternating so
// that neither side can block on a write the other is not reading:
//
//	initiator → hello    what network, where my chain is, what I hold
//	responder → hello    the same, answered
//	initiator → records  what the responder turned out to be missing
//	responder → records  what the initiator turned out to be missing
//
// Every frame is a log-head beacon in the sense docs/04-architecture.md
// describes: it carries the sender's `(epoch, head)` whether or not anything
// needs to be transferred. Sync is symmetric — one round makes both sides
// whole — because the alternative, each node pulling separately, doubles the
// rounds a revocation needs to reach a five-node mesh.
//
// The "what I hold" set is sent outright rather than walked back to a common
// ancestor. At this milestone's scale a whole log is a few kilobytes of
// hashes, and sending it makes the exchange stateless and immune to the branch
// bookkeeping an ancestor walk needs. [MaxHashesPerFrame] is where that stops
// being true, and a node past it falls back to converging over several rounds.
//
// # Why the underlay
//
// docs/04-architecture.md calls WireGuard tunnels the normal case for carrying
// records and this package the exception. At M2 it is the other way round:
// gossip runs on the underlay, because reaching a peer *over* the overlay
// needs the tunnel that gossip is what brings up. The layering is unchanged —
// records are self-certifying either way — and the cost is metadata, which
// [seal] covers by encrypting every frame under the epoch group secret. See
// docs/09-mesh-layer-notes.md.
package gossip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

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

	// Anchor is the record this node's chain is resolved from: its genesis,
	// or the newest checkpoint it has compacted to. Peers answer [Log.Missing]
	// relative to it, because records below it are ones this node's log will
	// refuse — see the field of the same name in the frame.
	Anchor types.Hash

	// Have is every record hash this node holds, including branches that
	// lost fork choice. Branches are included on purpose: a fork is
	// something both sides need to see in full before either can alarm on
	// it (docs/08-trust-layer-notes.md).
	Have []types.Hash
}

// A Log is the membership log as gossip needs it.
//
// It is an interface so that this package depends on behaviour rather than on
// trust/log's Authority, which keeps the sync layer out of the trust layer's
// import graph in the direction that matters: the log must be usable without
// a network, and it is the daemon that owns both and joins them.
type Log interface {
	// View reports this node's beacon and the records it holds.
	View() (View, error)

	// Missing returns records this node holds that the peer lacks and can
	// accept: descendants of the peer's anchor absent from have, ordered so
	// that every record's parent precedes it, and no more than
	// [MaxRecordsPerFrame] of them. A peer whose anchor this node does not
	// hold gets nothing — that peer is the one with history to offer, and
	// the other half of the same session is where it offers it.
	Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error)

	// Inform hands received records to the log, oldest first. An error is
	// expected in normal operation — a peer on a forked chain, a rollback
	// attempt, a record whose ancestors have not arrived yet — and is
	// reported, not fatal.
	Inform(records []types.AUM) error
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
	Keyring *secrets.Keyring

	// Endpoints is the announcement cache, shared with the reconciler.
	Endpoints *Cache

	// Announce returns this node's current announcement, or false if it has
	// none yet. Called per session, so it always reflects the live one.
	Announce func() (Endpoint, bool)

	// Listener accepts inbound sessions. Required.
	Listener net.Listener

	// Dial opens an outbound session. Nil uses a plain TCP dialer.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

	// Timeout bounds one session end to end. Zero uses [DefaultTimeout].
	Timeout time.Duration

	// OnRecords is called after a session accepted log records, so the
	// daemon can reconcile without waiting for its next tick. It must not
	// block for long; it runs on the session's goroutine.
	OnRecords func()

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// DefaultTimeout bounds one anti-entropy session. Generous for a LAN, and
// short enough that a peer that has gone away does not hold a slot until TCP
// gives up on its own.
const DefaultTimeout = 20 * time.Second

// maxInboundSessions bounds concurrent inbound sessions, so that a peer
// opening connections cannot make this node hold unbounded state. Excess
// connections are closed immediately rather than queued: the peer retries on
// its own timer, and a queue would only move the same limit somewhere less
// visible.
const maxInboundSessions = 16

// maxOutboundSessions bounds how many peers one [Node.Sync] call talks to at
// once. A round with the whole member set is the normal case at this scale;
// the limit is what stops a large network turning one local change into
// hundreds of simultaneous dials.
const maxOutboundSessions = 16

// A Node runs anti-entropy for one member.
type Node struct {
	opts    Options
	timeout time.Duration
	logf    func(string, ...any)

	// slots bounds inbound concurrency; a token is held for a session's
	// lifetime.
	slots chan struct{}

	// closing, and the wait set it guards, are the shutdown handshake.
	// sync.WaitGroup forbids an Add that takes the counter off zero from
	// racing a Wait, and that is exactly what an inbound session starting
	// while Close is draining would be — so the flag is checked and the Add
	// performed under one lock.
	closeOnce sync.Once
	closed    chan struct{}
	trackMu   sync.Mutex
	closing   bool
	wg        sync.WaitGroup

	// peerEpoch remembers the epoch each peer last spoke, so that a frame
	// pushed to a peer that has not yet caught up is sealed under an epoch
	// it can still open. Without it, the very push that carries a
	// revocation's epoch bump would be unreadable to every member that has
	// not already applied it.
	//
	// The value stored is the *authenticated* seal epoch of a session with the
	// peer — an epoch it demonstrably held, since it opened or sealed a frame
	// under it — never the frame's plaintext Epoch beacon, which is
	// attacker-chosen and decoupled from Self. Entry is gated by membership
	// exactly as the announcement cache is, so a flood of minted identities
	// cannot fill the map and lock every real peer out; see [Node.notePeer].
	mu        sync.Mutex
	peerEpoch map[types.Identity]uint64
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
	}
	n := &Node{
		opts:      opts,
		timeout:   cmpOr(opts.Timeout, DefaultTimeout),
		logf:      opts.Logf,
		slots:     make(chan struct{}, maxInboundSessions),
		closed:    make(chan struct{}),
		peerEpoch: map[types.Identity]uint64{},
	}
	if n.logf == nil {
		n.logf = func(string, ...any) {}
	}
	if n.opts.Dial == nil {
		n.opts.Dial = dialTCP
	}
	return n, nil
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
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
			// A transient accept error (fd exhaustion, a connection reset
			// between accept and return) must not end the loop: this is the
			// only way a member is reachable, and a node that stops
			// accepting is a node that silently drops out of the mesh.
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
		go func() {
			defer n.wg.Done()
			defer func() { <-n.slots }()
			defer c.Close()
			if err := n.session(c, false, types.Identity{}); err != nil {
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

// SyncWith runs one anti-entropy session against a peer.
//
// peerID may be zero when the peer is not known yet, in which case the frame
// is sealed under this node's own current epoch. Knowing it is what lets the
// push after a locally authored change reach members that are one epoch
// behind — which is every member, immediately after an epoch bump.
func (n *Node) SyncWith(ctx context.Context, addr netip.AddrPort, peerID types.Identity) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	c, err := n.opts.Dial(ctx, addr)
	if err != nil {
		return fmt.Errorf("gossip: dialing %v: %w", addr, err)
	}
	defer c.Close()
	// Unblock the session's blocking reads and writes when the context ends;
	// a peer that accepts a connection and then says nothing must not hold
	// this goroutine past the timeout.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err := n.session(c, true, peerID); err != nil {
		return fmt.Errorf("gossip: session with %v: %w", addr, err)
	}
	return nil
}

// Sync runs one round against every peer it can reach, concurrently, and
// returns how many sessions succeeded.
//
// peers names who to talk to; the daemon supplies the current member set so
// that a revoked device's cached announcement is not dialled. Failures are
// logged rather than returned: on a LAN a peer being asleep is the common
// case, not an error the caller can act on.
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
			// One peer gets one session's worth of time across all its
			// addresses, however many it announced. Without the budget an
			// announcement of [MaxEndpointAddrs] unreachable addresses costs
			// every member that many full timeouts per round — and since the
			// addresses are the announcer's to choose, that turns the member
			// set into a sustained connection flood aimed wherever it likes.
			// An announcement may cost its author reachability; it must not
			// cost a third party.
			pctx, cancel := context.WithTimeout(ctx, n.timeout)
			defer cancel()
			// Announced addresses are tried in order and the round stops at
			// the first that completes: they are alternative paths to one
			// peer, not several peers.
			for _, addr := range e.GossipAddrs() {
				if pctx.Err() != nil {
					return
				}
				if err := n.SyncWith(pctx, addr, id); err != nil {
					n.logf("%v", err)
					continue
				}
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

// session runs the four-frame exchange. See the package comment for the
// ordering and why it is strictly alternating.
func (n *Node) session(c net.Conn, initiator bool, peerID types.Identity) error {
	if err := c.SetDeadline(time.Now().Add(n.timeout)); err != nil {
		return err
	}
	view, err := n.opts.Log.View()
	if err != nil {
		return fmt.Errorf("reading local log state: %w", err)
	}

	var (
		epoch uint64 // the epoch the whole session is sealed under
		peer  frame
	)
	hello := n.hello(&view)

	if initiator {
		if epoch, err = n.sealEpoch(peerID, view.Epoch); err != nil {
			return err
		}
		if err := n.writeFrame(c, epoch, &hello); err != nil {
			return err
		}
		if peer, err = n.readFrame(c, &epoch); err != nil {
			return err
		}
	} else {
		if peer, err = n.readFrame(c, &epoch); err != nil {
			return err
		}
		// The reply goes out under the epoch the request came in on, so a
		// peer that is behind stays able to read us for the whole session.
		if err := n.writeFrame(c, epoch, &hello); err != nil {
			return err
		}
	}
	if peer.Kind != kindHello {
		return fmt.Errorf("expected a hello, got a %v frame", peer.Kind)
	}
	if peer.Network != view.Network {
		// Two networks on one LAN, or a peer whose genesis differs from
		// ours. Either way nothing it holds can apply here.
		return fmt.Errorf("peer belongs to network %v, this node to %v", peer.Network, view.Network)
	}
	if peer.Self != nil && peer.Self.Identity == n.opts.Self && peer.Self.Verify() == nil {
		// This node, reached through one of its own announced addresses. An
		// address a node announces is not necessarily unique to it: a bridge
		// address like 172.17.0.1 is identical on every host that has one, so
		// dialling a peer there reaches the local listener instead. The
		// session would then "succeed" against ourselves, and because
		// [Node.Sync] stops a peer's address list at the first address that
		// completes, the real peer would never be synced with — permanently,
		// and with nothing in the logs that looks like a failure.
		return errors.New("this session reached this node itself; the address is not unique to the peer")
	}
	n.notePeer(&peer, epoch)
	changed := n.takeEndpoints(peer.Self, peer.Endpoints)

	// What the peer is missing is computed from the hello it just sent, so
	// this is the same question in both directions.
	records, err := n.opts.Log.Missing(peer.Have, peer.Anchor)
	if err != nil {
		return fmt.Errorf("collecting records for the peer: %w", err)
	}
	reply := frame{
		Kind:    kindRecords,
		Network: view.Network,
		Epoch:   view.Epoch,
		Head:    view.Head,
		Anchor:  view.Anchor,
		Records: make([][]byte, 0, len(records)),
	}
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return fmt.Errorf("encoding record %v: %w", records[i].Hash(), err)
		}
		reply.Records = append(reply.Records, b)
	}

	var theirs frame
	if initiator {
		if err := n.writeFrame(c, epoch, &reply); err != nil {
			return err
		}
		if theirs, err = n.readFrame(c, &epoch); err != nil {
			return err
		}
	} else {
		if theirs, err = n.readFrame(c, &epoch); err != nil {
			return err
		}
		if err := n.writeFrame(c, epoch, &reply); err != nil {
			return err
		}
	}
	if theirs.Kind != kindRecords {
		return fmt.Errorf("expected records, got a %v frame", theirs.Kind)
	}
	if theirs.Network != view.Network {
		return fmt.Errorf("peer's records frame names network %v, this node is %v",
			theirs.Network, view.Network)
	}
	if n.takeEndpoints(theirs.Self, theirs.Endpoints) {
		changed = true
	}

	applied, err := n.apply(theirs.Records)
	if applied || changed {
		if n.opts.OnRecords != nil {
			n.opts.OnRecords()
		}
	}
	return err
}

// apply decodes and offers the peer's records to the log, reporting whether
// anything was accepted.
//
// Decoding goes through types.DecodeAUM, which enforces the canonical encoding
// the chain rests on; a frame is not a second way to build a record. A batch
// the log rejects is reported and dropped: the peer may be on a fork, may be
// replaying, or may simply have sent a record whose ancestors have not arrived
// yet, and none of those are this layer's to resolve.
func (n *Node) apply(raw [][]byte) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	if len(raw) > MaxRecordsPerFrame {
		return false, fmt.Errorf("peer sent %d records, over the %d limit", len(raw), MaxRecordsPerFrame)
	}
	records := make([]types.AUM, 0, len(raw))
	for _, b := range raw {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return false, fmt.Errorf("peer sent an undecodable record: %w", err)
		}
		records = append(records, aum)
	}
	if err := n.opts.Log.Inform(records); err != nil {
		return false, fmt.Errorf("offering %d records to the log: %w", len(records), err)
	}
	return true, nil
}

// takeEndpoints verifies and caches announcements, reporting whether any were
// new.
//
// An announcement that does not verify is dropped, logged, and does not end
// the session. The peer relaying it is not necessarily its author — relays
// forward from their caches — and integrity never rested on the transport
// anyway: a bad announcement admitted nothing, and the good ones in the same
// frame are still good.
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
		// Which ones survive is arbitrary: the set arrives in whatever order
		// the store reports, which is by hash and not by position in the
		// chain. That costs bandwidth and never correctness — a peer that
		// cannot see we hold a record simply sends it again, and the log
		// discards what it already has. A log this long is well past the
		// scale this milestone targets; ordering the set by chain position,
		// so that truncation keeps recent history, is the fix if it ever
		// matters, and it costs a chain resolution per beacon.
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
// sealEpoch is the epoch the whole session was sealed under. It is
// authenticated: to take part in the session the peer had to open a frame under
// it (as responder) or reply under it (as initiator), which it can only do
// holding that epoch's secret. The frame's plaintext Epoch beacon is used for
// nothing here — it is not covered by any signature and is decoupled from Self,
// so trusting it let a single crafted hello pin this value at 2^64-1 and defeat
// the epoch-skew push accommodation for a targeted peer.
//
// Only the frame's own Self announcement names the peer: the relayed ones
// describe other nodes, whose epochs this session says nothing about. Never
// lowering a remembered epoch keeps a stale relayed view from undoing what a
// live session established.
//
// Entry is gated by membership the same way [Cache.Add] gates the announcement
// cache, and for the same reason: an announcement is self-signed and identity
// keys cost nothing to mint, so without the gate a flood of invented
// identities would fill this map and — with no way to grow past the bound —
// lock every real peer out of it permanently, sending all their pushes under
// this node's own epoch and dropping revocation convergence back to the
// anti-entropy timer.
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
		// Full. A member's entry displaces a non-member's, exactly as in the
		// announcement cache; a subject that is not yet a member waits for
		// room, which costs it nothing — an unknown epoch means a push under
		// this node's own, and a just-admitted member is on this node's own
		// epoch anyway.
		if !n.opts.Endpoints.IsMember(id) || !n.evictNonMemberEpochLocked() {
			return
		}
	}
	if sealEpoch > n.peerEpoch[id] {
		n.peerEpoch[id] = sealEpoch
	}
}

// evictNonMemberEpochLocked drops one non-member's remembered epoch, so a
// member can take its slot. It reports whether it freed one. The caller holds
// n.mu.
//
// The bound is 2*[types.MaxNodes], so a full map always holds at least one
// non-member and this cannot fail to free a slot for a genuine member.
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
		return 0, errors.New("this node holds no epoch secret, so it cannot gossip; " +
			"it is not a member of the epoch its log resolves to")
	}
	return latest, nil
}

// --- stream framing --------------------------------------------------------

// Frames on the stream are length-prefixed sealed blobs. The prefix is
// checked against the sealed-size limit before a single byte is buffered, so
// a peer cannot announce a gigabyte and have this node try to hold it.
func (n *Node) writeFrame(c net.Conn, epoch uint64, f *frame) error {
	pt, err := encode(f)
	if err != nil {
		return err
	}
	s, ok := n.opts.Keyring.Secret(epoch)
	if !ok {
		return fmt.Errorf("gossip: no secret for epoch %d, which this session is sealed under", epoch)
	}
	blob, err := seal(s, epoch, pt)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := c.Write(hdr[:]); err != nil {
		return fmt.Errorf("gossip: writing a %v frame: %w", f.Kind, err)
	}
	if _, err := c.Write(blob); err != nil {
		return fmt.Errorf("gossip: writing a %v frame: %w", f.Kind, err)
	}
	return nil
}

// readFrame reads one frame. epoch is both an input and an output: on the
// first call of a session it is zero and takes the epoch the peer sealed
// under, and afterwards it is checked, so that a session cannot be walked from
// one epoch's key to another's mid-exchange.
func (n *Node) readFrame(c net.Conn, epoch *uint64) (frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return frame{}, fmt.Errorf("gossip: reading a frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > maxSealedSize {
		return frame{}, fmt.Errorf("gossip: peer announced a %d-byte frame, over the %d limit",
			size, maxSealedSize)
	}
	// Grown as the bytes arrive rather than allocated from the announced
	// size. The size is the peer's claim and nothing has authenticated it
	// yet, so trusting it would let one peer that opens the maximum number
	// of sessions, announces the maximum frame in each and then sends
	// nothing hold hundreds of megabytes here until the deadline. Growing
	// on receipt makes the memory cost what the peer actually sent.
	blob, err := readN(c, int(size))
	if err != nil {
		return frame{}, fmt.Errorf("gossip: reading a frame body: %w", err)
	}
	got, pt, err := open(n.opts.Keyring, blob)
	if err != nil {
		return frame{}, err
	}
	if *epoch == 0 {
		*epoch = got
	} else if got != *epoch {
		return frame{}, fmt.Errorf("gossip: session began at epoch %d and this frame is sealed under %d",
			*epoch, got)
	}
	return decodeFrame(pt)
}

// readN reads exactly n bytes, growing its buffer as they arrive.
//
// The caller has already checked n against the format's limit; what this adds
// is that an announced size costs nothing until it is backed by bytes on the
// wire. io.ReadFull into a pre-sized buffer would let the announcement itself
// be the allocation.
func readN(r io.Reader, n int) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(min(n, 32<<10))
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
