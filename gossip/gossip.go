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
// exchange stateless up to [MaxHashesPerFrame].
//
// Gossip runs on the underlay, since reaching a peer over the overlay needs
// the tunnel gossip brings up; [seal] covers the metadata that costs.
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
	"slices"
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

	// OverlayAddrs returns addresses to try after the ones a peer announced —
	// in practice its overlay addresses, which become reachable once the
	// tunnel is up. It is what lets two members behind NAT sync directly:
	// neither can open a TCP session to the other on the underlay, and the
	// tunnel that carries it is brought up by the connectivity layer rather
	// than by this one. Nil tries only what the announcement carries.
	OverlayAddrs func(types.Identity) []netip.AddrPort

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
	opts    Options
	timeout time.Duration
	logf    func(string, ...any)

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

	// unauth holds, per source address and oldest first, the inbound
	// connections that have not yet opened a frame under the group secret.
	// Guarded by mu.
	unauth map[netip.Addr][]*unauthConn
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

// unauthConn is one inbound connection that has not authenticated yet. It is
// identified by pointer, so eviction and release cannot confuse two
// connections from the same address.
type unauthConn struct{ c net.Conn }

// admitUnauth records a connection as not yet having said anything, evicting
// the oldest such connection from the same address if that address is over
// [maxUnauthPerSource]. Closing one unblocks its read, so its session ends and
// its slot comes back.
func (n *Node) admitUnauth(src netip.Addr, c net.Conn) *unauthConn {
	e := &unauthConn{c: c}
	n.mu.Lock()
	if n.unauth == nil {
		n.unauth = map[netip.Addr][]*unauthConn{}
	}
	q := n.unauth[src]
	var evicted []*unauthConn
	for len(q) >= maxUnauthPerSource {
		evicted = append(evicted, q[0])
		q = q[1:]
	}
	n.unauth[src] = append(q, e)
	n.mu.Unlock()

	// Closed outside the lock: Close and the logger are both other people's
	// code, and neither belongs inside a mutex the session path takes.
	for _, old := range evicted {
		n.logf("gossip: closing a silent connection from %v: %d from that address are "+
			"already waiting to speak", old.c.RemoteAddr(), maxUnauthPerSource)
		old.c.Close()
	}
	return e
}

// releaseUnauth takes a connection off the silent budget. Safe to call twice
// and safe on one already evicted: the session releases the moment its peer
// authenticates, and the accept loop releases whatever is left afterwards.
func (n *Node) releaseUnauth(src netip.Addr, e *unauthConn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	q := n.unauth[src]
	i := slices.Index(q, e)
	if i < 0 {
		return
	}
	q = slices.Delete(q, i, i+1)
	if len(q) == 0 {
		delete(n.unauth, src)
		return
	}
	n.unauth[src] = q
}

// sourceAddr reduces a remote address to the host it came from. An address
// that does not parse counts as one source, which is the safe direction: it
// shares a budget rather than escaping one.
func sourceAddr(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(t.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
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
		src := sourceAddr(c.RemoteAddr())
		silent := n.admitUnauth(src, c)
		go func() {
			defer n.wg.Done()
			defer func() { <-n.slots }()
			defer n.releaseUnauth(src, silent)
			defer c.Close()
			authed := func() { n.releaseUnauth(src, silent) }
			if err := n.session(c, false, types.Identity{}, authed); err != nil {
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
	if err := n.session(c, true, peerID, nil); err != nil {
		return fmt.Errorf("gossip: session with %v: %w", addr, err)
	}
	return nil
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
			if n.opts.OverlayAddrs != nil {
				// Last, not first: a peer's overlay address is only routable
				// once the tunnel is up, and a TCP connect into a tunnel that
				// is not would spend the whole per-peer budget waiting rather
				// than failing.
				addrs = append(addrs, n.opts.OverlayAddrs(id)...)
			}
			for _, addr := range addrs {
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
func (n *Node) session(c net.Conn, initiator bool, peerID types.Identity, authed func()) error {
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
		// A connection that has said nothing has proved nothing, so it gets a
		// short deadline; the full one starts once its hello is in.
		if err := c.SetDeadline(time.Now().Add(min(helloTimeout, n.timeout))); err != nil {
			return err
		}
		if peer, err = n.readFrame(c, &epoch); err != nil {
			return err
		}
		// The frame opened, so the peer holds a group secret: it is a member
		// or was recently one, and it stops counting against the budget for
		// connections that have said nothing.
		if authed != nil {
			authed()
		}
		if err := c.SetDeadline(time.Now().Add(n.timeout)); err != nil {
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
		// This node, reached through one of its own announced addresses: a
		// bridge address like 172.17.0.1 is identical on every host that has
		// one. The session would "succeed" against ourselves and the real
		// peer would never be synced with, with nothing that looks like a
		// failure in the logs.
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
	// Bounded by bytes as well as by count. Records are parents-first, so a
	// prefix is still applicable on its own, and the peer's next round asks
	// for the rest — where an over-long frame would fail to encode, fail the
	// same way every round, and wedge that pair's sync for good. A single
	// record always fits: [types.MaxRecordSize] is below the budget.
	budget := maxRecordBytesPerFrame
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return fmt.Errorf("encoding record %v: %w", records[i].Hash(), err)
		}
		if len(reply.Records) > 0 && len(b) > budget {
			break
		}
		budget -= len(b)
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

// readFrame reads one frame. epoch is in and out: zero on a session's first
// call, taking the epoch the peer sealed under, and checked afterwards, so a
// session cannot be walked from one epoch's key to another's.
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
	// Grown as bytes arrive, never allocated from the announced size: that
	// size is an unauthenticated claim, and trusting it lets a peer hold
	// hundreds of megabytes here by announcing frames it never sends.
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
