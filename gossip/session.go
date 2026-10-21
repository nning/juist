package gossip

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

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
		if so.initiator {
			n.takePair(&peer)
		}
		changed := n.heard(&peer)
		return n.swapRecords(c, ss, &view, &peer, so.initiator, changed, so.extra)
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
		if ss.catchUp, ss.with, err = n.askCatchUp(c, view); err != nil {
			return frame{}, err
		}
		// Nothing about this node or the others until the peer is known to
		// be a member; see catchup.go.
		hello.Self, hello.Endpoints, hello.Keys, hello.Seen = nil, nil, nil, nil
	case so.force != 0:
		ss.epoch = so.force
	default:
		if ss.epoch, err = n.sealEpoch(so.peerID, view.Epoch); err != nil {
			return frame{}, err
		}
		hello.Waiting = n.heldFor(view.Network, so.peerID)
	}
	if !so.catchUp {
		hello.Pair = n.pairFor(so.peerID)
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
	var waiting []byte
	var pair *pairkey.Msg
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
			n.takePair(&peer)
			waiting, pair = n.heldFor(view.Network, id), n.pairFor(id)
		}
	}
	hello := n.hello(view)
	hello.Waiting, hello.Pair = waiting, pair
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
func (n *Node) swapRecords(c net.Conn, ss *sessionSeal, view *View, peer *frame, writeFirst bool, changed Change,
	extra [][]byte) error {
	reply, err := n.records(view, peer)
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
	with, _ := n.claimed(peer)
	if ss.catchUp != nil {
		with = types.Identity{}
	}
	if writeFirst {
		reply.Pair = n.pairFor(with)
		if err := n.writeSealed(c, ss, &reply); err != nil {
			return err
		}
		n.handed(peer, sent)
		if theirs, err = n.readRecords(c, ss, view); err != nil {
			return err
		}
		n.takePair(&theirs)
	} else {
		if theirs, err = n.readRecords(c, ss, view); err != nil {
			return err
		}
		n.takePair(&theirs)
		reply.Pair = n.pairFor(with)
		if err := n.writeSealed(c, ss, &reply); err != nil {
			return err
		}
		n.handed(peer, sent)
	}
	changed = max(changed, n.takeEndpoints(theirs.Self, theirs.Endpoints, theirs.Keys))
	applied, err := n.take(&theirs)
	// After the records, which may be what a change waits on.
	if ss.catchUp == nil && n.takeWaiting(view.Network, &theirs) {
		changed = Changed
	}
	n.onNews(applied, changed)
	return err
}

// pairFor is this node's message to id in the exchange of a preshared key,
// or nil.
func (n *Node) pairFor(id types.Identity) *pairkey.Msg {
	if n.opts.Pair == nil || id.IsZero() || id == n.opts.Self {
		return nil
	}
	return n.opts.Pair(id)
}

// takePair hands the daemon a peer's message to this node in the exchange of
// a preshared key.
func (n *Node) takePair(f *frame) {
	if f.Pair != nil && f.Pair.To == n.opts.Self && n.opts.OnPair != nil {
		n.opts.OnPair(f.Pair)
	}
}

// recordBytes is what a records frame's records, leases and address keys
// take of its budget.
func recordBytes(f *frame) int {
	used := keyBytes(f.Keys)
	for _, b := range f.Records {
		used += len(b)
	}
	for _, b := range f.Leases {
		used += len(b)
	}
	return used
}

// keyBytes bounds what keys take of a frame: their wraps, and each its
// signatures and fields.
func keyBytes(keys []AddrKey) int {
	n := 0
	for i := range keys {
		n += len(keys[i].Wraps)*addrkey.WrapSize + types.PQSigSize + types.SigSize + 256
	}
	return n
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
	changed := max(n.heard(peer), n.takeEndpoints(theirs.Self, theirs.Endpoints, theirs.Keys))
	if after, err := n.opts.Log.View(); err == nil {
		view = &after
	}
	reply, err := n.records(view, peer)
	if err != nil {
		return err
	}
	n.announceIn(&reply)
	err = n.writeSealed(c, ss, &reply)
	n.onNews(applied, changed)
	return errors.Join(err, applyErr)
}

// heard takes what a peer's hello says: its head, its anchor and which records
// it holds, and its announcements, reporting whether any were new.
func (n *Node) heard(peer *frame) Change {
	if n.opts.OnHave != nil && peer.Self != nil && peer.Self.Identity != n.opts.Self && peer.Self.Verify() == nil {
		n.opts.OnHave(peer.Self.Identity, peer.Head, peer.Anchor, peer.Have)
	}
	return n.takeEndpoints(peer.Self, peer.Endpoints, peer.Keys)
}

// records builds the frame answering a peer's hello: what it is missing, and
// the leases.
func (n *Node) records(view *View, peer *frame) (frame, error) {
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
	if n.seenAlone() {
		n.newerThanSeen(&reply, peer)
	}
	// Bounded by bytes as well as by count. Records are parents-first, so a
	// prefix is still applicable on its own, and the peer's next round asks
	// for the rest — where an over-long frame would fail to encode, fail the
	// same way every round, and wedge that pair's sync for good. A single
	// record always fits: [types.MaxRecordSize] is below the budget.
	budget := maxRecordBytesPerFrame - keyBytes(reply.Keys)
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
	if n.opts.Leases != nil && !n.seenAlone() {
		reply.Leases = n.opts.Leases()
		if len(reply.Leases) > MaxLeasesPerFrame {
			reply.Leases = reply.Leases[:MaxLeasesPerFrame]
		}
	}
	return reply, nil
}

// announceIn adds this node's announcement and those it holds to f, for a
// peer that has not had them in a hello.
func (n *Node) announceIn(f *frame) {
	f.Self, f.Endpoints, _ = n.announcements()
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

// onNews tells the daemon what a session brought: records applied as such,
// anything else new as announced.
func (n *Node) onNews(applied bool, changed Change) {
	switch {
	case applied || changed != Unchanged && n.opts.OnAnnounced == nil:
		n.onRecords()
	case changed != Unchanged:
		n.opts.OnAnnounced()
	}
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
	// News alone is relayed: a peer that holds a copy this log leaves out
	// offers it every session, and relaying that would never end.
	if err := n.opts.Log.Inform(records); errors.Is(err, ErrNothingNew) {
		return false, stopped
	} else if err != nil {
		return false, fmt.Errorf("offering %d records to the log: %w", len(records), err)
	}
	return true, stopped
}

// takeEndpoints verifies and caches announcements, reporting what was new. One that does not verify is dropped and logged without ending the
// session: the relaying peer is not necessarily its author, and the good ones
// in the same frame are still good.
func (n *Node) takeEndpoints(self *Endpoint, relayed []Endpoint, keys []AddrKey) Change {
	eps := relayed
	if self != nil {
		eps = append([]Endpoint{*self}, relayed...)
	}
	changed := Unchanged
	for i := range eps {
		e := eps[i]
		if e.Identity == n.opts.Self {
			// Our own announcement, echoed back. We are the authority on it.
			if n.opts.OnOwn != nil {
				n.opts.OnOwn(e)
			}
			continue
		}
		if err := e.Verify(); err != nil {
			n.logf("gossip: dropping an announcement: %v", err)
			continue
		}
		changed = max(changed, n.opts.Endpoints.Added(e))
	}
	for i := range keys {
		k := keys[i]
		if k.Owner == n.opts.Self {
			continue
		}
		if err := k.Verify(); err != nil {
			n.logf("gossip: dropping an address key: %v", err)
			continue
		}
		if n.opts.Endpoints.AddKey(k) {
			changed = Changed
		}
	}
	return changed
}

// gossipAddrs is where e's node takes sessions on the underlay: each of its
// addresses this node can open, at its gossip port.
func (n *Node) gossipAddrs(e Endpoint) []netip.AddrPort {
	if n.opts.Underlay == nil {
		return e.GossipAddrs()
	}
	return e.gossipAddrsAt(n.opts.Underlay(e))
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
		f.Have = f.Have[:MaxHashesPerFrame]
	}
	var eps []Endpoint
	var keys []AddrKey
	f.Self, eps, keys = n.announcements()
	if n.seenAlone() {
		f.Seen = n.seen(f.Self, eps, keys)
		return f
	}
	f.Endpoints, f.Keys = eps, keys
	return f
}

func (n *Node) seenAlone() bool { return n.opts.SeenAlone != nil && n.opts.SeenAlone() }

// announcements are this node's announcement, those it holds and the
// address keys, as many as a frame carries.
func (n *Node) announcements() (self *Endpoint, eps []Endpoint, keys []AddrKey) {
	if n.opts.Announce != nil {
		if mine, ok := n.opts.Announce(); ok {
			self = &mine
		}
	}
	eps = n.opts.Endpoints.All()
	if len(eps) > MaxEndpointsPerFrame {
		eps = eps[:MaxEndpointsPerFrame]
	}
	var all []AddrKey
	if n.opts.OwnKey != nil {
		if mine, ok := n.opts.OwnKey(); ok {
			all = append(all, mine)
		}
	}
	size := 0
	for _, k := range append(all, n.opts.Endpoints.Keys()...) {
		if size += len(k.Wraps) * addrkey.WrapSize; size > maxKeyBytesPerFrame || len(keys) == MaxEndpointsPerFrame {
			break
		}
		keys = append(keys, k)
	}
	return self, eps, keys
}

// seen is what a hello says this node holds: of each node, its
// announcement, its address key and its newest lease.
func (n *Node) seen(self *Endpoint, eps []Endpoint, keys []AddrKey) []Seen {
	var out []Seen
	at := map[types.Identity]int{}
	entry := func(id types.Identity) *Seen {
		i, ok := at[id]
		if !ok {
			i = len(out)
			at[id] = i
			out = append(out, Seen{ID: id})
		}
		return &out[i]
	}
	if self != nil {
		entry(self.Identity).Seq = self.Seq
	}
	for i := range eps {
		entry(eps[i].Identity).Seq = eps[i].Seq
	}
	for i := range keys {
		entry(keys[i].Owner).Key = keys[i].Seq
	}
	for _, l := range n.leases() {
		if s := entry(l.Signer); l.Issued > s.Lease {
			s.Lease = l.Issued
		}
	}
	if len(out) > MaxEndpointsPerFrame+MaxLeasesPerFrame {
		out = out[:MaxEndpointsPerFrame+MaxLeasesPerFrame]
	}
	return out
}

// A heldLease is a lease this node sends, as encoded and decoded.
type heldLease struct {
	raw []byte
	types.Lease
}

// leases are the leases this node sends, at most a frame's.
func (n *Node) leases() []heldLease {
	if n.opts.Leases == nil {
		return nil
	}
	var out []heldLease
	for _, b := range n.opts.Leases() {
		if l, err := types.DecodeLease(b); err == nil && len(out) < MaxLeasesPerFrame {
			out = append(out, heldLease{b, l})
		}
	}
	return out
}

// newerThanSeen adds to f, a records frame answering peer, what this node
// holds newer than peer's hello says it does: everything where it says
// nothing, since this node's hello carried none of it.
func (n *Node) newerThanSeen(f *frame, peer *frame) {
	held := make(map[types.Identity]Seen, len(peer.Seen))
	for _, s := range peer.Seen {
		held[s.ID] = s
	}
	self, eps, keys := n.announcements()
	for i := range eps {
		if eps[i].Seq > held[eps[i].Identity].Seq && (self == nil || eps[i].Identity != self.Identity) {
			f.Endpoints = append(f.Endpoints, eps[i])
		}
	}
	// Room for the largest record beside them, which a frame must carry.
	room := maxRecordBytesPerFrame - types.MaxRecordSize
	for i := range keys {
		if keys[i].Seq > held[keys[i].Owner].Key {
			if room -= keyBytes(keys[i : i+1]); room < 0 {
				break
			}
			f.Keys = append(f.Keys, keys[i])
		}
	}
	f.Leases = nil
	for _, l := range n.leases() {
		if l.Issued > held[l.Signer].Lease {
			f.Leases = append(f.Leases, l.raw)
		}
	}
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
