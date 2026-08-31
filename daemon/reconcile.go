package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Reconcile makes the data plane match the log.
//
// This is the reconciler docs/05-roadmap.md puts at the centre of M2: log
// state ⇒ WireGuard config ⇒ netmap. It is the only path by which anything
// becomes a peer, and it reads authority from exactly one place — the
// membership log — joining connectivity hints onto it afterwards. A gossiped
// announcement can say where a member is; it can never make its subject one.
//
// Three ways a node ends up with no peer entry, all of them deliberate:
//
//   - The log does not carry it, or carries it no longer. This is
//     default-deny, and it is enforced below by WireGuard's cryptokey routing:
//     a key with no peer entry cannot complete a handshake, whatever it holds.
//   - Its membership has expired. Expiry is a backstop rather than the
//     revocation mechanism (see [types.NodeRecord.Expiry]), but a backstop
//     nothing consumes is not one, so it is consumed here.
//   - An unresolved fork alarm. Then *every* peer is dropped, including ones
//     the two branches agree on: a node that cannot tell who is a member must
//     not guess, and the fail-closed direction is the one that does not admit
//     a revoked device (docs/02-threat-model.md).
func (d *Daemon) Reconcile() error {
	// One reconcile at a time. The loop is the usual caller, but [Daemon.Inform]
	// reconciles on the IPC goroutine so its reply reflects the records it
	// applied — and two interleaved reconciles could install their peer sets
	// in the opposite order to their state reads, putting a set derived from
	// pre-removal state into the data plane after the one that dropped the
	// revoked device. Serializing makes "the last SetPeers is the newest
	// state" an invariant instead of a race.
	d.reconcileMu.Lock()
	defer d.reconcileMu.Unlock()

	// A State is immutable once handed out, so the lock is held only for
	// the call that produces it. Holding it across SetPeers would put the
	// data plane's own lock underneath the trust layer's, and every gossip
	// session would wait behind a reconfiguration.
	d.authMu.Lock()
	state, stateErr := d.authority.TrustedState()
	d.authMu.Unlock()
	if stateErr != nil {
		// An alarm, and nothing else: TrustedState fails for no other
		// reason. Tear the data plane down before returning, so that the
		// window between noticing and acting is not one where a revoked
		// device is still reachable.
		if err := d.manager.SetPeers(nil); err != nil {
			return fmt.Errorf("daemon: dropping every peer after %v: %w", stateErr, err)
		}
		d.setStatus(func(s *Status) {
			s.Alarm = stateErr.Error()
			// Nothing else is knowable while the fork is unresolved, and a
			// stale count next to an alarm reads as though some of the mesh
			// survived it. None of it did, so every derived field is cleared,
			// not only the peer counts — a lingering Members or Conflicted next
			// to a raised alarm is the same lie.
			s.Peers = 0
			s.Unreachable = 0
			s.Conflicted = 0
			s.Members = 0
			s.Expired = 0
			s.NotMember = false
			s.StaleKeys = false
		})
		return stateErr
	}

	d.adoptEpoch(state)

	now := d.now().Unix()
	members := state.Nodes()
	live := make(map[types.Identity]bool, len(members))
	var expired int
	for i := range members {
		if members[i].Expired(now) {
			// An expired membership is treated exactly like a former one,
			// everywhere: no peer entry, no gossip, no cached address. A
			// backstop that stops the data plane but leaves the device
			// inside the sync layer would still be handing it the member
			// set and every member's address.
			expired++
			continue
		}
		live[members[i].Identity] = true
	}

	// This device itself may be the one that is out. Then the whole data
	// plane comes down, not just the record-keeping: peers enforce membership
	// on their side either way, so this is not what keeps the network safe —
	// but a device that knows it was removed and keeps probing its former
	// peers is indistinguishable from an attack, and "your device is no
	// longer a member" is the one thing its operator most needs said plainly.
	if !live[d.self] {
		if err := d.manager.SetPeers(nil); err != nil {
			return fmt.Errorf("daemon: dropping every peer after losing membership: %w", err)
		}
		d.pruneEndpoints(live)
		d.setStatus(func(s *Status) {
			s.Alarm = ""
			s.NotMember = true
			s.Members = len(members)
			s.Expired = expired
			s.Peers = 0
			s.Unreachable = 0
			s.Epoch = state.Epoch()
			s.Head = state.Head()
			s.LastReconcile = d.now().Unix()
		})
		d.logOnce("daemon: this device is not in the member set (removed, or past its expiry); tunnels are down")
		return nil
	}

	// A rotation applied while this daemon runs leaves the log naming keys
	// this process does not hold. Peers move to the new keys immediately, so
	// everything fails from here — tunnels against the old WireGuard key,
	// the group secret against the old recipient key — and every failure
	// looks like a network problem unless something says otherwise.
	staleKeys := false
	if self, ok := state.Node(d.self); ok && self.WireGuard != d.wgPublic {
		staleKeys = true
		d.logOnce("daemon: the log names different keys for this device than this daemon holds; " +
			"restart juistd to pick up the promoted key file")
	}

	// A disco key is the one thing in a peer entry that the peer itself
	// chooses, and the connectivity layer requires them to be distinct — it
	// keys NAT-traversal state by them. So a member announcing another
	// member's disco key would make SetPeers refuse the whole set, and one
	// member could take every member's data plane down with one signed
	// announcement. Rather than hand out that kill switch, the conflict is
	// resolved here: every peer in a colliding set is dropped and the rest of
	// the mesh is installed. It is fail-closed and it is visible — the
	// announcer loses its own connectivity too, and the status says how many
	// were dropped.
	// The endpoint cache is written by gossip and discovery on their own
	// goroutines, and Reconcile holds only reconcileMu, which does not exclude
	// them. So each live member's announcement is read once here into a
	// snapshot, and both the collision count and the peer set are built from
	// that one snapshot. Reading the cache twice — once to count disco keys,
	// once to install — let an announcement Add'd between the two passes be
	// counted zero times and installed once, so two colliders both reached
	// conn.SetPeers, which rejects the *whole* set for the duplicate: the exact
	// kill switch moving the check into the reconciler was meant to remove.
	held := make(map[types.Identity]gossip.Endpoint, len(members))
	discoUsers := make(map[gossip.DiscoKey]int, len(members))
	for i := range members {
		if members[i].Identity == d.self || !live[members[i].Identity] {
			continue
		}
		if ep, ok := d.endpoints.Get(members[i].Identity); ok {
			held[members[i].Identity] = ep
			discoUsers[ep.Disco]++
		}
	}

	peers := make([]conn.Peer, 0, len(members))
	var unreachable, conflicted int
	for i := range members {
		n := &members[i]
		if n.Identity == d.self || !live[n.Identity] {
			continue
		}
		// The log says this node is a member and which WireGuard key it
		// holds. Where it is, and which disco key it answers with, come from
		// its own signed announcement — the two halves docs/04-architecture.md
		// splits between the trust layer and the connectivity layer.
		ep, ok := held[n.Identity]
		if !ok {
			unreachable++
			continue
		}
		if discoUsers[ep.Disco] > 1 || ep.Disco == d.discoPublic {
			conflicted++
			d.logOnce("daemon: two members announce the same NAT-traversal key, or one announces this " +
				"device's; none of them gets a peer entry until that is resolved")
			continue
		}
		peers = append(peers, conn.Peer{
			ID:        d.peerID(n.Identity),
			NodeKey:   conn.NodePublicFromRaw32(n.WireGuard),
			DiscoKey:  conn.DiscoPublicFromRaw32(ep.Disco),
			Addrs:     state.Addrs(n.Identity),
			Endpoints: ep.Addrs,
		})
	}

	if err := d.manager.SetPeers(peers); err != nil {
		return fmt.Errorf("daemon: installing %d peers: %w", len(peers), err)
	}

	d.pruneEndpoints(live)

	d.setStatus(func(s *Status) {
		s.Alarm = ""
		s.NotMember = false
		s.StaleKeys = staleKeys
		s.Network = state.GenesisHash()
		s.NetworkName = state.Network()
		s.Head = state.Head()
		s.Epoch = state.Epoch()
		s.Members = len(members)
		s.Expired = expired
		s.Peers = len(peers)
		s.Unreachable = unreachable
		s.Conflicted = conflicted
		s.LastReconcile = d.now().Unix()
	})
	return nil
}

// pruneEndpoints drops the cached announcements of members that are no longer
// members, and keeps everything else.
//
// The distinction matters in both directions. A device that *was* a member and
// is not any more — revoked, or expired — must not keep a cached address this
// node hangs on to; that is hygiene rather than access control, since the peer
// set and the gossip set both come from the log, but "why is my daemon still
// talking to that machine" is a fair question and it should not have an answer.
//
// A subject this node has never seen as a member is a different case, and
// dropping it would be a bug: gossip and LAN discovery routinely deliver an
// announcement before the record that admits its subject, and forgetting it
// would leave a joining member invisible until it announced itself again.
// [gossip.Cache] states that contract; this is the half that has to keep it.
// Such an announcement is inert — nothing reads it until the log catches up —
// and the cache's own bound is what stops it accumulating.
//
// The same call hands the cache the member set, which is what it prefers when
// the bound forces a choice — see [gossip.Cache.SetMembers].
func (d *Daemon) pruneEndpoints(live map[types.Identity]bool) {
	members := make([]types.Identity, 0, len(live))
	for id := range live {
		members = append(members, id)
	}

	d.mu.Lock()
	for id := range live {
		d.everMember[id] = true
	}
	former := make(map[types.Identity]bool, len(d.everMember))
	for id := range d.everMember {
		if !live[id] {
			former[id] = true
		}
	}
	// Remembered, not just acted on. A device learns of its own removal only
	// when a gossip session reaches it, and until then it keeps announcing —
	// legitimately, from its side. Forgetting without remembering makes each
	// of those announcements look new to every member: cached, logged, marked
	// dirty, reconciled, forgotten, and cached again on the next beacon. That
	// is a reconcile and a push round per member per announcement interval,
	// for as long as the removed device is powered on.
	d.mu.Unlock()

	// The cache enforces both halves, so that a relayed announcement in a
	// gossip session obeys the same rule as one heard on the LAN.
	// Re-enrollment clears it: the record that admits the device makes it
	// live at the next reconcile, which is the reconcile that record
	// triggers.
	formerIDs := make([]types.Identity, 0, len(former))
	for id := range former {
		formerIDs = append(formerIDs, id)
		d.endpoints.Forget(id)
	}
	d.endpoints.SetMembership(members, formerIDs)
}

// adoptEpoch opens this node's wrap of the current group secret and puts it in
// the keyring, so that gossip and discovery speak the epoch the log resolves
// to.
//
// A failure here is reported and survived rather than fatal. A member that
// cannot open its own wrap has been handed a secret sealed to keys it does not
// hold — a rotation whose staged keys were never promoted, or the malicious
// case the commitment in the record exists to make visible — and the honest
// response is to keep the data plane running on the epoch it already has while
// saying so, not to take the node off the network.
func (d *Daemon) adoptEpoch(state *log.State) {
	epoch := state.Epoch()
	if _, held := d.keyring.Secret(epoch); held {
		return
	}
	if !state.IsMember(d.self) {
		// Not a member of the chain we resolve to: there is no wrap for us
		// and there is not supposed to be one. Nothing to report.
		return
	}
	s, err := secrets.Open(state.EpochRecord(), d.self, d.recipient)
	if err != nil {
		d.logf("daemon: cannot open the epoch %d group secret: %v", epoch, err)
		d.setStatus(func(st *Status) { st.EpochError = err.Error() })
		return
	}
	d.keyring.Adopt(epoch, s)
	d.setStatus(func(st *Status) { st.EpochError = "" })
	d.logf("daemon: adopted the epoch %d group secret", epoch)
}

// backfillEpochs opens this node's wraps of the recent past epochs, so that a
// restarted daemon holds a keyring rather than a single secret.
//
// Without it a restart throws away exactly the property [secrets.KeyringDepth]
// exists for. A node that holds only the newest epoch cannot open a frame from
// a peer that is behind, and cannot seal one that peer could read — so the two
// have no epoch in common and neither can teach the other the record that
// would fix it. In a two-node network that is a permanent partition healed
// only by re-enrolling; in a larger one it is a node that stays dark to
// whichever members were offline across a bump.
//
// It walks the active chain backwards from the head, taking the newest
// distinct epoch records, and stops as soon as the keyring is full. Failures
// are not fatal for the same reason [Daemon.adoptEpoch]'s are not: an epoch
// this node cannot open is one it simply will not speak.
func (d *Daemon) backfillEpochs() {
	d.authMu.Lock()
	chain, err := d.authority.Chain()
	if err != nil {
		d.authMu.Unlock()
		d.logf("daemon: reading the chain to recover past epochs: %v", err)
		return
	}
	records := make([]*types.EpochRecord, 0, secrets.KeyringDepth)
	for i := len(chain) - 1; i >= 0 && len(records) < secrets.KeyringDepth; i-- {
		aum, err := d.storage.AUM(chain[i])
		if err != nil {
			break
		}
		// Two places carry an epoch: an ordinary record's Epoch field, and a
		// genesis or checkpoint's snapshot, which holds the wraps inline.
		// Missing the second would skip exactly the epoch a node that has
		// never seen a membership change is on.
		switch {
		case aum.Epoch != nil:
			records = append(records, aum.Epoch)
		case aum.State != nil:
			records = append(records, &types.EpochRecord{
				Epoch:  aum.State.Epoch,
				Commit: aum.State.EpochCommit,
				Wraps:  aum.State.EpochWraps,
			})
		}
	}
	d.authMu.Unlock()

	for _, rec := range records {
		if _, held := d.keyring.Secret(rec.Epoch); held {
			continue
		}
		s, err := secrets.Open(rec, d.self, d.recipient)
		if err != nil {
			// Ordinary: every epoch older than this device's enrollment has
			// no wrap for it, and a rotation means the older wraps are sealed
			// to keys it no longer holds.
			continue
		}
		d.keyring.Adopt(rec.Epoch, s)
		d.logf("daemon: recovered the epoch %d group secret", rec.Epoch)
	}
}

// peerID returns the local handle the connectivity layer knows a member by.
//
// It is assigned here, sequentially, and not derived from anything in the log.
// magicsock wants a non-zero 63-bit node ID that is unique among peers and
// stable while a peer is present; nothing requires two members to agree on
// what it is, because it never leaves this process. A derived ID would
// therefore buy nothing and cost a collision case — one in which a hash
// collision between two members' identity keys makes SetPeers reject the whole
// set and takes the node's whole data plane down.
func (d *Daemon) peerID(id types.Identity) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n, ok := d.peerIDs[id]; ok {
		return n
	}
	d.nextPeerID++
	d.peerIDs[id] = d.nextPeerID
	return d.nextPeerID
}

// announcement returns this node's signed endpoint record, rebuilding it when
// the underlay addresses or the data-plane port have changed.
//
// The sequence number advances whenever the content does, so that a peer
// holding an older copy replaces it. It starts from the wall clock so that a
// daemon restart does not reissue sequence numbers its peers have already
// seen and dismiss as replays.
func (d *Daemon) announcement() (gossip.Endpoint, bool) {
	addrs := gossip.SortAddrs(d.underlayEndpoints())

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status.NotMember {
		// A removed device goes quiet on the LAN as well as the data plane:
		// no unsolicited beacons, no answers to blinded queries, no Self in
		// a gossip hello. It still holds old epoch secrets for the length of
		// the keyring window, but holding a key is not a reason to keep
		// speaking — a device that knows it was removed and keeps announcing
		// itself is the same probing behaviour the reconciler already
		// refuses to do with tunnels. Re-enrollment arrives over IPC, so
		// going quiet costs it nothing it needs. A fork alarm is different:
		// staying discoverable is how the records that resolve the fork
		// reach this node, so an alarm does not gate this.
		return gossip.Endpoint{}, false
	}
	if d.announced != nil && slices.Equal(d.announced.Addrs, addrs) &&
		d.announced.GossipPort == d.gossipPort {
		return *d.announced.Clone(), true
	}
	e := gossip.Endpoint{
		Identity:   d.self,
		Disco:      d.discoPublic,
		Addrs:      addrs,
		GossipPort: d.gossipPort,
		Seq:        d.nextSeq(),
	}
	if err := e.Sign(d.identity); err != nil {
		d.logf("daemon: signing this node's announcement: %v", err)
		return gossip.Endpoint{}, false
	}
	d.announced = &e
	return *e.Clone(), true
}

// nextSeq returns a strictly increasing sequence number, seeded from the
// clock. The caller holds d.mu.
func (d *Daemon) nextSeq() uint64 {
	next := uint64(d.now().Unix())
	if next <= d.seq {
		next = d.seq + 1
	}
	d.seq = next
	return next
}

// underlayEndpoints reports where this node's data plane can be reached from
// the local network.
//
// docs/07-embedding-notes.md left this open for M2: magicsock refuses to
// report its own endpoints with neither a STUN result nor a DERP map
// ("ignoring pre-DERP map, STUN-less endpoint update"), and an M2 network has
// neither by construction. The resolution taken here is the first of the two
// it offers — read the host's interface addresses directly — because it is the
// one that needs no third party at all, which is what "LAN-only operation with
// zero internet works" (exit criterion 3) asks for. Reflexive addresses
// discovered through disco and member relays arrive at M3 and are added to
// this set rather than replacing it.
//
// Everything that is not a usable underlay address is filtered out: interfaces
// that are down, loopback, link-local, and the overlay's own ranges — the last
// because announcing an overlay address as an underlay endpoint would ask
// peers to reach the tunnel through the tunnel.
func (d *Daemon) underlayEndpoints() []netip.AddrPort {
	port := d.manager.LocalPort()
	if port == 0 {
		return nil
	}
	// Cached briefly. [Daemon.announcement] runs on every gossip session and
	// every discovery tick, and enumerating interfaces is a syscall walk over
	// every address on the host; a set that changes when someone plugs in a
	// cable does not need re-reading dozens of times a second.
	now := d.now()
	d.mu.Lock()
	if d.addrsPort == port && now.Before(d.addrsUntil) {
		cached := slices.Clone(d.addrs)
		d.mu.Unlock()
		return cached
	}
	d.mu.Unlock()

	ifaces, err := net.Interfaces()
	if err != nil {
		d.logf("daemon: listing interfaces: %v", err)
		return nil
	}
	var out []netip.AddrPort
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			pfx, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(pfx.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !d.usableUnderlay(ip) {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip, port))
		}
	}
	if len(out) > gossip.MaxEndpointAddrs {
		out = out[:gossip.MaxEndpointAddrs]
	}
	d.mu.Lock()
	d.addrs, d.addrsPort, d.addrsUntil = slices.Clone(out), port, now.Add(underlayCacheFor)
	d.mu.Unlock()
	return out
}

// underlayCacheFor is how long an interface scan is reused. Short enough that
// a laptop moving between networks re-announces within one discovery interval
// of arriving.
const underlayCacheFor = 2 * time.Second

func (d *Daemon) usableUnderlay(ip netip.Addr) bool {
	switch {
	case !ip.IsValid(), ip.IsLoopback(), ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsUnspecified():
		return false
	case types.CGNAT.Contains(ip):
		// The overlay's own v4 range. A host legitimately using 100.64/10 on
		// its LAN cannot also be reached there by members, so excluding it is
		// right either way.
		return false
	case d.ula.IsValid() && d.ula.Contains(ip):
		return false
	}
	return true
}

// now is the daemon's clock, overridable in tests.
func (d *Daemon) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}
