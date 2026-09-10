package daemon

import (
	"bytes"
	"fmt"
	"maps"
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

// Reconcile makes the data plane match the log. It is the only path by which
// anything becomes a peer, and authority comes from the log alone: a gossiped
// announcement says where a member is, never that it is one.
//
// A node gets no peer entry if the log does not carry it, if its membership
// has expired, or if a fork alarm is unresolved — in which case every peer is
// dropped, including ones both branches agree on.
func (d *Daemon) Reconcile() error {
	// One at a time: [Daemon.Inform] reconciles on the IPC goroutine, and two
	// interleaved reconciles could install their peer sets in the opposite
	// order to their state reads, leaving pre-removal state in the data plane.
	d.reconcileMu.Lock()
	defer d.reconcileMu.Unlock()

	// A State is immutable once handed out, so the lock covers only the call
	// that produces it: held across SetPeers, every gossip session would wait
	// behind a reconfiguration.
	d.authMu.Lock()
	state, stateErr := d.authority.TrustedState()
	d.authMu.Unlock()
	if stateErr != nil {
		// An alarm, and nothing else: TrustedState fails for no other reason.
		// Tear the data plane down before returning, and stop relaying: who
		// may use this member's relay is a membership question, and this node
		// no longer knows the answer.
		d.stopRelaying()
		if err := d.manager.SetPeers(nil); err != nil {
			err = fmt.Errorf("daemon: dropping every peer after %v: %w", stateErr, err)
			d.setStatus(func(s *Status) { s.DataPlaneError = err.Error() })
			return err
		}
		d.setStatus(func(s *Status) {
			s.Alarm = stateErr.Error()
			s.DataPlaneError = ""
			// Every derived field is cleared, not just the peer counts: a
			// stale count beside an alarm reads as though part of the mesh
			// survived it, and none of it did.
			s.Peers = 0
			s.Unreachable = 0
			s.Conflicted = 0
			s.Members = 0
			s.Expired = 0
			s.Relays = 0
			s.Relaying = false
			s.RelayCapable = 0
			s.NotMember = false
			s.StaleKeys = false
		})
		return stateErr
	}

	d.adoptEpoch(state)
	d.noteSchema()

	now := d.now().Unix()
	members := state.Nodes()
	live := make(map[types.Identity]bool, len(members))
	var expired int
	for i := range members {
		if members[i].Expired(now) {
			// An expired membership is treated exactly like a former one
			// everywhere: no peer entry, no gossip, no cached address.
			expired++
			continue
		}
		live[members[i].Identity] = true
	}

	// This device itself may be the one that is out, in which case the whole
	// data plane comes down. Peers enforce membership on their side anyway;
	// this is so a removed device stops probing them, and says why.
	if !live[d.self] {
		// A device that is not a member relays for nobody, whatever role the
		// last state it saw granted it.
		d.stopRelaying()
		if err := d.manager.SetPeers(nil); err != nil {
			err = fmt.Errorf("daemon: dropping every peer after losing membership: %w", err)
			d.setStatus(func(s *Status) { s.DataPlaneError = err.Error() })
			return err
		}
		d.pruneEndpoints(live)
		d.setStatus(func(s *Status) {
			s.Alarm = ""
			s.DataPlaneError = ""
			s.NotMember = true
			s.Members = len(members)
			s.Expired = expired
			s.Peers = 0
			s.Unreachable = 0
			s.Relays = 0
			s.Relaying = false
			s.RelayCapable = 0
			s.Epoch = state.Epoch()
			s.Head = state.Head()
			s.LastReconcile = d.now().Unix()
		})
		d.logOnce("daemon: this device is not in the member set (removed, or past its expiry); tunnels are down")
		return nil
	}

	// A rotation applied while this daemon runs leaves the log naming keys the
	// process does not hold. Peers move to them at once, so everything fails
	// from here and looks like a network problem unless something says so.
	staleKeys := false
	if self, ok := state.Node(d.self); ok && self.WireGuard != d.wgPublic {
		staleKeys = true
		d.logOnce("daemon: the log names different keys for this device than this daemon holds; " +
			"restart juistd to pick up the promoted key file")
	}

	// The disco key is the one field a peer chooses for itself, and conn
	// requires them distinct — left to conn, one member announcing another's
	// key would make SetPeers refuse the whole set, a mesh kill switch. Drop
	// every peer in a colliding set here instead and install the rest.
	//
	// Read each announcement once into a snapshot: gossip and discovery write
	// the cache concurrently, and reading twice lets one added between the
	// passes be counted zero times and installed once, restoring the kill
	// switch.
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

	// The relay set and the local relay are both derived from the same
	// snapshot as the peer set, and installed before it: a peer whose only
	// path is through a relay must find the relay already in the map.
	relayMembers := make(map[types.WGKey]bool, len(members))
	for i := range members {
		if live[members[i].Identity] {
			relayMembers[members[i].WireGuard] = true
		}
	}
	d.mu.Lock()
	d.relayMembers = relayMembers
	d.mu.Unlock()
	d.syncRelay(state)

	// This node's own relay belongs in its own map. Without it, a member that
	// is the network's only relay has no region to be reached through: it
	// would announce none, and every peer that cannot punch to it directly
	// would have nowhere to fall back to.
	relayHeld := held
	if mine, ok := d.announcement(); ok && mine.Relay != nil {
		relayHeld = maps.Clone(held)
		relayHeld[d.self] = mine
	}
	relays := d.relaySet(state.GenesisHash(), members, relayHeld)
	relayCapable := 0
	for i := range members {
		if live[members[i].Identity] && members[i].HasRole(types.RoleRelayCapable) {
			relayCapable++
		}
	}
	if err := d.manager.SetRelays(relays); err != nil {
		err = fmt.Errorf("daemon: installing %d relays: %w", len(relays), err)
		d.setStatus(func(s *Status) { s.DataPlaneError = err.Error() })
		return err
	}

	peers := make([]conn.Peer, 0, len(members))
	var unreachable, conflicted int
	for i := range members {
		n := &members[i]
		if n.Identity == d.self || !live[n.Identity] {
			continue
		}
		// The log says who is a member and which WireGuard key it holds; its
		// own signed announcement says where it is and which disco key it
		// answers with.
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
			ID:       d.peerID(n.Identity),
			NodeKey:  conn.NodePublicFromRaw32(n.WireGuard),
			DiscoKey: conn.DiscoPublicFromRaw32(ep.Disco),
			Addrs:    state.Addrs(n.Identity),
			// The peer says where it is and which relay it can be reached
			// through; the log says it is a member. A home relay naming a
			// region no relay-capable member holds is dropped rather than
			// installed, since sending there reaches nothing.
			Endpoints: ep.Addrs,
			HomeRelay: homeRelay(ep, relays),
		})
	}

	if err := d.manager.SetPeers(peers); err != nil {
		err = fmt.Errorf("daemon: installing %d peers: %w", len(peers), err)
		d.setStatus(func(s *Status) { s.DataPlaneError = err.Error() })
		return err
	}

	d.pruneEndpoints(live)
	// After pruning, so a former member's address is dropped from the file
	// as well as from memory.
	d.saveEndpointCache(d.cachePath)

	// Read before setStatus, which holds the same mutex.
	relaying := d.isRelaying()
	d.setStatus(func(s *Status) {
		s.Alarm = ""
		s.DataPlaneError = ""
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
		s.Relays = len(relays)
		s.Relaying = relaying
		s.RelayCapable = relayCapable
		s.LastReconcile = d.now().Unix()
	})
	return nil
}

// homeRelay is the region a peer says it can be reached through, kept only if
// the relay set this node installed actually holds it. A region nothing serves
// would make the data plane treat an unusable address as a path.
func homeRelay(ep gossip.Endpoint, relays []conn.Relay) int {
	if ep.HomeRelay == 0 {
		return 0
	}
	if !slices.ContainsFunc(relays, func(r conn.Relay) bool { return r.Region == int(ep.HomeRelay) }) {
		return 0
	}
	return int(ep.HomeRelay)
}

// isRelaying reports whether this device is currently serving a relay.
func (d *Daemon) isRelaying() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.relay != nil
}

// pruneEndpoints drops the cached announcements of former members and keeps
// everything else. A subject never yet seen as a member must be kept: an
// announcement routinely arrives before the record admitting its subject, and
// dropping it would leave a joining member invisible until it announced again.
// The same call hands the cache the member set, which it prefers when its
// bound forces a choice.
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
	// Remembered, not just acted on: a removed device keeps announcing until a
	// gossip session reaches it, and without this each beacon would look new
	// again — a reconcile and a push round per member per interval.
	d.mu.Unlock()

	// The cache enforces it, so a relayed announcement obeys the same rule as
	// one heard on the LAN. Re-enrollment clears it at the next reconcile.
	formerIDs := make([]types.Identity, 0, len(former))
	for id := range former {
		formerIDs = append(formerIDs, id)
		d.endpoints.Forget(id)
	}
	d.endpoints.SetMembership(members, formerIDs)
}

// noteSchema reports a network that has moved to a record schema this build
// cannot read. It is not an alarm that withdraws membership state: what the
// node holds was correct up to the upgrade, and taking every tunnel down the
// moment an admin raises the schema would turn a planned change into an
// outage. It does mean this device applies nothing further, including
// revocations, until it is upgraded.
func (d *Daemon) noteSchema() {
	d.authMu.Lock()
	tooNew := d.authority.SchemaAlarm()
	d.authMu.Unlock()
	msg := ""
	if tooNew != nil {
		msg = tooNew.Error()
		d.logOnce("daemon: " + msg)
	}
	d.setStatus(func(s *Status) { s.SchemaAlarm = msg })
}

// adoptEpoch opens this node's wrap of the current group secret and puts it in
// the keyring, so that gossip and discovery speak the epoch the log resolves
// to.
//
// A failure is reported and survived: a member that cannot open its own wrap
// keeps the data plane running on the epoch it already has.
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

// backfillEpochs opens this node's wraps of recent past epochs, so a restarted
// daemon holds a keyring rather than a single secret: a node holding only the
// newest epoch can neither read a frame from a peer that is behind nor be read
// by it, which in a two-node network is a permanent partition. It walks the
// active chain back from the head until the keyring is full.
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
		// Two places carry an epoch: a record's Epoch field, and a genesis or
		// checkpoint snapshot, which holds the wraps inline. Missing the
		// second skips the epoch a node that never saw a change is on.
		switch {
		case aum.Epoch != nil:
			records = append(records, aum.Epoch)
		case aum.State != nil:
			records = append(records, &types.EpochRecord{
				Epoch:  aum.State.Epoch,
				Commit: aum.State.EpochCommit,
				Wraps:  aum.State.EpochWraps,
				Suite:  aum.State.EpochSuite,
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

// peerID returns the local handle the connectivity layer knows a member by. It
// is assigned sequentially rather than derived: the ID never leaves this
// process, so deriving one would buy nothing and add a collision case that
// would take the whole data plane down.
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
// the underlay addresses or the data-plane port change. The sequence number
// advances with the content, and starts from the wall clock so a restart does
// not reissue numbers peers would dismiss as replays.
func (d *Daemon) announcement() (gossip.Endpoint, bool) {
	// The interface scan is what makes a LAN with no internet work; the
	// addresses the data plane learned are what makes an off-LAN peer
	// reachable. Reflexive addresses are added to the scan, never substituted
	// for it.
	addrs := mergeEndpoints(gossip.SortAddrs(d.underlayEndpoints()), d.manager.LocalEndpoints())
	relayInfo := d.relayInfo()
	home := uint16(d.manager.HomeRelay())

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status.NotMember {
		// A removed device goes quiet on the LAN too: no beacons, no answers
		// to queries, no Self in a gossip hello. Re-enrollment arrives over
		// IPC, so it loses nothing it needs. A fork alarm does not gate this
		// — staying discoverable is how the resolving records arrive.
		return gossip.Endpoint{}, false
	}
	if d.announced != nil && slices.Equal(d.announced.Addrs, addrs) &&
		d.announced.GossipPort == d.gossipPort && d.announced.HomeRelay == home &&
		sameRelayInfo(d.announced.Relay, relayInfo) {
		return *d.announced.Clone(), true
	}
	e := gossip.Endpoint{
		Identity:   d.self,
		Disco:      d.discoPublic,
		Addrs:      addrs,
		GossipPort: d.gossipPort,
		Seq:        d.nextSeq(),
		Relay:      relayInfo,
		HomeRelay:  home,
	}
	if err := e.Sign(d.identity); err != nil {
		d.logf("daemon: signing this node's announcement: %v", err)
		return gossip.Endpoint{}, false
	}
	d.announced = &e
	return *e.Clone(), true
}

// sameRelayInfo reports whether two relay announcements are identical, so an
// unchanged one does not cost a new sequence number and a mesh-wide push.
func sameRelayInfo(a, b *gossip.RelayInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.STUNPort == b.STUNPort &&
		a.HostName == b.HostName && bytes.Equal(a.Cert, b.Cert)
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
// the local network. The host's interfaces are read directly, since magicsock
// reports no endpoints without a STUN result or a DERP map and we want no
// third party. Down, loopback, link-local and overlay addresses are filtered
// out — the last would ask peers to reach the tunnel through the tunnel.
func (d *Daemon) underlayEndpoints() []netip.AddrPort {
	port := d.manager.LocalPort()
	if port == 0 {
		return nil
	}
	// Cached briefly: this runs on every gossip session and discovery tick,
	// and enumerating interfaces is a syscall walk over every host address.
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
