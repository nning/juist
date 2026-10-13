package daemon

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"tailscale.com/types/key"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/trust/log"
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
	unrevoked, lost := d.orphansLocked()
	d.authMu.Unlock()
	if stateErr != nil {
		// Disabled or an alarm: TrustedState fails for no other reason. Only
		// where the chain stood is kept: a count beside an alarm reads as
		// though part of the mesh survived it, and none of it did.
		prev := d.Status()
		v := ipc.Derived{NetworkName: prev.NetworkName, Head: prev.Head, Epoch: prev.Epoch, SelfName: prev.SelfName}
		var disabled *log.DisabledError
		if errors.As(stateErr, &disabled) {
			d.handOnDisable(disabled.At)
			v.Disabled = disabled.At.String()
			err := d.teardown(v, "after the network was disabled")
			d.logOnce("daemon: the network was disabled with a break-glass secret; tunnels are down for good")
			return err
		}
		v.Alarm = stateErr.Error()
		err := d.teardown(v, fmt.Sprintf("after %v", stateErr))
		return cmp.Or(err, stateErr)
	}

	d.adoptEpoch(state)
	d.keepSeeds()
	d.noteSchema()
	d.pruneWaiting(state)
	d.endpoints.SetRelayNames(state.Schema() >= types.SchemaRelayName)
	d.setPQ(state.Schema() >= types.SchemaPQ)
	d.setPadded(state.Schema() >= types.SchemaPadded)
	d.setSigning(state)
	if d.onAddrsMoved != nil && state.IsMember(d.self) &&
		!slices.Equal(d.overlayAddrs(state, d.self, d.now().Unix()), d.heldAddrs()) && d.movedSaid.CompareAndSwap(false, true) {
		go d.onAddrsMoved()
	}

	s := d.snapshotOf(state)
	// This device itself may be the one that is out, in which case the whole
	// data plane comes down. Peers enforce membership on their side anyway;
	// this is so a removed device stops probing them, and says why.
	if !s.live[d.self] {
		// A device that is not a member relays for nobody, whatever role the
		// last state it saw granted it.
		err := d.teardown(ipc.Derived{
			NotMember:   true,
			NetworkName: state.Network(), Head: state.Head(), Epoch: state.Epoch(),
			Members: len(s.members), Expired: s.expired,
			Unrevoked: unrevoked, Lost: lost,
			SelfName: d.selfName(state),
		}, "after losing membership")
		if err != nil {
			return err
		}
		d.noteIngressPorts(nil)
		d.pruneEndpoints(s.live)
		if !d.namedIn(s) {
			// Removed: should the same keys come back, under a store of its
			// own, which every member reads as the pairs it held given up.
			d.changePairs(func(p *pairkey.Store) bool { return p.Reset() })
		}
		d.logOnce("daemon: this device is not in the member set (removed, or past its expiry); tunnels are down")
		return nil
	}

	// By the keys the log names, expired members' too: a pair dropped while
	// its peer kept it would start over unseen.
	named := make(map[types.WGKey]bool, len(s.members))
	for i := range s.members {
		named[s.members[i].WireGuard] = true
	}
	d.changePairs(func(p *pairkey.Store) bool { return p.Prune(func(k types.WGKey) bool { return named[k] }) })
	staleKeys := d.keysAreStale(state)
	fresh, admit := d.checkFreshness(state, s.now)
	// Before anything below can end the reconcile early.
	d.setGossipPeers(s.view, !fresh.Fresh(s.now), admit)
	d.planSealing(s)
	d.pruneOpened(s.live)
	held, discoUsers := d.heldAnnouncements(s)
	relays, err := d.installRelays(s, held)
	if err != nil {
		d.applyExit(d.exitDown("the data plane refused the relay set"))
		// Published ports close too, as they would once the view went stale.
		d.closeToIngresses()
		return err
	}
	ports := d.planPublish(s, fresh.Fresh(s.now))
	ap := d.accessPlan(s, !fresh.Fresh(s.now), ports.access())
	b := d.buildPeers(s, held, discoUsers, relays, admit, &ap)
	d.prunePSKs(b.named)
	d.noteNewAnnouncements(b.named)
	d.setInstalled(b.named)
	sub := d.planSubnets(s, fresh.Fresh(s.now), held, b.peers, b.named)
	exit := d.planExit(s, fresh.Fresh(s.now), held, b.peers, b.named, sub.taken).withSubnets(sub, overlaySpace(state))
	d.mu.Lock()
	exit.accepted = d.acceptNames
	d.mu.Unlock()
	d.notePublishing()
	d.noteIngressPorts(d.publicPorts(s, fresh.Fresh(s.now)))
	exit.zone, exit.overrides, exit.namesUntil = d.namesZone(state, s.view, fresh, exit.accepted, s.now,
		func(id types.Identity) bool {
			return id == d.self && d.publishing() || id != d.self && held[id].Published
		})
	// The peer carrying the routes first, then the routing into it: the
	// other order would send traffic into a tunnel nobody carries.
	if err := d.manager.SetPeers(b.peers); err != nil {
		err = fmt.Errorf("daemon: installing %d peers: %w", len(b.peers), err)
		d.setStatus(func(s *ipc.Status) { s.DataPlaneError = err.Error() })
		d.applyExit(d.exitDown("the data plane refused the peer set"))
		return err
	}
	d.mu.Lock()
	d.lastPeers, d.lastIngresses = b.peers, b.ingresses
	d.mu.Unlock()
	d.applyExit(exit)

	d.pruneEndpoints(s.live)
	// After pruning, so a former member's address is dropped from the file
	// as well as from memory.
	d.saveEndpointCache(d.cachePath)
	unmoved := d.followRenumbering(state, s.live)

	refused := d.refusedEverywhere(s.members, s.live)
	if refused {
		d.logOnce("daemon: members refuse this device a catch-up and none answers it; it was most likely removed")
	}
	devices := peerDevices(ipc.DevicesOf(state, s.now), d.self, s.view)
	for i := range devices {
		devices[i].Serving = len(devices[i].Published) > 0 && d.servesPublished(devices[i].Identity)
	}
	d.setDerived(ipc.Derived{
		NetworkName: state.Network(), Head: state.Head(), Epoch: state.Epoch(), Schema: state.Schema(),
		Members: len(s.members), Expired: s.expired,
		Peers: len(b.peers), Unreachable: len(b.silent), Silent: b.silent,
		Unrevoked: unrevoked, Lost: lost,
		Devices: devices, Unmoved: unmoved,
		Refused: refused, SelfName: d.selfName(state),
		LeaseSigners: fresh.Signers, FreshSince: fresh.Since, FreshUntil: fresh.Until,
		Vouchers: fresh.Needed, Vouching: fresh.Vouching, Stale: !fresh.Fresh(s.now),
		Relays: len(relays), Relaying: d.isRelaying(), RelayCapable: relayCapableIn(s),
		Conflicted:    b.conflicted,
		NoKey:         b.noKey,
		StaleKeys:     staleKeys,
		LastReconcile: d.now().Unix(),
		Exit:          d.exitNow(),
		Subnets:       d.subnetsNow(),
		Publish:       d.publishNow(),
		HTTPS:         d.httpsNow(relays),
	})
	return nil
}

// A snapshot is the member set one reconcile works from.
type snapshot struct {
	state   *log.State
	now     int64
	members []types.NodeRecord
	live    map[types.Identity]bool
	expired int
	view    policy.View // what the policy means for this device
}

func (d *Daemon) snapshotOf(state *log.State) snapshot {
	s := d.membersOf(state)
	// Renumbering moves the ranges without moving this device, and its
	// deadline ends one with nothing applied.
	d.mu.Lock()
	d.v4 = state.V4RangesAt(s.now)
	d.mu.Unlock()
	return s
}

// membersOf is state's member set now, as [Daemon.snapshotOf] without what
// a reconcile takes up of it, for a reader outside one.
func (d *Daemon) membersOf(state *log.State) snapshot {
	s := snapshot{state: state, now: d.now().Unix(), members: state.Nodes()}
	s.live = make(map[types.Identity]bool, len(s.members))
	for i := range s.members {
		if s.members[i].Expired(s.now) {
			// An expired membership is treated exactly like a former one
			// everywhere: no peer entry, no gossip, no cached address.
			s.expired++
			continue
		}
		s.live[s.members[i].Identity] = true
	}
	s.view = policy.NetworkOf(state, s.now).View(d.self)
	return s
}

// keysNamedElsewhere reports whether state names other keys for this
// device than the mesh runs on.
func (d *Daemon) keysNamedElsewhere(state *log.State) bool {
	self, ok := state.Node(d.self)
	return ok && self.WireGuard != d.own.Load().wg
}

// keysAreStale reports a rotation applied while this daemon runs, which leaves
// the log naming keys the process does not hold. Peers move to them at once, so
// everything fails from here and looks like a network problem unless something
// says so.
func (d *Daemon) keysAreStale(state *log.State) bool {
	if !d.keysNamedElsewhere(state) {
		return false
	}
	if d.onKeysNamed == nil {
		d.logOnce("daemon: the log names different keys for this device than this daemon holds; " +
			"restart juistd to pick up the promoted key file")
	} else if d.keysSaid.CompareAndSwap(false, true) {
		go d.onKeysNamed()
	}
	return true
}

// checkFreshness renews and prunes the leases and reports what they say, and
// which members may have a tunnel: all of them while an admin device has
// vouched for this state recently, and only the admin devices, through which a
// newer view arrives, once none has. This bounds how long a partitioned node
// carries a member it has not heard was removed.
func (d *Daemon) checkFreshness(state *log.State, now int64) (log.Freshness, func(types.Identity) bool) {
	d.maybeIssueLease(state, time.Unix(now, 0))
	d.pruneLeases(time.Unix(now, 0))
	fresh := d.freshness(time.Unix(now, 0))
	stale := !fresh.Fresh(now)
	signers := map[types.Identity]bool{}
	for _, n := range state.LeaseSigners(now) {
		signers[n.Identity] = true
	}
	if wasStale := d.Status().Stale; stale && !wasStale {
		d.logf("daemon: no voucher has vouched for this node's view of the network within %v; "+
			"keeping tunnels only to vouchers until one does", d.ttl)
	} else if !stale && wasStale {
		d.logf("daemon: a voucher vouched for this node's view again; all tunnels allowed")
	}
	return fresh, func(id types.Identity) bool { return !stale || signers[id] }
}

// heldAnnouncements reads each live member's announcement once, and counts
// the members announcing each disco key. Gossip and discovery write the cache
// concurrently, and reading twice lets one added between the passes be
// counted zero times and installed once.
func (d *Daemon) heldAnnouncements(s snapshot) (map[types.Identity]gossip.Endpoint, map[gossip.DiscoKey]int) {
	held := make(map[types.Identity]gossip.Endpoint, len(s.members))
	discoUsers := make(map[gossip.DiscoKey]int, len(s.members))
	for i := range s.members {
		id := s.members[i].Identity
		if id == d.self || !s.live[id] {
			continue
		}
		if ep, ok := d.endpoints.Get(id); ok {
			held[id] = ep
			discoUsers[ep.Disco]++
		}
	}
	return held, discoUsers
}

// installRelays derives the relay set from the same snapshot as the peer set
// and installs it, and this device's own relay, first: a peer whose only path
// is through a relay must find the relay already in the map.
func (d *Daemon) installRelays(s snapshot, held map[types.Identity]gossip.Endpoint) ([]conn.Relay, error) {
	relayMembers := make(map[types.WGKey]bool, len(s.members))
	relayHosts := make(map[types.Identity]bool, len(s.members))
	for i := range s.members {
		if s.live[s.members[i].Identity] {
			relayMembers[s.members[i].WireGuard] = true
			relayHosts[s.members[i].Identity] = true
		}
	}
	d.mu.Lock()
	d.relayMembers, d.relayHosts = relayMembers, relayHosts
	d.mu.Unlock()
	d.syncRelay(s.state)

	// This node's own relay belongs in its own map. Without it, a member that
	// is the network's only relay has no region to be reached through: it
	// would announce none, and every peer that cannot punch to it directly
	// would have nowhere to fall back to.
	relayHeld := held
	if mine, ok := d.announcement(); ok && mine.Relay != nil {
		relayHeld = maps.Clone(held)
		relayHeld[d.self] = mine
	}
	network := s.state.GenesisHash()
	relays := d.relaySet(network, s.members, relayHeld)
	// Where two relays derive one region the lower identity keeps it, and a
	// peer homed there is homed at the other.
	ownRegion := false
	if mine, ok := relayHeld[d.self]; ok && mine.Relay != nil {
		region := relayRegion(network, d.self)
		ownRegion = slices.ContainsFunc(relays, func(r conn.Relay) bool {
			return r.Region == region && bytes.Equal(r.CertHash[:], mine.Relay.Cert)
		})
	}
	d.mu.Lock()
	d.ownRegion = ownRegion
	d.mu.Unlock()
	if err := d.manager.SetRelays(relays); err != nil {
		err = fmt.Errorf("daemon: installing %d relays: %w", len(relays), err)
		d.setStatus(func(s *ipc.Status) { s.DataPlaneError = err.Error() })
		return nil, err
	}
	named := slices.DeleteFunc(slices.Clone(relays), func(r conn.Relay) bool { return r.Name == "" })
	d.mu.Lock()
	d.namedRelays, d.relays = named, relays
	d.mu.Unlock()
	return relays, nil
}

// relayCapableIn counts the live members the log grants the relay role.
func relayCapableIn(s snapshot) int {
	n := 0
	for i := range s.members {
		if s.live[s.members[i].Identity] && s.members[i].HasRole(types.RoleRelayCapable) {
			n++
		}
	}
	return n
}

// A peerSet is the peer set a reconcile derived, and who was left out.
type peerSet struct {
	peers      []conn.Peer
	ingresses  map[key.NodePublic]bool // peers kept to what is published
	named      []namedPeer
	silent     []string // members with no announcement held
	conflicted int      // members left out for a disco key another uses

	// noKey are the peers given a preshared key nobody holds.
	noKey []string
}

// buildPeers renders the live members admit allows into peers: the log says
// who is a member and which WireGuard key it holds, its own signed
// announcement where it is and which disco key it answers with.
//
// The disco key is the one field a peer chooses for itself, and conn requires
// them distinct — left to conn, one member announcing another's key would
// make SetPeers refuse the whole set, a mesh kill switch. Every peer in a
// colliding set is dropped here instead.
func (d *Daemon) buildPeers(s snapshot, held map[types.Identity]gossip.Endpoint,
	discoUsers map[gossip.DiscoKey]int, relays []conn.Relay, admit func(types.Identity) bool, ap *accessPlan) peerSet {
	out := peerSet{peers: make([]conn.Peer, 0, len(s.members))}
	for i := range s.members {
		n := &s.members[i]
		if n.Identity == d.self || !s.live[n.Identity] || !admit(n.Identity) ||
			s.view.Restricted && !s.view.Peers[n.Identity] {
			continue
		}
		ep, ok := held[n.Identity]
		if !ok {
			out.silent = append(out.silent, n.Name)
			continue
		}
		if discoUsers[ep.Disco] > 1 || ep.Disco == d.discoPublic {
			out.conflicted++
			d.logOnce("daemon: two members announce the same NAT-traversal key, or one announces this " +
				"device's; none of them gets a peer entry until that is resolved")
			continue
		}
		p := conn.Peer{
			ID:        d.peerID(n.WireGuard),
			NodeKey:   conn.NodePublicFromRaw32(n.WireGuard),
			DiscoKey:  conn.DiscoPublicFromRaw32(ep.Disco),
			Addrs:     d.overlayAddrs(s.state, n.Identity, s.now),
			Endpoints: d.underlay(ep),
			HomeRelay: homeRelay(ep, relays),
			Access:    ap.access(n, ep),
		}
		psk, stage := d.psk(s.state, n, ep)
		p.PSK = psk
		if notPQ(s.state, stage) {
			// juist's own traffic alone, which seals itself.
			p.Access = ap.ownOnly(n, ep)
		}
		if stage == pairkey.StageUnknown {
			out.noKey = append(out.noKey, n.Name)
		}
		if n.HasRole(types.RoleIngress) {
			if out.ingresses == nil {
				out.ingresses = map[key.NodePublic]bool{}
			}
			out.ingresses[p.NodeKey] = true
		}
		out.peers = append(out.peers, p)
		out.named = append(out.named, namedPeer{name: n.Name, id: n.Identity, wg: n.WireGuard, peer: p, stage: stage})
	}
	return out
}

// namedIn reports whether s's log names this device, by its identity or,
// where that rotated, by its WireGuard key.
func (d *Daemon) namedIn(s snapshot) bool {
	return slices.ContainsFunc(s.members, func(n types.NodeRecord) bool {
		return n.Identity == d.self || n.WireGuard == d.own.Load().wg
	})
}

// selfName is this device's member name in state, or the last one known.
func (d *Daemon) selfName(state *log.State) string {
	if self, ok := state.Node(d.self); ok {
		return self.Name
	}
	return d.Status().SelfName
}

// setDerived replaces what the last reconcile derived.
func (d *Daemon) setDerived(v ipc.Derived) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status.Derived = v
}

// teardown drops every peer and stops relaying, for a node that cannot say
// who is a member, and publishes v for the status. why completes the error
// the data plane may return.
func (d *Daemon) teardown(v ipc.Derived, why string) error {
	d.stopRelaying()
	d.setInstalled(nil)
	d.mu.Lock()
	d.status.Tunnels = ipc.Tunnels{}
	d.relayUnreachedSince = time.Time{}
	d.reachGen++
	d.mu.Unlock()
	err := d.manager.SetPeers(nil)
	if err != nil {
		err = fmt.Errorf("daemon: dropping every peer %s: %w", why, err)
		v.DataPlaneError = err.Error()
	}
	down := "this device cannot tell who is a member"
	switch {
	case v.Disabled != "":
		down = "the network is disabled"
	case v.NotMember:
		down = "this device is no member of the network"
	}
	// A device that cannot tell who is a member resolves none of them.
	p := d.exitDown(down)
	p.zone = noZone
	d.applyExit(p)
	v.Exit = d.exitNow()
	v.Subnets = d.subnetsNow()
	v.LastReconcile = d.now().Unix()
	d.setDerived(v)
	return err
}

// orphansLocked names the changes that lost fork choice, for the status, with
// d.authMu held: the revocations not in effect until reissued, and the other
// changes that can be started again. The admission of a device among the
// latter leaves it out of the network, which nothing else would say outside
// "juist log"; those in an alarm's conflict are the alarm's to name.
func (d *Daemon) orphansLocked() (unrevoked, lost []string) {
	state := d.authority.State()
	for _, o := range d.authority.Orphans() {
		for _, h := range o.Unrevoked {
			if aum, who, ok := d.orphanLocked(state, h); ok {
				unrevoked = append(unrevoked, describeUnrevoked(aum, who))
			}
		}
		if o.Conflict != "" {
			continue
		}
		for _, h := range o.Records {
			if slices.Contains(o.Unrevoked, h) {
				continue
			}
			if aum, who, ok := d.orphanLocked(state, h); ok {
				lost = append(lost, describeLost(aum, who))
			}
		}
	}
	return unrevoked, lost
}

// orphanLocked reads an orphaned record and names its subject as state knows
// it, with d.authMu held.
func (d *Daemon) orphanLocked(state *log.State, h types.Hash) (types.AUM, string, bool) {
	aum, err := d.storage.AUM(h)
	if err != nil {
		return types.AUM{}, "", false
	}
	if aum.Subject == nil {
		return aum, "", true
	}
	who := aum.Subject.ShortString()
	if n, ok := state.Node(*aum.Subject); ok {
		who = n.Name
	} else if k, ok := state.Admin(*aum.Subject); ok {
		who = cmp.Or(k.Holder, k.Name, who)
	}
	return aum, who, true
}

func describeUnrevoked(aum types.AUM, who string) string {
	switch aum.Kind {
	case types.KindRemoveNode:
		return "the removal of " + who
	case types.KindRemoveAdminKey:
		return "taking the vote from " + who + "'s key"
	case types.KindSetNodeRoutes:
		return "taking the voucher role from " + who
	case types.KindSetVouchers:
		return "raising the vouching threshold"
	case types.KindSetQuorum:
		return "raising the quorum"
	case types.KindSetHolder:
		return "the stricter rule for " + aum.Holder.Name
	}
	return fmt.Sprintf("a %v", aum.Kind)
}

func describeLost(aum types.AUM, who string) string {
	switch {
	case aum.Kind == types.KindAddNode && aum.Node != nil:
		return "the admission of " + cmp.Or(aum.Node.Name, aum.Node.Identity.ShortString())
	case aum.Kind == types.KindSetNodeRoutes:
		return "the change of " + who + "'s roles"
	case aum.Kind == types.KindAddAdminKey && aum.Admin != nil:
		return "the admin key " + cmp.Or(aum.Admin.Holder, aum.Admin.Name)
	case aum.Kind == types.KindRenumberNetwork:
		return "the renumbering of the network"
	case aum.Kind == types.KindRenumberNode:
		return "the renumbering of " + who
	case aum.Kind == types.KindRenameNetwork && aum.Network != nil:
		return "the renaming of the network to " + *aum.Network
	case aum.Kind == types.KindSetNodeNames:
		return "the change of " + who + "'s names"
	case aum.Kind == types.KindSetPublished:
		return "the change of what " + who + " publishes"
	case aum.Kind == types.KindSetDomain:
		return "the change of the network's domain"
	case aum.Kind == types.KindRenameNode && aum.NodeName != nil:
		return fmt.Sprintf("the renaming of %s to %q", who, *aum.NodeName)
	}
	return fmt.Sprintf("a %v", aum.Kind)
}

// refusedEverywhere reports whether a member's log refused this device a
// catch-up while no member it holds an announcement of answered its last
// round. One not tried yet counts as answering, so the report errs quiet.
func (d *Daemon) refusedEverywhere(members []types.NodeRecord, live map[types.Identity]bool) bool {
	refused := false
	for i := range members {
		id := members[i].Identity
		if id == d.self || !live[id] {
			continue
		}
		if d.gossip.Refused(id) {
			refused = true
			continue
		}
		if _, held := d.endpoints.Get(id); held && !d.gossip.Failing(id) {
			return false
		}
	}
	return refused
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

// noteSchema reports a network moved to a record schema this build cannot
// read. It is no alarm, since what the node holds was correct up to the
// upgrade, but this device applies nothing further, revocations included,
// until it is upgraded.
func (d *Daemon) noteSchema() {
	d.authMu.Lock()
	tooNew := d.authority.SchemaAlarm()
	d.authMu.Unlock()
	msg := ""
	if tooNew != nil {
		msg = tooNew.Error()
		d.logOnce("daemon: " + msg)
	}
	d.setStatus(func(s *ipc.Status) { s.SchemaAlarm = msg })
}

// peerID returns the local handle the connectivity layer knows a member by,
// keyed by its WireGuard key: an identity rotation keeps that key, and the
// data plane refuses one key under two handles. It is assigned sequentially
// rather than derived: the ID never leaves this process, so deriving one would
// buy nothing and add a collision case that would take the whole data plane
// down.
func (d *Daemon) peerID(k types.WGKey) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n, ok := d.peerIDs[k]; ok {
		return n
	}
	d.nextPeerID++
	d.peerIDs[k] = d.nextPeerID
	return d.nextPeerID
}
