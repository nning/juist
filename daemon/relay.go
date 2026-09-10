package daemon

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// labelRelayRegion separates the relay-region derivation from every other
// digest this project takes, so no hash can be reinterpreted as another kind.
const labelRelayRegion = "juist/relay-region/v1"

// relayRegion is a relay's network-wide identifier, derived from the network
// and the relay member's identity so that every member computes the same
// number without agreeing on anything.
//
// A sorted index over the relay-capable set would collide never but *renumber*
// whenever that set changes, and a peer announces the region it can be reached
// through: two members a reconcile apart would then read the same announcement
// as two different relays. A derivation moves with nobody.
//
// The range is 1..65535 because the data plane keeps a peer's home region in
// 16 bits. Collisions are possible and handled where the set is built, not
// here.
func relayRegion(network types.Hash, id types.Identity) int {
	h := sha256.New()
	h.Write([]byte(labelRelayRegion))
	h.Write([]byte{0})
	h.Write(network[:])
	h.Write(id[:])
	sum := h.Sum(nil)
	return 1 + int(binary.BigEndian.Uint32(sum[:4])%uint32(conn.MaxRegionID))
}

// relaySet renders the relays this node should use: members the log grants
// `relay-capable`, whose announcement says where their relay listens. Both
// halves are required and they come from different places on purpose — a
// member may say where it is, and only quorum may say it may relay.
//
// This node's own relay is included when it runs one, which the caller passes
// in alongside the peers': the data plane needs a region in its map to pick as
// a home, and a member that relayed for others while being reachable through
// no relay itself would be invisible to exactly the peers that cannot punch
// to it.
func (d *Daemon) relaySet(network types.Hash, nodes []types.NodeRecord,
	held map[types.Identity]gossip.Endpoint) []conn.Relay {

	out := make([]conn.Relay, 0, 4)
	taken := make(map[int]types.Identity, 4)
	for i := range nodes {
		n := &nodes[i]
		if !n.HasRole(types.RoleRelayCapable) {
			continue
		}
		ep, ok := held[n.Identity]
		if !ok || ep.Relay == nil {
			continue
		}
		addrs := ep.RelayAddrs()
		if len(addrs) == 0 {
			continue
		}
		region := relayRegion(network, n.Identity)
		// Two relays in one region would share a DERP map entry, and since
		// member relays are not meshed, two clients landing on different
		// nodes of it would not reach each other. Keeping the lower identity
		// is deterministic, so every member drops the same one.
		if other, dup := taken[region]; dup {
			d.logOnce("daemon: two relay-capable members derive the same relay region; " +
				"the one with the lower identity keeps it and the other does not relay")
			if other.Compare(n.Identity) < 0 {
				continue
			}
			out = slices.DeleteFunc(out, func(r conn.Relay) bool { return r.Region == region })
		}
		taken[region] = n.Identity
		r := conn.Relay{
			Region:   region,
			HostName: ep.Relay.HostName,
			Addrs:    addrs,
			STUNPort: ep.Relay.STUNPort,
		}
		copy(r.CertHash[:], ep.Relay.Cert)
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b conn.Relay) int { return a.Region - b.Region })
	return out
}

// syncRelay starts this device's own relay when the log grants it
// `relay-capable`, and stops it when the grant is withdrawn. Running one is a
// standing offer of this member's bandwidth, so it follows the log rather than
// local configuration — with [Options.DisableRelay] as the operator's veto
// over their own machine.
//
// A nil state means this node cannot say who is a member — a fork alarm, or
// its own removal — and the relay stops for the same reason the data plane
// does: admitting members is a membership question, and a node that cannot
// answer one must not guess.
func (d *Daemon) syncRelay(state *log.State) {
	want := !d.noRelay
	if state != nil {
		self, ok := state.Node(d.self)
		want = want && ok && self.HasRole(types.RoleRelayCapable)
	} else {
		want = false
	}
	select {
	case <-d.closed:
		// Shutting down. Starting one here would outlive the Close that has
		// already run over it.
		want = false
	default:
	}

	d.mu.Lock()
	running := d.relay
	d.mu.Unlock()

	switch {
	case want && running == nil:
		srv, err := relay.New(relay.Options{
			Admit: d.admitToRelay,
			Port:  d.relayPort,
			Logf:  d.logf,
		})
		if err != nil {
			d.logOnce("daemon: this device holds the relay-capable role but its relay " +
				"could not start: " + err.Error())
			return
		}
		d.mu.Lock()
		d.relay = srv
		d.announced = nil // the announcement now has a relay to name
		d.mu.Unlock()
		d.logf("daemon: relaying for members on TCP port %d (STUN on UDP %d)",
			srv.Port(), srv.STUNPort())
	case !want && running != nil:
		d.mu.Lock()
		d.relay = nil
		d.announced = nil
		d.mu.Unlock()
		running.Close()
		d.logf("daemon: stopped relaying; the log no longer grants this device the relay-capable role")
	case want && running != nil:
		// Membership moved, so a client admitted earlier may no longer be a
		// member. Admission runs once per connection and never again.
		running.Reauthorize()
	}
}

// stopRelaying takes this device's relay down and empties the key set it
// admits, for the paths where membership cannot be read at all.
func (d *Daemon) stopRelaying() {
	d.mu.Lock()
	d.relayMembers = map[types.WGKey]bool{}
	d.mu.Unlock()
	d.syncRelay(nil)
}

// admitToRelay answers the relay's membership question from the last
// reconciled state. It reads a snapshot rather than the authority, because it
// runs on a DERP connection's goroutine and the authority is behind a lock the
// reconciler holds while it works.
func (d *Daemon) admitToRelay(wg [32]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.relayMembers[types.WGKey(wg)]
}

// relayInfo is what this node announces about its own relay, or nil.
func (d *Daemon) relayInfo() *gossip.RelayInfo {
	d.mu.Lock()
	srv := d.relay
	d.mu.Unlock()
	if srv == nil {
		return nil
	}
	sum := srv.CertHash()
	return &gossip.RelayInfo{
		Port:     srv.Port(),
		STUNPort: srv.STUNPort(),
		Cert:     sum[:],
		HostName: srv.HostName(),
	}
}

// closeRelay stops this device's relay, for shutdown.
func (d *Daemon) closeRelay() {
	d.mu.Lock()
	srv := d.relay
	d.relay = nil
	d.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

// mergeEndpoints adds the addresses the data plane learned — reflexive ones
// from a relay's STUN responder — to the interface scan, rather than replacing
// it. The scan is what makes a LAN with no internet work at all, and a
// reflexive address is what makes an off-LAN peer reachable; neither is a
// superset of the other.
//
// Where the two together exceed what one announcement may carry, the learned
// ones are kept. Truncating the sorted union instead would drop by numeric
// order, and a reflexive address is usually the highest one there is — so a
// multi-homed host would silently announce nothing but its own private
// addresses, which is the one case this exists for.
func mergeEndpoints(scanned, learned []netip.AddrPort) []netip.AddrPort {
	if len(learned) == 0 {
		return scanned
	}
	keep := gossip.SortAddrs(learned)
	if len(keep) > gossip.MaxEndpointAddrs {
		keep = keep[:gossip.MaxEndpointAddrs]
	}
	for _, ap := range scanned {
		if len(keep) >= gossip.MaxEndpointAddrs {
			break
		}
		if !slices.Contains(keep, ap) {
			keep = append(keep, ap)
		}
	}
	return gossip.SortAddrs(keep)
}
