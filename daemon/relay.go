package daemon

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// relayRegion is a relay's region, 1..65535 as the data plane keeps it in 16
// bits. It is derived from the network and the member so that it moves with
// nobody: an index over the relay-capable set would renumber as the set
// changes, and announcements name regions. Collisions are handled in relaySet.
func relayRegion(network types.Hash, id types.Identity) int {
	h := sha256.New()
	h.Write([]byte(types.LabelRelayRegion))
	h.Write([]byte{0})
	h.Write(network[:])
	h.Write(id[:])
	sum := h.Sum(nil)
	return 1 + int(binary.BigEndian.Uint32(sum[:4])%uint32(conn.MaxRegionID))
}

// relayState is this device's own relay, under the daemon's mu.
type relayState struct {
	// server runs while the log grants this device the role; members is
	// the WireGuard key set it admits, refreshed by every reconcile so that
	// a DERP connection never has to reach the authority, and hosts the
	// identity set that may wait at it for an invite's guest. region is
	// whether it holds its region.
	server  *relay.Server
	members map[types.WGKey]bool
	hosts   map[types.Identity]bool
	region  bool

	// https443 is its sockets on 443, by address, httpsErr why some could
	// not be bound, and httpsHanded that the ingress takes 443 instead.
	https443     map[netip.Addr]net.Listener
	httpsErr     string
	httpsHanded  bool
	handOff      net.Listener // the hand-off socket, served by handOffFor
	handOffFor   *relay.Server
	handOffTaken bool // the ingress has been told of it since

	// noCert is why it has no certificate for its name, hasCert that it
	// has had one, and certDue when to order one again, certGap after the
	// last.
	noCert  string
	hasCert bool
	certGap time.Duration
	certDue time.Time

	// unreachedSince is when the tunnel checks first found it reached by
	// nobody, while a live peer reaches no relay.
	unreachedSince time.Time
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
//
// The ingress that relays takes the name its role gives it in the log where
// it announces none proven, and first while this device reaches no relay
// without UDP, as once the name it announced is gone, and after that until
// it announces another: a name proven stays so until its server says
// otherwise, and an announcement found unsigned, as at a relay's rendezvous,
// names no relay. The name's server must say it is the member, as for any
// name.
func (d *Daemon) relaySet(network types.Hash, nodes []types.NodeRecord,
	held map[types.Identity]gossip.Endpoint, ingress nameClaim) []conn.Relay {
	blind := d.manager.ReachesNoRelay()

	out := make([]conn.Relay, 0, 4)
	taken := make(map[int]types.Identity, 4)
	var names []string
	nodes = slices.Clone(nodes)
	slices.SortFunc(nodes, func(a, b types.NodeRecord) int { return a.Identity.Compare(b.Identity) })
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
		if len(addrs) == 0 && ep.Relay.Name == "" {
			continue
		}
		candidates := []string{ep.Relay.Name}
		if ingress.name != "" && ingress.by == n.Identity && ingress.name != ep.Relay.Name {
			if was, over := d.nameProofs.passedOver(n.Identity); blind || over && was == ep.Relay.Name {
				candidates = []string{ingress.name, ep.Relay.Name}
			} else {
				candidates = append(candidates, ingress.name)
			}
		}
		name := ""
		for _, c := range candidates {
			if c != "" && d.relayNameProven(c, n.Identity) {
				name = c
				break
			}
		}
		if ingress.by == n.Identity {
			d.nameProofs.passOver(n.Identity, ep.Relay.Name, blind && name == ingress.name && name != ep.Relay.Name)
		}
		if name != "" && slices.Contains(names, name) {
			// A name is one relay's: two would be two regions on one
			// server. The first, by identity below, keeps it.
			d.logOnce("daemon: two relays announce the name " + name + "; the one with the lower identity keeps it")
			name = ""
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
			Name:     name,
			Own:      n.Identity == d.self,
		}
		copy(r.CertHash[:], ep.Relay.Cert)
		if len(r.Addrs) == 0 && r.Name == "" {
			continue
		}
		if name != "" {
			names = append(names, name)
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b conn.Relay) int { return a.Region - b.Region })
	return out
}

// syncRelay runs this device's relay while the log grants it relay-capable and
// [Options.DisableRelay] does not veto it. A nil state, under a fork alarm or
// after its own removal, stops it: who may use it is a membership question.
func (d *Daemon) syncRelay(state *log.State) {
	want := !d.noRelay
	if state != nil {
		self, ok := state.Node(d.self)
		want = want && ok && self.HasRole(types.RoleRelayCapable)
	} else {
		want = false
	}
	if d.ctx.Err() != nil {
		// Shutting down. Starting one here would outlive the Close that has
		// already run over it.
		want = false
	}

	d.mu.Lock()
	running := d.ownRelay.server
	d.mu.Unlock()

	switch {
	case want && running == nil:
		cert, err := d.session.relayCertificate(d.logf)
		if err != nil {
			d.logOnce("daemon: this device holds the relay-capable role but its relay " +
				"could not start: " + err.Error())
			return
		}
		srv, err := onPortOrAny(d, d.relayPort, syscall.EADDRINUSE, "relay", func(port uint16) (*relay.Server, error) {
			o := relay.Options{Admit: d.admitToRelay, AdmitHost: d.admitHostToRelay, Port: port,
				Certificate: cert, Rendezvous: (*relayRendezvous)(d), Identity: d.self, Logf: d.logf}
			if d.relayCerts != nil {
				o.Name, o.NamedCertificate = d.relayName, d.namedCertificate
			}
			return relay.New(o)
		})
		if err != nil {
			d.logOnce("daemon: this device holds the relay-capable role but its relay " +
				"could not start: " + err.Error())
			return
		}
		d.mu.Lock()
		// A rotation came between, and the next reconcile starts it on the
		// certificate for the new keys; or a Close, whose closeRelay has run.
		if !d.session.holds(cert) || d.ctx.Err() != nil {
			d.mu.Unlock()
			srv.Close()
			return
		}
		d.ownRelay.server = srv
		d.announced = nil // the announcement now has a relay to name
		d.mu.Unlock()
		d.logf("daemon: relaying for members on TCP port %d (STUN on UDP %d)",
			srv.Port(), srv.STUNPort())
		d.syncHTTPS(state, srv)
	case !want && running != nil:
		d.mu.Lock()
		d.ownRelay.server = nil
		d.announced = nil
		d.mu.Unlock()
		d.closeHTTPS()
		running.Close()
		d.logf("daemon: stopped relaying; the log no longer grants this device the relay-capable role")
	case want && running != nil:
		// Membership moved, so a client admitted earlier may no longer be a
		// member. Admission runs once per connection and never again.
		running.Reauthorize()
		d.syncHTTPS(state, running)
	}
}

// stopRelaying takes this device's relay down and empties the key set it
// admits, for the paths where membership cannot be read at all.
func (d *Daemon) stopRelaying() {
	d.mu.Lock()
	d.ownRelay.members = map[types.WGKey]bool{}
	d.ownRelay.hosts = map[types.Identity]bool{}
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
	return d.ownRelay.members[types.WGKey(wg)]
}

// admitHostToRelay reports whether an identity may wait at this device's
// relay for an invite's guest: any live member may.
func (d *Daemon) admitHostToRelay(id [32]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ownRelay.hosts[types.Identity(id)]
}

// relayInfo is what this node announces about its own relay, or nil.
func (d *Daemon) relayInfo() *gossip.RelayInfo {
	d.mu.Lock()
	srv := d.ownRelay.server
	d.mu.Unlock()
	if srv == nil {
		return nil
	}
	sum := srv.CertHash()
	info := &gossip.RelayInfo{
		Port:     srv.Port(),
		STUNPort: srv.STUNPort(),
		Cert:     sum[:],
		HostName: srv.HostName(),
	}
	d.mu.Lock()
	if d.relayCerts != nil {
		info.Name = d.relayName
	}
	d.mu.Unlock()
	return info
}

// closeRelay stops this device's relay, for shutdown.
func (d *Daemon) closeRelay() {
	d.mu.Lock()
	srv := d.ownRelay.server
	d.ownRelay.server = nil
	d.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

// inviteRelays are the member relays an invite from this device may wait at
// for its guest: every live member the log makes relay-capable whose
// announcement says where its relay is, this device last, whose own a guest
// on HTTPS alone needs where no other relay serves a name.
func (d *Daemon) inviteRelays(state *log.State) []forward.Relay {
	now := d.now().Unix()
	var relays []types.NodeRecord
	var self *types.NodeRecord
	held := map[types.Identity]gossip.Endpoint{}
	claims := map[string]int{}
	for _, n := range state.NodesWithRole(types.RoleRelayCapable) {
		if n.Expired(now) {
			continue
		}
		ep, ok := d.endpoints.Get(n.Identity)
		if n.Identity == d.self {
			ep, ok = d.announcement()
		}
		if !ok || ep.Relay == nil || len(ep.Relay.Cert) != sha256.Size {
			continue
		}
		if n.Identity == d.self {
			self = &n
		} else {
			relays = append(relays, n)
		}
		held[n.Identity] = ep
		if ep.Relay.Name != "" {
			claims[ep.Relay.Name]++
		}
	}
	if self != nil {
		relays = append(relays, *self)
	}
	var out []forward.Relay
	for _, n := range relays {
		ep := held[n.Identity]
		// A host waiting at a name tells its server the invite's forward
		// ID: a name two relays claim is the one's its server names, or
		// none's. One claimed alone is taken unasked, since the host may
		// reach no name, as from behind its own NAT, and a guest needs one.
		name := ep.Relay.Name
		if name != "" && claims[name] > 1 && !d.relayNameProven(name, n.Identity) {
			name = ""
		}
		addrs := ep.RelayAddrs()
		if len(addrs) == 0 && name == "" {
			continue
		}
		out = append(out, forward.Relay{Addrs: addrs, CertHash: [32]byte(ep.Relay.Cert),
			ServerName: ep.Relay.HostName, Name: name})
	}
	return out
}
