package daemon

import (
	"net/netip"
	"slices"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/types"
)

// A sealing is this device's address key, and the record handing it to its
// peers, where the policy keeps it apart from some member; or, where neither
// could be made, none, and its addresses are withheld.
type sealing struct {
	key      addrkey.Key
	rec      gossip.AddrKey
	withheld bool
}

// planSealing derives this device's address key from what the policy makes
// its peers: none where every member is one, as without a policy, and its
// addresses go under the group's key.
func (d *Daemon) planSealing(s snapshot) {
	peers := make([]types.Identity, 0, len(s.view.Peers))
	for id := range s.view.Peers {
		peers = append(peers, id)
	}
	slices.SortFunc(peers, types.Identity.Compare)
	others := len(s.live)
	if s.live[d.self] {
		others--
	}
	if !s.view.Restricted || len(peers) == others {
		d.mu.Lock()
		d.sealing = nil
		d.mu.Unlock()
		return
	}
	scalar, _ := d.recipient.Bytes()
	network := s.state.GenesisHash()
	k, err := addrkey.Derive(scalar, network, s.state.Epoch(), peers)
	if err != nil {
		d.logOnce("daemon: deriving this device's address key: " + err.Error())
		d.withholdAddrs()
		return
	}
	d.mu.Lock()
	same := d.sealing != nil && d.sealing.key == k
	d.mu.Unlock()
	if same {
		return
	}
	rec := gossip.AddrKey{Owner: d.self, ID: k.ID(), Seq: uint64(d.now().UnixNano())}
	for _, id := range peers {
		n, ok := s.state.Node(id)
		if !ok {
			continue
		}
		pair, err := addrkey.Pair(scalar, d.self, id, n.X25519, network)
		if err != nil {
			d.logOnce("daemon: deriving a pair key with " + n.Name + ": " + err.Error())
			continue
		}
		rec.Wraps = append(rec.Wraps, addrkey.Wrap(pair, d.self, k))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealing != nil && rec.Seq <= d.sealing.rec.Seq {
		rec.Seq = d.sealing.rec.Seq + 1
	}
	if err := rec.Sign(d.identity); err != nil {
		d.logf("daemon: signing this device's address key: %v", err)
		d.sealing = &sealing{withheld: true}
		return
	}
	d.sealing = &sealing{key: k, rec: rec}
}

// withholdAddrs has this device announce no address, rather than one
// readable by a member the policy keeps apart from it.
func (d *Daemon) withholdAddrs() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sealing = &sealing{withheld: true}
}

// decideSealing is planSealing from the log as it stands, for the start,
// before anything announces this device.
func (d *Daemon) decideSealing() {
	d.authMu.Lock()
	state := d.authority.State()
	d.authMu.Unlock()
	d.planSealing(d.membersOf(state))
}

// ownAddrKey is this device's address key record, where it seals.
func (d *Daemon) ownAddrKey() (gossip.AddrKey, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealing == nil || d.sealing.withheld {
		return gossip.AddrKey{}, false
	}
	return d.sealing.rec, true
}

// underlay is where e's node is reached: its addresses, or its sealed ones
// where this device holds their key; none where it does not.
func (d *Daemon) underlay(e gossip.Endpoint) []netip.AddrPort {
	if e.Sealed == nil {
		return e.Addrs
	}
	id, err := addrkey.SealedID(e.Sealed)
	if err != nil {
		return nil
	}
	k, ok := d.openKey(e.Identity, id)
	if !ok {
		return nil
	}
	addrs, err := addrkey.Open(k, e.Sealed)
	if err != nil || gossip.CheckAddrs(addrs) != nil {
		d.logOnce("daemon: a peer's sealed addresses do not open to a valid set; it is reached through relays alone")
		return nil
	}
	return addrs
}

// maxOpenedKeys bounds the keys kept per member: its current one, and those
// its announcements in flight may still be sealed under.
const maxOpenedKeys = 4

// openKey is owner's address key id, unwrapped from the record held for it
// where it wraps one for this device.
func (d *Daemon) openKey(owner types.Identity, id addrkey.ID) (addrkey.Key, bool) {
	d.mu.Lock()
	for _, o := range d.opened[owner] {
		if o.ID() == id {
			d.mu.Unlock()
			return o, true
		}
	}
	d.mu.Unlock()
	rec, ok := d.endpoints.Key(owner)
	if !ok || rec.ID != id {
		return addrkey.Key{}, false
	}
	state, err := d.gossipState()
	if err != nil {
		return addrkey.Key{}, false
	}
	n, ok := state.Node(owner)
	if !ok {
		return addrkey.Key{}, false
	}
	scalar, _ := d.recipient.Bytes()
	pair, err := addrkey.Pair(scalar, d.self, owner, n.X25519, state.GenesisHash())
	if err != nil {
		return addrkey.Key{}, false
	}
	for _, w := range rec.Wraps {
		if k, ok := addrkey.Unwrap(pair, owner, id, w); ok {
			d.mu.Lock()
			if d.opened == nil {
				d.opened = map[types.Identity][]addrkey.Key{}
			}
			keys := append(d.opened[owner], k)
			d.opened[owner] = keys[max(0, len(keys)-maxOpenedKeys):]
			d.mu.Unlock()
			return k, true
		}
	}
	return addrkey.Key{}, false
}

// pruneOpened forgets the keys of members no longer live.
func (d *Daemon) pruneOpened(live map[types.Identity]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id := range d.opened {
		if !live[id] {
			delete(d.opened, id)
		}
	}
}
