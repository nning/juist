package daemon

import (
	"net/netip"
	"slices"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A sealing is this device's address key, the keys it is wrapped under for
// each peer, and the record handing it to them, where the policy keeps it
// apart from some member; or, where neither could be made, none, and its
// addresses are withheld.
type sealing struct {
	key      addrkey.Key
	under    [][32]byte
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
	scalar, seed := d.own.Load().recipient.Bytes()
	network := s.state.GenesisHash()
	k, err := addrkey.Derive(append(slices.Clone(scalar), seed...), network, s.state.Epoch(), peers)
	if err != nil {
		d.logOnce("daemon: deriving this device's address key: " + err.Error())
		d.withholdAddrs()
		return
	}
	var under [][32]byte
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
		if env, ok := d.pairEnvOf(s.state, &n); ok {
			d.readPairs(func(p *pairkey.Store) {
				if psk, ok, _ := p.Held(env); ok {
					pair = addrkey.WithPSK(pair, psk)
				}
			})
		}
		under = append(under, pair)
	}
	d.mu.Lock()
	same := d.sealing != nil && d.sealing.key == k && slices.Equal(d.sealing.under, under) &&
		(d.sealing.rec.MLDSA != nil) == d.mldsa
	d.mu.Unlock()
	if same {
		return
	}
	rec := gossip.AddrKey{Owner: d.self, ID: k.ID(), Seq: uint64(d.now().UnixNano())}
	for _, pair := range under {
		rec.Wraps = append(rec.Wraps, addrkey.Wrap(pair, d.self, k))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealing != nil && rec.Seq <= d.sealing.rec.Seq {
		rec.Seq = d.sealing.rec.Seq + 1
	}
	sign := rec.Sign
	if d.mldsa {
		sign = rec.SignPQ
	}
	if err := sign(d.identity); err != nil {
		d.logf("daemon: signing this device's address key: %v", err)
		d.sealing = &sealing{withheld: true}
		return
	}
	d.sealing = &sealing{key: k, under: under, rec: rec}
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
	scalar, _ := d.own.Load().recipient.Bytes()
	pair, err := addrkey.Pair(scalar, d.self, owner, n.X25519, state.GenesisHash())
	if err != nil {
		return addrkey.Key{}, false
	}
	var under [][32]byte
	if env, ok := d.pairEnvOf(state, &n); ok {
		d.readPairs(func(p *pairkey.Store) {
			_, _, all := p.Held(env)
			for _, psk := range all {
				under = append(under, addrkey.WithPSK(pair, psk))
			}
		})
	}
	for _, w := range rec.Wraps {
		for _, pair := range append(under, pair) {
			k, ok := addrkey.Unwrap(pair, owner, id, w)
			if !ok {
				continue
			}
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

// pairEnvOf is [Daemon.pairEnv] for member n, with the announcement held for
// it.
func (d *Daemon) pairEnvOf(state *log.State, n *types.NodeRecord) (*pairkey.Env, bool) {
	ep, ok := d.endpoints.Get(n.Identity)
	if !ok {
		return nil, false
	}
	return d.pairEnv(state, n, ep)
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
