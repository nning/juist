package daemon

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A pskGiven is the preshared key a peer was last given, and what it is.
type pskGiven struct {
	key   pairkey.Key
	stage pairkey.Stage
}

// loadPairs reads the preshared keys kept, or starts a store of its own,
// which every peer reads as this node having given up the keys it held.
func (d *Daemon) loadPairs() *pairkey.Store {
	s, err := d.readPairsFile()
	if err != nil {
		d.logf("daemon: reading the preshared keys kept, starting over: %v", err)
	}
	if s == nil {
		s = pairkey.NewStore()
	}
	d.pairsKept, _ = s.Encode()
	return s
}

// readPairsFile is the store the pairs file holds, nil where there is none.
func (d *Daemon) readPairsFile() (*pairkey.Store, error) {
	if d.pairsPath == "" {
		return nil, nil
	}
	b, err := os.ReadFile(d.pairsPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	text, err := keys.OpenText(d.pairsPath, string(b))
	if err != nil {
		return nil, err
	}
	for line := range strings.Lines(text) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			raw, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				return nil, err
			}
			return pairkey.DecodeStore(raw)
		}
	}
	return nil, errors.New("no store in the file")
}

// changePairs runs change on the pair store and, where it changed anything,
// keeps the store before anything else reads it: a change that cannot be
// kept is undone, so no peer is told of a key this device would not hold
// after a restart. It reports whether a change was kept.
func (d *Daemon) changePairs(change func(*pairkey.Store) bool) bool {
	d.pairsMu.Lock()
	defer d.pairsMu.Unlock()
	if !change(d.pairs) {
		return false
	}
	b, err := d.pairs.Encode()
	if err == nil && d.pairsPath != "" {
		var text string
		text, err = keys.SealText("# juist preshared keys this device holds with its peers; as secret as node.keys\n" +
			base64.StdEncoding.EncodeToString(b) + "\n")
		if err == nil {
			err = statedir.WriteFilePrivate(d.pairsPath, []byte(text))
		}
	}
	if err != nil {
		d.logf("daemon: keeping the preshared keys, so the change is undone: %v", err)
		if rerr := d.pairs.Restore(d.pairsKept); rerr != nil {
			d.logf("daemon: undoing a change to the preshared keys: %v", rerr)
		}
		return false
	}
	d.pairsKept = b
	return true
}

// readPairs runs read on the pair store, as kept.
func (d *Daemon) readPairs(read func(*pairkey.Store)) {
	d.pairsMu.Lock()
	defer d.pairsMu.Unlock()
	read(d.pairs)
}

// keepSeeds adds the seeds of the epochs held to the pair store, so a peer
// behind is reached on its epoch's group key after the keyring dropped it.
func (d *Daemon) keepSeeds() {
	epochs, held := d.keyring.Held()
	d.changePairs(func(s *pairkey.Store) bool {
		changed := false
		for i, e := range epochs {
			changed = s.AddSeed(e, held[i].PSKSeed(e)) || changed
		}
		return changed
	})
}

// pqEpoch is what this node announces of its preshared keys: the newest
// epoch it holds and its pair store, zero where its handshakes mix in none.
func (d *Daemon) pqEpoch() (epoch, store uint64) {
	d.mu.Lock()
	pq := d.pq
	d.mu.Unlock()
	if !pq {
		return 0, 0
	}
	e, _, ok := d.keyring.Latest()
	if !ok {
		return 0, 0
	}
	return e, d.pairs.ID()
}

// pairEnv is the pair this node and member n form, as state and n's
// announcement ep say, or false where their handshakes mix in no key at all.
func (d *Daemon) pairEnv(state *log.State, n *types.NodeRecord, ep gossip.Endpoint) (*pairkey.Env, bool) {
	if state.Schema() < types.SchemaPQ || !ep.PQ() || ep.Identity != n.Identity {
		return nil, false
	}
	own, _, ok := d.keyring.Latest()
	self, member := state.Node(d.self)
	if !ok || !member {
		return nil, false
	}
	return &pairkey.Env{
		Network:     state.GenesisHash(),
		Self:        pairkey.Side{ID: d.self, WG: self.WireGuard},
		Peer:        pairkey.Side{ID: n.Identity, WG: n.WireGuard},
		PeerMLKEM:   n.MLKEM,
		PeerStore:   ep.PairStore,
		PeerSigning: n.Signing, // none below the cut-over
		Epoch:       min(own, ep.Epoch),
		Decap:       d.own.Load().recipient.Decapsulate,
		Now:         d.now(),
	}, true
}

// pairEnvFor is [Daemon.pairEnv] for the live member id, as the log and the
// announcements held stand now.
func (d *Daemon) pairEnvFor(id types.Identity) (*pairkey.Env, bool) {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil, false
	}
	n, ok := state.Node(id)
	if !ok || n.Expired(d.now().Unix()) {
		return nil, false
	}
	return d.pairEnvOf(state, &n)
}

// pairMsg is this node's message to the member to in the exchange of a
// preshared key, signed; nil where there is none to send.
func (d *Daemon) pairMsg(to types.Identity) *pairkey.Msg {
	env, ok := d.pairEnvFor(to)
	if !ok {
		return nil
	}
	d.advancePair(env, to.ShortString())
	var m pairkey.Msg
	d.readPairs(func(s *pairkey.Store) { m = s.Outgoing(env) })
	if err := m.Sign(d.identity, env.Network, env.PeerSigning != nil); err != nil {
		d.logf("daemon: signing a preshared key's message: %v", err)
		return nil
	}
	return &m
}

// onPair takes a member's message in the exchange of a preshared key.
func (d *Daemon) onPair(m *pairkey.Msg) {
	env, ok := d.pairEnvFor(m.From)
	if !ok {
		return
	}
	if err := m.Verify(env.Network, env.PeerSigning); err != nil {
		d.logf("daemon: dropping a preshared key's message: %v", err)
		return
	}
	if d.changePairs(func(s *pairkey.Store) bool {
		changed, err := s.Take(env, m)
		if err != nil {
			d.logf("daemon: a preshared key with %v: %v", m.From.ShortString(), err)
		}
		return changed
	}) {
		d.wantPair(m.From)
		d.MarkDirty()
	}
}

// advancePair starts a generation with env's peer, named who, where this
// node leads and has none in the pair's epoch, and has the next push reach
// the peer.
func (d *Daemon) advancePair(env *pairkey.Env, who string) {
	if d.changePairs(func(s *pairkey.Store) bool {
		changed, err := s.Advance(env)
		if err != nil {
			d.logf("daemon: a preshared key with %v: %v", who, err)
		}
		return changed
	}) {
		d.wantPair(env.Peer.ID)
		d.MarkDirty()
	}
}

// psk is the preshared key for member n, whose announcement is ep, and what
// it is, starting the exchange of a pair key where this node leads it, and
// noting what n is given.
func (d *Daemon) psk(state *log.State, n *types.NodeRecord, ep gossip.Endpoint) (pairkey.Key, pairkey.Stage) {
	env, ok := d.pairEnv(state, n, ep)
	if !ok {
		d.notePSK(n, pairkey.Key{}, pairkey.StageNone, "")
		return pairkey.Key{}, pairkey.StageNone
	}
	d.advancePair(env, n.Name)
	var k pairkey.Key
	var stage pairkey.Stage
	var gen uint64
	d.readPairs(func(s *pairkey.Store) {
		k, stage = s.Key(env)
		gen = s.Generation(env)
	})
	what := fmt.Sprintf("the group key of epoch %d", env.Epoch)
	switch stage {
	case pairkey.StagePair:
		what = fmt.Sprintf("a pair key, generation %d", gen)
	case pairkey.StageUnknown:
		what = fmt.Sprintf("none in common: epoch %d is past what this device keeps", env.Epoch)
	}
	d.notePSK(n, k, stage, what)
	return k, stage
}

// notePSK records the key n is given and what it is, and logs a new one.
func (d *Daemon) notePSK(n *types.NodeRecord, k pairkey.Key, stage pairkey.Stage, what string) {
	d.mu.Lock()
	if d.psks == nil {
		d.psks = map[types.Identity]pskGiven{}
	}
	g, ok := d.psks[n.Identity]
	if ok && g.key == k {
		d.mu.Unlock()
		return
	}
	d.psks[n.Identity] = pskGiven{key: k, stage: stage}
	d.mu.Unlock()
	if what != "" {
		d.logf("daemon: preshared key with %s: %s", n.Name, what)
	}
}

// probePairs has each exchange this node leads, whose commit the follower
// has not yet confirmed, try the key before it where a check just found the
// peer down and its session gone: the follower is on one of the two.
func (d *Daemon) probePairs(checks []tunnelCheck, probed []bool, handshakes map[uint64]time.Time) {
	changed := false
	for i, c := range checks {
		if !probed[i] || c.reach.Live || d.now().Sub(handshakes[c.peer.ID]) < tunnelFresh {
			continue
		}
		env, ok := d.pairEnvFor(c.id)
		if !ok {
			continue
		}
		d.readPairs(func(s *pairkey.Store) { changed = s.Probe(env) || changed })
	}
	if changed {
		d.MarkDirty()
	}
}

// setPQ says whether the network is at [types.SchemaPQ] or above, where
// handshakes mix in preshared keys and announcements say what they need.
func (d *Daemon) setPQ(on bool) {
	d.endpoints.SetPQ(on)
	d.mu.Lock()
	d.pq = on
	d.mu.Unlock()
}

// setPadded says whether the network is at [types.SchemaPadded] or above,
// where discovery items are padded and announcements name their build's
// schema.
func (d *Daemon) setPadded(on bool) {
	d.endpoints.SetSchemas(on)
	d.mu.Lock()
	d.padded = on
	d.mu.Unlock()
}

// setSigning follows the network to the cut-over: at [types.SchemaSigning]
// this node announces its signing key, and past the cut-over it signs by
// ML-DSA and holds announcements to the keys the log names.
func (d *Daemon) setSigning(state *log.State) {
	var keys map[types.Identity]types.SigningKey
	if state.PQ() {
		keys = make(map[types.Identity]types.SigningKey, len(state.Nodes()))
		for _, n := range state.Nodes() {
			if n.Signing != nil {
				keys[n.Identity] = *n.Signing
			}
		}
	}
	claiming, mldsa := state.Schema() == types.SchemaSigning, state.PQ()
	d.mu.Lock()
	changed := (keys == nil) != (d.signingKeys == nil) || !maps.Equal(keys, d.signingKeys)
	if claiming != d.claiming || mldsa != d.mldsa {
		// Signed again, with what the network now asks for.
		d.announced, d.signed = nil, nil
	}
	d.claiming, d.mldsa, d.signingKeys = claiming, mldsa, keys
	d.mu.Unlock()
	if changed {
		d.endpoints.SetSigningKeys(keys)
	}
}

// paddedItems reports whether discovery items are sealed padded.
func (d *Daemon) paddedItems() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.padded
}

// wantPair has the next push reach id, whom an exchange waits on.
func (d *Daemon) wantPair(id types.Identity) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pairWanted == nil {
		d.pairWanted = map[types.Identity]bool{}
	}
	d.pairWanted[id] = true
}

// takePairWanted returns the peers exchanges wait on, and forgets them.
func (d *Daemon) takePairWanted() map[types.Identity]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := d.pairWanted
	d.pairWanted = nil
	return w
}

// prunePSKs forgets what peers no longer installed were given.
func (d *Daemon) prunePSKs(installed []namedPeer) {
	keep := make(map[types.Identity]bool, len(installed))
	for _, p := range installed {
		keep[p.id] = true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	maps.DeleteFunc(d.psks, func(id types.Identity, _ pskGiven) bool { return !keep[id] })
}

// errNotPQ is why a peer whose tunnel mixes in no preshared key both hold
// carries nothing routed: it announces none.
const errNotPQ = "runs an older juist, or has yet to catch up"

// notPQ reports whether state is at [types.SchemaPQ] and a peer's tunnel,
// at stage, mixes in no preshared key both hold: nothing is routed through
// it, and it carries juist's own traffic alone.
func notPQ(state *log.State, stage pairkey.Stage) bool {
	return state.Schema() >= types.SchemaPQ && stage < pairkey.StageGroup
}
