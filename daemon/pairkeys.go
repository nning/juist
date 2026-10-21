package daemon

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"sync"
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

// A pairStore is the preshared keys this node holds with its peers, the
// file they are kept in, where path is not empty, and what was last kept
// there; mu is innermost.
type pairStore struct {
	*pairkey.Store
	path string
	mu   sync.Mutex
	kept []byte
}

// loadPairStore reads the preshared keys kept at path, or starts a store of
// its own, which every peer reads as this node having given up the keys it
// held.
func loadPairStore(path string, logf func(string, ...any)) *pairStore {
	p := &pairStore{path: path}
	s, err := p.readFile()
	if err != nil {
		logf("daemon: reading the preshared keys kept, starting over: %v", err)
	}
	if s == nil {
		s = pairkey.NewStore()
	}
	p.Store = s
	p.kept, _ = s.Encode()
	return p
}

// readFile is the store the file holds, nil where there is none.
func (p *pairStore) readFile() (*pairkey.Store, error) {
	if p.path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	text, err := keys.OpenText(p.path, string(b))
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

// change runs fn on the store and, where it changed anything, keeps the
// store before anything else reads it: a change that cannot be kept is
// undone, so no peer is told of a key this device would not hold after a
// restart. It reports whether a change was kept.
func (p *pairStore) change(fn func(*pairkey.Store) bool, logf func(string, ...any)) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !fn(p.Store) {
		return false
	}
	b, err := p.Encode()
	if err == nil && p.path != "" {
		var text string
		text, err = keys.SealText("# juist preshared keys this device holds with its peers; as secret as node.keys\n" +
			base64.StdEncoding.EncodeToString(b) + "\n")
		if err == nil {
			err = statedir.WriteFilePrivate(p.path, []byte(text))
		}
	}
	if err != nil {
		logf("daemon: keeping the preshared keys, so the change is undone: %v", err)
		if rerr := p.Restore(p.kept); rerr != nil {
			logf("daemon: undoing a change to the preshared keys: %v", rerr)
		}
		return false
	}
	p.kept = b
	return true
}

// changePairs is [pairStore.change] on this node's store.
func (d *Daemon) changePairs(change func(*pairkey.Store) bool) bool {
	return d.pairs.change(change, d.logf)
}

// readPairs runs read on the pair store, as kept.
func (d *Daemon) readPairs(read func(*pairkey.Store)) {
	d.pairs.mu.Lock()
	defer d.pairs.mu.Unlock()
	read(d.pairs.Store)
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
// epoch it holds and its pair store, zero where it holds no epoch.
func (d *Daemon) pqEpoch() (epoch, store uint64) {
	e, _, ok := d.keyring.Latest()
	if !ok {
		return 0, 0
	}
	return e, d.pairs.ID()
}

// pairEnv is the pair this node and member n form, as state and n's
// announcement ep say, or false where their handshakes mix in no key at all.
// Where ep is a hint alone, this node's newest epoch and the store of the
// pair held stand in for what n's announcement names: a forged hint would
// pick a key its author holds.
func (d *Daemon) pairEnv(state *log.State, n *types.NodeRecord, ep gossip.Endpoint) (*pairkey.Env, bool) {
	if !ep.PQ() && !ep.HintAlone() || ep.Identity != n.Identity {
		return nil, false
	}
	own, _, ok := d.keyring.Latest()
	self, member := state.Node(d.self)
	if !ok || !member {
		return nil, false
	}
	epoch, store := min(own, ep.Epoch), ep.PairStore
	if ep.HintAlone() {
		epoch = own
		d.readPairs(func(s *pairkey.Store) { store = s.PeerStore(n.WireGuard) })
	}
	return &pairkey.Env{
		Network:     state.GenesisHash(),
		Self:        pairkey.Side{ID: d.self, WG: self.WireGuard},
		Peer:        pairkey.Side{ID: n.Identity, WG: n.WireGuard},
		PeerMLKEM:   n.MLKEM,
		PeerStore:   store,
		PeerSigning: n.Signing,
		Epoch:       epoch,
		Decap:       d.own.Load().recipient.Decapsulate,
		Now:         d.now(),
	}, true
}

// pairEnvFor is [Daemon.pairEnv] for the live member id, as the log and the
// announcements held stand now, and false where a hint alone is held: an
// exchange moves only against its peer's own announcement.
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
	ep, ok := d.endpoints.Get(id)
	if !ok || ep.HintAlone() {
		return nil, false
	}
	return d.pairEnv(state, &n, ep)
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
	if err := m.Sign(d.identity, env.Network); err != nil {
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
		d.pushPair(m.From)
	}
}

// advancePair starts a generation with env's peer, named who, where this
// node leads and has none in the pair's epoch, and has the next push reach
// the peer; so does an offer it put off that is now due.
func (d *Daemon) advancePair(env *pairkey.Env, who string) {
	changed := d.changePairs(func(s *pairkey.Store) bool {
		changed, err := s.Advance(env)
		if err != nil {
			d.logf("daemon: a preshared key with %v: %v", who, err)
		}
		return changed
	})
	due := false
	d.readPairs(func(s *pairkey.Store) { due = s.Due(env) })
	if changed || due {
		d.pushPair(env.Peer.ID)
	}
}

// psk is the preshared key for member n, whose announcement is ep, and what
// it is, starting the exchange of a pair key where this node leads it, and
// noting what n is given. A hint alone changes no pair.
func (d *Daemon) psk(state *log.State, n *types.NodeRecord, ep gossip.Endpoint) (pairkey.Key, pairkey.Stage) {
	env, ok := d.pairEnv(state, n, ep)
	if !ok {
		d.notePSK(n, pairkey.Key{}, pairkey.StageNone, "")
		return pairkey.Key{}, pairkey.StageNone
	}
	if !ep.HintAlone() {
		d.advancePair(env, n.Name)
	}
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

// setSigning holds announcements to the members' signing keys, as the log
// names them.
func (d *Daemon) setSigning(state *log.State) {
	keys := make(map[types.Identity]types.SigningKey, len(state.Nodes()))
	for _, n := range state.Nodes() {
		if n.Signing != nil {
			keys[n.Identity] = *n.Signing
		}
	}
	d.mu.Lock()
	changed := !maps.Equal(keys, d.signingKeys)
	d.signingKeys = keys
	d.mu.Unlock()
	if changed {
		d.endpoints.SetSigningKeys(keys)
	}
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

// pushPair has the next push reach id with this node's message in their
// exchange, beside the members awake: no other that rests.
func (d *Daemon) pushPair(id types.Identity) {
	d.wantPair(id)
	d.announceSoon()
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

// notPQ reports whether a peer's tunnel, at stage, mixes in no preshared key
// both hold: nothing is routed through it, and it carries juist's own
// traffic alone.
func notPQ(stage pairkey.Stage) bool { return stage < pairkey.StageGroup }
