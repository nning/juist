package pairkey

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/nning/juist/types"
)

// SeedDepth is how many epochs' seeds a [Store] keeps: a peer that many
// epochs behind is still reached on the group key, where its keyring and
// this node's no longer overlap.
const SeedDepth = 64

// A Store holds this node's pairs and the seeds of the epochs it held. Safe
// for concurrent use.
type Store struct {
	mu    sync.Mutex
	id    uint64
	last  uint64 // the newest generation any pair started, so none is reused
	pairs map[types.WGKey]*Pair
	seeds map[uint64][32]byte
}

// NewStore returns an empty store under a fresh ID: every peer drops what it
// paired with any earlier one.
func NewStore() *Store {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("pairkey: drawing a store ID: %v", err))
		}
		if id := binary.BigEndian.Uint64(b[:]); id != 0 {
			return &Store{id: id, pairs: map[types.WGKey]*Pair{}, seeds: map[uint64][32]byte{}}
		}
	}
}

// ID names the store, as this node's announcement does.
func (s *Store) ID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

// Reset gives up every pair under a new ID, which every peer reads as the
// pairs it held with this node given up, and reports whether there were
// any to give up.
func (s *Store) Reset() bool {
	fresh := NewStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pairs) == 0 {
		return false
	}
	s.id, s.pairs, s.last = fresh.id, fresh.pairs, 0
	return true
}

// AddSeed keeps an epoch's seed, dropping the oldest past [SeedDepth],
// and reports whether it was new.
func (s *Store) AddSeed(epoch uint64, seed [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.seeds[epoch]; ok && old == seed {
		return false
	}
	s.seeds[epoch] = seed
	for len(s.seeds) > SeedDepth {
		delete(s.seeds, slices.Min(slices.Collect(maps.Keys(s.seeds))))
	}
	return true
}

func (s *Store) seed(epoch uint64) ([32]byte, bool) {
	k, ok := s.seeds[epoch]
	return k, ok
}

// pair is the pair env names, or a fresh one where the held one is bound to
// other keys; keep stores the fresh one.
func (s *Store) pair(env *Env, keep bool) *Pair {
	p := s.pairs[env.Peer.WG]
	if p == nil || !p.boundTo(env) {
		p = &Pair{Self: env.Self.WG, Peer: env.Peer.WG, PeerStore: env.PeerStore}
		if keep {
			s.pairs[env.Peer.WG] = p
		}
	}
	return p
}

// PeerStore is the store the pair held with peer is bound to, zero for
// none.
func (s *Store) PeerStore(peer types.WGKey) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.pairs[peer]; p != nil {
		return p.PeerStore
	}
	return 0
}

// Key is the preshared key for env's peer and what it is.
func (s *Store) Key(env *Env) (Key, Stage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pair(env, false).key(env, s.seed)
}

// Held is the pair key in use with env's peer that this node took up, if
// any, and every pair key either side may be on, for what is sealed between
// the two beside the tunnel.
func (s *Store) Held(env *Env) (agreed Key, ok bool, all []Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pair(env, false).held()
}

// Generation is the generation of the pair key in use with env's peer, zero
// for the group key.
func (s *Store) Generation(env *Env) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pair(env, false)
	if p.Next != nil && !p.Flip {
		return p.Next.N
	}
	return p.Cur.N
}

// Advance starts a generation with env's peer where this node leads and has
// none in the pair's epoch, reporting whether the store changed.
func (s *Store) Advance(env *Env) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := s.pairs[env.Peer.WG]
	p := s.pair(env, true)
	p.Last = max(p.Last, s.last)
	changed, err := p.advance(env, s.seed)
	s.last = max(s.last, p.Last)
	return changed || p != held, err
}

// Outgoing is this node's message to env's peer, unsigned.
func (s *Store) Outgoing(env *Env) Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pair(env, false).outgoing(env, s.id)
}

// Take moves on a message from env's peer, reporting whether the store
// changed. The caller has verified it; one not between this pair, or from
// another store of the peer's than env names, is ignored.
func (s *Store) Take(env *Env, m *Msg) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.From != env.Peer.ID || m.To != env.Self.ID || m.Store != env.PeerStore || m.ToStore != s.id ||
		m.FromWG != env.Peer.WG || m.ToWG != env.Self.WG {
		return false, nil
	}
	if env.leads() && max(m.Gen, m.Use) > s.last {
		// Every generation a follower holds started here.
		return false, nil
	}
	held := s.pairs[env.Peer.WG]
	p := s.pair(env, true)
	changed, err := p.take(env, m, s.seed)
	return changed || p != held, err
}

// Due reports, once, whether an offer from env's peer that this node put
// off within [Pace] may now be answered: the peer is to be reached for it.
// Nothing of it is kept.
func (s *Store) Due(env *Env) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pairs[env.Peer.WG]
	return p != nil && p.boundTo(env) && p.due(env.Now)
}

// Describe says where the exchange with env's peer stands, naming no key.
func (s *Store) Describe(env *Env) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pairs[env.Peer.WG]
	if p == nil || !p.boundTo(env) {
		return "no exchange"
	}
	return p.describe(env)
}

// Probe says env's peer's session is gone and its tunnel down, reporting
// whether the key for it changed. Nothing of it is kept.
func (s *Store) Probe(env *Env) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pairs[env.Peer.WG]
	return p != nil && p.boundTo(env) && p.probe()
}

// Generations is the generation in use with each peer, by its WireGuard
// key, zero for the group key.
func (s *Store) Generations() map[types.WGKey]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[types.WGKey]uint64, len(s.pairs))
	for k, p := range s.pairs {
		out[k] = p.Cur.N
	}
	return out
}

// Prune drops the pairs with peers whose WireGuard keys keep refuses,
// reporting whether any went.
func (s *Store) Prune(keep func(types.WGKey) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.pairs)
	maps.DeleteFunc(s.pairs, func(k types.WGKey, _ *Pair) bool { return !keep(k) })
	return len(s.pairs) != n
}

// stored is a store as persisted.
type stored struct {
	ID    uint64       `cbor:"1,keyasint"`
	Last  uint64       `cbor:"4,keyasint,omitempty"`
	Pairs []*Pair      `cbor:"2,keyasint,omitempty"`
	Seeds []storedSeed `cbor:"3,keyasint,omitempty"`
}

type storedSeed struct {
	Epoch uint64   `cbor:"1,keyasint"`
	Seed  [32]byte `cbor:"2,keyasint"`
}

// Encode is the store as persisted.
func (s *Store) Encode() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := stored{ID: s.id, Last: s.last}
	for _, k := range slices.SortedFunc(maps.Keys(s.pairs), func(a, b types.WGKey) int {
		return bytes.Compare(a[:], b[:])
	}) {
		out.Pairs = append(out.Pairs, s.pairs[k])
	}
	for _, e := range slices.Sorted(maps.Keys(s.seeds)) {
		out.Seeds = append(out.Seeds, storedSeed{Epoch: e, Seed: s.seeds[e]})
	}
	return encMode.Marshal(&out)
}

// Restore puts the store back to what b, its encoding, holds: what was last
// kept, where keeping a change failed.
func (s *Store) Restore(b []byte) error {
	kept, err := DecodeStore(b)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range kept.pairs {
		if held := s.pairs[k]; held != nil && held.Self == p.Self && held.PeerStore == p.PeerStore {
			p.paced, p.redo, p.putOff, p.Flip = held.paced, held.redo, held.putOff, held.Flip
		}
	}
	s.id, s.pairs, s.seeds, s.last = kept.id, kept.pairs, kept.seeds, kept.last
	return nil
}

// DecodeStore reads a persisted store.
func DecodeStore(b []byte) (*Store, error) {
	dec, err := types.StrictDecOptions(6, types.MaxNodes, 16).DecMode()
	if err != nil {
		return nil, err
	}
	var in stored
	if err := dec.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("pairkey: decoding the store: %w", err)
	}
	if in.ID == 0 || len(in.Seeds) > SeedDepth {
		return nil, errors.New("pairkey: a malformed store")
	}
	s := &Store{id: in.ID, last: in.Last, pairs: make(map[types.WGKey]*Pair, len(in.Pairs)), seeds: make(map[uint64][32]byte, len(in.Seeds))}
	for _, p := range in.Pairs {
		if p == nil {
			return nil, errors.New("pairkey: a malformed store")
		}
		if err := p.validate(); err != nil {
			return nil, err
		}
		s.pairs[p.Peer] = p
	}
	for _, e := range in.Seeds {
		s.seeds[e.Epoch] = e.Seed
	}
	return s, nil
}
