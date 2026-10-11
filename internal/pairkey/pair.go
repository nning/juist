package pairkey

import (
	"crypto/hmac"
	"crypto/mlkem"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/nning/juist/types"
)

// An Env is what a pair's state is read against: the log's view of both
// members now, the peer's announcement, and this node's ML-KEM key.
type Env struct {
	Network types.Hash
	Self    Side
	Peer    Side

	// PeerMLKEM is the peer's ML-KEM key as the log names it.
	PeerMLKEM types.MLKEMKey

	// PeerStore is the store the peer's announcement names; a pair key made
	// with another is dropped.
	PeerStore uint64

	// Epoch is the pair's: the lower of the epochs the two announce, so the
	// one both hold.
	Epoch uint64

	// Decap opens a ciphertext sealed to this node's ML-KEM key.
	Decap func(ct []byte) ([]byte, error)

	// Now is the time, which paces how often a pair starts or answers a
	// generation.
	Now time.Time
}

// Pace is the least time between two generations a pair starts or answers:
// what a peer can make this node encapsulate and write.
const Pace = 5 * time.Second

const mlkemCTSize = mlkem.CiphertextSize768

func (e *Env) leads() bool { return Leads(e.Self.WG, e.Peer.WG) }

// A Gen is a generation of a pair key: its number, the epoch whose group key
// it mixes in, and the key. N zero is the group key. A follower's carries its
// ciphertext and confirmation until the leader commits to it.
type Gen struct {
	N     uint64 `cbor:"1,keyasint,omitempty"`
	Epoch uint64 `cbor:"2,keyasint,omitempty"`
	Key   Key    `cbor:"3,keyasint"`
	CT    []byte `cbor:"4,keyasint,omitempty"`
}

// An offer is a leader's generation waiting for the follower's ciphertext.
type offer struct {
	N      uint64 `cbor:"1,keyasint"`
	Epoch  uint64 `cbor:"2,keyasint"`
	CT     []byte `cbor:"3,keyasint"`
	Shared []byte `cbor:"4,keyasint"`
}

// A Pair is this node's side of the exchange with one peer, bound to both
// members' WireGuard keys and the peer's store: a change in any starts it
// over. An identity rotation keeps it, so a member that slept through one
// still reaches the rotated device.
//
// The leader offers a generation, the follower answers it, the leader
// commits to it and the follower takes it up; each moves only on the other's
// confirmation that it derived the same key. The follower uses one key, the
// last it took up, so a lost message leaves the leader alone unsure, and it
// tries the key it had while its commit is unconfirmed and the session gone
// ([Pair.probe]), until the follower's message says it took the commit up:
// every key either side may use is a pair key or the group key, never
// none.
type Pair struct {
	Self      types.WGKey `cbor:"1,keyasint"`
	Peer      types.WGKey `cbor:"2,keyasint"`
	PeerStore uint64      `cbor:"3,keyasint"`

	Cur Gen `cbor:"4,keyasint"`

	// Leader: Next is committed to and not yet confirmed, Pend offered,
	// Last the newest generation started, and Flip says it is back on Cur
	// while Next is unconfirmed; Flip is not kept, as it tells the peer
	// nothing.
	Next *Gen   `cbor:"5,keyasint,omitempty"`
	Pend *offer `cbor:"6,keyasint,omitempty"`
	Last uint64 `cbor:"7,keyasint,omitempty"`
	Flip bool   `cbor:"-"`

	// Follower: Offered is answered and not yet committed to.
	Offered *Gen `cbor:"9,keyasint,omitempty"`

	// Prev is the pair key Cur replaced, which the peer may still be on.
	Prev *Gen `cbor:"10,keyasint,omitempty"`

	// paced is when this side last started or answered a generation, and
	// redo has the leader start one, the follower saying it uses another.
	paced time.Time
	redo  bool
}

// pacing reports whether a generation may not be started or answered at now.
func (p *Pair) pacing(now time.Time) bool {
	return !p.paced.IsZero() && now.Sub(p.paced) < Pace && now.After(p.paced)
}

// use makes g the generation in use.
func (p *Pair) use(g Gen) {
	if p.Cur.N != 0 {
		prev := p.Cur
		p.Prev = &prev
	}
	g.CT = nil
	p.Cur = g
}

func (p *Pair) boundTo(env *Env) bool {
	return p.Self == env.Self.WG && p.Peer == env.Peer.WG && p.PeerStore == env.PeerStore
}

// key is the preshared key for the peer, and what it is; seed reads the
// group key's seed for an epoch.
func (p *Pair) key(env *Env, seed func(uint64) ([32]byte, bool)) (Key, Stage) {
	g := p.Cur
	if p.Next != nil && !p.Flip {
		g = *p.Next
	}
	if g.N != 0 {
		return g.Key, StagePair
	}
	s, ok := seed(env.Epoch)
	if !ok {
		return Unknown, StageUnknown
	}
	return Group(s, env.Epoch, env.Self.WG, env.Peer.WG), StageGroup
}

// advance starts a generation where the leader has none in the pair's
// epoch, reporting whether it did.
func (p *Pair) advance(env *Env, seed func(uint64) ([32]byte, bool)) (bool, error) {
	switch {
	case !env.leads() || p.Next != nil:
		return false, nil
	case p.Pend != nil && p.Pend.Epoch >= env.Epoch:
		return false, nil
	case p.Pend == nil && p.Cur.N != 0 && p.Cur.Epoch >= env.Epoch && !p.redo:
		return false, nil
	}
	if _, ok := seed(env.Epoch); !ok || p.pacing(env.Now) || max(p.Last, p.Cur.N) == math.MaxUint64 {
		return false, nil
	}
	shared, ct, err := encapsulate(env.PeerMLKEM)
	if err != nil {
		return false, err
	}
	p.Last = max(p.Last, p.Cur.N) + 1
	p.Pend, p.paced, p.redo = &offer{N: p.Last, Epoch: env.Epoch, CT: ct, Shared: shared}, env.Now, false
	return true, nil
}

// outgoing is this side's message to the peer, unsigned.
func (p *Pair) outgoing(env *Env, store uint64) Msg {
	m := Msg{From: env.Self.ID, To: env.Peer.ID, Store: store, ToStore: env.PeerStore, FromWG: env.Self.WG,
		ToWG: env.Peer.WG, Gen: p.Cur.N, Use: p.Cur.N}
	switch {
	case env.leads() && p.Next != nil:
		m.Gen, m.Epoch, m.Use, m.Check = p.Next.N, p.Next.Epoch, p.Next.N, check(p.Next.Key, "leader")
	case env.leads() && p.Pend != nil:
		m.Gen, m.Epoch, m.CT = p.Pend.N, p.Pend.Epoch, slices.Clone(p.Pend.CT)
	case !env.leads() && p.Offered != nil:
		m.Gen, m.Epoch, m.CT, m.Check = p.Offered.N, p.Offered.Epoch, slices.Clone(p.Offered.CT),
			check(p.Offered.Key, "follower")
	}
	return m
}

// take moves on the peer's message, verified and addressed to this pair,
// reporting whether anything changed.
func (p *Pair) take(env *Env, m *Msg, seed func(uint64) ([32]byte, bool)) (bool, error) {
	if env.leads() {
		return p.takeAsLeader(env, m, seed)
	}
	return p.takeAsFollower(env, m, seed)
}

func (p *Pair) takeAsLeader(env *Env, m *Msg, seed func(uint64) ([32]byte, bool)) (bool, error) {
	changed := false
	// A follower on a generation this side did not commit to, as after
	// either side started the pair over, has the next one start past it.
	if last := max(p.Last, m.Gen, m.Use); last != p.Last {
		p.Last, changed = last, true
	}
	// Past it, or on none: a follower behind it says something stale.
	if p.Next == nil && p.Pend == nil && (m.Use > p.Cur.N || m.Use == 0 && p.Cur.N != 0) {
		p.redo = true
	}
	if o := p.Pend; o != nil && m.Gen == o.N && m.CT != nil {
		p.Pend, changed = nil, true
		s, ok := seed(o.Epoch)
		if !ok {
			return true, fmt.Errorf("pairkey: no longer holding epoch %d, which generation %d mixes in", o.Epoch, o.N)
		}
		shared, err := env.Decap(m.CT)
		if err != nil {
			return true, fmt.Errorf("pairkey: opening the peer's ciphertext: %w", err)
		}
		k := derive(env.Network, env.Self.WG, env.Peer.WG, o.N, o.Epoch, Group(s, o.Epoch, env.Self.WG, env.Peer.WG),
			o.Shared, o.CT, shared, m.CT)
		if !hmac.Equal(m.Check, check(k, "follower")) {
			return true, fmt.Errorf("pairkey: the peer derived another key for generation %d", o.N)
		}
		p.Next, p.Flip = &Gen{N: o.N, Epoch: o.Epoch, Key: k}, false
	}
	if p.Next != nil && m.Use == p.Next.N {
		p.use(*p.Next)
		p.Next, p.Flip, changed = nil, false, true
	}
	return changed, nil
}

func (p *Pair) takeAsFollower(env *Env, m *Msg, seed func(uint64) ([32]byte, bool)) (bool, error) {
	changed := false
	if m.CT != nil && m.Gen > p.Cur.N && (p.Offered == nil || m.Gen > p.Offered.N) && !p.pacing(env.Now) {
		if m.Epoch == 0 {
			return false, errors.New("pairkey: an offer mixing in no epoch")
		}
		s, ok := seed(m.Epoch)
		if !ok {
			return false, fmt.Errorf("pairkey: an offer mixing in epoch %d, which this node does not hold", m.Epoch)
		}
		sharedL, err := env.Decap(m.CT)
		if err != nil {
			return false, fmt.Errorf("pairkey: opening the peer's ciphertext: %w", err)
		}
		sharedF, ct, err := encapsulate(env.PeerMLKEM)
		if err != nil {
			return false, err
		}
		k := derive(env.Network, env.Peer.WG, env.Self.WG, m.Gen, m.Epoch, Group(s, m.Epoch, env.Self.WG, env.Peer.WG),
			sharedL, m.CT, sharedF, ct)
		p.Offered, p.paced, changed = &Gen{N: m.Gen, Epoch: m.Epoch, Key: k, CT: ct}, env.Now, true
	}
	if o := p.Offered; o != nil && m.Use == o.N && hmac.Equal(m.Check, check(o.Key, "leader")) {
		p.use(*o)
		p.Offered, changed = nil, true
	}
	return changed, nil
}

// held is the pair key both sides have taken up, if any, and every pair key
// either may be on.
func (p *Pair) held() (agreed Key, ok bool, all []Key) {
	for _, g := range []*Gen{&p.Cur, p.Next, p.Prev} {
		if g != nil && g.N != 0 {
			all = append(all, g.Key)
		}
	}
	return p.Cur.Key, p.Cur.N != 0, all
}

// probe has a leader whose commit is unconfirmed, and whose tunnel to the
// peer is down, try the other key: the follower uses one of the two.
func (p *Pair) probe() bool {
	if p.Next == nil {
		return false
	}
	p.Flip = !p.Flip
	return true
}

func (p *Pair) validate() error {
	for _, g := range []*Gen{&p.Cur, p.Next, p.Offered, p.Prev} {
		if g != nil && (g.CT != nil && len(g.CT) != mlkemCTSize || g.N != 0 && g.Key.IsZero()) {
			return fmt.Errorf("pairkey: a malformed generation with %v", p.Peer)
		}
	}
	if o := p.Pend; o != nil && (len(o.CT) != mlkemCTSize || len(o.Shared) != 32 || o.N == 0) {
		return fmt.Errorf("pairkey: a malformed offer to %v", p.Peer)
	}
	return nil
}
