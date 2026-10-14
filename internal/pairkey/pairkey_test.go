package pairkey

import (
	"crypto/rand"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

type member struct {
	priv  types.PrivateIdentity
	side  Side
	keys  *secrets.PrivateKeys
	mlkem types.MLKEMKey
	store *Store
	epoch uint64
}

var network = types.Hash{7}

func newMember(t testing.TB, group secrets.Secret, epochs ...uint64) *member {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, mk, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	m := &member{priv: priv, keys: keys, mlkem: mk, store: NewStore()}
	m.side.ID = priv.Public()
	rand.Read(m.side.WG[:])
	for _, e := range epochs {
		m.store.AddSeed(e, group.PSKSeed(e))
		m.epoch = max(m.epoch, e)
	}
	return m
}

// env is m's view of its pair with peer.
func (m *member) env(peer *member) *Env {
	return &Env{Network: network, Self: m.side, Peer: peer.side, PeerMLKEM: peer.mlkem,
		PeerStore: peer.store.ID(), Epoch: min(m.epoch, peer.epoch), Decap: m.keys.Decapsulate}
}

// send is m's signed message to peer, through the wire's encoding.
func (m *member) send(t *testing.T, peer *member) Msg {
	t.Helper()
	msg := m.store.Outgoing(m.env(peer))
	if err := msg.Sign(m.priv, network); err != nil {
		t.Fatal(err)
	}
	b, err := encMode.Marshal(&msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxMsgSize {
		t.Fatalf("a message of %d bytes, over %d", len(b), MaxMsgSize)
	}
	return msg
}

func (m *member) take(t *testing.T, from *member, msg Msg) bool {
	t.Helper()
	if err := msg.Verify(network, new(from.priv.SigningKey())); err != nil {
		t.Fatal(err)
	}
	changed, err := m.store.Take(m.env(from), &msg)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func (m *member) key(peer *member) (Key, Stage) { return m.store.Key(m.env(peer)) }

// pair returns two members ordered leader first.
func pair(t *testing.T, group secrets.Secret, epochs ...uint64) (leader, follower *member) {
	t.Helper()
	a, b := newMember(t, group, epochs...), newMember(t, group, epochs...)
	if Leads(b.side.WG, a.side.WG) {
		a, b = b, a
	}
	return a, b
}

// exchange runs one log sync's worth of messages, the leader first.
func exchange(t *testing.T, l, f *member) {
	t.Helper()
	if _, err := l.store.Advance(l.env(f)); err != nil {
		t.Fatal(err)
	}
	f.take(t, l, l.send(t, f))
	l.take(t, f, f.send(t, l))
	f.take(t, l, l.send(t, f))
	l.take(t, f, f.send(t, l))
}

func TestTheGroupKeyIsThePairsInItsEpoch(t *testing.T) {
	group, _ := secrets.NewSecret()
	seed := group.PSKSeed(3)
	a, b := types.WGKey{1}, types.WGKey{2}
	k := Group(seed, 3, a, b)
	if k != Group(seed, 3, b, a) {
		t.Error("the two sides derive different group keys")
	}
	if k == Group(seed, 3, a, types.WGKey{3}) || k == Group(group.PSKSeed(4), 4, a, b) || k.IsZero() {
		t.Error("the group key does not follow the pair and the epoch")
	}
}

// One log sync takes a pair from the group key to a pair key both hold.
func TestAnExchangeGivesBothThePairKey(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1)
	gl, sl := l.key(f)
	gf, sf := f.key(l)
	if sl != StageGroup || sf != StageGroup || gl != gf {
		t.Fatalf("before an exchange: %v and %v, equal %v", sl, sf, gl == gf)
	}
	exchange(t, l, f)
	kl, sl := l.key(f)
	kf, sf := f.key(l)
	if sl != StagePair || sf != StagePair || kl != kf {
		t.Fatalf("after an exchange: %v and %v, equal %v", sl, sf, kl == kf)
	}
	if kl == gl {
		t.Error("the pair key is the group key")
	}
	// Nothing moves on another round.
	exchange(t, l, f)
	if k, _ := l.key(f); k != kl {
		t.Error("a second round changed the key")
	}
}

// Exit criterion (5) of M15: a member holding the group secret, which sees
// every message the pair sends, derives no pair key, and the messages move
// nothing of its own.
func TestAThirdMemberCannotDeriveThePairKey(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1)
	third := newMember(t, group, 1)
	if _, err := l.store.Advance(l.env(f)); err != nil {
		t.Fatal(err)
	}
	offer := l.send(t, f)
	f.take(t, l, offer)
	answer := f.send(t, l)
	l.take(t, f, answer)
	commit := l.send(t, f)
	f.take(t, l, commit)
	want, _ := f.key(l)

	// What it can compute: the group key, and the secrets its own ML-KEM
	// key opens from the two ciphertexts, which were not sealed to it.
	seed, _ := third.store.seed(1)
	g := Group(seed, 1, l.side.WG, f.side.WG)
	sl, _ := third.keys.Decapsulate(offer.CT)
	sf, _ := third.keys.Decapsulate(answer.CT)
	if derive(network, l.side.WG, f.side.WG, 1, 1, g, sl, offer.CT, sf, answer.CT) == want || g == want {
		t.Fatal("a third member derived the pair key")
	}
	for _, m := range []Msg{offer, answer, commit} {
		if changed, err := third.store.Take(third.env(l), &m); changed || err != nil {
			t.Fatalf("a message between two others moved a third member: %v %v", changed, err)
		}
	}
}

// Whichever messages are lost, the follower uses a key the leader may use,
// both reach the same key once messages get through, and neither ever uses
// none: blocking the exchange keeps the pair on what it had.
func TestLostMessagesNeverLeaveTheTwoApart(t *testing.T) {
	group, _ := secrets.NewSecret()
	for round := range 200 {
		l, f := pair(t, group, 1, 2, 3)
		l.epoch, f.epoch = 1, 1
		drop := func() bool {
			n, _ := rand.Int(rand.Reader, big.NewInt(3))
			return n.Int64() == 0
		}
		var old Key
		for step := range 40 {
			if step == 10 {
				l.epoch, f.epoch = 2, 2
			}
			if step == 20 {
				l.epoch, f.epoch = 3, 3
			}
			if _, err := l.store.Advance(l.env(f)); err != nil {
				t.Fatal(err)
			}
			if !drop() {
				f.take(t, l, l.send(t, f))
			}
			if !drop() {
				l.take(t, f, f.send(t, l))
			}
			kf, sf := f.key(l)
			if kf.IsZero() || sf < StageGroup {
				t.Fatalf("round %d step %d: the follower uses %v", round, step, sf)
			}
			kl, _ := l.key(f)
			if kl == kf {
				old = kl
				continue
			}
			// Apart: the leader's other key is the follower's, which
			// probing finds.
			l.store.Probe(l.env(f))
			if k, _ := l.key(f); k != kf {
				t.Fatalf("round %d step %d: the follower uses a key the leader cannot probe for", round, step)
			}
			l.store.Probe(l.env(f))
		}
		for range 3 {
			exchange(t, l, f)
		}
		kl, sl := l.key(f)
		kf, _ := f.key(l)
		if kl != kf || sl != StagePair {
			t.Fatalf("round %d: after messages got through, %v and apart: %v", round, sl, kl != kf)
		}
		_ = old
	}
}

// An offer made for a follower's earlier store, or keys, takes nothing
// from the pair it starts over with: the follower answers the leader's
// next offer, and the two reach a pair key.
func TestAnOfferForAPairStartedOverIsIgnored(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1, 2)
	l.epoch, f.epoch = 1, 1
	exchange(t, l, f)
	l.epoch, f.epoch = 2, 2
	if _, err := l.store.Advance(l.env(f)); err != nil {
		t.Fatal(err)
	}
	stale := l.send(t, f)
	f.store = NewStore()
	f.store.AddSeed(1, group.PSKSeed(1))
	f.store.AddSeed(2, group.PSKSeed(2))
	if changed := f.take(t, l, stale); changed {
		t.Fatal("an offer for the follower's earlier store was answered")
	}
	for range 2 {
		exchange(t, l, f)
	}
	kl, sl := l.key(f)
	if kf, _ := f.key(l); sl != StagePair || kl != kf {
		t.Fatalf("after the follower started over: %v, apart %v", sl, kl != kf)
	}
}

// A message replayed from an earlier generation moves neither side back.
func TestAReplayedMessageMovesNothingBack(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1, 2)
	l.epoch, f.epoch = 1, 1
	if _, err := l.store.Advance(l.env(f)); err != nil {
		t.Fatal(err)
	}
	offer1 := l.send(t, f)
	f.take(t, l, offer1)
	answer1 := f.send(t, l)
	exchange(t, l, f)
	l.epoch, f.epoch = 2, 2
	exchange(t, l, f)
	kl, _ := l.key(f)
	kf, _ := f.key(l)
	if kl != kf {
		t.Fatal("the second generation left the two apart")
	}
	if changed := f.take(t, l, offer1); changed {
		t.Error("a replayed offer moved the follower")
	}
	if changed := l.take(t, f, answer1); changed {
		t.Error("a replayed answer moved the leader")
	}
	if k, _ := f.key(l); k != kf {
		t.Error("the follower's key moved")
	}
}

// A pair key holds for the keys and the store it was made with: a rotated
// WireGuard key, or a peer's store given up, takes both back to the group
// key.
func TestAPairKeyFollowsItsBinding(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1)
	exchange(t, l, f)
	if _, s := f.key(l); s != StagePair {
		t.Fatal("no pair key")
	}
	f.side.WG[0] ^= 1
	if _, s := l.key(f); s != StageGroup {
		t.Errorf("after the peer's key rotated, the leader uses the %v", s)
	}
	if _, s := f.key(l); s != StageGroup {
		t.Errorf("after its own key rotated, the follower uses the %v", s)
	}
	exchange(t, l, f)
	kl, sl := l.key(f)
	if kf, _ := f.key(l); sl != StagePair || kl != kf {
		t.Fatal("no new pair key after the rotation")
	}
	f.store = NewStore()
	f.store.AddSeed(1, group.PSKSeed(1))
	if _, s := l.key(f); s != StageGroup {
		t.Errorf("after the peer's store was given up, the leader uses the %v", s)
	}
}

// An identity rotation keeps the pair key and who leads: a member asleep
// through one reaches the rotated device on the key the two had.
func TestAnIdentityRotationKeepsThePairKey(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1)
	exchange(t, l, f)
	before, _ := l.key(f)
	rotated, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.priv, f.side.ID = rotated, rotated.Public()
	kl, sl := l.key(f)
	kf, sf := f.key(l)
	if sl != StagePair || sf != StagePair || kl != before || kf != before {
		t.Fatalf("after an identity rotation: %v and %v", sl, sf)
	}
	l.epoch, f.epoch = 2, 2
	l.store.AddSeed(2, group.PSKSeed(2))
	f.store.AddSeed(2, group.PSKSeed(2))
	exchange(t, l, f)
	kl, _ = l.key(f)
	if kf, _ := f.key(l); kl != kf || kl == before {
		t.Error("the rotated pair did not move to a new generation")
	}
}

// A peer an epoch behind past the keyring is reached on the group key of
// its epoch while a seed is kept, and on none that anyone holds after.
func TestSeedsReachAPeerFarBehind(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1)
	for e := uint64(2); e <= SeedDepth; e++ {
		l.store.AddSeed(e, group.PSKSeed(e))
	}
	l.epoch = SeedDepth
	if _, s := l.key(f); s != StageGroup {
		t.Fatalf("a peer %d epochs behind: %v", SeedDepth-1, s)
	}
	l.store.AddSeed(SeedDepth+1, group.PSKSeed(SeedDepth+1))
	l.epoch = SeedDepth + 1
	if k, s := l.key(f); s != StageUnknown || k != Unknown {
		t.Fatalf("a peer past the seeds kept: %v", s)
	}
}

func TestTheStoreSurvivesARestart(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1, 2)
	l.epoch, f.epoch = 1, 1
	exchange(t, l, f)
	l.epoch, f.epoch = 2, 2
	if _, err := l.store.Advance(l.env(f)); err != nil {
		t.Fatal(err)
	}
	f.take(t, l, l.send(t, f))
	before, _ := l.key(f)
	for _, m := range []*member{l, f} {
		b, err := m.store.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if m.store, err = DecodeStore(b); err != nil {
			t.Fatal(err)
		}
	}
	if k, _ := l.key(f); k != before {
		t.Error("the leader's key changed across a restart")
	}
	exchange(t, l, f)
	kl, _ := l.key(f)
	if kf, _ := f.key(l); kl != kf || kl == before {
		t.Error("the generation begun before the restart did not complete")
	}
	if _, err := DecodeStore([]byte{0xa1, 0x01, 0x00}); err == nil {
		t.Error("a store with no ID decoded")
	}
}

// A message signed for another network, or by another key, does not verify.
func TestAMessageIsBoundToItsSenderAndNetwork(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1)
	m := l.send(t, f)
	key := l.priv.SigningKey()
	if err := m.Verify(types.Hash{8}, &key); err == nil {
		t.Error("a message verified for another network")
	}
	m.From = f.side.ID
	if err := m.Verify(network, &key); err == nil {
		t.Error("a message verified as another member's")
	}
}

// A peer cannot make this node encapsulate and write faster than [Pace]: a
// follower answers one new generation per Pace, a leader starts one. An
// offer the follower put off is due once the pace has passed.
func TestGenerationsArePaced(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1, 2, 3)
	l.epoch, f.epoch = 1, 1
	at := time.Unix(1_000_000, 0)
	envAt := func(m, peer *member) *Env {
		e := m.env(peer)
		e.Now = at
		return e
	}
	if changed, err := l.store.Advance(envAt(l, f)); !changed || err != nil {
		t.Fatalf("no first generation: %v", err)
	}
	offer1 := l.store.Outgoing(envAt(l, f))
	if changed, _ := f.store.Take(envAt(f, l), &offer1); !changed {
		t.Fatal("the first offer was not answered")
	}
	l.epoch, f.epoch = 2, 2
	at = at.Add(time.Second)
	if changed, _ := l.store.Advance(envAt(l, f)); changed {
		t.Error("a leader started a second generation within the pace")
	}
	at = at.Add(Pace)
	if changed, _ := l.store.Advance(envAt(l, f)); !changed {
		t.Fatal("a leader started no generation after the pace")
	}
	offer2 := l.store.Outgoing(envAt(l, f))
	at = at.Add(-Pace + time.Second)
	if changed, _ := f.store.Take(envAt(f, l), &offer2); changed {
		t.Error("a follower answered a second generation within the pace")
	}
	if f.store.Due(envAt(f, l)) {
		t.Error("an offer put off is due within the pace")
	}
	at = at.Add(Pace)
	if !f.store.Due(envAt(f, l)) {
		t.Error("an offer put off is not due after the pace: nothing has the follower reach the leader for it")
	}
	if f.store.Due(envAt(f, l)) {
		t.Error("an offer put off is due twice")
	}
	if changed, _ := f.store.Take(envAt(f, l), &offer2); !changed {
		t.Error("a follower answered no generation after the pace")
	}
}

// A pair one side dropped and starts over, under the same keys and stores,
// reaches a pair key again: generations are not reused, and a follower on
// one the leader does not use has it start past it.
func TestAPairStartedOverOnOneSideMeetsAgain(t *testing.T) {
	group, _ := secrets.NewSecret()
	for _, side := range []string{"leader", "follower"} {
		l, f := pair(t, group, 1, 2, 3)
		for e := uint64(1); e <= 3; e++ {
			l.epoch, f.epoch = e, e
			exchange(t, l, f)
		}
		dropped := l
		if side == "follower" {
			dropped = f
		}
		dropped.store.Prune(func(types.WGKey) bool { return false })
		for range 3 {
			exchange(t, l, f)
		}
		kl, sl := l.key(f)
		if kf, _ := f.key(l); sl != StagePair || kl != kf {
			t.Errorf("the %s started over: %v, apart %v", side, sl, kl != kf)
		}
	}
}

// A follower names no generation past what the leader's store started: one
// that does is ignored, and cannot run the leader's count out.
func TestAFollowerCannotRunTheCountOut(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1, 2)
	l.epoch, f.epoch = 1, 1
	exchange(t, l, f)
	m := f.send(t, l)
	m.Gen, m.Use = math.MaxUint64, math.MaxUint64
	if changed, _ := l.store.Take(l.env(f), &m); changed {
		t.Fatal("a generation past the store's moved the leader")
	}
	l.epoch, f.epoch = 2, 2
	exchange(t, l, f)
	kl, sl := l.key(f)
	if kf, _ := f.key(l); sl != StagePair || kl != kf || l.store.Generations()[f.side.WG] != 2 {
		t.Fatalf("the next generation: %v, apart %v, %d", sl, kl != kf, l.store.Generations()[f.side.WG])
	}
}

// A follower's message from before the generation in use starts no new one.
func TestAStaleFollowerMessageStartsNothing(t *testing.T) {
	group, _ := secrets.NewSecret()
	l, f := pair(t, group, 1, 2)
	l.epoch, f.epoch = 1, 1
	exchange(t, l, f)
	stale := f.send(t, l)
	l.epoch, f.epoch = 2, 2
	exchange(t, l, f)
	l.take(t, f, stale)
	if changed, _ := l.store.Advance(l.env(f)); changed {
		t.Error("a stale message started a generation")
	}
}

// A message is held to its sender's ML-DSA signature, by the key the log
// names: one signed by Ed25519 alone, which a quantum computer forges, is
// refused, and so is one checked against no key.
func TestAMessageSignedByEd25519AloneIsRefused(t *testing.T) {
	group, _ := secrets.NewSecret()
	a, b := newMember(t, group, 1), newMember(t, group, 1)
	key := a.priv.SigningKey()
	msg := a.store.Outgoing(a.env(b))
	if err := msg.Sign(a.priv, network); err != nil {
		t.Fatal(err)
	}
	if err := msg.Verify(network, &key); err != nil {
		t.Fatalf("a message signed by both keys: %v", err)
	}
	if err := msg.Verify(network, nil); err == nil {
		t.Fatal("a message verified against no signing key")
	}
	other := b.priv.SigningKey()
	if err := msg.Verify(network, &other); err == nil {
		t.Fatal("a message verified against another member's signing key")
	}
	msg.MLDSA = nil
	if err := msg.Verify(network, &key); err == nil {
		t.Fatal("a message signed by Ed25519 alone verified")
	}
}
