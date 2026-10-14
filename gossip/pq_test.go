package gossip

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/types"
)

// pqEndpoint is a member's announcement, signed by both keys.
func pqEndpoint(t *testing.T, priv types.PrivateIdentity, seq uint64, addr string) Endpoint {
	t.Helper()
	e := Endpoint{Identity: priv.Public(), Disco: DiscoKey{9}, Addrs: []netip.AddrPort{netip.MustParseAddrPort(addr)},
		GossipPort: 41641, Seq: seq, Schema: types.CurrentSchema}
	if err := e.SignPQ(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

// Once the log names signing keys an announcement signed by Ed25519 alone is
// a hint: held beside the full announcement, never in its place, dialed where
// newer and relayed to no one.
func TestEd25519AnnouncementsAreHints(t *testing.T) {
	member, _ := types.GenerateIdentity()
	id := member.Public()
	c := NewCache()
	c.SetMembership([]types.Identity{id}, nil)
	c.SetSigningKeys(map[types.Identity]types.SigningKey{id: member.SigningKey()})
	hintOf := func(e Endpoint, seq uint64, addr string) Endpoint {
		h := e.Hint()
		h.Seq, h.Addrs = seq, []netip.AddrPort{netip.MustParseAddrPort(addr)}
		if err := h.Sign(member); err != nil {
			t.Fatal(err)
		}
		return h
	}

	full := pqEndpoint(t, member, 5, "192.0.2.1:41641")
	full.Exit, full.Epoch, full.PairStore = true, 7, 3
	if err := full.SignPQ(member); err != nil {
		t.Fatal(err)
	}
	early := hintOf(full, 4, "192.0.2.4:41641")
	if !c.Add(early) || !c.IsHint(id) {
		t.Fatal("an announcement signed by Ed25519 alone was not held as a hint")
	}
	if e, _ := c.Get(id); e.Exit || e.MLDSA != nil {
		t.Fatalf("a hint alone says what only its author may: %+v", e)
	}
	if len(c.All()) != 0 || len(c.WithHints()) != 1 {
		t.Fatalf("relayed %d announcements; a hint is relayed to no one", len(c.All()))
	}
	if !c.Add(full) || c.IsHint(id) || len(c.All()) != 1 {
		t.Fatal("a full announcement did not take the place of an older hint")
	}

	// A newer hint is dialed; what its author agreed to, and the preshared
	// key, stay the announcement's, and so does what is relayed.
	moved := hintOf(full, 9, "198.51.100.66:41641")
	moved.Exit, moved.Epoch, moved.PairStore = false, 0, 0
	_ = moved.Sign(member)
	if !c.Add(moved) || c.IsHint(id) {
		t.Fatal("a newer hint was not taken beside the announcement")
	}
	e, _ := c.Get(id)
	switch {
	case e.Addrs[0] != moved.Addrs[0] || e.Seq != 9:
		t.Fatalf("dialed at %v, not where the newer hint says", e.Addrs)
	case !e.Exit:
		t.Fatal("a hint took back what the announcement's author agreed to")
	case e.Epoch != 7 || e.PairStore != 3:
		t.Fatalf("a hint lowered the preshared key to epoch %d, store %d", e.Epoch, e.PairStore)
	case e.MLDSA != nil:
		t.Fatal("dialing information was held with a signature over other addresses")
	}
	if all := c.All(); len(all) != 1 || all[0].Seq != 5 || all[0].VerifyPQ(new(member.SigningKey())) != nil {
		t.Fatal("the hint, not the announcement, is relayed")
	}
	if c.Add(hintOf(full, 3, "192.0.2.3:41641")) {
		t.Fatal("a hint older than the announcement was taken")
	}
	forged := full
	forged.Seq, forged.Exit = 10, false
	_ = forged.Sign(member) // a quantum computer's Ed25519 signature, beside a stale ML-DSA one
	forged.MLDSA = full.MLDSA
	if !c.Add(forged) {
		t.Fatal("a newer announcement whose ML-DSA signature fails was not held as a hint")
	}
	if e, _ := c.Get(id); !e.Exit || e.Seq != 10 {
		t.Fatal("an announcement whose ML-DSA signature fails was held as more than a hint")
	}
	// A forger can neither lower the epoch a pair's key comes from nor
	// number a hint where no later one passes it.
	lower := hintOf(full, 10_000, "198.51.100.1:41641")
	lower.Epoch = 1
	_ = lower.Sign(member)
	if !c.Add(lower) {
		t.Fatal("a newer hint was not taken")
	}
	if e, _ := c.Get(id); e.Epoch != 7 {
		t.Fatalf("a hint lowered the epoch to %d", e.Epoch)
	}
	// Nor raise it, nor name another pair store, disco key or relay: only
	// where to dial is a hint's to say.
	upward := hintOf(full, 10_001, "198.51.100.3:41641")
	upward.Epoch, upward.PairStore, upward.Disco, upward.HomeRelay = 8, 99, DiscoKey{66}, 7
	upward.Relay = &RelayInfo{Port: 443, Cert: make([]byte, RelayCertSize), HostName: "forged"}
	if err := upward.Sign(member); err != nil {
		t.Fatal(err)
	}
	if !c.Add(upward) {
		t.Fatal("a newer hint was not taken")
	}
	switch e, _ := c.Get(id); {
	case e.Epoch != 7 || e.PairStore != 3:
		t.Fatalf("a hint moved the preshared key to epoch %d, store %d", e.Epoch, e.PairStore)
	case e.Disco != full.Disco:
		t.Fatal("a hint replaced the disco key")
	case e.Relay != nil:
		t.Fatal("a hint announced a relay")
	case e.Addrs[0] != upward.Addrs[0] || e.HomeRelay != 7 || e.HintAlone():
		t.Fatalf("not dialed where the newer hint says: %v, home relay %d", e.Addrs, e.HomeRelay)
	}
	if k, ok := c.HintDisco(id); !ok || k != upward.Disco {
		t.Fatal("the newer hint's disco key is not given apart")
	}
	// Its disco key alone is news: a member restarted says no more.
	rerun := hintOf(full, 10_001, "198.51.100.3:41641")
	rerun.Seq, rerun.Disco, rerun.HomeRelay = 10_002, DiscoKey{67}, 7
	if err := rerun.Sign(member); err != nil {
		t.Fatal(err)
	}
	if !c.Add(rerun) {
		t.Fatal("a newer hint naming another disco key alone is no news")
	}
	relaying := full
	relaying.Seq, relaying.Relay = 10_002, &RelayInfo{Port: 8443, Cert: make([]byte, RelayCertSize), HostName: "relay"}
	if err := relaying.SignPQ(member); err != nil {
		t.Fatal(err)
	}
	c.Add(relaying)
	unannounced := hintOf(relaying, 10_003, "198.51.100.4:41641")
	unannounced.Relay = nil
	if err := unannounced.Sign(member); err != nil {
		t.Fatal(err)
	}
	if !c.Add(unannounced) {
		t.Fatal("a newer hint was not taken")
	}
	if e, _ := c.Get(id); e.Relay == nil || e.Relay.Port != 8443 {
		t.Fatal("a hint took a member's relay away")
	}
	pinned := hintOf(full, math.MaxUint64, "198.51.100.2:41641")
	if c.Add(pinned) {
		t.Fatal("a hint numbered far past now was taken")
	}
	newer := pqEndpoint(t, member, 20_000, "192.0.2.11:41641")
	if !c.Add(newer) {
		t.Fatal("a newer full announcement was not taken")
	}
	if e, _ := c.Get(id); e.Addrs[0] != newer.Addrs[0] || e.MLDSA == nil {
		t.Fatal("a newer full announcement did not displace the older hint")
	}

	// Before the keys, as in the cache a restart reads, the same is a full
	// announcement, and a hint once they arrive.
	before := NewCache()
	if !before.Add(moved) || before.IsHint(id) || len(before.All()) != 1 {
		t.Fatal("before the keys an announcement signed by Ed25519 is a hint")
	}
	consenting := hintOf(full, 12, "192.0.2.12:41641")
	consenting.Exit, consenting.Share = true, &Share{Port: 22, Until: 1 << 40}
	_ = consenting.Sign(member)
	before.Add(consenting)
	before.SetSigningKeys(map[types.Identity]types.SigningKey{id: member.SigningKey()})
	if e, _ := before.Get(id); !before.IsHint(id) || e.Exit || e.Share != nil {
		t.Fatalf("an announcement held from before the keys kept what only its author may say: %+v", e)
	}
	if e, _ := before.Get(id); !e.HintAlone() {
		t.Fatal("a hint alone does not say it is one")
	}
}

// A hint alone is read as where to dial its member: no relay, overlay IPv4
// or preshared key's epoch and store. It is kept as signed, so the copy a
// restart reads back still verifies.
func TestAHintAloneSaysWhereToDialAlone(t *testing.T) {
	member, _ := types.GenerateIdentity()
	id := member.Public()
	c := NewCache()
	c.SetMembership([]types.Identity{id}, nil)
	c.SetSigningKeys(map[types.Identity]types.SigningKey{id: member.SigningKey()})
	e := pqEndpoint(t, member, 1, "192.0.2.1:41641")
	h := e.Hint()
	h.Relay = &RelayInfo{Port: 443, Cert: make([]byte, RelayCertSize), HostName: "forged", Name: "relay.example.org"}
	h.NoV4, h.Epoch, h.PairStore, h.Exit = true, 7, 3, true
	if err := h.Sign(member); err != nil {
		t.Fatal(err)
	}
	if !c.Add(h) || !c.IsHint(id) {
		t.Fatal("a hint alone was not held as one")
	}
	got, _ := c.Get(id)
	if got.Relay != nil || got.NoV4 || got.Epoch != 0 || got.PairStore != 0 || got.Exit {
		t.Fatalf("a hint alone says more than where to dial: %+v", got)
	}
	if got.Addrs[0] != h.Addrs[0] || got.Disco != h.Disco || !got.HintAlone() {
		t.Fatalf("a hint alone does not say where to dial: %+v", got)
	}
	kept := c.WithHints()
	if len(kept) != 1 || kept[0].Verify() != nil {
		t.Fatal("a hint alone is not kept as signed")
	}
}

// Before the keys an announcement is not shown signed by ML-DSA, so it is
// numbered no further ahead than a hint, and one held from then that runs
// further is dropped once the keys show it a hint.
func TestAnAnnouncementBeforeTheKeysIsNumberedLikeAHint(t *testing.T) {
	member, _ := types.GenerateIdentity()
	id := member.Public()
	now := time.Unix(1_000_000, 0)
	keys := map[types.Identity]types.SigningKey{id: member.SigningKey()}

	c := NewCache()
	c.SetClock(func() time.Time { return now })
	signed := pqEndpoint(t, member, math.MaxUint64, "192.0.2.9:41641")
	forged := signed.Hint()
	if c.Add(forged) {
		t.Fatal("before the keys an announcement numbered far past now was taken")
	}
	c.SetSigningKeys(keys)
	if !c.Add(signed) {
		t.Fatal("an announcement signed by ML-DSA was held to a hint's bound")
	}

	// Taken while a clock ran a year ahead.
	ahead := pqEndpoint(t, member, uint64(now.Add(365*24*time.Hour).Unix()), "198.51.100.9:41641")
	ahead = ahead.Hint()
	held := NewCache()
	held.SetClock(func() time.Time { return now.Add(365 * 24 * time.Hour) })
	if !held.Add(ahead) {
		t.Fatal("an announcement was refused")
	}
	held.SetClock(func() time.Time { return now })
	held.SetSigningKeys(keys)
	if _, ok := held.Get(id); ok {
		t.Fatal("a demoted announcement numbered far past now was kept as a hint")
	}
}

// Once the log names signing keys an address key is held only signed by
// ML-DSA: a forged one would have members open its owner's addresses under a
// key of the forger's.
func TestAddressKeysAreHeldOnlySignedByMLDSA(t *testing.T) {
	member, _ := types.GenerateIdentity()
	c := NewCache()
	c.SetMembership([]types.Identity{member.Public()}, nil)
	k := AddrKey{Owner: member.Public(), Seq: 1, Wraps: [][]byte{make([]byte, addrkey.WrapSize)}}
	if err := k.Sign(member); err != nil {
		t.Fatal(err)
	}
	if !c.AddKey(k) {
		t.Fatal("before the keys an address key signed by Ed25519 was refused")
	}
	c.SetSigningKeys(map[types.Identity]types.SigningKey{member.Public(): member.SigningKey()})
	if len(c.Keys()) != 0 {
		t.Fatal("an address key signed by Ed25519 alone was kept once the keys arrived")
	}
	k.Seq = 2
	_ = k.Sign(member)
	if c.AddKey(k) {
		t.Fatal("an address key signed by Ed25519 alone was taken")
	}
	if err := k.SignPQ(member); err != nil {
		t.Fatal(err)
	}
	if !c.AddKey(k) {
		t.Fatal("an address key signed by ML-DSA was refused")
	}
}

// A catch-up is signed by ML-DSA both ways, each side holding the other to
// the signing key its log names.
func TestACatchUpIsSignedByMLDSA(t *testing.T) {
	p := newCatchUpPair(t)
	other, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	misnamed := func(n *testNode) memberFunc {
		rec := n.record
		rec.Signing = new(other.SigningKey())
		return lists(&testNode{id: n.id, record: rec})
	}
	ask := func() error {
		view, _ := p.sleeper.log.View()
		key, from, err := p.sleeper.node.askCatchUp(dialRaw(t, p.peer), &view)
		if err == nil && (key == nil || from != p.peer.id) {
			t.Fatalf("granted by %v", from.ShortString())
		}
		return err
	}
	p.setPeerMember(misnamed(p.sleeper))
	if ask() == nil {
		t.Fatal("a proof whose ML-DSA signature fails the listed key was granted")
	}
	p.setPeerMember(lists(p.sleeper))
	p.setSleeperMember(misnamed(p.peer))
	if ask() == nil {
		t.Fatal("a grant whose ML-DSA signature fails the listed key was taken")
	}
	p.setSleeperMember(lists(p.peer))
	if err := ask(); err != nil {
		t.Fatalf("a catch-up signed by both keys: %v", err)
	}
}
