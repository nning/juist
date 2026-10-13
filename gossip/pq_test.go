package gossip

import (
	"math"
	"net/netip"
	"testing"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/types"
)

// pqEndpoint is a member's announcement, signed by both keys.
func pqEndpoint(t *testing.T, priv types.PrivateIdentity, seq uint64, addr string) Endpoint {
	t.Helper()
	e := Endpoint{Identity: priv.Public(), Disco: DiscoKey{9}, Addrs: []netip.AddrPort{netip.MustParseAddrPort(addr)},
		GossipPort: 41641, Seq: seq}
	if err := e.SignPQ(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

// Past the cut-over an announcement signed by Ed25519 alone is a hint: held
// beside the full announcement, never in its place, dialed where newer and
// relayed to no one. Exit criterion (1) for announcements.
func TestPastTheCutOverEd25519AnnouncementsAreHints(t *testing.T) {
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

	// Below the cut-over the same is a full announcement, as before; one held
	// so, as from the cache a restart reads, is a hint once the keys arrive.
	before := NewCache()
	if !before.Add(moved) || before.IsHint(id) || len(before.All()) != 1 {
		t.Fatal("below the cut-over an announcement signed by Ed25519 is a hint")
	}
	consenting := hintOf(full, 12, "192.0.2.12:41641")
	consenting.Exit, consenting.Share = true, &Share{Port: 22, Until: 1 << 40}
	_ = consenting.Sign(member)
	before.Add(consenting)
	before.SetSigningKeys(map[types.Identity]types.SigningKey{id: member.SigningKey()})
	if e, _ := before.Get(id); !before.IsHint(id) || e.Exit || e.Share != nil {
		t.Fatalf("an announcement held from before the keys kept what only its author may say: %+v", e)
	}
}

// Past the cut-over an address key is held only signed by ML-DSA: a forged
// one would have members open its owner's addresses under a key of the
// forger's.
func TestPastTheCutOverAddressKeysAreSignedByMLDSA(t *testing.T) {
	member, _ := types.GenerateIdentity()
	c := NewCache()
	c.SetMembership([]types.Identity{member.Public()}, nil)
	k := AddrKey{Owner: member.Public(), Seq: 1, Wraps: [][]byte{make([]byte, addrkey.WrapSize)}}
	if err := k.Sign(member); err != nil {
		t.Fatal(err)
	}
	if !c.AddKey(k) {
		t.Fatal("below the cut-over an address key signed by Ed25519 was refused")
	}
	c.SetSigningKeys(map[types.Identity]types.SigningKey{member.Public(): member.SigningKey()})
	if len(c.Keys()) != 0 {
		t.Fatal("an address key signed by Ed25519 alone was kept past the cut-over")
	}
	k.Seq = 2
	_ = k.Sign(member)
	if c.AddKey(k) {
		t.Fatal("past the cut-over an address key signed by Ed25519 alone was taken")
	}
	if err := k.SignPQ(member); err != nil {
		t.Fatal(err)
	}
	if !c.AddKey(k) {
		t.Fatal("past the cut-over an address key signed by ML-DSA was refused")
	}
}

// A build that reads no signing keys is sent announcements without them and
// without their ML-DSA signatures, whose Ed25519 signature still verifies,
// rather than a frame it would refuse whole.
func TestAnOlderBuildIsSentHints(t *testing.T) {
	member, _ := types.GenerateIdentity()
	signed := pqEndpoint(t, member, 1, "192.0.2.1:41641")
	e := signed.Hint()
	claim, err := ClaimSigningKey(member)
	if err != nil {
		t.Fatal(err)
	}
	e.Signing = claim
	if err := e.Verify(); err != nil {
		t.Fatalf("an announcement claiming its signing key: %v", err)
	}
	for _, e := range []Endpoint{e, signed} {
		old := reads{epochs: true, schemas: true}.shaped(e)
		if old.Signing != nil || old.MLDSA != nil || old.Verify() != nil {
			t.Fatalf("an older build is sent %+v", old)
		}
		if now := (reads{epochs: true, schemas: true, signing: true}).shaped(e); now.MLDSA != e.MLDSA || now.Signing != e.Signing {
			t.Fatal("a build that reads them is not sent the signing key or ML-DSA signature")
		}
	}
	other, _ := types.GenerateIdentity()
	stolen := e
	stolen.Signing = &SigningClaim{Key: other.SigningKey(), Endorsement: claim.Endorsement}
	if stolen.Verify() == nil {
		t.Fatal("an announcement claiming a signing key it did not endorse verified")
	}
}

// Past the cut-over a catch-up is signed by ML-DSA both ways: a responder
// takes no proof signed by Ed25519 alone, and grants one signed by both.
func TestPastTheCutOverACatchUpIsSignedByMLDSA(t *testing.T) {
	p := newCatchUpPair(t)
	p.peer.log.schema.Store(uint32(types.SchemaMLDSA))
	view, _ := p.sleeper.log.View()
	if _, _, err := p.sleeper.node.askCatchUp(dialRaw(t, p.peer), &view, reads{}); err == nil {
		t.Fatal("a catch-up proved by Ed25519 alone was granted past the cut-over")
	}
	p.sleeper.log.schema.Store(uint32(types.SchemaMLDSA))
	view, _ = p.sleeper.log.View()
	key, from, err := p.sleeper.node.askCatchUp(dialRaw(t, p.peer), &view, reads{signing: true})
	if err != nil || key == nil || from != p.peer.id {
		t.Fatalf("a catch-up proved by ML-DSA: %v", err)
	}
}

// A device that slept through the schema before the cut-over cannot tell
// that its peer reads ML-DSA; a peer past it hangs up on a proof by Ed25519
// alone, and the device asks again signing by both.
func TestASleeperFromBeforeTheSigningSchemaCatchesUp(t *testing.T) {
	p := newCatchUpPair(t)
	p.peer.log.schema.Store(uint32(types.SchemaMLDSA))
	p.sleeper.log.schema.Store(uint32(types.SchemaPadded))
	if err := p.sleeper.node.CatchUpWith(t.Context(), p.peer.addr()); err != nil {
		t.Fatalf("a sleeper from before the signing schema was not caught up: %v", err)
	}
}
