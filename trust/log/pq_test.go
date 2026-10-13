package log

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// signingKeysOf are the members' signing keys as their announcements claim
// them, endorsed.
func (h *harness) signingKeysOf(members ...types.NodeRecord) []types.MemberKey {
	h.t.Helper()
	var out []types.MemberKey
	for _, m := range members {
		priv := h.nodeIDs[m.Identity]
		e, err := priv.Endorse()
		if err != nil {
			h.t.Fatal(err)
		}
		out = append(out, types.MemberKey{Identity: m.Identity, Key: priv.SigningKey(), Endorsement: e})
	}
	return out
}

// adminSigning is an admin key's own signing key, endorsed.
func adminSigning(priv types.PrivateIdentity) types.MemberKey {
	return types.MemberKey{Identity: priv.Public(), Key: priv.SigningKey(), Endorsement: *priv.Endorsement()}
}

// registerAdmins registers every admin key's signing key, as each runs
// juist admins receive.
func (h *harness) registerAdmins() {
	h.t.Helper()
	for _, a := range h.admins {
		rec, err := h.auth.Builder().SetAdminSigning(adminSigning(a))
		if err != nil {
			h.t.Fatal(err)
		}
		h.signQuorum(&rec)
		if _, signed := rec.Signature(a.Public()); !signed {
			if err := h.sign(&rec, a); err != nil {
				h.t.Fatal(err)
			}
		}
		if err := h.auth.Inform(rec); err != nil {
			h.t.Fatalf("registering %v: %v", a.Public().ShortString(), err)
		}
	}
}

// cutOverRecord is the record cutting the network over, signed by the admin
// keys given.
func (h *harness) cutOverRecord(keys []types.MemberKey, by ...types.PrivateIdentity) types.AUM {
	h.t.Helper()
	aum, err := h.auth.Builder().SetSigningKeys(h.signingKeysOf(h.auth.State().Nodes()...), h.sealer())
	if err != nil {
		h.t.Fatalf("building the cut-over: %v", err)
	}
	aum.Signing.Members = slices.Clone(keys)
	slices.SortFunc(aum.Signing.Members, func(x, y types.MemberKey) int { return x.Identity.Compare(y.Identity) })
	for _, k := range by {
		if err := h.sign(&aum, k); err != nil {
			h.t.Fatal(err)
		}
	}
	return aum
}

// preCutOver is a network at the schema before the cut-over, with two
// members and two admin keys that have registered their signing keys, and a
// quorum of one.
func preCutOver(t *testing.T) (*harness, types.NodeRecord, types.NodeRecord) {
	t.Helper()
	h := newHarnessAt(t, 2, 1, types.SchemaSigning)
	laptop, phone := h.addNode("laptop"), h.addNode("phone")
	h.registerAdmins()
	return h, laptop, phone
}

// An admin key registers its signing key before the cut-over, endorsed by it
// and signed by it beside the quorum.
func TestAnAdminKeyRegistersItsSigningKey(t *testing.T) {
	h := newHarnessAt(t, 2, 1, types.SchemaSigning)
	h.addNode("laptop")
	keys := h.signingKeysOf(h.auth.State().Nodes()...)
	if _, err := h.auth.Builder().SetSigningKeys(keys, h.sealer()); err == nil {
		t.Fatal("a cut-over was built before every admin key registered its signing key")
	}
	own := adminSigning(h.admins[1])
	h.mustReject("a registration its key has not signed", RuleUnauthorized,
		h.signed(types.AUM{Kind: types.KindSetAdminSigning, Signing: &types.SigningKeys{Members: []types.MemberKey{own}}}))
	unendorsed := own
	other, _ := types.GenerateIdentity()
	unendorsed.Key = other.SigningKey()
	rec := h.signed(types.AUM{Kind: types.KindSetAdminSigning, Signing: &types.SigningKeys{Members: []types.MemberKey{unendorsed}}})
	if err := h.sign(&rec, h.admins[1]); err != nil {
		t.Fatal(err)
	}
	h.mustReject("a registration of a key its admin key did not endorse", RuleState, rec)
	stranger := h.signed(types.AUM{Kind: types.KindSetAdminSigning, Signing: &types.SigningKeys{Members: []types.MemberKey{adminSigning(other)}}})
	if err := h.sign(&stranger, other); err != nil {
		t.Fatal(err)
	}
	h.mustReject("a registration by no admin key", RuleState, stranger)

	h.registerAdmins()
	state := h.auth.State()
	if k, _ := state.Admin(h.admins[1].Public()); k.Signing == nil || *k.Signing != h.admins[1].SigningKey() {
		t.Fatalf("the registered signing key is %v", k.Signing)
	}
	if state.PQ() {
		t.Fatal("a registration cut the network over")
	}
	// Nothing is verified against it, nor signed by it, before the cut-over.
	if got := state.SigningKey(h.admins[1].Public()); got != nil {
		t.Fatalf("below the cut-over a registered key is the one verified against: %v", got)
	}
	// A record is still verified by Ed25519 alone.
	h.apply(h.auth.Builder().EpochBump(h.sealer()))

	low := newHarnessAt(t, 1, 1, types.SchemaPadded)
	low.mustReject("a registration below its schema", RuleState, low.signed(types.AUM{Kind: types.KindSetAdminSigning,
		Signing: &types.SigningKeys{Members: []types.MemberKey{adminSigning(low.admins[0])}}}))
}

// The cut-over takes every member's endorsed key, signed by a quorum, and
// from then on the network signs by ML-DSA alone.
func TestTheCutOverTakesEveryKey(t *testing.T) {
	h, laptop, phone := preCutOver(t)
	keys := h.signingKeysOf(laptop, phone)

	h.mustReject("a cut-over leaving a member out", RuleState, h.cutOverRecord(keys[:1], h.admins...))

	forged := slices.Clone(keys)
	forged[0].Key = keys[1].Key
	h.mustReject("a cut-over naming one key twice", RuleState, h.cutOverRecord(forged, h.admins...))

	stolen := slices.Clone(keys)
	other, _ := types.GenerateIdentity()
	stolen[1].Key = other.SigningKey()
	h.mustReject("a cut-over naming a key its member did not endorse", RuleState, h.cutOverRecord(stolen, h.admins...))

	// An Ed25519 signature carrying a key is no longer how one enters.
	carrying := h.cutOverRecord(keys, h.admins[0])
	s, _ := carrying.Signature(h.admins[0].Public())
	k := h.admins[0].SigningKey()
	s.Key = &k
	h.mustReject("a cut-over whose signature carries a key", RuleMalformed, carrying)

	cut := h.cutOverRecord(keys, h.admins[0])
	if err := h.auth.Inform(cut); err != nil {
		t.Fatalf("the cut-over: %v", err)
	}
	state := h.auth.State()
	if !state.PQ() || state.Schema() != types.SchemaMLDSA {
		t.Fatalf("after the cut-over the network is at %v", state.Schema())
	}
	for _, m := range []types.NodeRecord{laptop, phone} {
		if got := state.SigningKey(m.Identity); got == nil || *got != h.nodeIDs[m.Identity].SigningKey() {
			t.Errorf("%s has signing key %v", m.Name, got)
		}
	}
	for _, a := range h.admins {
		if got := state.SigningKey(a.Public()); got == nil || *got != a.SigningKey() {
			t.Errorf("admin key %v has signing key %v", a.Public().ShortString(), got)
		}
	}
	again := cut.Clone()
	again.Prev, again.Signatures = new(h.auth.Head()), nil
	for _, a := range h.admins {
		if err := h.sign(again, a); err != nil {
			t.Fatal(err)
		}
	}
	h.mustReject("a second cut-over", RuleState, *again)

	// Exit criterion (1) for records: Ed25519 alone is refused past it.
	bump, err := h.auth.Builder().EpochBump(h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := bump.Sign(h.admins[0]); err != nil {
		t.Fatal(err)
	}
	h.mustReject("a record signed by Ed25519 past the cut-over", RuleUnauthorized, bump)
	bump.Signatures = nil
	h.signQuorum(&bump)
	if err := h.auth.Inform(bump); err != nil {
		t.Fatalf("a record signed by ML-DSA past the cut-over: %v", err)
	}
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&cp)
	if _, err := Bootstrap(NewMemStorage(), cp); err != nil {
		t.Fatalf("bootstrapping from a checkpoint past the cut-over: %v", err)
	}
}

// Below the cut-over an ML-DSA signature is refused, as an Ed25519 one is
// past it: never both required, never either accepted.
func TestBelowTheCutOverMLDSAIsRefused(t *testing.T) {
	h, _, _ := preCutOver(t)
	bump, err := h.auth.Builder().EpochBump(h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := bump.SignUnder(h.admins[0], types.SchemaMLDSA); err != nil {
		t.Fatal(err)
	}
	h.mustReject("a record signed by ML-DSA below the cut-over", RuleUnauthorized, bump)
}

// The cut-over is reached by the record that takes the keys alone: an
// upgrade cannot name it, as it cannot carry them.
func TestAnUpgradeCannotCutOver(t *testing.T) {
	for _, from := range []types.SchemaVersion{types.SchemaPadded, types.SchemaSigning} {
		h := newHarnessAt(t, 1, 1, from)
		v := types.SchemaMLDSA
		h.mustReject("an upgrade to "+v.String(), RuleState, h.signed(types.AUM{Kind: types.KindSchemaUpgrade, Schema: &v}))
	}
}

// The upgrade to the schema that caps a member's name bytes is refused while
// a member holds more, and so is a change that would give it more.
func TestNameBytesAreCapped(t *testing.T) {
	h := newHarnessAt(t, 1, 1, types.SchemaPadded)
	n := h.addNode("mail")
	var names []string
	for i := range 10 {
		label := strings.Repeat("a", 63)
		names = append(names, label+"."+label+"."+label+"."+string(rune('a'+i))+".example.org")
	}
	h.apply(h.auth.Builder().SetNodeNames(n.Identity, names))
	v := types.SchemaSigning
	h.mustReject("an upgrade while a member's names take too many bytes", RuleState,
		h.signed(types.AUM{Kind: types.KindSchemaUpgrade, Schema: &v}))
	h.apply(h.auth.Builder().SetNodeNames(n.Identity, names[:5]))
	h.apply(h.auth.Builder().SchemaUpgrade(types.SchemaSigning))
	h.mustReject("names past the cap", RuleState, h.signed(types.AUM{Kind: types.KindSetNodeNames, Subject: &n.Identity,
		Names: &types.NameGrant{Names: names}}))
}

// Past the cut-over an admin key enters with its signing key, which no other
// identity names, and an identity rotated to brings its own in its own
// signature: a member's slot never takes a key on the quorum's word alone.
func TestKeysEnterWithTheirIdentities(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("laptop")
	alice, _ := types.GenerateIdentity()
	if _, err := h.auth.Builder().AddAdminKey(types.AdminKey{Public: alice.Public(), Votes: 1}); err == nil {
		t.Fatal("an admin key with no signing key was built")
	}
	h.mustReject("an admin key with no signing key", RuleState, h.signed(types.AUM{Kind: types.KindAddAdminKey,
		Admin: &types.AdminKey{Public: alice.Public(), Votes: 1}}))
	h.mustReject("an admin key naming a member's signing key", RuleMalformed, h.signed(types.AUM{Kind: types.KindAddAdminKey,
		Admin: &types.AdminKey{Public: alice.Public(), Votes: 1, Signing: n.Signing, Endorsement: alice.Endorsement()}}))
	h.apply(h.auth.Builder().AddAdminKey(types.AdminKey{Public: alice.Public(), Votes: 1, Signing: new(alice.SigningKey()), Endorsement: alice.Endorsement()}))
	if got := h.auth.State().SigningKey(alice.Public()); got == nil || *got != alice.SigningKey() {
		t.Fatalf("the added admin key's signing key is %v", got)
	}

	fresh, _ := types.GenerateIdentity()
	rot, err := h.auth.Builder().RotateIdentity(n.Identity, fresh.Public(), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rot)
	if err := h.sign(&rot, h.nodeIDs[n.Identity]); err != nil {
		t.Fatal(err)
	}
	keyless := rot.Clone()
	if err := keyless.SignUnder(fresh, types.SchemaMLDSA); err != nil {
		t.Fatal(err)
	}
	s, _ := keyless.Signature(fresh.Public())
	s.Key = nil
	h.mustReject("an identity rotated to without its signing key", RuleUnauthorized, *keyless)
	if err := h.sign(&rot, fresh); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(rot); err != nil {
		t.Fatalf("an identity rotated past the cut-over: %v", err)
	}
	if got := h.auth.State().SigningKey(fresh.Public()); got == nil || *got != fresh.SigningKey() {
		t.Fatalf("the rotated identity's signing key is %v", got)
	}
	if h.auth.State().SigningKey(n.Identity) != nil {
		t.Fatal("the old identity still names a signing key")
	}
}

// A genesis past the cut-over names every admin key's and member's signing
// key, no two alike.
func TestAGenesisPastTheCutOver(t *testing.T) {
	h := newHarness(t, 2, 1)
	if got := h.auth.State().SigningKey(h.admins[1].Public()); got == nil || *got != h.admins[1].SigningKey() {
		t.Fatalf("a genesis admin key's signing key is %v", got)
	}
	for what, mutate := range map[string]func([]types.AdminKey){
		"naming no signing key for an admin key": func(k []types.AdminKey) { k[1].Signing = nil },
		"naming one signing key twice":           func(k []types.AdminKey) { k[1].Signing = k[0].Signing },
	} {
		keys := h.adminKeys()
		mutate(keys)
		if _, err := Genesis("net", 1, keys, h.commitments(), nil, h.sealer()); err == nil {
			t.Errorf("a genesis %s was built", what)
		}
	}
}

// A device past the cut-over takes no record below it, which a quantum
// computer could sign: such a branch is dropped unstored, wins no fork
// choice and raises no alarm. Exit criterion (6).
func TestABranchBelowTheCutOverIsDropped(t *testing.T) {
	h, laptop, phone := preCutOver(t)
	below := h.auth.State()
	if err := h.auth.Inform(h.cutOverRecord(h.signingKeysOf(laptop, phone), h.admins...)); err != nil {
		t.Fatal(err)
	}
	head := h.auth.Head()

	// What a forger holding the admin keys' Ed25519 scalars signs: a
	// revocation beside the cut-over, which would win fork choice on it.
	revoke, err := NewBuilder(below).RemoveNode(laptop.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := revoke.SignUnder(h.admins[0], below.Schema()); err != nil {
		t.Fatal(err)
	}
	stored, _ := h.storage.Hashes()
	if err := h.auth.Inform(revoke); err != nil {
		t.Fatalf("a branch below the cut-over was refused rather than dropped: %v", err)
	}
	after, _ := h.storage.Hashes()
	switch {
	case len(after) != len(stored):
		t.Fatal("a branch below the cut-over was stored")
	case h.auth.Head() != head:
		t.Fatal("a branch below the cut-over moved the head")
	case h.auth.Alarm() != nil:
		t.Fatalf("a branch below the cut-over raised an alarm: %v", h.auth.Alarm())
	case !slices.Contains(h.auth.Dropped(), revoke.Hash()):
		t.Fatal("the dropped record is not named, so peers offer it again")
	}

	// A record with no parent this device holds is refused as before, and
	// a disable record is taken wherever it hangs.
	orphan, _ := NewBuilder(below).EpochBump(h.sealer())
	orphan.Prev = &types.Hash{9}
	_ = orphan.SignUnder(h.admins[0], below.Schema())
	var re *RejectError
	if err := h.auth.Inform(orphan); !errors.As(err, &re) || re.Rule != RuleParent {
		t.Fatalf("a record with an unknown parent: %v", err)
	}
	disable, err := NewBuilder(below).Disable(types.DisablementSecret(h.disablement[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(disable); err != nil || h.auth.Disabled() == nil {
		t.Fatalf("a disable record below the cut-over: %v", err)
	}
}

// For a device behind, a branch that reaches the cut-over beats a sibling
// that does not, a revocation among them, so that it settles where the
// devices past the cut-over are, whichever it saw first.
func TestTheCutOverWinsForkChoice(t *testing.T) {
	h, laptop, phone := preCutOver(t)
	below := h.auth.State()
	cut := h.cutOverRecord(h.signingKeysOf(laptop, phone), h.admins...)
	revoke, err := NewBuilder(below).RemoveNode(laptop.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := revoke.SignUnder(h.admins[1], below.Schema()); err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]types.AUM{{cut, revoke}, {revoke, cut}} {
		auth := h.fork()
		for _, rec := range order {
			if err := auth.Inform(rec); err != nil {
				t.Fatalf("informing %v: %v", rec.Kind, err)
			}
		}
		if auth.Head() != cut.Hash() || !auth.State().PQ() {
			t.Fatalf("delivered %v first, the chain chose %v", order[0].Kind, auth.Head())
		}
		if auth.Alarm() != nil {
			t.Fatalf("delivered %v first: %v", order[0].Kind, auth.Alarm())
		}
	}
}

// Copies of one cut-over signed by different keys, as two approvals that
// completed its quorum at once make, settle on the copy built on further,
// then on the lower hash, wherever a device stands: one past either copy
// keeps the other rather than dropping it.
func TestCopiesOfTheCutOverSettle(t *testing.T) {
	h, laptop, phone := preCutOver(t)
	first := h.cutOverRecord(h.signingKeysOf(laptop, phone), h.admins[0])
	second := first.Clone()
	second.Signatures = nil
	if err := second.SignUnder(h.admins[1], types.SchemaSigning); err != nil {
		t.Fatal(err)
	}
	low, high := first, *second
	if high.Hash().Compare(low.Hash()) < 0 {
		low, high = high, low
	}

	builtOn := h.fork()
	if err := builtOn.Inform(high); err != nil {
		t.Fatal(err)
	}
	bump, err := builtOn.Builder().EpochBump(h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := bump.SignUnder(h.admins[0], types.SchemaMLDSA); err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]types.AUM{{high, bump, low}, {low, high, bump}} {
		auth := h.fork()
		for _, rec := range order {
			if err := auth.Inform(rec); err != nil {
				t.Fatalf("informing %v: %v", rec.Hash(), err)
			}
		}
		if auth.Head() != bump.Hash() {
			t.Fatalf("delivered %v first, the chain left the copy built on", order[0].Hash())
		}
		if auth.Alarm() != nil {
			t.Fatalf("copies of the cut-over raised an alarm: %v", auth.Alarm())
		}
	}
	for _, order := range [][]types.AUM{{high, low}, {low, high}} {
		auth := h.fork()
		for _, rec := range order {
			if err := auth.Inform(rec); err != nil {
				t.Fatalf("informing %v: %v", rec.Hash(), err)
			}
		}
		if auth.Head() != low.Hash() {
			t.Fatalf("delivered %v first, the chain chose the higher copy", order[0].Hash())
		}
	}
}

// A removed admin key cannot undo its removal by cutting over on a branch
// rooted before it: a key its sibling removes loses before the cut-over
// counts, on a device that holds the removal or takes both at once.
func TestARemovedKeyCannotCutOverPastItsRemoval(t *testing.T) {
	h, laptop, phone := preCutOver(t)
	mallory, honest := h.admins[0], h.admins[1]
	removal, err := h.auth.Builder().RemoveAdminKey(mallory.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sign(&removal, honest); err != nil {
		t.Fatal(err)
	}
	cut := h.cutOverRecord(h.signingKeysOf(laptop, phone), mallory)
	for _, batches := range [][][]types.AUM{{{removal}, {cut}}, {{cut, removal}}, {{removal, cut}}} {
		auth := h.fork()
		for _, b := range batches {
			if err := auth.Inform(b...); err != nil {
				t.Fatalf("informing %d records: %v", len(b), err)
			}
		}
		if _, back := auth.State().Admin(mallory.Public()); back || auth.State().PQ() {
			t.Fatalf("delivered as %d batches, the removed key's cut-over won", len(batches))
		}
	}
}

// Where a removed key's branch removes its remover first, each branch is
// undone by the other; the cut-over on one of them does not decide.
func TestAContestedForkIsNotDecidedByTheCutOver(t *testing.T) {
	h, laptop, phone := preCutOver(t)
	mallory, honest := h.admins[0], h.admins[1]
	removal, err := h.auth.Builder().RemoveAdminKey(mallory.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sign(&removal, honest); err != nil {
		t.Fatal(err)
	}
	fork := h.fork()
	counter, err := fork.Builder().RemoveAdminKey(honest.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sign(&counter, mallory); err != nil {
		t.Fatal(err)
	}
	if err := fork.Inform(counter); err != nil {
		t.Fatal(err)
	}
	cut, err := fork.Builder().SetSigningKeys(h.signingKeysOf(laptop, phone), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := cut.SignUnder(mallory, fork.State().Schema()); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(removal); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(counter, cut); err != nil {
		t.Fatal(err)
	}
	if _, back := h.auth.State().Admin(mallory.Public()); back || h.auth.State().PQ() {
		t.Fatal("the cut-over decided a contested fork for the removed key")
	}
}
