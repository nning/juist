package log

import (
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// A change that would give a member more name bytes than the cap is refused.
func TestNameBytesAreCapped(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("mail")
	var names []string
	for i := range 10 {
		label := strings.Repeat("a", 63)
		names = append(names, label+"."+label+"."+label+"."+string(rune('a'+i))+".example.org")
	}
	h.apply(h.auth.Builder().SetNodeNames(n.Identity, names[:5]))
	h.mustReject("names past the cap", RuleState, h.signed(types.AUM{Kind: types.KindSetNodeNames, Subject: &n.Identity,
		Names: &types.NameGrant{Names: names}}))
}

// An admin key enters with its signing key, which no other identity names,
// and an identity rotated to with the one its record names.
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
	rot := h.rotation(n, fresh)
	if err := h.auth.Inform(rot); err != nil {
		t.Fatalf("an identity rotated: %v", err)
	}
	if got := h.auth.State().SigningKey(fresh.Public()); got == nil || *got != fresh.SigningKey() {
		t.Fatalf("the rotated identity's signing key is %v", got)
	}
	if h.auth.State().SigningKey(n.Identity) != nil {
		t.Fatal("the old identity still names a signing key")
	}
}

// An identity rotation's new signing key is in what its signers sign: whoever
// relays the record cannot bind the member's slot to a signing key of their
// own, by swapping the new identity's signature or the key with it.
func TestARotationsSigningKeyCannotBeSwapped(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("laptop")
	fresh, _ := types.GenerateIdentity()
	attacker, _ := types.GenerateIdentity()
	rot := h.rotation(n, fresh)

	resign := func(a *types.AUM) {
		t.Helper()
		sh := a.SigHash()
		pq, err := attacker.SignPQ(sh[:])
		if err != nil {
			t.Fatal(err)
		}
		s, _ := a.Signature(fresh.Public())
		s.PQ = &pq
	}
	forged := rot.Clone()
	resign(forged)
	h.mustReject("a rotation whose new identity signed by another key", RuleUnauthorized, *forged)
	swapped := rot.Clone()
	swapped.NewSigning = new(attacker.SigningKey())
	resign(swapped)
	h.mustReject("a rotation naming another signing key", RuleUnauthorized, *swapped)
	keyless := rot.Clone()
	keyless.NewSigning = nil
	h.mustReject("a rotation naming no signing key", RuleMalformed, *keyless)

	if err := h.auth.Inform(rot); err != nil {
		t.Fatalf("an identity rotated: %v", err)
	}
	if got := h.auth.State().SigningKey(fresh.Public()); got == nil || *got != fresh.SigningKey() {
		t.Fatalf("the rotated identity's signing key is %v", got)
	}
}

// Below schema 19 an identity does not rotate, as its signing key would not be
// signed; the upgrade to 19 is what allows it.
func TestARotationNeedsSchema19(t *testing.T) {
	h := newHarnessWith(t, 1, 1, func(s *types.Snapshot) { s.Schema = 18 })
	n := h.addNode("laptop")
	fresh, _ := types.GenerateIdentity()
	if _, err := h.auth.Builder().RotateIdentity(n.Identity, fresh.Public(), fresh.SigningKey(), h.sealer()); err == nil {
		t.Fatal("a rotation was built at schema 18")
	}
	h.mustReject("a rotation at schema 18", RuleState, h.handAssembledRotation(n, fresh))

	h.apply(h.auth.Builder().SchemaUpgrade(19))
	if err := h.auth.Inform(h.rotation(n, fresh)); err != nil {
		t.Fatalf("a rotation at schema 19: %v", err)
	}
}

// A genesis names every admin key's and member's signing key, no two alike.
func TestAGenesisNamesEverySigningKey(t *testing.T) {
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
