package log

import (
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func newRecipient(t *testing.T) types.RecipientKey {
	t.Helper()
	priv, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	x, m, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	return types.RecipientKey{X25519: x, MLKEM: m}
}

// An admin key's encryption key is set by a quorum and the key itself, and by
// nothing less, and survives a checkpoint bootstrapped from.
func TestSetAdminRecipient(t *testing.T) {
	h := newHarness(t, 2, 1)
	first, second := h.admins[0], h.admins[1]
	r := newRecipient(t)
	set := func(subject types.Identity, r types.RecipientKey, by ...types.PrivateIdentity) types.AUM {
		aum := types.AUM{Kind: types.KindSetAdminRecipient, Prev: new(h.auth.Head()), Subject: &subject, Recipient: &r}
		for _, k := range by {
			if err := h.sign(&aum, k); err != nil {
				t.Fatal(err)
			}
		}
		return aum
	}
	h.mustReject("another key's encryption key, by the quorum alone", RuleUnauthorized,
		set(second.Public(), r, first))
	if err := h.auth.Inform(set(first.Public(), r, first)); err != nil {
		t.Fatalf("an admin key setting its own encryption key: %v", err)
	}
	if k, _ := h.auth.State().Admin(first.Public()); k.Recipient == nil || *k.Recipient != r {
		t.Fatalf("the admin key's encryption key is %v, want %v", k.Recipient, r)
	}
	h.mustReject("the encryption key it has", RuleState, set(first.Public(), r, first))
	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Past the cut-over a key the log names no signing key for cannot sign.
	h.mustReject("a key that is no admin's", RuleUnauthorized, set(stranger.Public(), r, first, stranger))
	added := h.signed(types.AUM{Kind: types.KindAddAdminKey,
		Admin: &types.AdminKey{Public: stranger.Public(), Signing: new(stranger.SigningKey()), Endorsement: stranger.Endorsement(), Votes: 1, Recipient: &r}})
	h.mustReject("an admin key added with an encryption key", RuleState, added)

	cp := h.apply(h.auth.Builder().Checkpoint())
	boot, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if k, _ := boot.State().Admin(first.Public()); k.Recipient == nil || *k.Recipient != r {
		t.Fatal("a checkpoint lost the encryption key")
	}

	old := newHarnessAt(t, 1, 1, types.SchemaRename)
	old.mustReject("an encryption key at schema 6", RuleState,
		old.signed(types.AUM{Kind: types.KindSetAdminRecipient, Subject: new(old.admins[0].Public()), Recipient: &r}))
}

// A genesis gives an admin key an encryption key only where the key signs it.
func TestAGenesisRecipientIsSignedForByItsKey(t *testing.T) {
	founder, other := fixedIdentity(1), fixedIdentity(2)
	r := newRecipient(t)
	genesis, err := Genesis("net", 1, []types.AdminKey{
		{Public: founder.Public(), Votes: 1, Signing: new(founder.SigningKey()), Endorsement: founder.Endorsement()},
		{Public: other.Public(), Votes: 1, Recipient: &r, Signing: new(other.SigningKey()), Endorsement: other.Endorsement()},
	}, []types.Hash{{1}}, nil, fixedSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := genesis.Sign(founder); err != nil {
		t.Fatal(err)
	}
	if st, err := GenesisStatus(&genesis); err != nil || st.Authorized() {
		t.Fatalf("a genesis its recipient's key did not sign: %+v, %v", st, err)
	}
	if _, err := Create(NewMemStorage(), genesis); err == nil {
		t.Fatal("created a network whose genesis names an encryption key its key did not sign for")
	}
	if err := genesis.Sign(other); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(NewMemStorage(), genesis); err != nil {
		t.Fatalf("a genesis signed by the key with the encryption key: %v", err)
	}
}

// An encryption key that is not one is refused where the record is, and what
// a state hands out is a copy of its admin keys, not the keys themselves.
func TestAnAdminEncryptionKeyIsAKey(t *testing.T) {
	h := newHarness(t, 1, 1)
	admin := h.admins[0]
	bad := newRecipient(t)
	for i := range bad.MLKEM {
		bad.MLKEM[i] = 0xff
	}
	aum := types.AUM{Kind: types.KindSetAdminRecipient, Prev: new(h.auth.Head()), Subject: new(admin.Public()),
		Recipient: &bad}
	if err := h.sign(&aum, admin); err != nil {
		t.Fatal(err)
	}
	h.mustReject("an encryption key that does not parse", RuleMalformed, aum)

	r := newRecipient(t)
	aum.Recipient = &r
	aum.Signatures = nil
	if err := h.sign(&aum, admin); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(aum); err != nil {
		t.Fatal(err)
	}
	k, _ := h.auth.State().Admin(admin.Public())
	k.Recipient.X25519[0] ^= 1
	h.auth.State().Admins()[0].Recipient.X25519[1] ^= 1
	if got, _ := h.auth.State().Admin(admin.Public()); *got.Recipient != r {
		t.Fatal("changing an admin key handed out changed the state")
	}
}
