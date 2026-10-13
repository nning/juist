package types

import (
	"strings"
	"testing"
)

// An admin key's token carries its signing key and the endorsement binding
// the two; one whose endorsement is not the identity's is refused, so no one
// handing a token on can swap in a key of their own.
func TestAnAdminKeyTokenIsEndorsed(t *testing.T) {
	admin, other := mustIdentity(t), mustIdentity(t)
	text, err := AdminKeyText(admin)
	if err != nil {
		t.Fatal(err)
	}
	id, key, e, err := ParseAdminKey(text)
	if err != nil || id != admin.Public() || *key != admin.SigningKey() || !id.VerifyEndorsement(key, *e) {
		t.Fatalf("parsing a token: %v", err)
	}
	theirs, _ := AdminKeyText(other)
	_, keyText, _ := strings.Cut(theirs, ".")
	swapped := admin.Public().String() + "." + keyText
	if _, _, _, err := ParseAdminKey(swapped); err == nil {
		t.Fatal("a token naming another identity's signing key and endorsement was taken")
	}
	if _, _, _, err := ParseAdminKey(strings.SplitN(text, ".", 3)[0] + "." + strings.SplitN(text, ".", 3)[1]); err == nil {
		t.Fatal("a token with no endorsement was taken")
	}
	if id, key, _, err := ParseAdminKey(admin.Public().String()); err != nil || id != admin.Public() || key != nil {
		t.Fatalf("an identity alone: %v, %v", key, err)
	}

	k := AdminKey{Public: admin.Public(), Votes: 1, Signing: key, Endorsement: other.Endorsement()}
	if err := k.StaticValidate(); err == nil {
		t.Fatal("an admin key whose endorsement is another's validated")
	}
	k.Endorsement = nil
	if err := k.StaticValidate(); err == nil {
		t.Fatal("an admin key with a signing key and no endorsement validated")
	}
}

// A registration names one admin key's signing key, no more.
func TestARegistrationNamesOneKey(t *testing.T) {
	a, b := mustIdentity(t), mustIdentity(t)
	member := func(p PrivateIdentity) MemberKey {
		return MemberKey{Identity: p.Public(), Key: p.SigningKey(), Endorsement: *p.Endorsement()}
	}
	prev := Hash{1}
	rec := AUM{Kind: KindSetAdminSigning, Prev: &prev, Signing: &SigningKeys{Members: []MemberKey{member(a)}}}
	if err := rec.Sign(a); err != nil {
		t.Fatal(err)
	}
	if err := rec.StaticValidate(); err != nil {
		t.Fatalf("a registration: %v", err)
	}
	two := AUM{Kind: KindSetAdminSigning, Prev: &prev, Signing: &SigningKeys{Members: []MemberKey{member(a), member(b)}}}
	if err := two.Sign(a); err != nil {
		t.Fatal(err)
	}
	if err := two.StaticValidate(); err == nil {
		t.Fatal("a registration of two keys validated")
	}
}
