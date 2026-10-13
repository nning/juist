package log

import (
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

func namesOf(t *testing.T, st *State, id types.Identity) []string {
	t.Helper()
	n, ok := st.Node(id)
	if !ok {
		t.Fatalf("%v is no member", id.ShortString())
	}
	return n.Names
}

// A quorum points names at a member, replaces and withdraws them; they
// survive reopening, a checkpoint and the member's new identity, and go
// with the member.
func TestNamesFollowTheMember(t *testing.T) {
	h := newHarness(t, 2, 2)
	mailer := h.addNode("mailer")
	h.apply(h.auth.Builder().SetNodeNames(mailer.Identity, []string{"mx.example.net", "imap.example.net", "mx.example.net"}))
	if got := namesOf(t, h.auth.State(), mailer.Identity); !slices.Equal(got, []string{"imap.example.net", "mx.example.net"}) {
		t.Fatalf("mailer answers for %q", got)
	}
	if got := namesOf(t, h.fork().State(), mailer.Identity); len(got) != 2 {
		t.Fatalf("reopened, mailer answers for %q", got)
	}
	cp := h.apply(h.auth.Builder().Checkpoint())
	boot, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if got := namesOf(t, boot.State(), mailer.Identity); len(got) != 2 {
		t.Fatalf("bootstrapped from a checkpoint, mailer answers for %q", got)
	}

	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rot, err := h.auth.Builder().RotateIdentity(mailer.Identity, fresh.Public(), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rot)
	for _, k := range []types.PrivateIdentity{fresh, h.nodeIDs[mailer.Identity]} {
		if err := h.sign(&rot, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.auth.Inform(rot); err != nil {
		t.Fatal(err)
	}
	if got := namesOf(t, h.auth.State(), fresh.Public()); len(got) != 2 {
		t.Fatalf("under its new identity, mailer answers for %q", got)
	}

	h.apply(h.auth.Builder().SetNodeNames(fresh.Public(), []string{"mx.example.net"}))
	if got := namesOf(t, h.auth.State(), fresh.Public()); !slices.Equal(got, []string{"mx.example.net"}) {
		t.Fatalf("replaced, mailer answers for %q", got)
	}
	h.apply(h.auth.Builder().SetNodeNames(fresh.Public(), nil))
	if got := namesOf(t, h.auth.State(), fresh.Public()); len(got) != 0 {
		t.Fatalf("withdrawn, mailer answers for %q", got)
	}

	h.apply(h.auth.Builder().SetNodeNames(fresh.Public(), []string{"mx.example.net"}))
	h.removeNode(fresh.Public())
	other := h.addNode("zeus")
	h.apply(h.auth.Builder().SetNodeNames(other.Identity, []string{"mx.example.net"}))
}

// A name another member holds, a non-member, the names a member has already,
// a quorum short, a network before schema 8, and a name that is no public
// DNS name are refused.
func TestNamesAreRefused(t *testing.T) {
	h := newHarness(t, 2, 2)
	mailer, zeus := h.addNode("mailer"), h.addNode("zeus")
	h.apply(h.auth.Builder().SetNodeNames(mailer.Identity, []string{"mx.example.net"}))
	names := func(id types.Identity, n ...string) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetNodeNames, Subject: &id, Names: &types.NameGrant{Names: n}})
	}
	h.mustReject("a name another member holds", RuleState, names(zeus.Identity, "mx.example.net"))
	stranger := h.newNode("stranger")
	h.mustReject("names for a non-member", RuleState, names(stranger.Identity, "www.example.net"))
	h.mustReject("the names it has", RuleState, names(mailer.Identity, "mx.example.net"))

	id := zeus.Identity
	short := types.AUM{Kind: types.KindSetNodeNames, Prev: new(h.auth.Head()), Subject: &id,
		Names: &types.NameGrant{Names: []string{"www.example.net"}}}
	if err := h.sign(&short, h.admins[0]); err != nil {
		t.Fatal(err)
	}
	h.mustReject("names one vote short", RuleUnauthorized, short)

	for _, bad := range []string{"10.0.0.1", "mailer.home.juist", "MX.example.net"} {
		a := names(zeus.Identity, bad)
		b, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := types.DecodeAUM(b); err == nil {
			t.Errorf("a record pointing %q decodes", bad)
		}
	}

	old := newHarnessAt(t, 1, 1, types.SchemaSealing)
	n := old.addNode("mailer")
	old.mustReject("names at schema 7", RuleState, old.signed(types.AUM{Kind: types.KindSetNodeNames, Subject: &n.Identity,
		Names: &types.NameGrant{Names: []string{"mx.example.net"}}}))
	withNames := old.newNode("zeus")
	withNames.Names = []string{"www.example.net"}
	if _, err := old.auth.Builder().AddNode(withNames, old.sealer()); err == nil {
		t.Error("the builder authored an admission with names at schema 7")
	}
	old.mustReject("a member admitted with names at schema 7", RuleState, old.handAssembledAddNode(withNames))
}
