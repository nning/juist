package log

import (
	"testing"

	"github.com/nning/juist/types"
)

// A rename changes the name and nothing that identifies the network, and the
// name survives reopening and a checkpoint bootstrapped from.
func TestRenameNetwork(t *testing.T) {
	h := newHarness(t, 2, 2)
	before := h.auth.State()
	h.apply(h.auth.Builder().RenameNetwork("office"))
	st := h.auth.State()
	if st.Network() != "office" {
		t.Fatalf("the network is named %q after the rename, want office", st.Network())
	}
	if st.GenesisHash() != before.GenesisHash() || st.ULA() != before.ULA() || st.Epoch() != before.Epoch() {
		t.Fatal("a rename changed what identifies the network")
	}
	if got := h.fork().State().Network(); got != "office" {
		t.Fatalf("reopened, the network is named %q", got)
	}
	cp := h.apply(h.auth.Builder().Checkpoint())
	boot, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if got := boot.State().Network(); got != "office" {
		t.Fatalf("bootstrapped from a checkpoint, the network is named %q", got)
	}

	rename := func(name string) types.AUM {
		return h.signed(types.AUM{Kind: types.KindRenameNetwork, Network: &name})
	}
	h.mustReject("a rename to the name it has", RuleState, rename("office"))
	if _, err := h.auth.Builder().RenameNetwork("office"); err == nil {
		t.Error("the builder authored a rename to the name the network has")
	}
	short := types.AUM{Kind: types.KindRenameNetwork, Prev: new(h.auth.Head()), Network: new("lab")}
	if err := short.Sign(h.admins[0]); err != nil {
		t.Fatal(err)
	}
	h.mustReject("a rename one vote short", RuleUnauthorized, short)

	old := newHarnessAt(t, 1, 1, types.SchemaRenumber)
	old.mustReject("a rename at schema 5", RuleState, old.signed(types.AUM{Kind: types.KindRenameNetwork, Network: new("lab")}))
}

// Two admins renaming at once are a fork like any other: one name wins, and
// the other is a change to start again, never a conflict that stops the
// network. Two renames to one name leave nothing to start again.
func TestConcurrentRenames(t *testing.T) {
	for _, tc := range []struct {
		other     string
		reissuing bool
	}{{"lab", true}, {"office", false}} {
		h := newHarness(t, 2, 1)
		b := h.auth.Builder()
		first, err := b.RenameNetwork("office")
		if err != nil {
			t.Fatal(err)
		}
		second, err := b.RenameNetwork(tc.other)
		if err != nil {
			t.Fatal(err)
		}
		if err := first.Sign(h.admins[0]); err != nil {
			t.Fatal(err)
		}
		if err := second.Sign(h.admins[1]); err != nil {
			t.Fatal(err)
		}
		auth := h.fork()
		if err := auth.Inform(first, second); err != nil {
			t.Fatal(err)
		}
		if alarm := auth.Alarm(); alarm != nil {
			t.Fatalf("renames to office and %s stopped the network: %v", tc.other, alarm)
		}
		winner := map[bool]string{true: "office", false: tc.other}[first.Hash().Compare(second.Hash()) < 0]
		if got := auth.State().Network(); got != winner {
			t.Errorf("renames to office and %s: the network is named %q, want %q", tc.other, got, winner)
		}
		orphans := auth.Orphans()
		if len(orphans) != 1 || orphans[0].Conflict != "" {
			t.Fatalf("renames to office and %s left %+v, want one branch to reissue", tc.other, orphans)
		}
		// The probe of the loser is what "start it again" rests on.
		loser := map[bool]types.AUM{true: second, false: first}[winner == "office"]
		_, err = auth.State().apply(&loser, loser.Hash(), applyProbe)
		if err != nil {
			t.Errorf("the losing rename to %s does not replay on the winner: %v", *loser.Network, err)
		}
		if tc.reissuing {
			if _, err := NewBuilder(auth.State()).RenameNetwork(*loser.Network); err != nil {
				t.Errorf("the losing rename cannot be started again: %v", err)
			}
		}
	}
}
