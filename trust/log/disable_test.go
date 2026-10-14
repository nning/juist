package log

import (
	"errors"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

func (h *harness) disable(i int, st *State) types.AUM {
	h.t.Helper()
	aum, err := NewBuilder(st).Disable(types.DisablementSecret(h.disablement[i]))
	if err != nil {
		h.t.Fatalf("building a disable record: %v", err)
	}
	return aum
}

// mustBeDisabled asserts that auth refuses its state for the disable record
// at, and still does from a fresh open of its storage.
func mustBeDisabled(t *testing.T, what string, auth *Authority, st Storage, at types.Hash) {
	t.Helper()
	for _, a := range []*Authority{auth, reopen(t, st)} {
		var d *DisabledError
		if _, err := a.TrustedState(); !errors.As(err, &d) {
			t.Fatalf("%s: TrustedState returned %v, want the network disabled", what, err)
		}
		if a.Disabled() == nil || a.Disabled().At != at {
			t.Fatalf("%s: disabled by %v, want %v", what, a.Disabled(), at)
		}
	}
}

func reopen(t *testing.T, st Storage) *Authority {
	t.Helper()
	a, err := Open(st)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return a
}

func TestDisableEndsTheNetwork(t *testing.T) {
	h := newHarness(t, 2, 2)
	n := h.addNode("alpha")
	head := h.auth.Head()
	aum := h.disable(1, h.auth.State())
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	mustBeDisabled(t, "disabled", h.auth, h.storage, aum.Hash())
	// The chain does not move: the record ends the network, it does not change it.
	if h.auth.Head() != head || !h.auth.State().IsMember(n.Identity) {
		t.Fatal("the disable record changed the chain")
	}
	if h.auth.Alarm() != nil || len(h.auth.Orphans()) != 0 {
		t.Fatal("the disable record raised an alarm or left an orphan")
	}
}

func TestDisableNeedsABreakGlassSecret(t *testing.T) {
	h := newHarness(t, 1, 1)
	head := h.auth.Head()
	h.mustReject("a disable record with a made-up secret", RuleUnauthorized,
		types.AUM{Kind: types.KindDisable, Prev: &head, Secret: &types.DisablementSecret{7}})

	other := newHarness(t, 1, 1)
	theirs := types.DisablementSecret(other.disablement[0])
	h.mustReject("another network's secret", RuleUnauthorized,
		types.AUM{Kind: types.KindDisable, Prev: &head, Secret: &theirs})
	if _, err := h.auth.Builder().Disable(theirs); err == nil {
		t.Fatal("the builder made a disable record of another network's secret")
	}
	if _, err := h.auth.TrustedState(); err != nil {
		t.Fatalf("refused disable records disabled the network: %v", err)
	}
}

// A signature could only give the record a second encoding, and a second hash.
func TestDisableCarriesNoSignature(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum := h.disable(0, h.auth.State())
	if err := h.sign(&aum, h.admins[0]); err == nil {
		t.Fatal("a disable record was signed")
	}
	sig := types.Signature{KeyID: h.admins[0].Public(), PQ: &types.PQSig{1}}
	aum.Signatures = []types.Signature{sig}
	h.mustReject("a signed disable record", RuleMalformed, aum)
	b, err := aum.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := types.DecodeUnsignedAUM(b); err == nil {
		t.Fatal("a signed disable record decodes")
	}
}

func TestNothingFollowsADisable(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum := h.disable(0, h.auth.State())
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	at := aum.Hash()
	after := h.auth.State().clone()
	after.head = at
	next, err := NewBuilder(after).SetQuorum(1)
	if err != nil {
		t.Fatalf("SetQuorum: %v", err)
	}
	h.signQuorum(&next)
	h.mustReject("a record on top of a disable record", RuleParent, next)
	if err := h.auth.Inform(next); err == nil || !strings.Contains(err.Error(), "follows a disable record") {
		t.Fatalf("a record on top of a disable record: %v", err)
	}
}

// A secret hung anywhere on the chain ends the network: there is no position
// from which it would lose.
func TestDisableBelowTheHead(t *testing.T) {
	h := newHarness(t, 1, 1)
	genesis := h.genesisState()
	h.addNode("alpha")
	h.addNode("bravo")
	aum := h.disable(2, genesis)
	head := h.auth.Head()
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	mustBeDisabled(t, "disabled below the head", h.auth, h.storage, aum.Hash())
	if h.auth.Head() != head || len(h.auth.Orphans()) != 0 {
		t.Fatal("a disable record below the head moved the chain or made it fork")
	}
}

// A disable record on a branch that loses fork choice still counts: its author
// hung it on the head it saw, which a concurrent change may since have beaten.
func TestDisableOnALosingBranch(t *testing.T) {
	h := newHarness(t, 1, 1)
	base := h.auth.State()
	alpha, bravo := h.newNode("alpha"), h.newNode("bravo")
	var branches []types.AUM
	for _, n := range []types.NodeRecord{alpha, bravo} {
		aum, err := NewBuilder(base).AddNode(n, h.sealer())
		if err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		h.signQuorum(&aum)
		branches = append(branches, aum)
	}
	if err := h.auth.Inform(branches...); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	loser := branches[0]
	if h.auth.Head() == loser.Hash() {
		loser = branches[1]
	}
	st, err := base.apply(&loser, loser.Hash(), applyChain)
	if err != nil {
		t.Fatalf("applying the losing admission: %v", err)
	}
	aum := h.disable(0, st)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	mustBeDisabled(t, "disabled on a losing branch", h.auth, h.storage, aum.Hash())
}

func TestDisableIsFinal(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum := h.disable(0, h.auth.State())
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	// What admins sign afterwards is stored and changes nothing about it.
	h.addNode("alpha")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		t.Fatalf("Inform checkpoint: %v", err)
	}
	mustBeDisabled(t, "after later records", h.auth, h.storage, aum.Hash())
	// Compaction would advance the anchor past the record's parent.
	var d *DisabledError
	if _, err := h.auth.Compact(); !errors.As(err, &d) {
		t.Fatalf("Compact: %v, want refused for the disabled network", err)
	}
	mustBeDisabled(t, "after a refused compaction", h.auth, h.storage, aum.Hash())
}

// Two secrets revealed at once, in either order, name the same record: which
// one a node reports must not depend on what reached it first.
func TestConcurrentDisablesAgree(t *testing.T) {
	h := newHarness(t, 1, 1)
	base := h.auth.State()
	h.addNode("alpha")
	lower, upper := h.disable(0, base), h.disable(1, h.auth.State())
	other := h.fork()
	for _, aum := range []types.AUM{lower, upper} {
		if err := h.auth.Inform(aum); err != nil {
			t.Fatal(err)
		}
	}
	for _, aum := range []types.AUM{upper, lower} {
		if err := other.Inform(aum); err != nil {
			t.Fatal(err)
		}
	}
	if h.auth.Disabled() == nil || other.Disabled() == nil || h.auth.Disabled().At != other.Disabled().At {
		t.Fatalf("disabled by %v here and %v there", h.auth.Disabled(), other.Disabled())
	}
	// Chain first: the one hung lower on the chain.
	if h.auth.Disabled().At != lower.Hash() {
		t.Fatalf("disabled by %v, want the record nearer the anchor, %v", h.auth.Disabled().At, lower.Hash())
	}
}

// Whatever its parent, a secret of the network ends it: the parent may be one
// this node compacted away, never held, or holds past a schema it stopped at.
func TestDisableWhereverItHangs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *harness) types.Hash // the parent to hang it on
	}{
		{"on a parent never seen", func(h *harness) types.Hash { return types.Hash{7, 7, 7} }},
		{"below a compacted anchor", func(h *harness) types.Hash {
			below := h.auth.Head()
			h.addNode("alpha")
			cp, err := h.auth.Builder().Checkpoint()
			if err != nil {
				h.t.Fatal(err)
			}
			h.signQuorum(&cp)
			if err := h.auth.Inform(cp); err != nil {
				h.t.Fatal(err)
			}
			if _, err := h.auth.Compact(); err != nil {
				h.t.Fatal(err)
			}
			return below
		}},
		{"past a schema this build stops at", func(h *harness) types.Hash {
			up := h.handAssembledSchemaUpgrade(types.CurrentSchema + 1)
			if err := h.auth.Inform(up); err != nil {
				h.t.Fatal(err)
			}
			if h.auth.SchemaAlarm() == nil {
				h.t.Fatal("no schema alarm")
			}
			return up.Hash()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, 1, 1)
			parent := tc.setup(h)
			secret := types.DisablementSecret(h.disablement[2])
			aum := types.AUM{Kind: types.KindDisable, Prev: &parent, Secret: &secret}
			if err := h.auth.Inform(aum); err != nil {
				t.Fatalf("Inform: %v", err)
			}
			mustBeDisabled(t, tc.name, h.auth, h.storage, aum.Hash())
			wrong := types.AUM{Kind: types.KindDisable, Prev: &parent, Secret: &types.DisablementSecret{9}}
			// Refused, or past a schema stop dropped unread.
			_ = h.auth.Inform(wrong)
			if _, err := h.storage.AUM(wrong.Hash()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a made-up secret was stored: %v", err)
			}
		})
	}
}

// A node joining from a checkpoint still holds the commitments the secret
// is checked against.
func TestDisableAfterBootstrap(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	st := NewMemStorage()
	joined, err := Bootstrap(st, cp)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	aum := h.disable(1, joined.State())
	if err := joined.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	mustBeDisabled(t, "after bootstrap", joined, st, aum.Hash())
}
