package guest

import (
	"errors"
	"testing"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A chain an invite brought replaces a log only on an admin's admission: the
// device that answered a typed code could otherwise hand over one of its own.
// A chain holding the log's anchor is taken from there, and never replaces it.
func TestAnInvitesChainReplacesALogOnlyOnAnAdmission(t *testing.T) {
	prev := types.Hash{1}
	chain := []types.AUM{{Kind: types.KindCheckpoint, Prev: &prev}, {Kind: types.KindEpochBump}}
	var informed, rebased []types.AUM
	refused := func(r []types.AUM) error {
		informed = r
		return &log.RejectError{Rule: log.RuleParent}
	}
	rebase := func(r []types.AUM) error { rebased = r; return nil }
	elsewhere := types.AUM{Kind: types.KindGenesis, Network: new("x")}

	if err := Extend(elsewhere, refused, rebase, chain, false); err == nil || rebased != nil {
		t.Fatal("a chain no admission vouches for replaced the log")
	}
	if err := Extend(elsewhere, refused, rebase, chain, true); err != nil || len(rebased) != 2 {
		t.Fatalf("an admitted chain did not replace the log: %v", err)
	}

	rebased = nil
	took := func(r []types.AUM) error { informed = r; return nil }
	if err := Extend(chain[1], took, rebase, chain, true); err != nil || rebased != nil ||
		len(informed) != 1 || informed[0].Hash() != chain[1].Hash() {
		t.Fatal("a chain holding the log's anchor was not taken from there")
	}

	copied := *chain[0].Clone()
	copied.Signatures = []types.Signature{{KeyID: types.Identity{1}}}
	if err := Extend(copied, took, rebase, chain, true); err != nil || rebased != nil || len(informed) != 2 {
		t.Fatal("a chain holding a copy of the log's anchor was not taken from there")
	}

	other := errors.New("refused for another reason")
	if err := Extend(elsewhere, func([]types.AUM) error { return other }, rebase, chain, true); !errors.Is(err, other) ||
		rebased != nil {
		t.Fatal("a chain refused on its merits replaced the log")
	}
}
