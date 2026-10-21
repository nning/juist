package log

import (
	"errors"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// Preview says what a batch would do, and does none of it: whom a removal
// removes, before the log holds it.
func TestPreviewStoresNothing(t *testing.T) {
	h := newHarness(t, 1, 1)
	node := h.newNode("phone")
	add, err := h.auth.Builder().AddNode(node, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&add)
	if err := h.auth.Inform(add); err != nil {
		t.Fatal(err)
	}
	remove, err := h.auth.Builder().RemoveNode(node.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&remove)
	head := h.auth.Head()

	next, err := h.auth.Preview(remove)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if next.IsMember(node.Identity) || next.Head() != remove.Hash() {
		t.Fatalf("the preview keeps the member (%v) or has head %v, not the removal's", next.IsMember(node.Identity),
			next.Head())
	}
	if h.auth.Head() != head || !h.auth.State().IsMember(node.Identity) {
		t.Fatal("previewing changed the log")
	}
	if _, err := h.auth.storage.AUM(remove.Hash()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("previewing stored the record (%v)", err)
	}

	// A record that does not descend from the anchor is refused, as by Inform.
	stray := remove
	stray.Prev, stray.Signatures = &types.Hash{7}, nil
	h.signQuorum(&stray)
	var rej *RejectError
	if _, err := h.auth.Preview(stray); !errors.As(err, &rej) {
		t.Fatalf("a stray record previewed: %v", err)
	}
}

// Preview refuses a record following a disable record for that, as Inform
// does.
func TestPreviewRefusesWhatFollowsADisable(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum := h.disable(0, h.auth.State())
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	after := h.auth.State().clone()
	after.head = aum.Hash()
	next, err := NewBuilder(after).SetQuorum(1)
	if err != nil {
		t.Fatalf("SetQuorum: %v", err)
	}
	h.signQuorum(&next)
	var rej *RejectError
	_, err = h.auth.Preview(next)
	if !errors.As(err, &rej) || rej.Rule != RuleParent || !strings.Contains(err.Error(), "follows a disable record") {
		t.Fatalf("a record on top of a disable record previewed: %v", err)
	}
}
