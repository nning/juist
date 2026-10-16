package log

import (
	"net/netip"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func TestGenesisAndLifecycle(t *testing.T) {
	h := newHarness(t, 3, 2)
	st := h.auth.State()
	if st.Network() != "test-net" || st.Quorum() != 2 || st.Epoch() != 1 {
		t.Fatalf("unexpected genesis state: network=%q quorum=%d epoch=%d",
			st.Network(), st.Quorum(), st.Epoch())
	}
	if len(st.Nodes()) != 0 {
		t.Fatal("genesis should have no members")
	}
	if !st.ULA().IsValid() || st.ULA().Bits() != 48 || st.ULA().Addr().As16()[0] != 0xfd {
		t.Fatalf("overlay prefix %v is not a ULA /48", st.ULA())
	}

	a := h.addNode("alpha")
	b := h.addNode("bravo")
	st = h.auth.State()
	if len(st.Nodes()) != 2 || st.Epoch() != 3 {
		t.Fatalf("after two AddNodes: %d members, epoch %d", len(st.Nodes()), st.Epoch())
	}
	// Every member must be able to open the current epoch's wrap.
	for _, n := range []types.NodeRecord{a, b} {
		got, err := secrets.Open(st.EpochRecord(), n.Identity, h.nodeKeys[n.Identity])
		if err != nil {
			t.Fatalf("member %s cannot open its epoch wrap: %v", n.Name, err)
		}
		if !got.Equal(h.secrets[st.Epoch()]) {
			t.Fatalf("member %s opened a different secret", n.Name)
		}
	}
	// Addresses are derived, distinct, and inside the overlay prefix.
	addrA, addrB := st.Addr6(a.Identity), st.Addr6(b.Identity)
	if addrA == addrB {
		t.Fatal("two members derive the same overlay address")
	}
	for _, addr := range []netip.Addr{addrA, addrB} {
		if !st.ULA().Contains(addr) {
			t.Fatalf("derived address %v is outside the overlay prefix %v", addr, st.ULA())
		}
	}

	h.removeNode(a.Identity)
	st = h.auth.State()
	if st.IsMember(a.Identity) {
		t.Fatal("removed member is still a member")
	}
	if st.Epoch() != 4 {
		t.Fatalf("removal did not bump the epoch: %d", st.Epoch())
	}
	// The removed member must no longer have a wrap, so it cannot follow the
	// group secret forward.
	if _, err := secrets.Open(st.EpochRecord(), a.Identity, h.nodeKeys[a.Identity]); err == nil {
		t.Fatal("a removed member still has an epoch wrap")
	}
	if _, err := secrets.Open(st.EpochRecord(), b.Identity, h.nodeKeys[b.Identity]); err != nil {
		t.Fatalf("surviving member lost access to the group secret: %v", err)
	}
}

func TestReopenReproducesState(t *testing.T) {
	h := newHarness(t, 2, 2)
	h.addNode("alpha")
	h.addNode("bravo")
	want := h.auth.State().Snapshot().Encode()

	reopened, err := Open(h.storage)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := reopened.State().Snapshot().Encode(); string(got) != string(want) {
		t.Fatal("reopening the same storage produced different state")
	}
	if reopened.Head() != h.auth.Head() {
		t.Fatal("reopening the same storage produced a different head")
	}
}

// TestInformOrderIndependence is the determinism property from
// docs/06-verification.md: the state a node reaches is a function of the record
// set, not of the order the records arrived in.
func TestInformOrderIndependence(t *testing.T) {
	h := newHarness(t, 1, 1)
	var records []types.AUM
	b := h.auth.Builder()
	for i := range 4 {
		n := h.newNode(string(rune('a' + i)))
		aum, err := b.AddNode(n, h.sealer())
		if err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		h.signQuorum(&aum)
		records = append(records, aum)
		// Chain the next record onto this one, so the batch is a linear run
		// that has never been delivered anywhere.
		b = NewBuilder(h.project(records...))
	}

	// Deliver the same records to two independent authorities, as one batch
	// and one at a time, and compare the resulting state byte for byte.
	forward := h.fork()
	if err := forward.Inform(records...); err != nil {
		t.Fatalf("batch Inform: %v", err)
	}
	oneByOne := h.fork()
	for _, r := range records {
		if err := oneByOne.Inform(r); err != nil {
			t.Fatalf("incremental Inform: %v", err)
		}
	}
	if string(forward.State().Snapshot().Encode()) != string(oneByOne.State().Snapshot().Encode()) {
		t.Fatal("batched and incremental delivery produced different state")
	}
	if forward.Head() != oneByOne.Head() {
		t.Fatal("batched and incremental delivery produced different heads")
	}
}

// Check is Dry for a record still collecting its votes: an unsigned record
// that would apply passes, and one that never could does not — a checkpoint
// stating another state, a record on another head, or a signature the
// network does not trust.
func TestCheckIsDryWithoutTheQuorum(t *testing.T) {
	h := newHarness(t, 2, 2)
	h.addNode("a")
	add, err := h.auth.Builder().AddNode(h.newNode("b"), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.auth.Builder().Check(&add); err != nil {
		t.Fatalf("an unsigned record that would apply: %v", err)
	}
	if _, err := h.auth.Builder().Dry(&add); err == nil {
		t.Fatal("Dry accepted an unsigned record")
	}

	lie := h.handAssembledCheckpoint(append(h.auth.State().Nodes(), h.newNode("ghost")))
	lie.Signatures = nil
	if _, err := h.auth.Builder().Check(&lie); err == nil {
		t.Fatal("a checkpoint stating another state passed")
	}
	honest, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.auth.Builder().Check(&honest); err != nil {
		t.Fatalf("the honest checkpoint: %v", err)
	}

	stale := add
	prev := types.Hash{1}
	stale.Prev = &prev
	if _, err := h.auth.Builder().Check(&stale); err == nil {
		t.Fatal("a record on another head passed")
	}

	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spoiled := add
	if err := h.sign(&spoiled, stranger); err != nil {
		t.Fatal(err)
	}
	if _, err := h.auth.Builder().Check(&spoiled); err == nil {
		t.Fatal("a record signed by a key the network does not trust passed")
	}
}

// The chain names the signing key of every member it listed from the anchor
// on, removed or rotated away, after a reopen too; a compaction past a removal
// forgets it.
func TestTheChainNamesTheKeyOfEveryMemberItListed(t *testing.T) {
	h := newHarness(t, 1, 1)
	kept, removed, rotated := h.addNode("kept"), h.addNode("removed"), h.addNode("rotated")
	h.removeNode(removed.Identity)
	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(h.rotation(rotated, fresh)); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(h.storage)
	if err != nil {
		t.Fatal(err)
	}
	for what, n := range map[string]types.NodeRecord{"a member": kept, "a removed member": removed,
		"an identity rotated away": rotated} {
		if k := reopened.ListedSigningKey(n.Identity); k == nil || *k != *n.Signing {
			t.Errorf("the reopened log names %v for %s, want the key it was listed with", k, what)
		}
	}
	if k := reopened.ListedSigningKey(fresh.Public()); k == nil || *k != fresh.SigningKey() {
		t.Error("the reopened log does not name the key an identity was rotated to")
	}
	if k := reopened.ListedSigningKey(h.newNode("stranger").Identity); k != nil {
		t.Error("the log names a key for an identity it never listed")
	}

	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		t.Fatal(err)
	}
	h.checkpoint()
	if _, err := h.auth.Compact(); err != nil || h.auth.Anchor() != cp.Hash() {
		t.Fatal(err)
	}
	if h.auth.ListedSigningKey(removed.Identity) != nil {
		t.Error("a log compacted past a removal still names the removed member's key")
	}
	if h.auth.ListedSigningKey(kept.Identity) == nil {
		t.Error("a compacted log no longer names a member's key")
	}
}
