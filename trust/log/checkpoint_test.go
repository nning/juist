package log

import (
	"errors"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// checkpoint signs and informs a checkpoint of the current head.
func (h *harness) checkpoint() types.AUM {
	h.t.Helper()
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		h.t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		h.t.Fatalf("Inform checkpoint: %v", err)
	}
	return cp
}

// A checkpoint drafted beside a concurrent change that wins fork choice
// states a state no chain reaches any more; it has nothing to reissue, and
// raises no alarm.
func TestALostCheckpointRaisesNoAlarm(t *testing.T) {
	h := newHarness(t, 1, 1)
	alpha := h.addNode("alpha")
	h.addNode("bravo")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&cp)
	removal, err := h.auth.Builder().RemoveNode(alpha.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&removal)
	if err := h.auth.Inform(cp, removal); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if h.auth.Head() != removal.Hash() {
		t.Fatal("the checkpoint won over a removal")
	}
	if a := h.auth.Alarm(); a != nil {
		t.Fatalf("a lost checkpoint raised an alarm: %v", a)
	}
	if _, err := h.auth.TrustedState(); err != nil {
		t.Fatalf("a lost checkpoint withheld the state: %v", err)
	}
	orphans := h.auth.Orphans()
	if len(orphans) != 1 || orphans[0].Root != cp.Hash() || orphans[0].Conflict != "" {
		t.Fatalf("orphans %+v, want the checkpoint alone and no conflict", orphans)
	}
}

// A device whose log starts below what its peers keep is invited again: the
// chain the invite brings replaces its log, its ratchets kept, and only a
// chain of its network at a later epoch does.
func TestRebaseMovesALogBehindToTheInvitesChain(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	behind := h.fork()
	h.addNode("bravo")
	cp := h.checkpoint()
	h.addNode("charlie")
	chain, err := h.auth.Chain()
	if err != nil {
		t.Fatal(err)
	}
	var records []types.AUM
	for _, c := range chain[slices.Index(chain, cp.Hash()):] {
		r, err := h.storage.AUM(c)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	if err := behind.Inform(records...); err == nil {
		t.Fatal("a log behind took a chain that does not descend from its anchor")
	}

	// Nothing older, nothing of another network.
	if err := behind.Rebase(records[:0:0]); err == nil {
		t.Fatal("rebased onto no chain")
	}
	if err := h.auth.Rebase(records); err == nil {
		t.Fatal("rebased onto a chain at no later epoch")
	}
	other := newHarness(t, 1, 1)
	other.addNode("x")
	other.addNode("y")
	ocp := other.checkpoint()
	if err := behind.Rebase([]types.AUM{ocp}); err == nil {
		t.Fatal("rebased onto another network's chain")
	}

	if err := behind.Rebase(records); err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	if behind.Head() != h.auth.Head() || behind.Anchor() != cp.Hash() {
		t.Fatal("the rebased log does not follow the invite's chain")
	}
	reopened, err := Open(behind.storage)
	if err != nil {
		t.Fatalf("Open after Rebase: %v", err)
	}
	if reopened.Head() != h.auth.Head() {
		t.Fatal("the rebase did not survive reopening")
	}
	floor, _ := behind.storage.EpochFloor()
	if floor != h.auth.State().Epoch() {
		t.Fatalf("epoch floor %d after the rebase, want %d", floor, h.auth.State().Epoch())
	}
}

// A disabled network stays so: a rebase does not take a device past it.
func TestRebaseRefusesADisabledLog(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	behind := h.fork()
	if err := behind.Inform(h.disable(0, behind.State())); err != nil {
		t.Fatal(err)
	}
	h.addNode("bravo")
	cp := h.checkpoint()
	var d *DisabledError
	if err := behind.Rebase([]types.AUM{cp}); !errors.As(err, &d) {
		t.Fatalf("a disabled log rebased: %v", err)
	}
}

// A rebase takes no chain whose anchor this log's admins did not sign, though
// it claims the network and a later epoch.
func TestRebaseRefusesACheckpointOtherKeysSigned(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	victim := h.fork()
	other := newHarness(t, 1, 1)
	for _, n := range []string{"x", "y", "z", "w"} {
		other.addNode(n)
	}
	forged, err := other.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	g := victim.State().GenesisHash()
	forged.State.GenesisHash = &g
	other.signQuorum(&forged)
	if err := victim.Rebase([]types.AUM{forged}); err == nil {
		t.Fatal("rebased onto a checkpoint other keys signed")
	}
}

// compact informs a checkpoint, then another, and compacts: the anchor moves
// to the first.
func (h *harness) compact() types.AUM {
	h.t.Helper()
	first := h.checkpoint()
	h.addNode("filler")
	h.checkpoint()
	if _, err := h.auth.Compact(); err != nil || h.auth.Anchor() != first.Hash() {
		h.t.Fatalf("compacting: %v", err)
	}
	return first
}

// The anchor stays a checkpoint behind the newest, so a removal drafted beside
// the newest is decided on a device that compacted as on one that did not.
func TestACompactedDeviceTakesARevocationBesideTheNewestCheckpoint(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	h.checkpoint()
	h.addNode("other")
	at := h.auth.State()
	newest := h.checkpoint()
	compacted, behind := h.fork(), h.fork()
	if _, err := compacted.Compact(); err != nil || compacted.Anchor() == newest.Hash() {
		t.Fatalf("compacting: %v", err)
	}
	removal, err := NewBuilder(at).RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&removal)
	for _, n := range []*Authority{compacted, behind} {
		if err := n.Inform(removal); err != nil {
			t.Fatalf("the removal was refused: %v", err)
		}
		st, err := n.TrustedState()
		if err != nil || st.IsMember(victim.Identity) || n.Head() != removal.Hash() {
			t.Fatalf("the removal is not in effect: %v", err)
		}
	}
}

// A record hanging below the anchor is refused, a settled orphan offered
// again included, and raises no alarm.
func TestARecordBelowTheAnchorIsRefused(t *testing.T) {
	h := newHarness(t, 1, 1)
	alpha := h.addNode("alpha")
	beta := h.addNode("beta")
	routes := func() types.AUM {
		g, err := h.auth.Builder().SetNodeRoutes(alpha.Identity, []types.Role{types.RoleRelayCapable}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&g)
		return g
	}
	grant := routes()
	h.removeNode(beta.Identity)
	if err := h.auth.Inform(grant); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(routes()); err != nil {
		t.Fatal(err)
	}
	anchor := h.compact()
	h.removeNode(alpha.Identity)
	var r *RejectError
	if err := h.auth.Inform(grant); !errors.As(err, &r) || r.Rule != RuleParent {
		t.Fatalf("a settled orphan offered again: %v", err)
	}
	if _, err := h.auth.TrustedState(); err != nil || h.auth.Anchor() != anchor.Hash() {
		t.Fatalf("a record below the anchor moved it or alarmed: %v", err)
	}
}

// The chain kept below the anchor ends at the previous anchor, whichever of
// its copies the chain runs through.
func TestTheChainKeptBelowEndsAtACopyOfThePreviousAnchor(t *testing.T) {
	h := newHarness(t, 3, 1)
	h.addNode("a")
	h.checkpoint()
	b := h.addNode("b")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	low, high := cp.Clone(), cp.Clone()
	if err := low.Sign(h.admins[1]); err != nil {
		t.Fatal(err)
	}
	if err := high.Sign(h.admins[2]); err != nil {
		t.Fatal(err)
	}
	if low.Hash().Compare(high.Hash()) > 0 {
		low, high = high, low
	}
	if err := h.auth.Inform(*high); err != nil {
		t.Fatal(err)
	}
	at := h.auth.State().at(low.Hash())
	h.addNode("c")
	h.checkpoint()
	if _, err := h.auth.Compact(); err != nil || h.auth.Anchor() != high.Hash() {
		t.Fatalf("compacting to one copy: %v", err)
	}
	// A removal on the other copy wins, so the chain runs through it.
	removal, err := NewBuilder(at).RemoveNode(b.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&removal)
	if err := h.auth.Inform(*low, removal); err != nil || h.auth.Head() != removal.Hash() {
		t.Fatalf("the removal on the other copy: %v", err)
	}
	h.addNode("d")
	h.checkpoint()
	h.addNode("e")
	h.checkpoint()
	if _, err := h.auth.Compact(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.storage.AUM(h.auth.State().GenesisHash()); !errors.Is(err, ErrNotFound) {
		t.Fatal("the genesis outlived a compaction past the anchor before it")
	}
}

// Checkpoints are cheap to a quorum at the point it forks from: two minted
// by a key a raised quorum left without one do not undo the raise, nor
// anything after it. No count of checkpoints may outrank a revocation.
func TestMintedCheckpointsDoNotUndoARevocation(t *testing.T) {
	h := newHarness(t, 2, 1)
	at := h.auth.State()
	raise, err := NewBuilder(at).SetQuorum(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := raise.Sign(h.admins[0]); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(raise); err != nil {
		t.Fatal(err)
	}
	h.quorum = 2
	h.addNode("alpha")
	h.checkpoint()
	head := h.auth.Head()

	cp1, err := NewBuilder(at).Checkpoint()
	if err == nil {
		err = cp1.Sign(h.admins[1])
	}
	if err != nil {
		t.Fatal(err)
	}
	st, err := at.apply(&cp1, cp1.Hash(), applyChain)
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := NewBuilder(st).Checkpoint()
	if err == nil {
		err = cp2.Sign(h.admins[1])
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(cp1, cp2); err != nil {
		t.Fatal(err)
	}
	if h.auth.Head() != head || h.auth.State().Quorum() != 2 {
		t.Fatal("two minted checkpoints undid a raised quorum")
	}
}
