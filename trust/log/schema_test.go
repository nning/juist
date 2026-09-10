package log

import (
	"errors"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// TestSchemaUpgradeStopsAnOlderBuildLoudly is what the versioned schema buys.
// A quorum raises the schema past what this build implements; the node must
// keep the state it had, say why it has stopped, and neither pretend the
// record is invalid nor act on what follows it.
func TestSchemaUpgradeStopsAnOlderBuildLoudly(t *testing.T) {
	h := newHarness(t, 1, 1)
	keep := h.addNode("keep")
	doomed := h.addNode("doomed")
	before := h.auth.Head()

	upgrade := h.handAssembledSchemaUpgrade(types.CurrentSchema + 1)
	if err := h.auth.Inform(upgrade); err != nil {
		t.Fatalf("a quorum-signed schema upgrade was refused rather than reported: %v", err)
	}

	alarm := h.auth.SchemaAlarm()
	if alarm == nil {
		t.Fatal("no schema alarm after the network moved past this build")
	}
	if alarm.Version != types.CurrentSchema+1 || alarm.At != upgrade.Hash() {
		t.Errorf("alarm names %v at %v, want %v at %v",
			alarm.Version, alarm.At, types.CurrentSchema+1, upgrade.Hash())
	}

	// The state is the one from before the upgrade, and it is still usable:
	// what the node holds was correct up to that record, and taking every
	// tunnel down the moment an admin raises the schema would turn a planned
	// change into an outage.
	if got := h.auth.Head(); got != before {
		t.Errorf("head moved to %v; the chain must stop at %v", got, before)
	}
	state, err := h.auth.TrustedState()
	if err != nil {
		t.Fatalf("TrustedState refused after a schema alarm: %v", err)
	}
	if !state.IsMember(keep.Identity) || !state.IsMember(doomed.Identity) {
		t.Error("the membership from before the upgrade was not kept")
	}

	// The record is stored, so it is still offered to peers: a node that
	// cannot apply a record must not swallow the one that explains why.
	if _, err := h.storage.AUM(upgrade.Hash()); err != nil {
		t.Errorf("the upgrade record was not stored: %v", err)
	}

	// Compaction would delete exactly the records a newer build resumes from.
	if _, err := h.auth.Compact(); err == nil {
		t.Error("compaction was allowed while the chain was stopped at an unreadable schema")
	}
}

// TestRecordsPastAnUnreadableSchemaAreNotStored: this build does not know the
// rules records after the upgrade are judged by, so it cannot verify them.
// Storing them anyway would let any member fill a stopped node's disk with
// records nothing here ever checked.
func TestRecordsPastAnUnreadableSchemaAreNotStored(t *testing.T) {
	h := newHarness(t, 1, 1)
	doomed := h.addNode("doomed")

	upgrade := h.handAssembledSchemaUpgrade(types.CurrentSchema + 1)
	// A removal authored after the upgrade, of a kind this build does know:
	// its kind is readable, its position is not.
	past := types.AUM{Kind: types.KindRemoveNode, Subject: &doomed.Identity}
	prev := upgrade.Hash()
	past.Prev = &prev
	epoch, err := h.sealer()(3, nil)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	past.Epoch = epoch
	h.signQuorum(&past)

	if err := h.auth.Inform(upgrade, past); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if _, err := h.storage.AUM(upgrade.Hash()); err != nil {
		t.Errorf("the upgrade record was not stored: %v", err)
	}
	if _, err := h.storage.AUM(past.Hash()); !errors.Is(err, ErrNotFound) {
		t.Errorf("a record past the stop point was stored; err = %v", err)
	}
	if state, _ := h.auth.TrustedState(); state != nil && !state.IsMember(doomed.Identity) {
		t.Error("a removal past the stop point was applied")
	}
}

// TestSchemaUpgradeStillNeedsQuorum: the alarm is reachable only through an
// authorized record. Without that, any member could freeze every node in the
// network by asserting a version.
func TestSchemaUpgradeStillNeedsQuorum(t *testing.T) {
	h := newHarness(t, 3, 3)
	prev := h.auth.Head()
	v := types.CurrentSchema + 1
	aum := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &v}
	if err := aum.Sign(h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("schema upgrade below quorum", aum)
	if h.auth.SchemaAlarm() != nil {
		t.Error("an unauthorized record raised the schema alarm")
	}
}

// TestSchemaFloorRefusesADowngrade covers the fork half of the rule: a branch
// that never took the upgrade must not be adoptable by a node that did. Fork
// choice is deliberately not taught to prefer upgrades — a second bias in
// pickPrimary could let one orphan a revocation, which is what "revoked wins"
// exists to prevent — so the ratchet is what refuses it.
func TestSchemaFloorRefusesADowngrade(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("a")
	if err := h.storage.SetSchemaFloor(types.CurrentSchema + 1); err != nil {
		t.Fatalf("raising the schema floor: %v", err)
	}
	if _, err := Open(h.storage); err == nil {
		t.Fatal("a chain below the adopted schema was accepted")
	}
}

// TestDowngradedBuildSaysSoRatherThanCryingRollback: a node that adopted a
// newer schema and was then started under an older build resolves to whatever
// preceded the upgrade, which is legitimately below its own floors. Reporting
// that as a rollback would send an operator looking for a compromised quorum.
func TestDowngradedBuildSaysSoRatherThanCryingRollback(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("a")
	upgrade := h.handAssembledSchemaUpgrade(types.CurrentSchema + 1)
	if err := h.auth.Inform(upgrade); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	// What the newer build would have left behind.
	if err := h.storage.SetSchemaFloor(types.CurrentSchema + 1); err != nil {
		t.Fatalf("raising the schema floor: %v", err)
	}

	_, err := Open(h.storage)
	var tooNew *SchemaTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("Open reported %v, want a schema error naming the newer version", err)
	}
	if tooNew.Version != types.CurrentSchema+1 {
		t.Errorf("error names %v, want %v", tooNew.Version, types.CurrentSchema+1)
	}
}

// TestUpgradeToTheSchemaAlreadyInForceIsRefused: an upgrade that raises
// nothing is not a no-op worth chaining, and one to schema 0 could not be.
func TestUpgradeToTheSchemaAlreadyInForceIsRefused(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.mustReject("upgrade to the current schema", h.handAssembledSchemaUpgrade(types.CurrentSchema))

	prev := h.auth.Head()
	var zero types.SchemaVersion
	aum := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &zero}
	h.signQuorum(&aum)
	if err := aum.StaticValidate(); err == nil {
		t.Error("a record adopting schema 0 was accepted")
	}
}

// TestBuilderRefusesToAuthorAnUnreadableUpgrade: a device must not move the
// network to a schema it could not then read, which would strand it on a
// version nobody present can write records under.
func TestBuilderRefusesToAuthorAnUnreadableUpgrade(t *testing.T) {
	h := newHarness(t, 1, 1)
	if _, err := h.auth.Builder().SchemaUpgrade(types.CurrentSchema + 1); err == nil {
		t.Error("the builder authored an upgrade past what this build implements")
	}
	if _, err := h.auth.Builder().SchemaUpgrade(types.CurrentSchema); err == nil {
		t.Error("the builder authored an upgrade to the schema already in force")
	}
}

// TestSchemaTravelsInEveryStateStatement: a checkpoint and a genesis both
// carry the version, so a node bootstrapping from either learns it without the
// history. Without that a fresh node would read a newer network as schema 0
// and act on the part of it it understood.
func TestSchemaTravelsInEveryStateStatement(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("a")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if cp.State.Schema != h.auth.State().Schema() {
		t.Errorf("checkpoint states %v, the chain is at %v", cp.State.Schema, h.auth.State().Schema())
	}

	// A bootstrap anchor at a schema this build cannot read is refused
	// outright: there is no earlier state to fall back to.
	cp.State.Schema = types.CurrentSchema + 1
	cp.Signatures = nil
	h.signQuorum(&cp)
	fresh := NewMemStorage()
	_, err = Bootstrap(fresh, cp)
	var tooNew *SchemaTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("Bootstrap reported %v, want a schema error", err)
	}
	if hashes, herr := fresh.Hashes(); herr != nil || len(hashes) != 0 {
		t.Errorf("a refused bootstrap left %v in the store (err %v)", hashes, herr)
	}
}

// TestStoredUpgradeRecordIsStillOfferedToPeers: a stopped node stays a useful
// relay for the record that stopped it, so the member behind it learns what
// happened rather than watching sync go quiet.
func TestStoredUpgradeRecordIsStillOfferedToPeers(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("a")
	upgrade := h.handAssembledSchemaUpgrade(types.CurrentSchema + 1)
	if err := h.auth.Inform(upgrade); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	hashes, err := h.storage.Hashes()
	if err != nil {
		t.Fatalf("Hashes: %v", err)
	}
	if !slices.Contains(hashes, upgrade.Hash()) {
		t.Error("the upgrade record is not in the store, so it can never be relayed")
	}
}
