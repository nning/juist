package log

import (
	"fmt"
	"testing"

	"github.com/nning/juist/types"
)

// TestRecordSizeAtMaxNodes is the measurement docs/05-roadmap.md requires
// before the M3 record-schema freeze, kept as a regression guard: the epoch
// group secret fans out one 1168-byte wrap per member, inline, in every record
// that changes the member set and in every checkpoint. What the numbers
// decided is in docs/08-trust-layer-notes.md.
//
// It also bounds what one record may cost a receiver: a checkpoint at
// [types.MaxNodes] must stay inside [types.MaxRecordSize], and an epoch bump
// inside a single gossip frame, or a network at the schema's ceiling could
// author a record its own members refuse.
func TestRecordSizeAtMaxNodes(t *testing.T) {
	h := newHarness(t, 1, 1)
	members := make([]types.NodeRecord, 0, types.MaxNodes)
	for i := range types.MaxNodes {
		members = append(members, h.newNode(fmt.Sprintf("n%d", i)))
	}

	cp := h.handAssembledCheckpoint(members)
	checkpoint, err := cp.Encode()
	if err != nil {
		t.Fatalf("encoding the checkpoint: %v", err)
	}
	epoch, err := h.sealer()(2, members)
	if err != nil {
		t.Fatalf("sealing an epoch: %v", err)
	}
	prev := h.auth.Head()
	bump := types.AUM{Kind: types.KindEpochBump, Prev: &prev, Epoch: epoch}
	h.signQuorum(&bump)
	bumped, err := bump.Encode()
	if err != nil {
		t.Fatalf("encoding the epoch bump: %v", err)
	}

	t.Logf("at %d members: checkpoint %d bytes (%.0f KiB), epoch bump %d bytes (%.0f KiB)",
		types.MaxNodes, len(checkpoint), float64(len(checkpoint))/1024,
		len(bumped), float64(len(bumped))/1024)
	t.Logf("one membership change costs each member %.0f KiB and the network %.0f MiB",
		float64(len(bumped))/1024, float64(len(bumped))*(types.MaxNodes-1)/(1024*1024))

	if len(checkpoint) > types.MaxRecordSize {
		t.Errorf("a checkpoint at %d members is %d bytes, over the %d-byte record limit "+
			"every node enforces", types.MaxNodes, len(checkpoint), types.MaxRecordSize)
	}
	if len(bumped) > types.MaxRecordSize {
		t.Errorf("an epoch bump at %d members is %d bytes, over the %d-byte record limit",
			types.MaxNodes, len(bumped), types.MaxRecordSize)
	}
}
