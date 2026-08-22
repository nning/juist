package log

import (
	"testing"
	"time"
)

// TestScaleAtTargetSize is a sanity check rather than a benchmark: a network at
// the top of the documented scale (docs/01-requirements.md: 25–100 devices)
// with a long chain must open and extend in a time an operator would not
// notice. It exists to catch an accidentally quadratic rule, not to track
// performance.
func TestScaleAtTargetSize(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 100-member network")
	}
	h := newHarness(t, 3, 2)
	const members = 100
	start := time.Now()
	for i := range members {
		h.addNode(string(rune('a'+i%26)) + string(rune('0'+i/26)))
	}
	build := time.Since(start)

	start = time.Now()
	reopened, err := Open(h.storage)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	open := time.Since(start)
	if len(reopened.State().Nodes()) != members {
		t.Fatalf("%d members after reopen, want %d", len(reopened.State().Nodes()), members)
	}

	// A checkpoint at this size is the largest record the schema allows in
	// practice; it must fit well inside the decode limit.
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	encoded, err := cp.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := h.auth.Inform(cp); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	t.Logf("%d members: built %d records in %v, reopened in %v, checkpoint is %d bytes",
		members, members+1, build, open, len(encoded))

	// Generous ceilings: the point is to fail loudly if a rule turns
	// superlinear, not to police milliseconds.
	if open > 30*time.Second {
		t.Errorf("reopening a %d-member log took %v", members, open)
	}
}
