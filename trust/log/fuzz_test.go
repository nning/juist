package log

import (
	"testing"

	"github.com/nning/wg-p2p/types"
)

// FuzzChainValidate is the chain-validator target docs/06-verification.md
// schedules for M1. Raw bytes are decoded into records and offered to a real
// authority, which models the only way records ever arrive: from an untrusted
// transport, in whatever shape the sender chose.
//
// The assertions are the invariants that must hold no matter what arrives:
//
//   - no panic — a panic reachable from a gossiped record is a denial of
//     service against every member;
//   - a rejected batch changes nothing, so a hostile sender cannot move the
//     head or the epoch by sending something that fails halfway;
//   - the epoch never goes backwards;
//   - whatever state is reached, reopening the store reproduces it.
func FuzzChainValidate(f *testing.F) {
	for _, seed := range chainSeeds(f) {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		h := newFuzzHarness(t)
		aum, err := types.DecodeAUM(data)
		if err != nil {
			return
		}
		headBefore := h.auth.Head()
		epochBefore := h.auth.State().Epoch()
		stateBefore := h.auth.State().Snapshot().Encode()

		informErr := h.auth.Inform(aum)
		if informErr != nil {
			if h.auth.Head() != headBefore {
				t.Fatal("a rejected record moved the head")
			}
			if string(h.auth.State().Snapshot().Encode()) != string(stateBefore) {
				t.Fatal("a rejected record changed the state")
			}
		}
		if h.auth.State().Epoch() < epochBefore {
			t.Fatalf("epoch went backwards: %d then %d", epochBefore, h.auth.State().Epoch())
		}
		reopened, err := Open(h.storage)
		if err != nil {
			t.Fatalf("store no longer opens after Inform (err was %v): %v", informErr, err)
		}
		if reopened.Head() != h.auth.Head() {
			t.Fatal("reopening the store produced a different head")
		}
		if string(reopened.State().Snapshot().Encode()) != string(h.auth.State().Snapshot().Encode()) {
			t.Fatal("reopening the store produced different state")
		}
	})
}

// fuzzHarness is a minimal fixed network. It cannot use the main harness,
// which needs *testing.T for its fatal paths and fresh keys per call; a fuzz
// target needs the same network on every exec so that a failing input
// reproduces.
type fuzzHarness struct {
	storage *MemStorage
	auth    *Authority
}

func newFuzzHarness(t *testing.T) *fuzzHarness {
	t.Helper()
	genesis, _, err := fixedGenesis()
	if err != nil {
		t.Fatalf("building the fixed genesis: %v", err)
	}
	st := NewMemStorage()
	auth, err := Create(st, genesis)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return &fuzzHarness{storage: st, auth: auth}
}

// chainSeeds returns records that are valid against the fixed network, so the
// fuzzer starts from inputs that get past authorization and reach the state
// machine.
func chainSeeds(t interface{ Fatalf(string, ...any) }) [][]byte {
	genesis, admin, err := fixedGenesis()
	if err != nil {
		t.Fatalf("building the fixed genesis: %v", err)
	}
	auth, err := Create(NewMemStorage(), genesis)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sealer := testSealer()
	node := fixedNode(1)
	var out [][]byte

	add, err := auth.Builder().AddNode(node, sealer)
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if err := add.Sign(admin); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if b, err := add.Encode(); err == nil {
		out = append(out, b)
	}
	if err := auth.Inform(add); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	remove, err := auth.Builder().RemoveNode(node.Identity, sealer)
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	if err := remove.Sign(admin); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if b, err := remove.Encode(); err == nil {
		out = append(out, b)
	}
	cp, err := auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if err := cp.Sign(admin); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if b, err := cp.Encode(); err == nil {
		out = append(out, b)
	}
	return out
}
