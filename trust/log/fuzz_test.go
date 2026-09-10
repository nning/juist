package log

import (
	"testing"

	"github.com/nning/juist/types"
)

// FuzzChainValidate offers raw bytes, decoded into records, to a real
// authority — the only way records ever arrive. The invariants:
//
//   - no panic, which from a gossiped record would be a denial of service;
//   - a rejected batch changes nothing;
//   - the epoch never goes backwards;
//   - reopening the store reproduces whatever state is reached.
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

// fuzzHarness is a minimal fixed network: the main harness needs *testing.T
// and draws fresh keys, while a fuzz target needs the same network on every
// exec so a failing input reproduces.
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
