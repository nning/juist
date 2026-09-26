package log

import (
	"errors"
	"testing"

	"github.com/nning/juist/types"
)

type failingAdd struct{ *MemStorage }

var errDisk = errors.New("disk full")

func (failingAdd) Add(...types.AUM) error { return errDisk }

// TestStorageFailureIsNotARejection: a record this node failed to store is
// not a record the network refused, and a caller must be able to tell.
func TestStorageFailureIsNotARejection(t *testing.T) {
	h := newHarness(t, 1, 1)
	auth, err := Open(failingAdd{h.copyStorage()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	aum, err := auth.Builder().AddNode(h.newNode("n"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	err = auth.Inform(aum)
	if !errors.Is(err, errDisk) || errors.As(err, new(*RejectError)) {
		t.Fatalf("Inform over a failing store: %v, want the storage error and no rejection", err)
	}
}

// TestMemStorageIsolatesRecords: what a caller holds, handed in or read out,
// is its own; changing it must not change the record stored under its hash.
func TestMemStorageIsolatesRecords(t *testing.T) {
	h := newHarness(t, 1, 1)
	schema := types.SchemaHolders
	vouchers := uint32(1)
	prev := h.auth.Head()
	for _, rec := range []types.AUM{
		{Kind: types.KindSetHolder, Prev: &prev, Holder: &types.HolderPolicy{Name: "admin0", Votes: 1, Needed: 1}},
		{Kind: types.KindSetVouchers, Prev: &prev, Vouchers: &vouchers},
		{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &schema},
	} {
		h.signQuorum(&rec)
		hash := rec.Hash()
		st := NewMemStorage()
		if err := st.Add(rec); err != nil {
			t.Fatalf("%v: Add: %v", rec.Kind, err)
		}
		read, err := st.AUM(hash)
		if err != nil {
			t.Fatalf("%v: AUM: %v", rec.Kind, err)
		}
		for _, held := range []*types.AUM{&rec, &read} {
			switch {
			case held.Holder != nil:
				held.Holder.Votes++
			case held.Vouchers != nil:
				*held.Vouchers++
			case held.Schema != nil:
				*held.Schema++
			}
		}
		again, err := st.AUM(hash)
		if err != nil {
			t.Fatalf("%v: AUM: %v", rec.Kind, err)
		}
		if again.Hash() != hash {
			t.Errorf("%v: a caller's copy changed the stored record", rec.Kind)
		}
	}
}
