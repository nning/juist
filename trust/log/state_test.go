package log

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// everyFieldSet fails for each field of the struct v that is zero, but those
// in unset: a fixture that leaves one out proves nothing about it.
func everyFieldSet(t *testing.T, v any, unset ...string) {
	t.Helper()
	rv := reflect.ValueOf(v)
	for i := range rv.NumField() {
		if f := rv.Type().Field(i); rv.Field(i).IsZero() && !slices.Contains(unset, f.Name) {
			t.Errorf("%s.%s is not set in the fixture", rv.Type().Name(), f.Name)
		}
	}
}

// State mirrors Snapshot field by field, in stateFromSnapshot, Snapshot and
// clone; a field one of them misses drops out of checkpoints, or of every
// state after the record that set it.
func TestStateCarriesEveryField(t *testing.T) {
	gh := types.Hash{1}
	prefix := netip.MustParsePrefix("198.18.4.0/22")
	snap := types.Snapshot{
		GenesisHash: &gh,
		Network:     "home",
		Quorum:      1,
		Epoch:       3,
		EpochCommit: types.Hash{2},
		Disablement: []types.Hash{{3}},
		Admins:      []types.AdminKey{{Public: types.Identity{4}, Votes: 1, Name: "alice"}},
		Nodes: []types.NodeRecord{{Identity: types.Identity{5}, Name: "laptop", Names: []string{"mx.example.org"},
			Published: []types.PublishedName{{Label: "immich", Port: 443}}}},
		EpochWraps: []types.EpochWrap{{Recipient: types.Identity{5}, Sealed: []byte{6}}},
		Schema:     types.CurrentSchema,
		Vouchers:   2,
		V4Prefix:   &prefix,
		V4Retiring: &types.RetiringRanges{Prefixes: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/22")}, Until: 7},
		Domain:     "pub.example.org",
		Policy:     &types.Policy{Rules: []types.PolicyRule{{From: types.PolicyRefs{Any: true}, To: types.PolicyRefs{Any: true}}}},
	}
	// v1 has one suite, the zero value.
	everyFieldSet(t, snap, "EpochSuite")

	s, err := stateFromSnapshot(&snap, types.Hash{8})
	if err != nil {
		t.Fatal(err)
	}
	everyFieldSet(t, *s)
	if back := s.Snapshot(); !reflect.DeepEqual(*back, snap) {
		t.Errorf("a state's snapshot is not the one it was built from:\n got %+v\nwant %+v", *back, snap)
	}
	if c := s.clone(); !reflect.DeepEqual(*c, *s) {
		t.Errorf("a clone differs from its state:\n got %+v\nwant %+v", *c, *s)
	}
}
