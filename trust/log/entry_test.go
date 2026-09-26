package log

import (
	"bytes"
	"testing"

	"github.com/nning/juist/types"
)

// TestGenesisStatusTracksTheCeremony: a genesis collecting its signatures
// reports what is missing under the policy it declares, and a record that is
// no genesis, or no valid one, is an error rather than a status.
func TestGenesisStatusTracksTheCeremony(t *testing.T) {
	h := newHarness(t, 2, 2)
	genesis, err := Genesis("ceremony", 2, h.adminKeys(), h.commitments(), nil, fixedSealer())
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	for i, admin := range h.admins {
		st, err := GenesisStatus(&genesis)
		if err != nil {
			t.Fatalf("GenesisStatus with %d signatures: %v", i, err)
		}
		if st.Votes != uint32(i) || st.Quorum != 2 || st.Authorized() {
			t.Fatalf("with %d signatures: %+v", i, st)
		}
		if err := genesis.Sign(admin); err != nil {
			t.Fatalf("signing: %v", err)
		}
	}
	if st, err := GenesisStatus(&genesis); err != nil || !st.Authorized() {
		t.Fatalf("fully signed: %+v, %v", st, err)
	}

	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := genesis.Sign(stranger); err != nil {
		t.Fatal(err)
	}
	if st, err := GenesisStatus(&genesis); err != nil || st.Authorized() || len(st.Untrusted) != 1 {
		t.Fatalf("signed by a stranger too: %+v, %v", st, err)
	}

	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if _, err := GenesisStatus(&cp); err == nil {
		t.Error("GenesisStatus reported on a checkpoint")
	}
	genesis.State.Quorum = 0
	if _, err := GenesisStatus(&genesis); err == nil {
		t.Error("GenesisStatus reported on a genesis no one could authorize")
	}
}

// TestFromRecords: a chain handed over whole, from a genesis or from a
// checkpoint, reaches the state the chain it came from holds; anything else is
// refused.
func TestFromRecords(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("a")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	h.addNode("b")

	hashes, err := h.auth.Chain()
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	var chain []types.AUM
	for _, hash := range hashes {
		aum, err := h.storage.AUM(hash)
		if err != nil {
			t.Fatalf("reading %v: %v", hash, err)
		}
		chain = append(chain, aum)
	}
	want := h.auth.State().Snapshot().Encode()
	for _, from := range []int{0, 2} { // the genesis, and the checkpoint
		auth, err := FromRecords(NewMemStorage(), chain[from:])
		if err != nil {
			t.Fatalf("FromRecords from %v: %v", chain[from].Kind, err)
		}
		if !bytes.Equal(auth.State().Snapshot().Encode(), want) {
			t.Errorf("FromRecords from %v reached another state", chain[from].Kind)
		}
	}
	if _, err := FromRecords(NewMemStorage(), nil); err == nil {
		t.Error("FromRecords accepted no records")
	}
	if _, err := FromRecords(NewMemStorage(), chain[1:]); err == nil {
		t.Error("FromRecords accepted a chain starting at an admission")
	}
	if _, err := FromRecords(NewMemStorage(), []types.AUM{chain[0], chain[3]}); err == nil {
		t.Error("FromRecords accepted a chain with a gap")
	}
}

// TestAlreadyRevoked is the question a losing revocation's branch asks of the
// chosen chain: whether what it withdraws is withdrawn there already.
func TestAlreadyRevoked(t *testing.T) {
	h := newHarness(t, 2, 1)
	admin := h.addNode("admin device")
	plain := h.addNode("plain")
	h.apply(h.auth.Builder().SetNodeRoutes(admin.Identity, []types.Role{types.RoleAdmin}, nil))
	alice, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	h.apply(h.auth.Builder().AddAdminKey(types.AdminKey{Public: alice.Public(), Votes: 1, Holder: "alice"}))
	s := h.auth.State()

	stranger := h.newNode("stranger").Identity
	firstAdmin := h.admins[0].Public()
	one, two := uint32(1), uint32(2)
	for _, tc := range []struct {
		what string
		aum  types.AUM
		want bool
	}{
		{"removing a member", types.AUM{Kind: types.KindRemoveNode, Subject: &plain.Identity}, false},
		{"removing a non-member", types.AUM{Kind: types.KindRemoveNode, Subject: &stranger}, true},
		{"removing an admin key", types.AUM{Kind: types.KindRemoveAdminKey, Subject: &firstAdmin}, false},
		{"removing a key that is none", types.AUM{Kind: types.KindRemoveAdminKey, Subject: &stranger}, true},
		{"taking an admin device's role", types.AUM{Kind: types.KindSetNodeRoutes, Subject: &admin.Identity}, false},
		{"taking a role a member lacks", types.AUM{Kind: types.KindSetNodeRoutes, Subject: &plain.Identity}, true},
		{"taking a non-member's role", types.AUM{Kind: types.KindSetNodeRoutes, Subject: &stranger}, true},
		{"vouchers at the threshold", types.AUM{Kind: types.KindSetVouchers, Vouchers: &one}, true},
		{"vouchers above it", types.AUM{Kind: types.KindSetVouchers, Vouchers: &two}, false},
		{"quorum at the threshold", types.AUM{Kind: types.KindSetQuorum, Quorum: &one}, true},
		{"quorum above it", types.AUM{Kind: types.KindSetQuorum, Quorum: &two}, false},
		{"a holder's policy as it is", types.AUM{Kind: types.KindSetHolder,
			Holder: &types.HolderPolicy{Name: "alice", Votes: 1, Needed: 1}}, true},
		{"a holder needing more keys", types.AUM{Kind: types.KindSetHolder,
			Holder: &types.HolderPolicy{Name: "alice", Votes: 1, Needed: 2}}, false},
		{"a holder with no keys", types.AUM{Kind: types.KindSetHolder,
			Holder: &types.HolderPolicy{Name: "bob", Votes: 1, Needed: 1}}, true},
		{"a record withdrawing nothing", types.AUM{Kind: types.KindEpochBump}, false},
	} {
		if got := s.alreadyRevoked(&tc.aum); got != tc.want {
			t.Errorf("%s: alreadyRevoked %v, want %v", tc.what, got, tc.want)
		}
	}
}
