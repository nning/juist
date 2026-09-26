package log

import (
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// holders is a network whose admin keys belong to people: each name in
// people holds the given number of keys, with one vote.
type holders struct {
	t    *testing.T
	auth *Authority
	keys map[string][]types.PrivateIdentity
	h    *harness
}

func newHolders(t *testing.T, quorum uint32, people map[string]int) *holders {
	t.Helper()
	h := newHarness(t, 1, 1)
	hs := &holders{t: t, keys: map[string][]types.PrivateIdentity{}, h: h}
	var admins []types.AdminKey
	for name, n := range people {
		for range n {
			k, err := types.GenerateIdentity()
			if err != nil {
				t.Fatal(err)
			}
			hs.keys[name] = append(hs.keys[name], k)
			admins = append(admins, types.AdminKey{Public: k.Public(), Votes: 1, Name: name, Holder: name})
		}
	}
	genesis, err := Genesis("people", quorum, admins, h.commitments(), nil, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	for _, ks := range hs.keys {
		for _, k := range ks {
			if err := genesis.Sign(k); err != nil {
				t.Fatal(err)
			}
		}
	}
	if hs.auth, err = Create(NewMemStorage(), genesis); err != nil {
		t.Fatal(err)
	}
	return hs
}

// signed is a change signed by the given keys.
func (hs *holders) signed(aum types.AUM, by ...types.PrivateIdentity) types.AUM {
	hs.t.Helper()
	for _, k := range by {
		if err := aum.Sign(k); err != nil {
			hs.t.Fatal(err)
		}
	}
	return aum
}

func (hs *holders) epochBump() types.AUM {
	hs.t.Helper()
	aum, err := hs.auth.Builder().EpochBump(hs.h.sealer())
	if err != nil {
		hs.t.Fatal(err)
	}
	return aum
}

// Two people with two keys each, and a change needing two votes: one person
// signing with both keys is one vote, and each person with one key is two.
func TestAPersonsKeysCastOneVote(t *testing.T) {
	hs := newHolders(t, 2, map[string]int{"alice": 2, "bob": 2})
	a, b := hs.keys["alice"], hs.keys["bob"]
	if st := hs.auth.State().SignatureStatus(ptr(hs.signed(hs.epochBump(), a[0], a[1]))); st.Authorized() {
		t.Fatalf("alice alone, with both her keys, cast %d votes", st.Votes)
	}
	change := hs.signed(hs.epochBump(), a[1], b[0])
	if st := hs.auth.State().SignatureStatus(&change); !st.Authorized() {
		t.Fatalf("alice and bob together cast %d votes", st.Votes)
	}
	if err := hs.auth.Inform(change); err != nil {
		t.Fatal(err)
	}
	if got := hs.auth.State().TotalVotes(); got != 2 {
		t.Fatalf("four keys of two people can cast %d votes, want 2", got)
	}
}

// A person running a network alone can require two of her devices for every
// change, where she configured it so; one device is then not enough.
func TestAHolderCanNeedSeveralOfItsKeys(t *testing.T) {
	hs := newHolders(t, 1, map[string]int{"alice": 3})
	a := hs.keys["alice"]
	set, err := hs.auth.Builder().SetHolder(types.HolderPolicy{Name: "alice", Votes: 1, Needed: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := hs.auth.Inform(hs.signed(set, a[0])); err != nil {
		t.Fatalf("setting alice's policy: %v", err)
	}
	if st := hs.auth.State().SignatureStatus(ptr(hs.signed(hs.epochBump(), a[0]))); st.Authorized() {
		t.Fatal("one of alice's devices authorized a change she needs two for")
	}
	if err := hs.auth.Inform(hs.signed(hs.epochBump(), a[0], a[2])); err != nil {
		t.Fatalf("two of alice's devices: %v", err)
	}

	// Needing more keys than she has would leave nobody able to change the
	// network, and is refused; so is removing a key she then lacks.
	// The builder refuses what the log would, so the log is asked directly.
	more := types.AUM{Kind: types.KindSetHolder, Holder: &types.HolderPolicy{Name: "alice", Votes: 1, Needed: 4}}
	if _, err := hs.auth.Builder().SetHolder(*more.Holder); err == nil {
		t.Fatal("the builder built a policy that leaves nobody able to change the network")
	}
	if _, err := hs.auth.State().apply(&more, types.Hash{1}, applyProbe); err == nil ||
		!strings.Contains(err.Error(), "unmanageable") {
		t.Fatalf("alice needing four of her three keys: %v", err)
	}
	all, err := hs.auth.Builder().SetHolder(types.HolderPolicy{Name: "alice", Votes: 1, Needed: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := hs.auth.Inform(hs.signed(all, a[0], a[1])); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.auth.Builder().RemoveAdminKey(a[2].Public()); err == nil ||
		!strings.Contains(err.Error(), "unmanageable") {
		t.Fatalf("alice giving up a key she needs: %v", err)
	}
}

// Holders are schema 3: before it, a key naming one is refused, since older
// builds would count its votes apart.
func TestHoldersNeedTheirSchema(t *testing.T) {
	h := newHarnessAt(t, 1, 1, types.SchemaRevokingRoles)
	k, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.auth.Builder().AddAdminKey(types.AdminKey{Public: k.Public(), Votes: 1, Holder: "alice"}); err == nil ||
		!strings.Contains(err.Error(), "needs schema 3") {
		t.Fatalf("a holder at schema 2: %v", err)
	}
	if _, err := h.auth.Builder().SetHolder(types.HolderPolicy{Name: "admin0", Votes: 1, Needed: 1}); err == nil {
		t.Fatal("a holder policy applied at schema 2")
	}
}

// Asking more of a holder's keys is a revocation: a concurrent change does
// not orphan it on its hash.
func TestNeedingMoreKeysWinsForkChoice(t *testing.T) {
	hs := newHolders(t, 1, map[string]int{"alice": 2})
	a := hs.keys["alice"]
	raise, err := hs.auth.Builder().SetHolder(types.HolderPolicy{Name: "alice", Votes: 1, Needed: 2})
	if err != nil {
		t.Fatal(err)
	}
	raise = hs.signed(raise, a[0])
	if !hs.auth.State().Revokes(&raise) {
		t.Fatal("needing more of a holder's keys is not a revocation")
	}
	lower, err := hs.auth.Builder().SetHolder(types.HolderPolicy{Name: "alice", Votes: 2, Needed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if hs.auth.State().Revokes(&lower) {
		t.Fatal("giving a holder more votes counted as a revocation")
	}
}

// Holders a person could not tell apart are refused, as the CLI folds names;
// "alice" and "Alice" would otherwise be two voters the approver sees as one.
func TestHoldersDifferingOnlyInCaseAreRefused(t *testing.T) {
	hs := newHolders(t, 1, map[string]int{"alice": 1})
	k, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.auth.Builder().AddAdminKey(types.AdminKey{Public: k.Public(), Votes: 1, Name: "Alice",
		Holder: "Alice"}); err == nil || !strings.Contains(err.Error(), "only in case") {
		t.Fatalf("a holder differing only in case: %v", err)
	}
	// One key needed is written one way only.
	if _, err := hs.auth.Builder().AddAdminKey(types.AdminKey{Public: k.Public(), Votes: 1, Holder: "alice",
		Needed: 1}); err == nil {
		t.Fatal("a key needing one key, written as one, was accepted")
	}
}

// A policy that grants authority as well as taking some is no revocation,
// and a raised quorum is one from schema 3.
func TestWhatCountsAsWithdrawingAuthority(t *testing.T) {
	hs := newHolders(t, 1, map[string]int{"alice": 3})
	mixed := types.AUM{Kind: types.KindSetHolder, Holder: &types.HolderPolicy{Name: "alice", Votes: 4096, Needed: 2}}
	if hs.auth.State().Revokes(&mixed) {
		t.Fatal("more votes with more keys needed counted as a revocation")
	}
	q := uint32(2)
	raise := types.AUM{Kind: types.KindSetQuorum, Quorum: &q}
	if !hs.auth.State().Revokes(&raise) {
		t.Fatal("a raised quorum is not a revocation at schema 3")
	}
}

// Raising a network to schema 3 makes each named key its own holder, so an
// admin's further keys can be added under the name they know, and no vote
// changes; keys whose names collide stay voters of their own.
func TestTheUpgradeNamesHolders(t *testing.T) {
	h := newHarnessAt(t, 3, 1, types.SchemaRevokingRoles)
	up, err := h.auth.Builder().SchemaUpgrade(types.SchemaHolders)
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&up)
	before := h.auth.State().TotalVotes()
	if err := h.auth.Inform(up); err != nil {
		t.Fatal(err)
	}
	for _, k := range h.auth.State().Admins() {
		if k.Holder != k.Name {
			t.Errorf("key %q holds for %q after the upgrade", k.Name, k.Holder)
		}
	}
	if after := h.auth.State().TotalVotes(); after != before {
		t.Fatalf("the upgrade changed the votes from %d to %d", before, after)
	}
}

// A removed admin key cannot undo its own removal: a branch it signed, rooted
// before the removal, loses to the branch that removes it, whatever its hash
// and even as a revocation. At schema 2 it wins on a lower hash.
func TestARemovedKeyCannotUndoItsRemoval(t *testing.T) {
	for _, schema := range []types.SchemaVersion{types.SchemaRevokingRoles, types.SchemaHolders} {
		h := newHarnessAt(t, 2, 1, schema)
		mallory, honest := h.admins[0], h.admins[1]
		victim := h.addNode("victim")
		var removal, counter types.AUM
		for {
			b := h.auth.Builder()
			var err error
			if removal, err = b.RemoveAdminKey(mallory.Public()); err != nil {
				t.Fatal(err)
			}
			if err := removal.Sign(honest); err != nil {
				t.Fatal(err)
			}
			// Mallory's move at the same parent, signed by her alone: a
			// revocation too, so the bias alone does not decide.
			if counter, err = b.RemoveNode(victim.Identity, h.sealer()); err != nil {
				t.Fatal(err)
			}
			if err := counter.Sign(mallory); err != nil {
				t.Fatal(err)
			}
			if counter.Hash().Compare(removal.Hash()) < 0 {
				break
			}
			bump, err := b.EpochBump(h.sealer())
			if err != nil {
				t.Fatal(err)
			}
			h.signQuorum(&bump)
			if err := h.auth.Inform(bump); err != nil {
				t.Fatal(err)
			}
		}
		auth := h.fork()
		if err := auth.Inform(removal, counter); err != nil {
			t.Fatalf("schema %d: %v", schema, err)
		}
		_, malloryStays := auth.State().Admin(mallory.Public())
		if want := schema < types.SchemaHolders; malloryStays != want {
			t.Errorf("schema %d: the removed key is an admin after the fork: %v", schema, malloryStays)
		}
	}
}

// Two keys removing each other at once is no removal the log can settle: at
// quorum one either could do anything, so it alarms rather than choosing.
func TestKeysRemovingEachOtherAlarm(t *testing.T) {
	h := newHarness(t, 2, 1)
	a, b := h.admins[0], h.admins[1]
	builder := h.auth.Builder()
	one, err := builder.RemoveAdminKey(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := one.Sign(a); err != nil {
		t.Fatal(err)
	}
	other, err := builder.RemoveAdminKey(a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Sign(b); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(one, other); err != nil {
		t.Fatal(err)
	}
	if h.auth.Alarm() == nil {
		t.Fatal("two admins removing each other raised no alarm")
	}
}

// Two removals at once do not stop the network: the one that lost is named
// as not in effect, and one of a device already removed is nothing.
func TestConcurrentRemovalsDoNotStopTheNetwork(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.addNode("a"), h.addNode("b")
	builder := h.auth.Builder()
	removeA, err := builder.RemoveNode(a.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&removeA)
	removeB, err := builder.RemoveNode(b.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&removeB)
	auth := h.fork()
	if err := auth.Inform(removeA, removeB); err != nil {
		t.Fatal(err)
	}
	if auth.Alarm() != nil {
		t.Fatalf("two removals at once stopped the network: %v", auth.Alarm())
	}
	lost := removeA
	if auth.Head() == removeA.Hash() {
		lost = removeB
	}
	if o := auth.Orphans(); len(o) != 1 || !slices.Equal(o[0].Unrevoked, []types.Hash{lost.Hash()}) {
		t.Fatalf("the removal that lost is not named: %+v", o)
	}

	again, err := builder.RemoveNode(a.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&again)
	twice := h.fork()
	if err := twice.Inform(removeA, again); err != nil && !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	for _, o := range twice.Orphans() {
		if len(o.Unrevoked) > 0 || o.Conflict != "" {
			t.Fatalf("removing one device twice at once was reported: %+v", o)
		}
	}
}
