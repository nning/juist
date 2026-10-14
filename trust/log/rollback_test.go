package log

import (
	"errors"
	"testing"

	"github.com/nning/juist/types"
)

// A node that applied a branch which then lost fork choice to one at a lower
// epoch neither follows the winner nor keeps serving the loser: it holds the
// winner, a removal on it included, and fails closed under an alarm that a
// restart keeps, until a record on the winner, in a batch of its own, brings
// the chain back to the floor.
func TestAForkSwitchBelowTheEpochFloorFailsClosedAndKeepsTakingRecords(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.addNode("a")
	b := h.addNode("b")
	winner := h.fork()
	build := func(auth *Authority, f func(*Builder) (types.AUM, error)) types.AUM {
		t.Helper()
		aum, err := f(auth.Builder())
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&aum)
		if err := auth.Inform(aum); err != nil {
			t.Fatal(err)
		}
		return aum
	}
	// A removal wins fork choice over the epoch bump beside it.
	removeA := build(winner, func(bl *Builder) (types.AUM, error) { return bl.RemoveNode(a.Identity, h.sealer()) })
	removeB := build(winner, func(bl *Builder) (types.AUM, error) { return bl.RemoveNode(b.Identity, h.sealer()) })
	var lost []types.AUM
	for range 3 {
		lost = append(lost, build(h.auth, func(bl *Builder) (types.AUM, error) { return bl.EpochBump(h.sealer()) }))
	}
	floor := h.auth.State().Epoch()
	if winner.State().Epoch() >= floor {
		t.Fatalf("the winning branch is at epoch %d, not below the floor %d", winner.State().Epoch(), floor)
	}

	informErr := h.auth.Inform(removeA, removeB)
	state, err := h.auth.TrustedState()
	if err == nil {
		t.Fatalf("serves epoch %d, b a member: %v, and no alarm; the winning branch was answered with %v",
			state.Epoch(), state.IsMember(b.Identity), informErr)
	}
	if informErr != nil {
		t.Fatalf("the winning branch was refused: %v", informErr)
	}
	var ra *RollbackAlarm
	if !errors.As(err, &ra) || ra.Floor != floor || ra.Epoch != floor-1 || ra.Branch != lost[0].Hash() {
		t.Fatalf("trusted state: %v, want a rollback alarm from %d to %d naming %v", err, floor, floor-1,
			lost[0].Hash())
	}
	if h.auth.Head() != removeB.Hash() || h.auth.State().IsMember(b.Identity) {
		t.Fatal("the removal on the winning branch is not held")
	}
	if got, _ := h.storage.EpochFloor(); got != floor {
		t.Fatalf("epoch floor moved to %d", got)
	}
	if h.fork().Rollback() == nil {
		t.Fatal("a restart cleared the rollback alarm")
	}

	bump := build(winner, func(bl *Builder) (types.AUM, error) { return bl.EpochBump(h.sealer()) })
	if err := h.auth.Inform(bump); err != nil {
		t.Fatalf("the record that brings the chain back to the floor: %v", err)
	}
	state, err = h.auth.TrustedState()
	if err != nil {
		t.Fatalf("still alarmed at the floor: %v", err)
	}
	if state.Head() != bump.Hash() || state.Epoch() != floor || state.IsMember(a.Identity) || state.IsMember(b.Identity) {
		t.Fatalf("head %v epoch %d, want the winning branch at %d without a and b", state.Head(), state.Epoch(), floor)
	}
}

// A signature added to a record after a node's floor moved past it, which
// makes the record win where it lost, alarms on that node and names the branch
// that lost, rather than leaving it silently on a head no node shown the same
// copies in time holds.
func TestALateSurplusSignaturePastTheFloorAlarms(t *testing.T) {
	for range 64 {
		h := newHarness(t, 4, 2)
		d1 := h.addNode("dev1")
		d2 := h.addNode("dev2")
		d3 := h.addNode("dev3")
		signed := func(aum types.AUM, err error) func(...types.PrivateIdentity) types.AUM {
			return func(keys ...types.PrivateIdentity) types.AUM {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				for _, k := range keys {
					if err := h.sign(&aum, k); err != nil {
						t.Fatal(err)
					}
				}
				return aum
			}
		}
		// A revocation that needs A0, and beside it A0's removal.
		r1 := signed(h.auth.Builder().RemoveNode(d1.Identity, h.sealer()))(h.admins[:2]...)
		r2 := signed(h.auth.Builder().RemoveAdminKey(h.admins[0].Public()))(h.admins[2:]...)
		if r1.SigHash().Compare(r2.SigHash()) >= 0 {
			continue
		}

		b := h.fork()
		if err := b.Inform(r1, r2); err != nil {
			t.Fatal(err)
		}
		if b.Head() != r2.Hash() {
			t.Fatalf("B: head %v, want R2 %v", b.Head(), r2.Hash())
		}
		r3 := signed(b.Builder().RemoveNode(d2.Identity, h.sealer()))(h.admins[2:]...)
		mustInform(t, b, r3)
		r4 := signed(b.Builder().RemoveNode(d3.Identity, h.sealer()))(h.admins[2:]...)
		mustInform(t, b, r4)

		// A2 signs R1 too: no key is needed on it now, and it wins.
		r1x := withSignature(t, r1, h.admins[2])
		a := h.fork()
		mustInform(t, a, r1x, r2, r3, r4)
		if a.Head() != r1x.Hash() || a.Alarm() != nil || a.Rollback() != nil {
			t.Fatalf("A: head %v, want R1's copy, alarms %v, %v", a.Head(), a.Alarm(), a.Rollback())
		}

		informErr := b.Inform(r1x)
		state, err := b.TrustedState()
		if err == nil {
			t.Fatalf("B serves head %v at epoch %d with no alarm, A is at %v; the copy was answered with %v",
				state.Head(), state.Epoch(), a.Head(), informErr)
		}
		if informErr != nil {
			t.Fatalf("B refused the copy: %v", informErr)
		}
		var ra *RollbackAlarm
		if !errors.As(err, &ra) || ra.Branch != r2.Hash() {
			t.Fatalf("B: %v, want a rollback alarm naming R2's branch %v", err, r2.Hash())
		}
		if head := b.Head(); head != r1.Hash() && head != r1x.Hash() {
			t.Fatalf("B: head %v, want R1", head)
		}
		return
	}
	t.Skip("no draw gave R1 the lower SigHash")
}

// A schema upgrade this build cannot read, on a branch that took the chain
// below the epoch floor, neither clears the rollback alarm nor keeps it from
// being raised: such a quorum could otherwise hide its rollback behind it.
func TestAnUnreadableUpgradeHidesNoRollback(t *testing.T) {
	for _, together := range []bool{false, true} {
		h := newHarness(t, 1, 1)
		a := h.addNode("a")
		winner := h.fork()
		build := func(auth *Authority, f func(*Builder) (types.AUM, error)) types.AUM {
			t.Helper()
			aum, err := f(auth.Builder())
			if err != nil {
				t.Fatal(err)
			}
			h.signQuorum(&aum)
			if err := auth.Inform(aum); err != nil {
				t.Fatal(err)
			}
			return aum
		}
		removeA := build(winner, func(bl *Builder) (types.AUM, error) { return bl.RemoveNode(a.Identity, h.sealer()) })
		prev, v := winner.Head(), types.CurrentSchema+1
		upgrade := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &v}
		h.signQuorum(&upgrade)
		for range 3 {
			build(h.auth, func(bl *Builder) (types.AUM, error) { return bl.EpochBump(h.sealer()) })
		}
		floor := h.auth.State().Epoch()

		if together {
			if err := h.auth.Inform(removeA, upgrade); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := h.auth.Inform(removeA); err != nil {
				t.Fatal(err)
			}
			if h.auth.Rollback() == nil {
				t.Fatal("no rollback alarm before the upgrade")
			}
			if err := h.auth.Inform(upgrade); err != nil {
				t.Fatal(err)
			}
		}
		if state, err := h.auth.TrustedState(); err == nil {
			t.Fatalf("together %v: serves epoch %d below the floor %d", together, state.Epoch(), floor)
		}
		if h.auth.Rollback() == nil {
			t.Fatalf("together %v: no rollback alarm", together)
		}
	}
}
