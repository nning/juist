package log

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// The M1 exit criterion (docs/05-roadmap.md): forged signatures, replayed
// records, reordered chains, epoch rollback, sub-quorum changes, colliding
// addresses, conflicting concurrent records, fork injection and self-asserted
// route grants are all rejected. Nothing is stubbed — every record here is one
// a real quorum could have produced, but for the defect under test.

// --- forged and mis-signed records -----------------------------------------

func TestRejectsUnsignedRecord(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum, err := h.auth.Builder().AddNode(h.newNode("intruder"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.mustReject("unsigned AddNode", RuleMalformed, aum)
}

func TestRejectsSignatureByUnknownKey(t *testing.T) {
	h := newHarness(t, 1, 1)
	outsider, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	aum, err := h.auth.Builder().AddNode(h.newNode("intruder"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if err := h.sign(&aum, outsider); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("AddNode signed by a key the network never trusted", RuleUnauthorized, aum)
}

// TestRejectsExtraSignatureByUntrustedKey: appending a signature to an
// authorized record leaves the content and quorum intact but changes the hash,
// so accepting it would let anyone manufacture a fork.
func TestRejectsExtraSignatureByUntrustedKey(t *testing.T) {
	h := newHarness(t, 1, 1)
	outsider, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	aum, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.sign(&aum, outsider); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("authorized AddNode with an extra untrusted signature", RuleUnauthorized, aum)
}

func TestRejectsTamperedPayload(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.newNode("victim")
	aum, err := h.auth.Builder().AddNode(victim, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	// Swap in the attacker's own WireGuard key after the record was signed:
	// the classic "authorize one device, admit another" substitution.
	attacker := h.newNode("attacker")
	aum.Node.WireGuard = attacker.WireGuard
	h.mustReject("AddNode whose WireGuard key was swapped after signing", RuleUnauthorized, aum)
}

func TestRejectsTamperedSignatureBits(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	aum.Signatures[0].PQ[0] ^= 0x01
	h.mustReject("AddNode with a corrupted signature", RuleUnauthorized, aum)
}

// --- quorum ----------------------------------------------------------------

func TestRejectsSubQuorumChange(t *testing.T) {
	h := newHarness(t, 3, 2)
	// One compromised admin key out of three, against a quorum of two: the
	// sub-quorum admin compromise from docs/02-threat-model.md.
	aum, err := h.auth.Builder().AddNode(h.newNode("intruder"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if err := h.sign(&aum, h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("AddNode with one of two required votes", RuleUnauthorized, aum)

	// The same record becomes valid once a second admin signs it, which is
	// what makes the rejection above about quorum and not about something else.
	if err := h.sign(&aum, h.admins[1]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("quorum-signed AddNode rejected: %v", err)
	}
}

func TestRejectsDuplicateSignatureForVotes(t *testing.T) {
	h := newHarness(t, 3, 2)
	aum, err := h.auth.Builder().AddNode(h.newNode("intruder"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if err := h.sign(&aum, h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	// One admin, two copies of its signature: the cheapest way to fake a
	// quorum if vote counting deduplicated nothing.
	aum.Signatures = append(aum.Signatures, aum.Signatures[0])
	h.mustReject("AddNode carrying one admin's signature twice", RuleMalformed, aum)
}

func TestRejectsAdminRemovalBelowQuorum(t *testing.T) {
	h := newHarness(t, 2, 2)
	// Both admins agree to remove one of them, which would leave one vote
	// against a quorum of two: a network nobody could ever change again,
	// including to undo this.
	// The builder refuses, so the ceremony never happens; a quorum that skips
	// it is refused by the receiving node.
	subject := h.admins[0].Public()
	_, err := h.auth.Builder().RemoveAdminKey(subject)
	mustBreak(t, "building a RemoveAdminKey that strands the quorum", RuleState, err)
	h.mustReject("RemoveAdminKey that strands the quorum", RuleState,
		h.signed(types.AUM{Kind: types.KindRemoveAdminKey, Subject: &subject}))
}

// TestRemoveAdminKey is the happy path the rejection test above guards: the
// remaining admins sign one of their own out, and the removed key loses the
// ability to authorize anything — including restoring itself.
func TestRemoveAdminKey(t *testing.T) {
	h := newHarness(t, 3, 2)
	aum, err := h.auth.Builder().RemoveAdminKey(h.admins[2].Public())
	if err != nil {
		t.Fatalf("RemoveAdminKey: %v", err)
	}
	// The two remaining admins sign; the one being removed does not, and
	// cannot veto — quorum is reached without it.
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	st := h.auth.State()
	if _, ok := st.Admin(h.admins[2].Public()); ok {
		t.Fatal("the removed admin key is still in the admin set")
	}
	if _, ok := st.Admin(h.admins[0].Public()); !ok {
		t.Fatal("an admin that was not removed lost its key")
	}
	if st.TotalVotes() != 2 || st.Quorum() != 2 {
		t.Fatalf("after removal: %d votes against quorum %d, want 2 and 2",
			st.TotalVotes(), st.Quorum())
	}

	// The removed key's signature is now untrusted, not merely under-voted.
	next, err := h.auth.Builder().AddNode(h.newNode("intruder"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if err := h.sign(&next, h.admins[2]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	status := st.SignatureStatus(&next)
	if len(status.Untrusted) != 1 || status.Untrusted[0] != h.admins[2].Public() {
		t.Fatalf("removed key's signature reported %+v, want untrusted", status)
	}
	h.mustReject("AddNode signed by the removed admin key", RuleUnauthorized, next)

	// And the removed key cannot re-add itself: restoring it would need
	// quorum of the set that no longer contains it.
	restore, err := h.auth.Builder().AddAdminKey(types.AdminKey{
		Public: h.admins[2].Public(), Votes: 1, Signing: new(h.admins[2].SigningKey()), Endorsement: h.admins[2].Endorsement(),
	})
	if err != nil {
		t.Fatalf("AddAdminKey: %v", err)
	}
	if err := h.sign(&restore, h.admins[2]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("AddAdminKey re-adding the removed key, signed by that key", RuleUnauthorized, restore)
}

// TestOneAdminCanRemoveTheOtherAtQuorumOne: with two single-vote keys and a
// quorum of one, either admin signs the other out. The anti-stranding rule
// still holds; governance by a single key is the price of a quorum of one.
func TestOneAdminCanRemoveTheOtherAtQuorumOne(t *testing.T) {
	h := newHarness(t, 2, 1)
	aum, err := h.auth.Builder().RemoveAdminKey(h.admins[1].Public())
	if err != nil {
		t.Fatalf("RemoveAdminKey: %v", err)
	}
	if err := h.sign(&aum, h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	st := h.auth.State()
	if _, ok := st.Admin(h.admins[1].Public()); ok {
		t.Fatal("the removed admin key is still in the admin set")
	}
	if st.TotalVotes() != 1 || st.Quorum() != 1 {
		t.Fatalf("after removal: %d votes against quorum %d, want 1 and 1",
			st.TotalVotes(), st.Quorum())
	}
}

func TestQuorumPolicyCanBeTightened(t *testing.T) {
	h := newHarness(t, 3, 1)
	aum, err := h.auth.Builder().SetQuorum(3)
	if err != nil {
		t.Fatalf("SetQuorum: %v", err)
	}
	h.signQuorum(&aum) // one vote, which is the current quorum
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("SetQuorum rejected: %v", err)
	}
	if h.auth.State().Quorum() != 3 {
		t.Fatalf("quorum is %d, want 3", h.auth.State().Quorum())
	}
	// The tightened policy applies immediately: one vote is no longer enough.
	h.quorum = 1
	next, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&next)
	h.mustReject("AddNode under the old quorum after tightening", RuleUnauthorized, next)
}

func TestRejectsUnsatisfiableQuorum(t *testing.T) {
	h := newHarness(t, 2, 1)
	_, err := h.auth.Builder().SetQuorum(99)
	mustBreak(t, "building a SetQuorum above the total admin vote weight", RuleState, err)
	h.mustReject("SetQuorum above the total admin vote weight", RuleState,
		h.signed(types.AUM{Kind: types.KindSetQuorum, Quorum: new(uint32(99))}))
}

// --- replay, reorder, rollback ---------------------------------------------

// TestRejectsReplayedRecord is the on-path attacker replaying a record it
// captured earlier. Its parent is no longer the head, so it cannot be applied
// twice — the hash chain, not a nonce or a timestamp, is what stops it.
func TestRejectsReplayedRecord(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.newNode("alpha")
	aum, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	// Re-delivering the identical record is a no-op, not an error: it is the
	// same record, and gossip will deliver it repeatedly.
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("re-delivering a stored record should be a no-op: %v", err)
	}
	if len(h.auth.State().Nodes()) != 1 {
		t.Fatal("re-delivery admitted the member twice")
	}
	// Re-parent the captured record onto the current head to apply it twice.
	// The signature covers the parent hash, so this invalidates it.
	h.addNode("bravo")
	replay := *aum.Clone()
	head := h.auth.Head()
	replay.Prev = &head
	h.mustReject("captured AddNode re-parented onto the current head", RuleUnauthorized, replay)
}

// TestReauthorizedRecordAtTheSamePositionIsAFork: a quorum re-signing the same
// change at the same position is not a replay but two records competing for
// one slot, which surfaces as a conflict rather than being absorbed.
func TestReauthorizedRecordAtTheSamePositionIsAFork(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.newNode("alpha")
	first, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&first)
	second, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&second)
	if first.Hash() == second.Hash() {
		t.Fatal("the two records are identical; the epoch secret should differ")
	}
	if err := h.auth.Inform(first, second); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if len(h.auth.State().Nodes()) != 1 {
		t.Fatalf("expected one member, got %d", len(h.auth.State().Nodes()))
	}
	if h.auth.Alarm() == nil {
		t.Fatal("two records admitting the same member at the same position raised no alarm")
	}
}

func TestRejectsRecordWithUnknownParent(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	aum, err := h.auth.Builder().AddNode(h.newNode("bravo"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	// Point the record at a parent nobody has: an attacker splicing in a
	// history the victim cannot check.
	ghost := types.Hash{0xde, 0xad}
	aum.Prev = &ghost
	aum.Signatures = nil
	h.signQuorum(&aum)
	h.mustReject("AddNode chaining to an unknown parent", RuleParent, aum)
}

func TestRejectsOutOfOrderBatch(t *testing.T) {
	h := newHarness(t, 1, 1)
	first, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&first)
	second, err := NewBuilder(h.project(first)).AddNode(h.newNode("bravo"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&second)

	// Child before parent. The whole batch must be refused, not partially
	// applied: a store holding a record whose parent is missing is a store
	// that will never look at that record again.
	h.mustReject("batch delivered child-first", RuleParent, second)
	if err := h.auth.Inform(second, first); err != nil {
		t.Fatalf("reversed batch rejected: %v", err)
	}
	if len(h.auth.State().Nodes()) != 2 {
		t.Fatalf("both records should have applied, got %d members", len(h.auth.State().Nodes()))
	}
}

// A chain resolving to an epoch this node has passed takes admin signatures to
// build, so it may be a compromised quorum rewriting history: the node does not
// follow it, and says so, also after a restart.
func TestAnEpochRollbackIsNotFollowed(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.newNode("victim")

	// The rogue must win the hash tiebreak against `add`. Draw the pair each
	// attempt, never one side: holding one fixed makes the per-attempt chance
	// target.Hash()/2^256, which fails 1/66 of the time over 65 attempts
	// rather than 2^-65.
	var add, rogue types.AUM
	for attempt := 0; ; attempt++ {
		if attempt > 64 {
			t.Fatal("could not draw a pair that puts the rogue record ahead on fork choice")
		}
		var err error
		add, err = h.auth.Builder().AddNode(victim, h.sealer())
		if err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		h.signQuorum(&add)
		// A record forking from genesis: same network, same admin key, one
		// record deep, so any chain through it resolves to epoch 2.
		rogue, err = NewBuilder(h.genesisState()).AddNode(h.newNode("attacker"), h.sealer())
		if err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		h.signQuorum(&rogue)
		if rogue.SigHash().Compare(add.SigHash()) < 0 {
			break
		}
	}

	if err := h.auth.Inform(add); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	h.removeNode(victim.Identity)
	if h.auth.State().Epoch() != 3 {
		t.Fatalf("epoch is %d, want 3", h.auth.State().Epoch())
	}
	floor, err := h.storage.EpochFloor()
	if err != nil {
		t.Fatalf("EpochFloor: %v", err)
	}
	if floor != 3 {
		t.Fatalf("epoch floor is %d, want 3", floor)
	}

	if err := h.auth.Inform(rogue); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	for _, auth := range []*Authority{h.auth, h.fork()} {
		_, err := auth.TrustedState()
		var rb *RollbackAlarm
		if !asRollback(err, &rb) {
			t.Fatalf("trusted state under a rollback: %v, want a rollback alarm", err)
		}
		if rb.Floor != floor || rb.Epoch != 2 {
			t.Fatalf("rollback alarm reports floor %d epoch %d, want 3 and 2", rb.Floor, rb.Epoch)
		}
		if got, _ := h.storage.EpochFloor(); got != floor {
			t.Fatalf("epoch floor moved to %d", got)
		}
		if _, err := auth.Compact(); err == nil {
			t.Fatal("compacted under a rollback alarm")
		}
	}
}

func TestRejectsNonSequentialEpoch(t *testing.T) {
	h := newHarness(t, 1, 1)
	// An epoch that skips ahead would let a quorum jump the counter past a
	// floor another node is holding, or toward exhaustion.
	skipper := func(_ uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(99, members)
		return rec, err
	}
	if _, err := h.auth.Builder().AddNode(h.newNode("alpha"), skipper); err == nil {
		t.Fatal("built an AddNode whose epoch skips ahead")
	}

	// Also reject it when assembled by hand, past the builder.
	n := h.newNode("bravo")
	aum, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	aum.Epoch.Epoch = 99
	aum.Signatures = nil
	h.signQuorum(&aum)
	h.mustReject("AddNode claiming a non-sequential epoch", RuleState, aum)
}

// --- epoch coverage --------------------------------------------------------

// TestRejectsEpochExcludingAMember is the quiet lockout: a bump omitting one
// member's wrap costs it discovery, with nothing in the log saying so.
func TestRejectsEpochExcludingAMember(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	newcomer := h.newNode("newcomer")

	excluding := func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		kept := make([]types.NodeRecord, 0, len(members))
		for _, m := range members {
			if m.Identity != victim.Identity {
				kept = append(kept, m)
			}
		}
		_, rec, err := secrets.NewEpoch(epoch, kept)
		return rec, err
	}
	if _, err := h.auth.Builder().AddNode(newcomer, excluding); err == nil {
		t.Fatal("built an AddNode whose epoch bump excludes an existing member")
	}
}

// TestRejectsEpochIncludingANonMember is the reverse: handing the group secret
// to a device that is not in the member set.
func TestRejectsEpochIncludingANonMember(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	outsider := h.newNode("outsider")

	including := func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, append(members, outsider))
		return rec, err
	}
	if _, err := h.auth.Builder().EpochBump(including); err == nil {
		t.Fatal("built an epoch bump that seals the secret to a non-member")
	}
}

func TestRejectsMembershipChangeWithoutEpochBump(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.newNode("alpha")
	aum, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	aum.Epoch = nil
	aum.Signatures = nil
	h.signQuorum(&aum)
	h.mustReject("AddNode with the epoch bump stripped", RuleMalformed, aum)
}

// --- collisions ------------------------------------------------------------

func TestRejectsDuplicateMember(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("alpha")
	if _, err := h.auth.Builder().AddNode(n, h.sealer()); err == nil {
		t.Fatal("admitted the same identity twice")
	}
}

func TestRejectsCollidingV4Address(t *testing.T) {
	h := newHarness(t, 1, 1)
	addr := netip.MustParseAddr("198.18.0.5")
	first := h.newNode("alpha")
	first.V4 = &addr
	aum, err := h.auth.Builder().AddNode(first, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}

	second := h.newNode("bravo")
	second.V4 = &addr
	if _, err := h.auth.Builder().AddNode(second, h.sealer()); err == nil {
		t.Fatal("admitted two members claiming the same overlay v4 address")
	}
}

// TestRejectsCollidingDerivedAddress forces the collision the validator exists
// to reject. A hash collision cannot be found in a test, so the check is
// exercised through the snapshot validator, as a hostile checkpoint would.
func TestRejectsCollidingDerivedAddress(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	snap := h.auth.State().Snapshot()

	// Two node records with the same identity key derive the same address by
	// construction; the snapshot validator must reject the pair.
	dup := snap.Nodes[0]
	dup.Name = "clone"
	snap.Nodes = append(snap.Nodes, dup)
	if err := snap.ValidateInNetwork(); err == nil {
		t.Fatal("snapshot validator accepted two members with the same derived address")
	}
	if err := snap.StaticValidate(false); err == nil {
		t.Fatal("snapshot validator accepted an unsorted, duplicated member list")
	}
}

// TestRejectsCollisionsFromAQuorumSignedRecord exercises the collision rules
// on the attacker's path rather than the builder's: a quorum that skips the
// tool produces a fully authorized record, and only the receiving node's own
// validation stands between it and the member set.
func TestRejectsCollisionsFromAQuorumSignedRecord(t *testing.T) {
	addr := netip.MustParseAddr("198.18.0.5")
	first := func(h *harness) types.NodeRecord {
		n := h.newNode("alpha")
		n.V4 = &addr
		aum := h.handAssembledAddNode(n)
		if err := h.auth.Inform(aum); err != nil {
			h.t.Fatalf("admitting the first member: %v", err)
		}
		return n
	}

	for _, tc := range []struct {
		what    string
		collide func(seen types.NodeRecord, n *types.NodeRecord)
	}{
		{"a second member claiming the same overlay v4 address",
			func(seen types.NodeRecord, n *types.NodeRecord) { n.V4 = seen.V4 }},
		{"a second member presenting the first's WireGuard key",
			func(seen types.NodeRecord, n *types.NodeRecord) { n.WireGuard = seen.WireGuard }},
		{"a second member presenting the first's X25519 key",
			func(seen types.NodeRecord, n *types.NodeRecord) { n.X25519 = seen.X25519 }},
		{"a second member presenting the first's ML-KEM key",
			func(seen types.NodeRecord, n *types.NodeRecord) { n.MLKEM = seen.MLKEM }},
	} {
		t.Run(tc.what, func(t *testing.T) {
			h := newHarness(t, 1, 1)
			seen := first(h)
			clone := h.newNode("clone")
			tc.collide(seen, &clone)
			h.mustReject(tc.what, RuleState, h.handAssembledAddNode(clone))
		})
	}
}

func TestRejectsSharedWireGuardKey(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.addNode("alpha")
	// A second device presenting the first device's WireGuard key: two members
	// keyed identically in the data plane, where one would silently displace
	// the other. Also what a copied device state looks like.
	clone := h.newNode("clone")
	clone.WireGuard = a.WireGuard
	if _, err := h.auth.Builder().AddNode(clone, h.sealer()); err == nil {
		t.Fatal("admitted two members sharing a WireGuard key")
	}
	clone = h.newNode("clone2")
	clone.X25519 = a.X25519
	if _, err := h.auth.Builder().AddNode(clone, h.sealer()); err == nil {
		t.Fatal("admitted two members sharing an X25519 key")
	}
	clone = h.newNode("clone3")
	clone.MLKEM = a.MLKEM
	if _, err := h.auth.Builder().AddNode(clone, h.sealer()); err == nil {
		t.Fatal("admitted two members sharing an ML-KEM key")
	}
}

// TestRejectsSharedKeysInAWholeState covers the two paths that seat a member
// set without authoring a record that admits anyone: a genesis naming founding
// members, and a checkpoint adopted as a bootstrap anchor. Both take a member
// set on a quorum's word, so both have to apply the key rules the incremental
// path applies.
func TestRejectsSharedKeysInAWholeState(t *testing.T) {
	collisions := []struct {
		what    string
		collide func(seen types.NodeRecord, n *types.NodeRecord)
	}{
		{"a WireGuard key", func(seen types.NodeRecord, n *types.NodeRecord) { n.WireGuard = seen.WireGuard }},
		{"an X25519 key", func(seen types.NodeRecord, n *types.NodeRecord) { n.X25519 = seen.X25519 }},
		{"an ML-KEM key", func(seen types.NodeRecord, n *types.NodeRecord) { n.MLKEM = seen.MLKEM }},
	}

	for _, tc := range collisions {
		t.Run("a genesis whose founders share "+tc.what, func(t *testing.T) {
			h := newHarness(t, 1, 1)
			first := h.newNode("alpha")
			clone := h.newNode("clone")
			tc.collide(first, &clone)

			genesis, err := Genesis("test-net", 1, h.adminKeys(), h.commitments(),
				[]types.NodeRecord{first, clone}, h.sealer())
			if err != nil {
				t.Fatalf("building the hostile genesis: %v", err)
			}
			h.signQuorum(&genesis)
			if _, err := Create(NewMemStorage(), genesis); err == nil {
				t.Fatalf("created a network whose founding members share %s", tc.what)
			}
		})

		t.Run("a bootstrap checkpoint whose members share "+tc.what, func(t *testing.T) {
			h := newHarness(t, 1, 1)
			first := h.addNode("alpha")
			clone := h.newNode("clone")
			tc.collide(first, &clone)

			cp := h.handAssembledCheckpoint(append(h.auth.State().Nodes(), clone))
			if _, err := Bootstrap(NewMemStorage(), cp); err == nil {
				t.Fatalf("bootstrapped from a checkpoint whose members share %s", tc.what)
			}
		})
	}
}

// --- route grants ----------------------------------------------------------

// TestRejectsSelfAssertedRoute: no record kind lets a node grant itself
// anything. Routes arrive only in AddNode or SetNodeRoutes, both by quorum.
func TestRejectsSelfAssertedRoute(t *testing.T) {
	h := newHarness(t, 2, 2)
	n := h.addNode("router")
	aum, err := h.auth.Builder().SetNodeRoutes(n.Identity,
		[]types.Role{types.RoleExit}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatalf("SetNodeRoutes: %v", err)
	}
	// The node signs for itself, with its own identity key.
	if err := h.sign(&aum, h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("SetNodeRoutes signed only by the node it grants", RuleUnauthorized, aum)

	// One admin short of quorum is equally not enough.
	aum.Signatures = nil
	if err := h.sign(&aum, h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("SetNodeRoutes with one of two required votes", RuleUnauthorized, aum)

	// With quorum it applies, which is what makes the rejections above about
	// authority rather than about the grant's contents.
	aum.Signatures = nil
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("quorum-signed SetNodeRoutes rejected: %v", err)
	}
	got, _ := h.auth.State().Node(n.Identity)
	if !got.HasRole(types.RoleExit) || len(got.Routes) != 1 {
		t.Fatalf("grant did not apply: roles=%v routes=%v", got.Roles, got.Routes)
	}
}

func TestRejectsOverlayOverlappingRoutes(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("router")
	ula := h.auth.State().ULA()

	// Every one of these would let the grant holder intercept traffic meant
	// for other members, which is the one thing an exit node must never be
	// able to do (docs/02-threat-model.md, the route-grant adversary).
	for _, tc := range []struct {
		name  string
		route netip.Prefix
	}{
		{"the overlay prefix itself", ula},
		{"a subnet of the overlay prefix", netip.PrefixFrom(ula.Addr(), 64)},
		{"a supernet of the overlay prefix", netip.MustParsePrefix("fd00::/8")},
		{"the overlay v4 range", types.CGNAT},
		{"a subnet of the overlay v4 range", netip.MustParsePrefix("100.64.1.0/24")},
		{"a supernet of the overlay v4 range", netip.MustParsePrefix("100.0.0.0/8")},
		{"loopback", netip.MustParsePrefix("127.0.0.0/8")},
		{"link-local v4", netip.MustParsePrefix("169.254.0.0/16")},
		{"link-local v6", netip.MustParsePrefix("fe80::/10")},
		{"v4 multicast", netip.MustParsePrefix("224.0.0.0/4")},
		{"v6 multicast", netip.MustParsePrefix("ff00::/8")},
		{"reserved v4 and broadcast", netip.MustParsePrefix("255.255.255.255/32")},
		{"tailscaled's IPv6 overlay", netip.MustParsePrefix("fd7a:115c:a1e0:ab12::/64")},
		{"juist's IPv4 overlay range", netip.MustParsePrefix("198.18.200.0/24")},
		{"unique-local /48s", netip.MustParsePrefix("fd12::/16")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.auth.Builder().SetNodeRoutes(n.Identity,
				[]types.Role{types.RoleExit}, []netip.Prefix{tc.route}); err == nil {
				t.Fatalf("accepted a route grant covering %s (%v)", tc.name, tc.route)
			}
		})
	}
}

// Two members never route one address: the one granted a prefix first keeps
// it, and a grant overlapping it, either way, is refused, as is one member's
// grant overlapping itself. Exit nodes' default routes are no subnet routes.
func TestTwoMembersNeverRouteOneAddress(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.addNode("a"), h.addNode("b")
	p := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, x := range s {
			out = append(out, netip.MustParsePrefix(x))
		}
		return out
	}
	grant := func(n types.NodeRecord, roles []types.Role, routes []netip.Prefix) {
		t.Helper()
		aum, err := h.auth.Builder().SetNodeRoutes(n.Identity, roles, routes)
		if err != nil {
			t.Fatalf("granting %v: %v", routes, err)
		}
		h.signQuorum(&aum)
		if err := h.auth.Inform(aum); err != nil {
			t.Fatalf("granting %v: %v", routes, err)
		}
	}
	grant(a, nil, p("192.168.1.0/24"))
	for _, routes := range [][]netip.Prefix{p("192.168.1.0/24"), p("192.168.0.0/16"), p("192.168.1.128/25")} {
		_, err := h.auth.Builder().SetNodeRoutes(b.Identity, nil, routes)
		mustBreak(t, fmt.Sprintf("building a grant of %v, which a routes", routes), RuleState, err)
		h.mustReject(fmt.Sprintf("a grant of %v, which a routes", routes), RuleState,
			h.signed(types.AUM{Kind: types.KindSetNodeRoutes, Subject: &b.Identity,
				Grant: &types.RouteGrant{Routes: routes}}))
	}
	if _, err := h.auth.Builder().SetNodeRoutes(a.Identity, nil, p("10.0.0.0/8", "10.1.0.0/16")); err == nil {
		t.Error("accepted a grant overlapping itself")
	}
	grant(b, nil, p("192.168.2.0/24"))
	exits := []types.Role{types.RoleExit}
	grant(a, exits, p("0.0.0.0/0", "192.168.1.0/24"))
	grant(b, exits, p("0.0.0.0/0", "::/0", "192.168.2.0/24"))
}

func TestDefaultRouteRequiresExitNodeRole(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("router")
	for _, def := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	} {
		if _, err := h.auth.Builder().SetNodeRoutes(n.Identity, nil, []netip.Prefix{def}); err == nil {
			t.Fatalf("accepted %v without the exit role", def)
		}
		if _, err := h.auth.Builder().SetNodeRoutes(n.Identity,
			[]types.Role{types.RoleExit}, []netip.Prefix{def}); err != nil {
			t.Fatalf("rejected %v with the exit role: %v", def, err)
		}
	}
	// Withdrawing the role must withdraw the default route with it, rather
	// than leaving a grant nothing authorizes.
	aum, err := h.auth.Builder().SetNodeRoutes(n.Identity,
		[]types.Role{types.RoleExit}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatalf("SetNodeRoutes: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	defaultRoute := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	_, err = h.auth.Builder().SetNodeRoutes(n.Identity, nil, defaultRoute)
	mustBreak(t, "building a grant keeping a default route without the exit role", RuleState, err)
	h.mustReject("keeping a default route while dropping the exit role", RuleState,
		h.signed(types.AUM{Kind: types.KindSetNodeRoutes, Subject: &n.Identity,
			Grant: &types.RouteGrant{Routes: defaultRoute}}))
}

func TestRejectsUnmaskedRoute(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("router")
	// 10.1.2.3/8 and 10.0.0.0/8 are the same prefix written two ways. One
	// spelling per value, or a record has two encodings.
	unmasked := netip.PrefixFrom(netip.MustParseAddr("10.1.2.3"), 8)
	if _, err := h.auth.Builder().SetNodeRoutes(n.Identity, nil, []netip.Prefix{unmasked}); err == nil {
		t.Fatal("accepted a route with host bits set")
	}
}

// --- forks -----------------------------------------------------------------

// TestConcurrentNonConflictingRecordsResolveDeterministically is the benign
// fork: two admins each admit a different device against the same head. One
// record wins by hash, the other has to be reissued, and no alarm is raised.
func TestConcurrentNonConflictingRecordsResolveDeterministically(t *testing.T) {
	h := newHarness(t, 1, 1)
	b := h.auth.Builder()
	left, err := b.AddNode(h.newNode("left"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&left)
	right, err := b.AddNode(h.newNode("right"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&right)

	// Deliver in both orders to two nodes; both must land on the same head.
	one := h.fork()
	if err := one.Inform(left, right); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	two := h.fork()
	if err := two.Inform(right, left); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if one.Head() != two.Head() {
		t.Fatal("two nodes with the same records chose different heads")
	}
	if want := minBySigHash(left, right); one.Head() != want.Hash() {
		t.Fatal("fork choice did not prefer the lower signed content")
	}
	if one.Alarm() != nil {
		t.Fatalf("benign concurrent AddNodes raised an alarm: %v", one.Alarm())
	}
	if len(one.Orphans()) != 1 || one.Orphans()[0].Conflict != "" {
		t.Fatalf("expected one benign orphan, got %+v", one.Orphans())
	}
	if len(one.State().Nodes()) != 1 {
		t.Fatalf("expected one member on the chosen chain, got %d", len(one.State().Nodes()))
	}
}

// TestRevocationWinsForkChoice is the safety bias: where a removal and an
// unrelated change race, the removal is the one that lands, so a revocation is
// never the branch that gets orphaned.
func TestRevocationWinsForkChoice(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	b := h.auth.Builder()
	removal, err := b.RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	h.signQuorum(&removal)
	addition, err := b.AddNode(h.newNode("newcomer"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&addition)

	// Both delivery orders, on independent copies of the same chain. The
	// removal must land in both, whichever hash happens to be lower.
	for i, order := range [][]types.AUM{{removal, addition}, {addition, removal}} {
		auth := h.fork()
		if err := auth.Inform(order...); err != nil {
			t.Fatalf("order %d: Inform: %v", i, err)
		}
		if auth.State().IsMember(victim.Identity) {
			t.Fatalf("order %d: fork choice kept a member the revocation removed", i)
		}
		if auth.Head() != removal.Hash() {
			t.Fatalf("order %d: head is not the revocation", i)
		}
		// The orphaned addition is benign: reissuing it against the new head
		// would work, so no alarm.
		if auth.Alarm() != nil {
			t.Fatalf("order %d: orphaning an unrelated AddNode raised an alarm: %v", i, auth.Alarm())
		}
	}
}

// TestConflictingConcurrentRecordsAlarm is the true fork: two branches that
// disagree about the same member. No deterministic rule should silently pick
// one, so the authority alarms and refuses to hand out membership.
func TestConflictingConcurrentRecordsAlarm(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	b := h.auth.Builder()

	// Branch one removes the victim.
	removal, err := b.RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	h.signQuorum(&removal)
	// Branch two rotates the victim's keys — which cannot be reissued on a
	// chain where the victim is gone.
	rotate, err := b.RotateNodeKey(victim.Identity, types.NodeKeys{
		WireGuard: types.WGKey{9}, X25519: victim.X25519, MLKEM: victim.MLKEM,
	}, h.sealer())
	if err != nil {
		t.Fatalf("RotateNodeKey: %v", err)
	}
	h.signQuorum(&rotate)
	if err := h.sign(&rotate, h.nodeIDs[victim.Identity]); err != nil {
		t.Fatalf("node self-signature: %v", err)
	}

	if err := h.auth.Inform(removal, rotate); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	// The removal wins fork choice, so the rotation is orphaned and cannot be
	// reissued: a genuine conflict.
	if h.auth.State().IsMember(victim.Identity) {
		t.Fatal("the revocation did not win fork choice")
	}
	alarm := h.auth.Alarm()
	if alarm == nil {
		t.Fatal("a branch that cannot be reissued raised no alarm")
	}
	if _, err := h.auth.TrustedState(); err == nil {
		t.Fatal("TrustedState served membership while an alarm was raised")
	}
	t.Logf("alarm: %v", alarm)
}

// TestAnOrphanedRevocationIsNamed is the dangerous fork: a removal buried on a
// branch that loses. Fork choice's bias only looks at immediate siblings, so a
// revocation deeper on a losing branch would otherwise disappear silently. It
// is named as not in effect, for reissuing, rather than stopping the network:
// it could be reissued on the chosen chain.
func TestAnOrphanedRevocationIsNamed(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	b := h.auth.Builder()

	// Sibling AddNode records at equal depth, so fork choice separates them on
	// the hash tiebreak; branch A must win, leaving the revocation orphaned.
	// Draw both and assign the roles from the comparison rather than redrawing
	// against a fixed target, which is not uniform.
	first, err := b.AddNode(h.newNode("fork-one"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&first)
	second, err := b.AddNode(h.newNode("fork-two"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&second)
	a1, b1 := first, second
	if b1.SigHash().Compare(a1.SigHash()) < 0 {
		a1, b1 = b1, a1
	}

	// Branch B, the loser: the victim's removal one record deeper than the
	// fork point — deep enough that fork choice's revocation bias, which only
	// ever compares immediate siblings, cannot see it.
	b2, err := NewBuilder(h.project(b1)).RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	h.signQuorum(&b2)

	// Branch A, the winner: an unrelated addition at the same depth.
	a2, err := NewBuilder(h.project(a1)).AddNode(h.newNode("a2"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&a2)

	if err := h.auth.Inform(a1, a2, b1, b2); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if h.auth.Head() != a2.Hash() {
		t.Fatal("fork choice did not take branch A, so the test is not testing what it claims")
	}
	if !h.auth.State().IsMember(victim.Identity) {
		t.Fatal("the orphaned removal was applied after all")
	}
	if alarm := h.auth.Alarm(); alarm != nil {
		t.Fatalf("a revocation that can be reissued stopped the network: %v", alarm)
	}
	var unrevoked []types.Hash
	for _, o := range h.auth.Orphans() {
		unrevoked = append(unrevoked, o.Unrevoked...)
	}
	if !slices.Equal(unrevoked, []types.Hash{b2.Hash()}) {
		t.Fatalf("the orphaned removal is not named as not in effect: %v", unrevoked)
	}

	// Compaction would drop the branch, and with it the notice, until the
	// removal is redone.
	h.checkpoint()
	if _, err := h.auth.Compact(); err == nil {
		t.Fatal("compaction dropped a revocation still to be redone")
	}
	h.removeNode(victim.Identity)
	h.checkpoint()
	if _, err := h.auth.Compact(); err != nil {
		t.Fatalf("compacting once the removal is redone: %v", err)
	}
}

// TestConcurrentAdmissionsOfOneAddressNeedOnlyReissuing: two admins admit
// two devices at once, and both allocate the same free IPv4 address. The
// address is where a record sits, not what it says — reissued against the
// chosen chain, the losing admission is given another — so the loser is a
// change to start again, not a fork alarm that stops every tunnel.
func TestConcurrentAdmissionsOfOneAddressNeedOnlyReissuing(t *testing.T) {
	h := newHarness(t, 1, 1)
	b := h.auth.Builder()
	addr := h.auth.State().V4Range().Addr().Next().Next()
	one, two := h.newNode("one"), h.newNode("two")
	one.V4, two.V4 = &addr, &addr
	first, err := b.AddNode(one, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&first)
	second, err := b.AddNode(two, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&second)

	for i, order := range [][]types.AUM{{first, second}, {second, first}} {
		auth := h.fork()
		if err := auth.Inform(order...); err != nil {
			t.Fatalf("order %d: Inform: %v", i, err)
		}
		if alarm := auth.Alarm(); alarm != nil {
			t.Fatalf("order %d: two admissions of one address stopped the network: %v", i, alarm)
		}
		var lost int
		for _, o := range auth.Orphans() {
			if o.Conflict == "" {
				lost += len(o.Records) - len(o.Unrevoked)
			}
		}
		if lost != 1 {
			t.Fatalf("order %d: %d changes to reissue, want the losing admission", i, lost)
		}
	}
}

// --- checkpoints -----------------------------------------------------------

func TestCheckpointMustMatchDerivedState(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		t.Fatalf("honest checkpoint rejected: %v", err)
	}

	// A checkpoint that asserts a membership the chain never produced is how a
	// quorum would rewrite history without leaving the changes in the log.
	forged, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	intruder := h.newNode("intruder")
	forged.State.Nodes = append(forged.State.Nodes, intruder)
	forged.State.EpochWraps = append(forged.State.EpochWraps, types.EpochWrap{
		Recipient: intruder.Identity,
		Sealed:    make([]byte, types.SealedSecretSize),
	})
	sortSnapshot(forged.State)
	forged.Signatures = nil
	h.signQuorum(&forged)
	h.mustReject("checkpoint asserting a member the chain never admitted", RuleState, forged)
}

func TestCheckpointFromAnotherNetworkRejected(t *testing.T) {
	h := newHarness(t, 1, 1)
	other := newHarness(t, 1, 1)
	other.addNode("theirs")
	cp, err := other.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	other.signQuorum(&cp)
	// Re-parent it onto our chain. Its signatures are by the other network's
	// admin key, which ours does not trust; even if it did, the genesis hash
	// it names is not ours.
	head := h.auth.Head()
	cp.Prev = &head
	cp.Signatures = nil
	h.signQuorum(&cp)
	h.mustReject("checkpoint belonging to another network", RuleState, cp)
}

func TestBootstrapFromCheckpointAndCompact(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("alpha")
	h.addNode("bravo")
	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	want := h.auth.State().Snapshot().Encode()

	// A joining node given only the checkpoint reaches the same state.
	joined, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if string(joined.State().Snapshot().Encode()) != string(want) {
		t.Fatal("bootstrapping from a checkpoint produced different state")
	}

	// A checkpoint alone moves no anchor: it stays one behind the newest.
	if _, err := h.auth.Compact(); err != nil || h.auth.Anchor() == cp.Hash() {
		t.Fatalf("compacted to the newest checkpoint: %v", err)
	}
	next := h.checkpoint()

	// Then compaction advances the anchor to the checkpoint without changing
	// the state, and keeps the chain leading up to it from the anchor before.
	removed, err := h.auth.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if removed != 0 {
		t.Fatalf("compaction removed %d records of the chain up to the checkpoint", removed)
	}
	if h.auth.Anchor() != cp.Hash() {
		t.Fatal("compaction did not advance the anchor to the checkpoint")
	}
	if !bytes.Equal(h.auth.State().Snapshot().Encode(), next.State.Encode()) {
		t.Fatal("compaction changed the state")
	}
	if held := h.auth.Held(); len(held) != 2 || !slices.Contains(held, next.Hash()) {
		t.Fatalf("the log serves %d records past its anchor, want the two checkpoints", len(held))
	}

	// The next compaction drops it.
	h.addNode("charlie")
	cp2, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp2)
	if err := h.auth.Inform(cp2); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if _, err := h.auth.Compact(); err != nil || h.auth.Anchor() != next.Hash() {
		t.Fatalf("the second compaction: %v", err)
	}
	h.checkpoint()
	want = h.auth.State().Snapshot().Encode()
	if removed, err := h.auth.Compact(); err != nil || removed == 0 {
		t.Fatalf("the third compaction removed %d records: %v", removed, err)
	}
	if _, err := h.storage.AUM(h.auth.State().GenesisHash()); !errors.Is(err, ErrNotFound) {
		t.Fatal("the genesis outlived a second compaction")
	}
	if _, err := h.storage.AUM(next.Hash()); err != nil {
		t.Fatalf("the anchor before went with it: %v", err)
	}
	reopened, err := Open(h.storage)
	if err != nil {
		t.Fatalf("Open after compaction: %v", err)
	}
	if string(reopened.State().Snapshot().Encode()) != string(want) {
		t.Fatal("reopening a compacted store produced different state")
	}
	// And the dropped history can no longer be used to walk this node back.
	if _, err := reopened.Chain(); err != nil {
		t.Fatalf("Chain after compaction: %v", err)
	}
}

// TestCompactedAnchorRejectsPreCheckpointFork is the "never drop a checkpoint
// you hold" rule: once the anchor has advanced past the chain a compaction
// keeps, a branch that forks before it is not merely outvoted, it is not
// considered at all. Within the kept chain it is taken as by a device that
// never compacted (TestACompactedDeviceTakesARevocationBesideItsCheckpoint).
func TestCompactedAnchorRejectsPreCheckpointFork(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	preFork := h.auth.State()
	for range 2 {
		h.addNode("filler")
		h.checkpoint()
		if _, err := h.auth.Compact(); err != nil {
			t.Fatalf("Compact: %v", err)
		}
	}

	// A record forking from before both checkpoints, removing a device on a
	// history this node has compacted away.
	fork, err := NewBuilder(preFork).RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	h.signQuorum(&fork)
	h.mustReject("a fork rooted before the adopted checkpoint", RuleParent, fork)
	if !h.auth.State().IsMember(victim.Identity) {
		t.Fatal("the pre-checkpoint fork changed membership")
	}
}

// --- rotation --------------------------------------------------------------

func TestRotateNodeKeyRequiresNodeSignature(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("alpha")
	keys := types.NodeKeys{WireGuard: types.WGKey{7}, X25519: n.X25519, MLKEM: n.MLKEM}
	aum, err := h.auth.Builder().RotateNodeKey(n.Identity, keys, h.sealer())
	if err != nil {
		t.Fatalf("RotateNodeKey: %v", err)
	}
	h.signQuorum(&aum)
	h.mustReject("RotateNodeKey with quorum but no node signature", RuleUnauthorized, aum)

	if err := h.sign(&aum, h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	got, _ := h.auth.State().Node(n.Identity)
	if got.WireGuard != keys.WireGuard {
		t.Fatal("rotation did not replace the WireGuard key")
	}
}

func TestRotateIdentityRequiresNewKeySignature(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("alpha")
	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	aum, err := h.auth.Builder().RotateIdentity(n.Identity, fresh.Public(), fresh.SigningKey(), h.sealer())
	if err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	h.signQuorum(&aum)
	h.mustReject("RotateIdentity with no proof the new key is held", RuleUnauthorized, aum)

	// Signing with the *old* key is not a substitute: the point is that some
	// device holds the new one.
	aum.Signatures = nil
	h.signQuorum(&aum)
	if err := h.sign(&aum, h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("RotateIdentity signed by the old key", RuleUnauthorized, aum)

	// Nor is the new key alone: the device whose slot it is
	// has to agree, or admins alone could move an admin device's membership
	// and role to a key of their choosing.
	aum.Signatures = nil
	h.signQuorum(&aum)
	if err := h.sign(&aum, fresh); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("RotateIdentity without the old key's signature", RuleUnauthorized, aum)

	if err := h.sign(&aum, h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	st := h.auth.State()
	if st.IsMember(n.Identity) || !st.IsMember(fresh.Public()) {
		t.Fatal("identity rotation did not move the membership")
	}
	if st.Addr6(fresh.Public()) == st.Addr6(n.Identity) {
		t.Fatal("the rotated identity kept the old overlay address")
	}
}

// TestARotationOntoAnAdminCastsNoVote: a member's rotation onto an admin's
// identity, naming a key of the member's own and that admin's signature
// forged with it, is refused when its signatures are checked, not only when
// it is applied, and casts no vote for the CLI either.
func TestARotationOntoAnAdminCastsNoVote(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("alpha")
	forger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	aum, err := h.auth.Builder().RotateIdentity(n.Identity, forger.Public(), forger.SigningKey(), h.sealer())
	if err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	admin := h.admins[0].Public()
	aum.NewIdentity = &admin
	if err := h.sign(&aum, h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := h.sign(&aum, forger); err != nil {
		t.Fatalf("signing: %v", err)
	}
	for i := range aum.Signatures {
		if aum.Signatures[i].KeyID == forger.Public() {
			aum.Signatures[i].KeyID = admin
		}
	}
	slices.SortFunc(aum.Signatures, func(x, y types.Signature) int { return x.KeyID.Compare(y.KeyID) })

	st := h.auth.State()
	if sst := st.SignatureStatus(&aum); sst.Votes > 0 || sst.Authorized() {
		t.Fatalf("the forged signature cast %d votes", sst.Votes)
	}
	if aum.VerifySignature(admin, st.SigningKey(admin)) {
		t.Fatal("the forged signature verifies as the admin's")
	}
	mustBreak(t, "a rotation onto an admin, checked", RuleUnauthorized, verifyAgainst(&aum, st))
	h.mustReject("a rotation onto an admin with its signature forged", RuleUnauthorized, aum)
}

// --- break-glass -----------------------------------------------------------

func TestDisablementCommitments(t *testing.T) {
	h := newHarness(t, 1, 1)
	st := h.auth.State()
	if len(st.Disablement()) != 3 {
		t.Fatalf("%d disablement commitments, want 3", len(st.Disablement()))
	}
	for i, secret := range h.disablement {
		if !st.ValidDisablement(secret) {
			t.Fatalf("break-glass secret %d not recognized", i)
		}
	}
	wrong := make([]byte, types.DisablementSecretSize)
	if st.ValidDisablement(wrong) {
		t.Fatal("an unrelated value was accepted as a break-glass secret")
	}
	if st.ValidDisablement(nil) || st.ValidDisablement(h.disablement[0][:8]) {
		t.Fatal("a wrong-length value was accepted as a break-glass secret")
	}
}

// --- helpers ---------------------------------------------------------------

func asRollback(err error, target **RollbackAlarm) bool {
	for err != nil {
		if rb, ok := err.(*RollbackAlarm); ok {
			*target = rb
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// minBySigHash returns the sibling fork choice prefers, all else equal.
func minBySigHash(a, b types.AUM) types.AUM {
	if b.SigHash().Compare(a.SigHash()) < 0 {
		return b
	}
	return a
}

func sortSnapshot(s *types.Snapshot) {
	sortByIdentity(s.Nodes, func(n types.NodeRecord) types.Identity { return n.Identity })
	sortByIdentity(s.EpochWraps, func(w types.EpochWrap) types.Identity { return w.Recipient })
}

func sortByIdentity[T any](items []T, key func(T) types.Identity) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && key(items[j]).Compare(key(items[j-1])) < 0; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// Withdrawing vouching authority is a revocation: taking an admin device's
// role away, or raising the threshold, lands whichever hash is lower, so a
// concurrent change cannot orphan it and keep a distrusted admin device
// vouching.
func TestWithdrawingVouchingAuthorityWinsForkChoice(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.addNode("admin-a"), h.addNode("admin-b")
	h.grantAdmin(a.Identity)
	h.grantAdmin(b.Identity)
	builder := h.auth.Builder()
	demote, err := builder.SetNodeRoutes(b.Identity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&demote)
	raise, err := builder.SetVouchers(2)
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&raise)
	for _, withdraw := range []types.AUM{demote, raise} {
		// A sibling that would win on its hash: added under names until
		// its hash is lower than the withdrawal's.
		var other types.AUM
		for i := 0; ; i++ {
			other, err = builder.AddNode(h.newNode(fmt.Sprintf("n%d", i)), h.sealer())
			if err != nil {
				t.Fatal(err)
			}
			h.signQuorum(&other)
			if other.SigHash().Compare(withdraw.SigHash()) < 0 {
				break
			}
		}
		auth := h.fork()
		if err := auth.Inform(other, withdraw); err != nil {
			t.Fatal(err)
		}
		if auth.Head() != withdraw.Hash() {
			t.Errorf("%v: the withdrawal lost fork choice", withdraw.Kind)
		}
	}
}
