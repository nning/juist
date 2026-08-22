package log

import (
	"net/netip"
	"testing"

	"github.com/nning/wg-p2p/trust/secrets"
	"github.com/nning/wg-p2p/types"
)

// The M1 exit criterion (docs/05-roadmap.md): forged signatures, replayed
// records, reordered chains, rollback to a lower epoch, sub-quorum membership
// changes, colliding addresses, conflicting concurrent records, fork injection,
// and self-asserted or overlay-overlapping route grants are rejected 100 % of
// the time.
//
// Each test states the attack in the terms an attacker would: what they hold,
// what they submit, and what they would gain. Nothing is stubbed — every record
// here is a real record that a real quorum could have produced, except for the
// specific defect under test.

// --- forged and mis-signed records -----------------------------------------

func TestRejectsUnsignedRecord(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum, err := h.auth.Builder().AddNode(h.newNode("intruder"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.mustReject("unsigned AddNode", aum)
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
	if err := aum.Sign(outsider); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("AddNode signed by a key the network never trusted", aum)
}

// TestRejectsExtraSignatureByUntrustedKey covers the record-laundering variant:
// take a properly authorized record and append one more signature. The content
// is unchanged and quorum is still met, but the record hash is different — so
// accepting it would let anyone mint a sibling of any legitimate record and
// manufacture a fork.
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
	if err := aum.Sign(outsider); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("authorized AddNode with an extra untrusted signature", aum)
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
	h.mustReject("AddNode whose WireGuard key was swapped after signing", aum)
}

func TestRejectsTamperedSignatureBits(t *testing.T) {
	h := newHarness(t, 1, 1)
	aum, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&aum)
	aum.Signatures[0].Sig[0] ^= 0x01
	h.mustReject("AddNode with a corrupted signature", aum)
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
	if err := aum.Sign(h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("AddNode with one of two required votes", aum)

	// The same record becomes valid once a second admin signs it, which is
	// what makes the rejection above about quorum and not about something else.
	if err := aum.Sign(h.admins[1]); err != nil {
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
	if err := aum.Sign(h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	// One admin, two copies of its signature: the cheapest way to fake a
	// quorum if vote counting deduplicated nothing.
	aum.Signatures = append(aum.Signatures, aum.Signatures[0])
	h.mustReject("AddNode carrying one admin's signature twice", aum)
}

func TestRejectsAdminRemovalBelowQuorum(t *testing.T) {
	h := newHarness(t, 2, 2)
	// Both admins agree to remove one of them, which would leave one vote
	// against a quorum of two: a network nobody could ever change again,
	// including to undo this.
	aum, err := h.auth.Builder().RemoveAdminKey(h.admins[0].Public())
	if err == nil {
		h.signQuorum(&aum)
		h.mustReject("RemoveAdminKey that strands the quorum", aum)
		return
	}
	// Rejected at build time, which is the better outcome: the ceremony never
	// happens.
	t.Logf("rejected while building: %v", err)
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
	if err := next.Sign(h.admins[2]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	status := st.SignatureStatus(&next)
	if len(status.Untrusted) != 1 || status.Untrusted[0] != h.admins[2].Public() {
		t.Fatalf("removed key's signature reported %+v, want untrusted", status)
	}
	h.mustReject("AddNode signed by the removed admin key", next)

	// And the removed key cannot re-add itself: restoring it would need
	// quorum of the set that no longer contains it.
	restore, err := h.auth.Builder().AddAdminKey(types.AdminKey{
		Public: h.admins[2].Public(), Votes: 1,
	})
	if err != nil {
		t.Fatalf("AddAdminKey: %v", err)
	}
	if err := restore.Sign(h.admins[2]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("AddAdminKey re-adding the removed key, signed by that key", restore)
}

// TestOneAdminCanRemoveTheOtherAtQuorumOne answers the two-admin question in
// its permissive form: with two single-vote keys and a quorum of one, either
// admin signs the other out. The anti-stranding rule still holds — one vote
// remains against a quorum of one — but the network is now governed by a
// single key, which is the price of a quorum of one.
func TestOneAdminCanRemoveTheOtherAtQuorumOne(t *testing.T) {
	h := newHarness(t, 2, 1)
	aum, err := h.auth.Builder().RemoveAdminKey(h.admins[1].Public())
	if err != nil {
		t.Fatalf("RemoveAdminKey: %v", err)
	}
	if err := aum.Sign(h.admins[0]); err != nil {
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
	h.mustReject("AddNode under the old quorum after tightening", next)
}

func TestRejectsUnsatisfiableQuorum(t *testing.T) {
	h := newHarness(t, 2, 1)
	aum, err := h.auth.Builder().SetQuorum(99)
	if err == nil {
		h.signQuorum(&aum)
		h.mustReject("SetQuorum above the total admin vote weight", aum)
		return
	}
	t.Logf("rejected while building: %v", err)
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
	// The attack an on-path adversary can actually mount: take the captured
	// record and re-parent it onto the current head, to apply the change a
	// second time. The signature covers the parent hash, so re-parenting
	// invalidates it — and re-signing is not available to anyone short of a
	// quorum.
	h.addNode("bravo")
	replay := *aum.Clone()
	head := h.auth.Head()
	replay.Prev = &head
	h.mustReject("captured AddNode re-parented onto the current head", replay)
}

// TestReauthorizedRecordAtTheSamePositionIsAFork covers what happens when a
// quorum does re-sign the same change at the same chain position: it is not a
// replay, it is two records competing for one slot. Fork choice picks one, and
// the other cannot be reissued on top of it — so this surfaces as a conflict
// rather than being silently absorbed.
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
	h.mustReject("AddNode chaining to an unknown parent", aum)
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
	h.mustReject("batch delivered child-first", second)
	if err := h.auth.Inform(second, first); err != nil {
		t.Fatalf("reversed batch rejected: %v", err)
	}
	if len(h.auth.State().Nodes()) != 2 {
		t.Fatalf("both records should have applied, got %d members", len(h.auth.State().Nodes()))
	}
}

// TestRejectsEpochRollback is the rollback attack: a chain that resolves to an
// epoch this node has already passed. Reaching an older epoch through valid
// records takes admin signatures, so this models a compromised quorum
// rewriting history — and the node refuses rather than following.
func TestRejectsEpochRollback(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.newNode("victim")
	add, err := h.auth.Builder().AddNode(victim, h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&add)
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

	// A record forking from genesis: same network, same admin key, one record
	// deep, so any chain through it resolves to epoch 2. To make the rollback
	// the outcome rather than a coin flip, keep drawing until the rogue record
	// wins fork choice against the record it displaces — which needs only a
	// lower hash, since neither is a revocation.
	var rogue types.AUM
	for attempt := 0; ; attempt++ {
		if attempt > 64 {
			t.Fatal("could not draw a record that wins fork choice")
		}
		candidate, err := NewBuilder(h.genesisState()).AddNode(h.newNode("attacker"), h.sealer())
		if err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		h.signQuorum(&candidate)
		if compareHash(candidate.Hash(), add.Hash()) < 0 {
			rogue = candidate
			break
		}
	}

	err = h.auth.Inform(rogue)
	var rb *RollbackError
	if !asRollback(err, &rb) {
		t.Fatalf("expected a rollback error, got %v", err)
	}
	if rb.Floor != floor || rb.Offered != 2 {
		t.Fatalf("rollback error reports floor %d offered %d, want 3 and 2", rb.Floor, rb.Offered)
	}
	if h.auth.State().Epoch() != floor {
		t.Fatalf("epoch changed to %d despite the rejection", h.auth.State().Epoch())
	}
	if len(rb.Records) != 1 {
		t.Fatalf("rollback error carries %d records, want the 1 it refused", len(rb.Records))
	}
	// Nothing was stored, so reopening the store gives the same chain back.
	reopened, err := Open(h.storage)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if reopened.Head() != h.auth.Head() || reopened.State().Epoch() != floor {
		t.Fatal("the refused record left a trace in storage")
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
	h.mustReject("AddNode claiming a non-sequential epoch", aum)
}

// --- epoch coverage --------------------------------------------------------

// TestRejectsEpochExcludingAMember is the quiet lockout: a membership change
// whose epoch bump omits one member's wrap. That member keeps its WireGuard
// peer entries but loses discovery, with nothing in the log saying it was
// removed.
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
	h.mustReject("AddNode with the epoch bump stripped", aum)
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
	addr := netip.MustParseAddr("100.64.0.5")
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

// TestRejectsCollidingDerivedAddress forces the derived-address collision the
// validator exists to reject. It cannot be produced by finding a hash collision
// in a test, so the check is exercised through the snapshot validator with two
// records that a hostile checkpoint could contain.
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

// TestRejectsCollisionsFromAQuorumSignedRecord is the collision rules on the
// attacker's path rather than the builder's.
//
// The tests above stop at the builder, which refuses these records before they
// are signed. That proves the honest tool will not produce one; it says nothing
// about a node receiving one from a quorum that skipped the tool. Since a
// colliding record is fully authorized — real signatures, real quorum — the
// only thing standing between it and the member set is the receiving node's own
// validation, which is exactly what this exercises.
func TestRejectsCollisionsFromAQuorumSignedRecord(t *testing.T) {
	addr := netip.MustParseAddr("100.64.0.5")
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
			h.mustReject(tc.what, h.handAssembledAddNode(clone))
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

// --- route grants ----------------------------------------------------------

// TestRejectsSelfAssertedRoute is the shape of the guarantee rather than a
// single case: there is no record kind through which a node grants itself
// anything. A route arrives only in AddNode or SetNodeRoutes, both of which
// need quorum, and a node's own signature is never a substitute.
func TestRejectsSelfAssertedRoute(t *testing.T) {
	h := newHarness(t, 2, 2)
	n := h.addNode("router")
	aum, err := h.auth.Builder().SetNodeRoutes(n.Identity,
		[]types.Role{types.RoleExitNode}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatalf("SetNodeRoutes: %v", err)
	}
	// The node signs for itself, with its own identity key.
	if err := aum.Sign(h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("SetNodeRoutes signed only by the node it grants", aum)

	// One admin short of quorum is equally not enough.
	aum.Signatures = nil
	if err := aum.Sign(h.admins[0]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("SetNodeRoutes with one of two required votes", aum)

	// With quorum it applies, which is what makes the rejections above about
	// authority rather than about the grant's contents.
	aum.Signatures = nil
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("quorum-signed SetNodeRoutes rejected: %v", err)
	}
	got, _ := h.auth.State().Node(n.Identity)
	if !got.HasRole(types.RoleExitNode) || len(got.Routes) != 1 {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.auth.Builder().SetNodeRoutes(n.Identity,
				[]types.Role{types.RoleExitNode}, []netip.Prefix{tc.route}); err == nil {
				t.Fatalf("accepted a route grant covering %s (%v)", tc.name, tc.route)
			}
		})
	}
}

func TestDefaultRouteRequiresExitNodeRole(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.addNode("router")
	for _, def := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	} {
		if _, err := h.auth.Builder().SetNodeRoutes(n.Identity, nil, []netip.Prefix{def}); err == nil {
			t.Fatalf("accepted %v without the exit-node role", def)
		}
		if _, err := h.auth.Builder().SetNodeRoutes(n.Identity,
			[]types.Role{types.RoleExitNode}, []netip.Prefix{def}); err != nil {
			t.Fatalf("rejected %v with the exit-node role: %v", def, err)
		}
	}
	// Withdrawing the role must withdraw the default route with it, rather
	// than leaving a grant nothing authorizes.
	aum, err := h.auth.Builder().SetNodeRoutes(n.Identity,
		[]types.Role{types.RoleExitNode}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatalf("SetNodeRoutes: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	stripRole, err := h.auth.Builder().SetNodeRoutes(n.Identity, nil,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err == nil {
		h.signQuorum(&stripRole)
		h.mustReject("keeping a default route while dropping the exit-node role", stripRole)
	}
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
	if compareHash(one.Head(), max2(left.Hash(), right.Hash())) == 0 {
		t.Fatal("fork choice did not prefer the lower record hash")
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
	if err := rotate.Sign(h.nodeIDs[victim.Identity]); err != nil {
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

// TestOrphanedRevocationAlarms is the dangerous fork: a removal buried on a
// branch that loses. Fork choice's bias only looks at immediate siblings, so a
// revocation deeper on a losing branch would otherwise disappear silently.
func TestOrphanedRevocationAlarms(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	b := h.auth.Builder()

	// Branch B: an unrelated addition, then the victim's removal one record
	// deeper — deep enough that fork choice's revocation bias, which only ever
	// compares immediate siblings, cannot see it.
	b1, err := b.AddNode(h.newNode("b1"), h.sealer())
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	h.signQuorum(&b1)
	b2, err := NewBuilder(h.project(b1)).RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	h.signQuorum(&b2)

	// Branch A: two unrelated additions. Draw until A's root wins fork choice
	// against B's, so the branch carrying the revocation is the one orphaned.
	var a1 types.AUM
	for attempt := 0; ; attempt++ {
		if attempt > 64 {
			t.Fatal("could not draw a record that wins fork choice")
		}
		candidate, err := b.AddNode(h.newNode("a1"), h.sealer())
		if err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		h.signQuorum(&candidate)
		if compareHash(candidate.Hash(), b1.Hash()) < 0 {
			a1 = candidate
			break
		}
	}
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
	alarm := h.auth.Alarm()
	if alarm == nil {
		t.Fatal("a revocation on an orphaned branch raised no alarm")
	}
	if _, err := h.auth.TrustedState(); err == nil {
		t.Fatal("TrustedState served membership with an orphaned revocation")
	}
	t.Logf("alarm: %v", alarm)
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
	h.mustReject("checkpoint asserting a member the chain never admitted", forged)
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
	h.mustReject("checkpoint belonging to another network", cp)
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

	// Compaction advances the anchor to the checkpoint and drops what precedes
	// it, without changing the state.
	removed, err := h.auth.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if removed == 0 {
		t.Fatal("compaction removed nothing despite a checkpoint on the chain")
	}
	if h.auth.Anchor() != cp.Hash() {
		t.Fatal("compaction did not advance the anchor to the checkpoint")
	}
	if string(h.auth.State().Snapshot().Encode()) != string(want) {
		t.Fatal("compaction changed the state")
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
// you hold" rule: once the anchor has advanced, a branch that forks before it
// is not merely outvoted, it is not considered at all.
func TestCompactedAnchorRejectsPreCheckpointFork(t *testing.T) {
	h := newHarness(t, 1, 1)
	victim := h.addNode("victim")
	preFork := h.auth.State()

	cp, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	h.signQuorum(&cp)
	if err := h.auth.Inform(cp); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if _, err := h.auth.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	// A record forking from before the checkpoint, re-admitting a device on a
	// history this node has compacted away.
	fork, err := NewBuilder(preFork).RemoveNode(victim.Identity, h.sealer())
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	h.signQuorum(&fork)
	h.mustReject("a fork rooted before the adopted checkpoint", fork)
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
	h.mustReject("RotateNodeKey with quorum but no node signature", aum)

	if err := aum.Sign(h.nodeIDs[n.Identity]); err != nil {
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
	aum, err := h.auth.Builder().RotateIdentity(n.Identity, fresh.Public(), h.sealer())
	if err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	h.signQuorum(&aum)
	h.mustReject("RotateIdentity with no proof the new key is held", aum)

	// Signing with the *old* key is not a substitute: the point is that some
	// device holds the new one.
	aum.Signatures = nil
	h.signQuorum(&aum)
	if err := aum.Sign(h.nodeIDs[n.Identity]); err != nil {
		t.Fatalf("signing: %v", err)
	}
	h.mustReject("RotateIdentity signed by the old key", aum)

	aum.Signatures = nil
	h.signQuorum(&aum)
	if err := aum.Sign(fresh); err != nil {
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

func asRollback(err error, target **RollbackError) bool {
	for err != nil {
		if rb, ok := err.(*RollbackError); ok {
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

func max2(a, b types.Hash) types.Hash {
	if compareHash(a, b) > 0 {
		return a
	}
	return b
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
