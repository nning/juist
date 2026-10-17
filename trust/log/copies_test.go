package log

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// withSignature returns a copy of rec signed by key too.
func withSignature(t *testing.T, rec types.AUM, key types.PrivateIdentity) types.AUM {
	t.Helper()
	c := rec.Clone()
	if err := c.Sign(key); err != nil {
		t.Fatal(err)
	}
	return *c
}

// withoutSignature returns a copy of rec without id's signature.
func withoutSignature(rec types.AUM, id types.Identity) types.AUM {
	c := rec.Clone()
	c.Signatures = slices.DeleteFunc(c.Signatures, func(s types.Signature) bool { return s.KeyID == id })
	return *c
}

// mustBeCalm asserts that auth is at head with no fork to report.
func mustBeCalm(t *testing.T, what string, auth *Authority, head types.Hash) {
	t.Helper()
	if alarm := auth.Alarm(); alarm != nil {
		t.Fatalf("%s: %v", what, alarm)
	}
	if o := auth.Orphans(); len(o) != 0 {
		t.Fatalf("%s: left %+v", what, o)
	}
	if auth.Head() != head {
		t.Fatalf("%s: the head is %v, want %v", what, auth.Head(), head)
	}
}

// mustInform informs auth of records in turn.
func mustInform(t *testing.T, auth *Authority, records ...types.AUM) {
	t.Helper()
	for _, r := range records {
		if err := auth.Inform(r); err != nil {
			t.Fatalf("Inform %v: %v", r.Kind, err)
		}
	}
}

// A copy of an applied record signed by one admin key more, below quorum, is
// that record, whether it arrives before the record or after it: no fork, and
// every node on one head.
func TestACopySignedByOneMoreKeyIsTheRecord(t *testing.T) {
	h := newHarness(t, 3, 2)
	early := h.fork()
	rec, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rec)
	mustInform(t, h.auth, rec)
	h.addNode("bravo")
	child, err := h.storage.AUM(h.auth.Head())
	if err != nil {
		t.Fatal(err)
	}
	head := h.auth.Head()
	oversigned := withSignature(t, rec, h.admins[2])
	if oversigned.Hash() == rec.Hash() || oversigned.SigHash() != rec.SigHash() {
		t.Fatal("the copy is not a copy")
	}

	late := h.fork()
	mustInform(t, late, oversigned)
	mustBeCalm(t, "the copy after the record", late, head)
	mustInform(t, early, oversigned, rec, child)
	mustBeCalm(t, "the copy before the record", early, head)
	if _, err := late.TrustedState(); err != nil {
		t.Fatal(err)
	}
}

// A copy of an over-signed record with a signature dropped, as any relay can
// make, is that record too, at the head as below it: nodes holding either or
// both copies converge on one head.
func TestAStrippedCopyIsTheRecord(t *testing.T) {
	h := newHarness(t, 3, 2)
	early := h.fork()
	rec, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rec)
	if err := h.sign(&rec, h.admins[2]); err != nil {
		t.Fatal(err)
	}
	stripped := withoutSignature(rec, h.admins[0].Public())
	low, high := rec, stripped
	if high.Hash().Compare(low.Hash()) < 0 {
		low, high = high, low
	}

	one, other := h.fork(), h.fork()
	mustInform(t, one, high)
	mustInform(t, other, low)
	mustInform(t, one, low)
	mustInform(t, other, high)
	mustBeCalm(t, "both copies at the head", one, low.Hash())
	mustBeCalm(t, "both copies at the head, the other way round", other, low.Hash())

	mustInform(t, h.auth, rec)
	h.addNode("bravo")
	child, err := h.storage.AUM(h.auth.Head())
	if err != nil {
		t.Fatal(err)
	}
	head := h.auth.Head()
	late := h.fork()
	mustInform(t, late, stripped)
	mustBeCalm(t, "the stripped copy after the record", late, head)
	mustInform(t, early, stripped, rec, child)
	mustBeCalm(t, "the stripped copy before the record", early, head)
}

// Changes made on either copy of a record are siblings: two nodes that each
// built on the copy they held, and then exchange everything, agree on one
// head, with the change that lost to be started again, as for any two
// changes made at once.
func TestChangesOnTwoCopiesAreSiblings(t *testing.T) {
	h := newHarness(t, 3, 2)
	rec, err := h.auth.Builder().AddNode(h.newNode("alpha"), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rec)
	if err := h.sign(&rec, h.admins[2]); err != nil {
		t.Fatal(err)
	}
	stripped := withoutSignature(rec, h.admins[0].Public())
	one, other := h.fork(), h.fork()
	mustInform(t, one, rec)
	mustInform(t, other, stripped)
	build := func(auth *Authority, name string) types.AUM {
		a, err := auth.Builder().AddNode(h.newNode(name), h.sealer())
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&a)
		mustInform(t, auth, a)
		return a
	}
	onRec, onStripped := build(one, "bravo"), build(other, "charlie")
	mustInform(t, one, stripped, onStripped)
	mustInform(t, other, rec, onRec)
	if one.Head() != other.Head() {
		t.Fatalf("the nodes hold %v and %v", one.Head(), other.Head())
	}
	for _, auth := range []*Authority{one, other} {
		if auth.Alarm() != nil {
			t.Fatal(auth.Alarm())
		}
		if o := auth.Orphans(); len(o) != 1 || o[0].Conflict != "" || len(o[0].Records) != 1 {
			t.Fatalf("left %+v, want one change to start again", o)
		}
	}
}

// A copy signed by a key a sibling branch removes does not make that key a
// signer of the branch it copies into: one key cannot turn fork choice by
// signing a record the chain holds already.
func TestACopyDoesNotSignItsBranch(t *testing.T) {
	h := newHarness(t, 3, 1)
	mallory, a, b := h.admins[0], h.admins[1], h.admins[2]
	h.addNode("victim")
	var rec, sibling types.AUM
	for i := 0; ; i++ {
		builder := h.auth.Builder()
		var err error
		if rec, err = builder.AddNode(h.newNode("alpha"), h.sealer()); err != nil {
			t.Fatal(err)
		}
		if err := h.sign(&rec, a); err != nil {
			t.Fatal(err)
		}
		if sibling, err = builder.AddNode(h.newNode("bravo"), h.sealer()); err != nil {
			t.Fatal(err)
		}
		if err := h.sign(&sibling, b); err != nil {
			t.Fatal(err)
		}
		if rec.SigHash().Compare(sibling.SigHash()) < 0 {
			break
		}
	}
	auth := h.fork()
	mustInform(t, auth, rec, sibling)
	removal, err := NewBuilder(h.project(sibling)).RemoveAdminKey(mallory.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sign(&removal, b); err != nil {
		t.Fatal(err)
	}
	mustInform(t, auth, removal)
	if auth.Head() != rec.Hash() {
		t.Fatal("the lower signed content did not win")
	}
	copied := withSignature(t, rec, mallory)
	mustInform(t, auth, copied)
	if head := auth.Head(); head != rec.Hash() && head != copied.Hash() {
		t.Fatal("a copy signed by a key the sibling removes turned fork choice")
	}
}

// A store keeps the copies of a record that bring a key's signature or are
// among the two lowest hashes, in whatever order they arrive, refuses none of
// the rest, and holds every signature any of them carried.
func TestCopiesAreBoundedBySigners(t *testing.T) {
	h := newHarness(t, 4, 1)
	rec, err := h.auth.Builder().EpochBump(h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range h.admins {
		if err := h.sign(&rec, k); err != nil {
			t.Fatal(err)
		}
	}
	var copies []types.AUM
	for set := 1; set < 1<<len(h.admins); set++ {
		c := rec.Clone()
		c.Signatures = nil
		for i, s := range rec.Signatures {
			if set&(1<<i) != 0 {
				c.Signatures = append(c.Signatures, s)
			}
		}
		copies = append(copies, *c)
	}
	// Highest first: each arrives as the lowest yet.
	slices.SortFunc(copies, func(a, b types.AUM) int { return b.Hash().Compare(a.Hash()) })
	reversed := slices.Clone(copies)
	slices.Reverse(reversed)
	for _, order := range []struct {
		name    string
		records []types.AUM
		batch   bool
	}{
		{"highest first", copies, false},
		{"lowest first", reversed, false},
		{"in one batch", copies, true},
	} {
		t.Run(order.name, func(t *testing.T) {
			auth := h.fork()
			if order.batch {
				if err := auth.Inform(order.records...); err != nil {
					t.Fatal(err)
				}
			} else {
				mustInform(t, auth, order.records...)
			}
			held := heldCopies(t, auth, rec)
			if len(held) > len(h.admins)+2 {
				t.Fatalf("%d of %d copies held, want at most %d", len(held), len(copies), len(h.admins)+2)
			}
			signed := map[types.Identity]bool{}
			for _, c := range held {
				aum, err := auth.storage.AUM(c)
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range aum.Signatures {
					signed[s.KeyID] = true
				}
			}
			if len(signed) != len(h.admins) {
				t.Fatalf("the copies held carry %d keys' signatures, want %d", len(signed), len(h.admins))
			}
			for _, c := range copies {
				if news, err := auth.Learn(c); err != nil || news {
					t.Fatalf("a copy offered again: news %v, err %v", news, err)
				}
			}
			mustBeCalm(t, "copies", auth, reversed[0].Hash())
		})
	}
}

// A store keeps every copy of a checkpoint it is shown, any of which a peer
// may be anchored at, up to a bound however many are minted.
func TestCheckpointCopiesAreKeptToABound(t *testing.T) {
	h := newHarness(t, 4, 1)
	rec, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range h.admins {
		if err := h.sign(&rec, k); err != nil {
			t.Fatal(err)
		}
	}
	var copies []types.AUM
	for set := 1; set < 1<<len(h.admins); set++ {
		c := rec.Clone()
		c.Signatures = nil
		for i, s := range rec.Signatures {
			if set&(1<<i) != 0 {
				c.Signatures = append(c.Signatures, s)
			}
		}
		copies = append(copies, *c)
	}
	slices.SortFunc(copies, func(a, b types.AUM) int { return a.Hash().Compare(b.Hash()) })
	three := h.fork()
	mustInform(t, three, copies[:3]...)
	if held := heldCopies(t, three, rec); len(held) != 3 {
		t.Fatalf("%d of 3 copies held", len(held))
	}
	all := h.fork()
	mustInform(t, all, copies...)
	if held := heldCopies(t, all, rec); len(held) < maxCheckpointCopies || len(held) > maxCheckpointCopies+len(h.admins)+2 {
		t.Fatalf("%d of %d copies held", len(held), len(copies))
	}
}

// heldCopies returns the copies of rec auth's store holds, in hash order.
func heldCopies(t *testing.T, auth *Authority, rec types.AUM) []types.Hash {
	t.Helper()
	siblings, err := auth.storage.Children(*rec.Prev)
	if err != nil {
		t.Fatal(err)
	}
	var out []types.Hash
	for _, s := range siblings {
		aum, err := auth.storage.AUM(s)
		if err != nil {
			t.Fatal(err)
		}
		if aum.SigHash() == rec.SigHash() {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, types.Hash.Compare)
	return out
}

// mintedCopies returns every copy of rec an admin key can make of it alone:
// a subset of its signatures that reaches quorum, with key's added.
func mintedCopies(t *testing.T, rec types.AUM, key types.PrivateIdentity, quorum int) []types.AUM {
	t.Helper()
	var out []types.AUM
	for set := 1; set < 1<<len(rec.Signatures); set++ {
		c := rec.Clone()
		c.Signatures = nil
		for i, s := range rec.Signatures {
			if set&(1<<i) != 0 {
				c.Signatures = append(c.Signatures, s)
			}
		}
		if len(c.Signatures) < quorum {
			continue
		}
		if err := c.Sign(key); err != nil {
			t.Fatal(err)
		}
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b types.AUM) int { return a.Hash().Compare(b.Hash()) })
	return out
}

// An admin key a sibling removes, minting copies of a record other admins
// signed with votes to spare, decides fork choice at no node: one fed those
// copies before the record itself, and more of them than a store once took
// in, settles where every other node does.
func TestCopiesAKeyMintsDoNotDecideForkChoice(t *testing.T) {
	h := newHarness(t, 5, 2)
	mallory := h.admins[4]
	victim := h.addNode("victim")
	var removal, kRemoval types.AUM
	var copies []types.AUM
	for {
		b := h.auth.Builder()
		var err error
		if removal, err = b.RemoveNode(victim.Identity, h.sealer()); err != nil {
			t.Fatal(err)
		}
		for _, k := range h.admins[:4] {
			if err := h.sign(&removal, k); err != nil {
				t.Fatal(err)
			}
		}
		if kRemoval, err = h.auth.Builder().RemoveAdminKey(mallory.Public()); err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&kRemoval)
		copies = mintedCopies(t, removal, mallory, 2)
		// The removal wins wherever its copies do not count against it, by
		// hash as by what it says: a switch away from it would cross the
		// epoch floor, which is not what is under test.
		if copies[0].Hash().Compare(kRemoval.Hash()) < 0 && removal.Hash().Compare(kRemoval.Hash()) < 0 &&
			removal.SigHash().Compare(kRemoval.SigHash()) < 0 {
			break
		}
	}
	if len(copies) <= 8 {
		t.Fatalf("only %d copies", len(copies))
	}
	honest, fed := h.fork(), h.fork()
	mustInform(t, honest, removal)
	mustInform(t, honest, copies...)
	mustInform(t, honest, kRemoval)
	mustInform(t, fed, kRemoval)
	mustInform(t, fed, copies...)
	mustInform(t, fed, removal)

	next, err := honest.Builder().EpochBump(h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&next)
	mustInform(t, honest, next)
	mustInform(t, fed, next)
	for name, auth := range map[string]*Authority{"honest": honest, "fed": fed} {
		if auth.Alarm() != nil {
			t.Fatalf("%s: %v", name, auth.Alarm())
		}
		if _, ok := auth.State().Node(victim.Identity); ok {
			t.Errorf("%s: the removed member is a member", name)
		}
	}
	if honest.Head() != fed.Head() || honest.Head() != next.Hash() {
		t.Fatalf("heads %v and %v, want %v", honest.Head(), fed.Head(), next.Hash())
	}
}

// A compaction to one copy of a checkpoint keeps the others, and what a peer
// built on another copy is taken after it.
func TestCompactingToOneCopyKeepsWhatHangsFromAnother(t *testing.T) {
	h := newHarness(t, 3, 2)
	h.addNode("alpha")
	low, high := twoCopies(t, h)

	peer := h.fork()
	mustInform(t, peer, high)
	child, err := peer.Builder().AddNode(h.newNode("bravo"), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&child)
	mustInform(t, peer, child)

	mustInform(t, h.auth, high, low)
	next := h.checkpoint()
	if _, err := h.auth.Compact(); err != nil {
		t.Fatal(err)
	}
	if h.auth.Anchor() != low.Hash() {
		t.Fatalf("anchor %v, want the low copy %v", h.auth.Anchor(), low.Hash())
	}
	if _, err := h.storage.AUM(high.Hash()); err != nil {
		t.Fatalf("the other copy did not survive compaction: %v", err)
	}
	mustInform(t, h.auth, child)
	mustInform(t, peer, low, next)
	if !slices.Contains(h.auth.Held(), child.Hash()) || h.auth.Head() != peer.Head() {
		t.Fatalf("heads %v and %v, and what hangs from the other copy held: %v", h.auth.Head(), peer.Head(),
			slices.Contains(h.auth.Held(), child.Hash()))
	}
}

// A device bootstrapped from one copy of a checkpoint takes what hangs from
// another, offered with it.
func TestABootstrapFromOneCopyTakesWhatHangsFromAnother(t *testing.T) {
	h := newHarness(t, 3, 2)
	h.addNode("alpha")
	low, high := twoCopies(t, h)
	mustInform(t, h.auth, high)
	child, err := h.auth.Builder().AddNode(h.newNode("bravo"), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&child)
	mustInform(t, h.auth, child)

	joiner, err := Bootstrap(NewMemStorage(), low)
	if err != nil {
		t.Fatal(err)
	}
	if err := joiner.Inform(high, child); err != nil {
		t.Fatal(err)
	}
	if joiner.Head() != child.Hash() {
		t.Fatalf("head %v, want %v", joiner.Head(), child.Hash())
	}
}

// Nodes shown one set of records, copies of them included, each in its own
// order settle on one head and one state, with no alarm: copies minted by an
// admin key a sibling removes, a relay's stripped copy, and changes made on
// different copies among them.
func TestCopiesInAnyOrderLeaveOneHeadAndState(t *testing.T) {
	t.Parallel()
	h := newHarness(t, 5, 2)
	adm, mallory := h.admins, h.admins[4]
	victim := h.addNode("victim")
	build := func(on []types.AUM, f func(*Builder) (types.AUM, error), keys ...types.PrivateIdentity) types.AUM {
		t.Helper()
		a, err := f(NewBuilder(h.project(on...)))
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if err := h.sign(&a, k); err != nil {
				t.Fatal(err)
			}
		}
		return a
	}
	add := func(name string) func(*Builder) (types.AUM, error) {
		return func(b *Builder) (types.AUM, error) { return b.AddNode(h.newNode(name), h.sealer()) }
	}

	r1 := build(nil, add("alpha"), adm[0], adm[1], adm[2])
	r1k := withSignature(t, r1, mallory)
	r1a := withoutSignature(r1, adm[0].Public())
	r1b := withSignature(t, withoutSignature(r1, adm[1].Public()), mallory)
	a := build([]types.AUM{r1a}, add("bravo"), adm[0], adm[1])
	b := build([]types.AUM{r1}, add("charlie"), adm[0], adm[1])
	w, below := a, r1a
	if b.SigHash().Compare(a.SigHash()) < 0 {
		w, below = b, r1
	}
	var removal, kRemoval types.AUM
	for {
		removal = build([]types.AUM{below, w}, func(b *Builder) (types.AUM, error) {
			return b.RemoveNode(victim.Identity, h.sealer())
		}, adm[:4]...)
		kRemoval = build([]types.AUM{below, w}, func(b *Builder) (types.AUM, error) {
			return b.RemoveAdminKey(mallory.Public())
		}, adm[0], adm[1])
		// A switch away from the removal would cross the epoch floor.
		if removal.SigHash().Compare(kRemoval.SigHash()) < 0 {
			break
		}
	}
	minted := mintedCopies(t, removal, mallory, 2)
	x := build([]types.AUM{below, w, minted[0]}, add("delta"), adm[0], adm[1])
	records := append([]types.AUM{r1, r1k, r1a, r1b, a, b, removal, kRemoval, x}, minted...)

	type outcome struct {
		head     types.Hash
		snapshot string
	}
	var first *outcome
	for seed := range uint64(8) {
		order := slices.Clone(records)
		rand.New(rand.NewPCG(seed, 7)).Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		auth := h.fork()
		deliverAll(t, auth, order)
		if auth.Alarm() != nil {
			t.Fatalf("seed %d: %v", seed, auth.Alarm())
		}
		if _, ok := auth.State().Node(victim.Identity); ok {
			t.Errorf("seed %d: the removed member is a member", seed)
		}
		got := outcome{auth.Head(), string(auth.State().Snapshot().Encode())}
		switch {
		case first == nil:
			first = &got
		case got.head != first.head:
			t.Fatalf("seed %d: head %v, another order's %v", seed, got.head, first.head)
		case got.snapshot != first.snapshot:
			t.Fatalf("seed %d: another state than another order's", seed)
		}
	}
	if first.head != x.Hash() {
		t.Fatalf("head %v, want %v", first.head, x.Hash())
	}
}

// A key a sibling removes counts against a branch only where its vote was
// needed; below schema 19, as M17's build has it, any signature counts, and
// the hash breaks ties.
func TestOnlyANeededSignatureUndoesABranch(t *testing.T) {
	for _, schema := range []types.SchemaVersion{types.SchemaContentForkChoice - 1, types.SchemaContentForkChoice} {
		t.Run(schema.String(), func(t *testing.T) {
			h := newHarnessWith(t, 3, 1, func(s *types.Snapshot) { s.Schema = schema })
			mallory, honest := h.admins[0], h.admins[1]
			victim := h.addNode("victim")
			var removal, kRemoval types.AUM
			for {
				var err error
				if removal, err = h.auth.Builder().RemoveNode(victim.Identity, h.sealer()); err != nil {
					t.Fatal(err)
				}
				for _, k := range []types.PrivateIdentity{honest, mallory} {
					if err := h.sign(&removal, k); err != nil {
						t.Fatal(err)
					}
				}
				if kRemoval, err = h.auth.Builder().RemoveAdminKey(mallory.Public()); err != nil {
					t.Fatal(err)
				}
				if err := h.sign(&kRemoval, honest); err != nil {
					t.Fatal(err)
				}
				if removal.Hash().Compare(kRemoval.Hash()) < 0 && removal.SigHash().Compare(kRemoval.SigHash()) < 0 {
					break
				}
			}
			auth := h.fork()
			if err := auth.Inform(removal, kRemoval); err != nil {
				t.Fatal(err)
			}
			want := removal
			if schema < types.SchemaContentForkChoice {
				want = kRemoval
			}
			if auth.Head() != want.Hash() {
				t.Fatalf("head %v, want the %v", auth.Head(), want.Kind)
			}
		})
	}
}

// deliverAll offers records to auth one at a time, as gossip would: a record
// whose parent auth lacks comes again later, with that parent if it was
// offered already.
func deliverAll(t *testing.T, auth *Authority, records []types.AUM) {
	t.Helper()
	byHash := map[types.Hash]types.AUM{}
	for _, r := range records {
		byHash[r.Hash()] = r
	}
	offered := map[types.Hash]bool{}
	queue := slices.Clone(records)
	for stalled := 0; len(queue) > 0; {
		r := queue[0]
		queue = queue[1:]
		batch := []types.AUM{r}
		if p, ok := byHash[*r.Prev]; ok && offered[*r.Prev] {
			batch = []types.AUM{p, r}
		}
		err := auth.Inform(batch...)
		var rej *RejectError
		switch {
		case err == nil:
			offered[r.Hash()] = true
			stalled = 0
		case errors.As(err, &rej) && rej.Rule == RuleParent:
			queue = append(queue, r)
			if stalled++; stalled > len(queue) {
				t.Fatalf("%d records never taken: %v", len(queue), err)
			}
		default:
			t.Fatalf("Inform %v: %v", r.Kind, err)
		}
	}
}

// twoCopies returns a quorum-signed checkpoint and a copy of it carrying the
// third admin's signature, lowest hash first.
func twoCopies(t *testing.T, h *harness) (low, high types.AUM) {
	t.Helper()
	rec, err := h.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rec)
	other := withSignature(t, rec, h.admins[2])
	if other.Hash().Compare(rec.Hash()) < 0 {
		return other, rec
	}
	return rec, other
}
