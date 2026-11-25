package log

import (
	"fmt"
	"maps"
	"slices"

	"github.com/nning/juist/types"
)

// byContent reports whether fork choice among the records after s goes by
// what they say alone, not by which copies are held.
func byContent(s *State) bool { return s.Schema() >= types.SchemaContentForkChoice }

// copiesOf returns the stored records with a's parent and [types.AUM.SigHash],
// in hash order: a's copies, a among them if it is stored.
func copiesOf(r reader, a *types.AUM) ([]types.Hash, error) {
	siblings, err := r.Children(*a.Prev)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(siblings, types.Hash.Compare)
	sh := a.SigHash()
	var out []types.Hash
	for _, s := range siblings {
		sib, err := r.AUM(s)
		if err != nil {
			return nil, fmt.Errorf("log: reading %v: %w", s, err)
		}
		if sib.SigHash() == sh {
			out = append(out, s)
		}
	}
	return out, nil
}

// anchorCopies returns the stored copies of the anchor that verify as it
// does, lowest hash first.
func anchorCopies(r reader, anchor types.Hash, a *types.AUM) ([]types.Hash, error) {
	if a.Prev == nil {
		return []types.Hash{anchor}, nil
	}
	copies, err := copiesOf(r, a)
	if err != nil {
		return nil, err
	}
	out := make([]types.Hash, 0, len(copies))
	for _, h := range copies {
		if h != anchor {
			c, err := r.AUM(h)
			if err != nil {
				return nil, fmt.Errorf("log: reading %v: %w", h, err)
			}
			if verifySelfSigned(&c, a.Kind) != nil {
				continue
			}
		}
		out = append(out, h)
	}
	if !slices.Contains(out, anchor) {
		return nil, fmt.Errorf("log: anchor %v is not stored under its parent", anchor)
	}
	return out, nil
}

// copyGroups gathers hashes, siblings, into copies of one record, each group
// in hash order.
func copyGroups(r reader, hashes []types.Hash) ([][]types.Hash, error) {
	slices.SortFunc(hashes, types.Hash.Compare)
	var out [][]types.Hash
	index := map[types.Hash]int{}
	for _, h := range hashes {
		aum, err := r.AUM(h)
		if err != nil {
			return nil, fmt.Errorf("log: reading %v: %w", h, err)
		}
		sh := aum.SigHash()
		if i, ok := index[sh]; ok {
			out[i] = append(out[i], h)
			continue
		}
		index[sh] = len(out)
		out = append(out, []types.Hash{h})
	}
	return out, nil
}

// pickPrimary applies fork choice to valid siblings of parent, in order:
//  1. a branch loses to a sibling whose branch removes the admin keys a
//     record on it stands by, so a removed key cannot undo its own removal;
//     this is weighed against every sibling before the other rules, which
//     rank only the branches it leaves;
//  2. a revocation beats anything else;
//  3. the lower hash wins, from [types.SchemaContentForkChoice] on the lower
//     [types.AUM.SigHash].
//
// Signature weight is deliberately not a rule: it would let one quorum outbid
// another by collecting extras. mutual are the siblings the log cannot settle
// against the winner, which the caller alarms on rather than choosing: two
// branches each removing a key that signed the other, or every branch undone
// by another.
func pickPrimary(r reader, candidates []candidate, parent *State) (_ candidate, mutual map[types.Hash]bool, _ error) {
	// Walking each branch on a chain without forks makes resolution quadratic.
	if len(candidates) == 1 {
		return candidates[0], nil, nil
	}
	keys := make([]branchKeys, len(candidates))
	removes := false
	budget := maxOrphanRecords
	for i := range candidates {
		k, err := keysOfBranch(r, candidates[i], parent, false, &budget)
		if err != nil {
			return candidate{}, nil, err
		}
		keys[i] = k
		removes = removes || len(k.removed) > 0
	}
	// Signers need states to tell; only collect them if some branch removes a
	// key.
	if removes {
		budget = maxOrphanRecords
		for i := range candidates {
			k, err := keysOfBranch(r, candidates[i], parent, true, &budget)
			if err != nil {
				return candidate{}, nil, err
			}
			keys[i] = k
		}
	}
	// undone reports whether a record of the branch at i stands by keys the
	// branch at j removes.
	undone := func(i, j int) bool {
		return len(keys[j].removed) > 0 && slices.ContainsFunc(keys[i].signed, func(s signedRecord) bool {
			return s.undoneBy(keys[j].removed)
		})
	}
	lower := func(c, b *candidate) bool { return c.hash.Compare(b.hash) < 0 }
	if byContent(parent) {
		lower = func(c, b *candidate) bool { return c.sigHash.Compare(b.sigHash) < 0 }
	}
	ranks := func(c, b *candidate) bool {
		rev, bRev := parent.Revokes(&c.aum), parent.Revokes(&b.aum)
		return rev && !bRev || rev == bRev && lower(c, b)
	}
	// Rule 1 rules a branch out wherever it loses so; where it rules out
	// every branch, the rest choose and the caller alarms.
	out, cycle := make([]bool, len(candidates)), true
	for i := range candidates {
		for j := range candidates {
			out[i] = out[i] || j != i && undone(i, j) && !undone(j, i)
		}
		cycle = cycle && out[i]
	}
	best := -1
	for i := range candidates {
		if (!out[i] || cycle) && (best < 0 || ranks(&candidates[i], &candidates[best])) {
			best = i
		}
	}
	mutual = map[types.Hash]bool{}
	for i := range candidates {
		mutual[candidates[i].hash] = i != best && (cycle || undone(i, best) && undone(best, i))
	}
	return candidates[best], mutual, nil
}

// branchKeys are the admin keys a branch's records remove, and what each of
// them was signed with.
type branchKeys struct {
	removed map[types.Identity]bool
	signed  []signedRecord
}

// A signedRecord is a record's signatures, any copy's, and the state it
// applies to: nil where any signature counts, as below
// [types.SchemaContentForkChoice].
type signedRecord struct {
	aum    *types.AUM
	signed map[types.Identity]bool
	at     *State
}

// undoneBy reports whether the record stands only by keys in removed: one it
// requires, or a vote without which the rest fall short of quorum, those keys
// taken together.
func (s signedRecord) undoneBy(removed map[types.Identity]bool) bool {
	if s.at == nil {
		return slices.ContainsFunc(slices.Collect(maps.Keys(s.signed)), func(id types.Identity) bool { return removed[id] })
	}
	if slices.ContainsFunc(SelfSigners(s.aum), func(id types.Identity) bool { return s.signed[id] && removed[id] }) {
		return true
	}
	return types.CountVotes(s.at.Admins(), func(x types.Identity) bool { return s.signed[x] && !removed[x] }) < s.at.quorum
}

// keysOfBranch collects branchKeys (signatures only withSigners) over every
// stored record from root on, within budget.
func keysOfBranch(r reader, root candidate, parent *State, withSigners bool, budget *int) (branchKeys, error) {
	k := branchKeys{removed: map[types.Identity]bool{}}
	needed := withSigners && byContent(parent)
	type group struct {
		copies []types.Hash
		// parent is the state the record applies to, nil below one that
		// does not apply.
		parent *State
	}
	stack := []group{{root.copies, parent}}
	for len(stack) > 0 {
		g := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if *budget -= 1; *budget < -maxChainLength {
			return k, fmt.Errorf("log: branches past %d records; refusing to resolve", maxChainLength)
		}
		var aum types.AUM
		signed := map[types.Identity]bool{}
		var children []types.Hash
		for i, h := range g.copies {
			c, err := r.AUM(h)
			if err != nil {
				return k, fmt.Errorf("log: reading %v: %w", h, err)
			}
			if i == 0 {
				aum = c
			}
			for j := range c.Signatures {
				signed[c.Signatures[j].KeyID] = true
			}
			ch, err := r.Children(h)
			if err != nil {
				return k, err
			}
			children = append(children, ch...)
		}
		if aum.Kind == types.KindDisable {
			continue
		}
		if aum.Kind == types.KindRemoveAdminKey {
			k.removed[*aum.Subject] = true
		}
		var next *State
		switch {
		case !withSigners:
		case !needed || g.parent == nil:
			k.signed = append(k.signed, signedRecord{&aum, signed, nil})
		default:
			at := g.parent.at(*aum.Prev)
			k.signed = append(k.signed, signedRecord{&aum, signed, at})
			if n, err := at.apply(&aum, g.copies[0], applyChain); err == nil {
				next = n
			}
		}
		groups, err := copyGroups(r, children)
		if err != nil {
			return k, err
		}
		for _, c := range groups {
			stack = append(stack, group{c, next})
		}
	}
	return k, nil
}
