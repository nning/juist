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

// pickPrimary applies fork choice to a set of valid siblings of parent: a
// revocation beats anything else, otherwise the lower hash wins, from
// [types.SchemaContentForkChoice] on the lower [types.AUM.SigHash]. Signature
// weight is deliberately not part of the rule — every change already needs
// quorum, so weight would only let one quorum outbid another by collecting
// extras.
//
// One rule comes first: a branch loses to a sibling whose branch removes an
// admin key that signed anything on it. An admin key removed at some point
// could otherwise sign a sibling rooted before its removal, win on the
// revocation bias or a ground hash, and undo its own removal with everything
// after it.
func pickPrimary(r reader, candidates []candidate, parent *State) (candidate, error) {
	// Walking each branch on a chain without forks makes resolution quadratic.
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	keys := make([]branchKeys, len(candidates))
	removes := false
	budget := maxOrphanRecords
	for i := range candidates {
		k, err := keysOfBranch(r, candidates[i], parent, false, &budget)
		if err != nil {
			return candidate{}, err
		}
		keys[i] = k
		removes = removes || len(k.removed) > 0
	}
	// Signers take states to tell, and matter only where a branch removes a
	// key.
	if removes {
		budget = maxOrphanRecords
		for i := range candidates {
			k, err := keysOfBranch(r, candidates[i], parent, true, &budget)
			if err != nil {
				return candidate{}, err
			}
			keys[i] = k
		}
	}
	// undone reports whether the branch at i signs with a key the branch at
	// j removes.
	undone := func(i, j int) bool {
		for id := range keys[i].signers {
			if keys[j].removed[id] {
				return true
			}
		}
		return false
	}
	lower := func(c, b *candidate) bool { return c.hash.Compare(b.hash) < 0 }
	if byContent(parent) {
		lower = func(c, b *candidate) bool { return c.sigHash.Compare(b.sigHash) < 0 }
	}
	best := 0
	for i := 1; i < len(candidates); i++ {
		c, b := &candidates[i], &candidates[best]
		cUndone, bUndone := undone(i, best), undone(best, i)
		rev, bestRev := parent.Revokes(&c.aum), parent.Revokes(&b.aum)
		switch {
		case cUndone != bUndone:
			if bUndone {
				best = i
			}
		case rev != bestRev:
			if rev {
				best = i
			}
		case lower(c, b):
			best = i
		}
	}
	return candidates[best], nil
}

// branchKeys are the admin keys that signed a branch's records, and those
// its records remove.
type branchKeys struct {
	signers, removed map[types.Identity]bool
}

// keysOfBranch collects branchKeys, the signers only withSigners, over every
// stored record from root, whose parent is parent, on, within budget: the
// chain ahead of a fork is at most as long as the chain. A record's signers
// are the keys any copy of it carries; from [types.SchemaContentForkChoice] on
// only those it needs ([neededSigners]), so a key that adds its signature to
// a record others authorized does not make the record its own.
func keysOfBranch(r reader, root candidate, parent *State, withSigners bool, budget *int) (branchKeys, error) {
	k := branchKeys{signers: map[types.Identity]bool{}, removed: map[types.Identity]bool{}}
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
			maps.Copy(k.signers, signed)
		default:
			at := g.parent.at(*aum.Prev)
			for _, id := range neededSigners(&aum, at, signed) {
				k.signers[id] = true
			}
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

// neededSigners returns the keys of signed, the signers of a, whose
// signature a needs under parent: one its kind requires, or an admin key
// without whose vote the others fall short of quorum.
func neededSigners(a *types.AUM, parent *State, signed map[types.Identity]bool) []types.Identity {
	self := SelfSigners(a)
	admins := parent.Admins()
	var out []types.Identity
	for id := range signed {
		if slices.Contains(self, id) {
			out = append(out, id)
			continue
		}
		if _, ok := parent.admins[id]; !ok {
			continue
		}
		without := types.CountVotes(admins, func(x types.Identity) bool { return x != id && signed[x] })
		if without < parent.quorum {
			out = append(out, id)
		}
	}
	return out
}
