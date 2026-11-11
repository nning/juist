package log

import (
	"fmt"

	"github.com/nning/juist/types"
)

// An Orphan is a branch that lost fork choice.
type Orphan struct {
	// Root is the sibling record where the branch diverges from the chain.
	Root types.Hash

	// Records are the branch's records, oldest first.
	Records []types.Hash

	// Conflict explains why the branch cannot simply be reissued on the
	// current head, or is empty if it can.
	Conflict string

	// Unrevoked are the branch's revocations that lost fork choice but can be
	// reissued on the current head. Unlike a conflict they do not stop the
	// network.
	Unrevoked []types.Hash
}

// floorBranch returns the root of the first orphaned branch with a record at
// epoch floor or past it, or zero.
func floorBranch(st reader, orphans []Orphan, floor uint64) (types.Hash, error) {
	for _, o := range orphans {
		for _, h := range o.Records {
			aum, err := st.AUM(h)
			if err != nil {
				return types.Hash{}, err
			}
			if aum.Epoch != nil && aum.Epoch.Epoch >= floor {
				return o.Root, nil
			}
		}
	}
	return types.Hash{}, nil
}

// walkOrphan decides whether a record on a losing branch needs reissuing or
// conflicts, then walks its children. Every record must verify against branch
// (unauthorized records mean a corrupt store, not a fork); probe replays the
// branch onto the winning chain.
func walkOrphan(r reader, c candidate, branch, probe *State, o *Orphan, budget *int, res *resolution) error {
	if *budget <= 0 {
		if o.Conflict == "" {
			o.Conflict = fmt.Sprintf("branch exceeds %d records; too large to analyze", maxOrphanRecords)
		}
		return nil
	}
	*budget--

	h, aum := c.hash, c.aum
	nextBranch, err := branch.apply(&aum, h, applyChain)
	if err != nil {
		return fmt.Errorf("log: applying branch record %v (%v): %w", h, aum.Kind, err)
	}
	o.Records = append(o.Records, h)
	for _, cp := range c.copies {
		res.reachable[cp] = true
	}

	var nextProbe *State
	switch {
	case branch.Revokes(&aum) && probe != nil && probe.alreadyRevoked(&aum):
		// Lost, but what it withdraws is withdrawn on the chosen chain too:
		// two admins removing one device at once.
		nextProbe = probe
	case branch.Revokes(&aum) && probe != nil:
		// Lost to a sibling that also revokes. If the chosen chain can take
		// it, it is reported for reissue; otherwise it is a conflict.
		nextProbe, err = probe.apply(&aum, h, applyProbe)
		switch {
		case err != nil && o.Conflict == "":
			o.Conflict = fmt.Sprintf("record %v revokes %s and cannot be reissued on the chosen chain: %v",
				h, revocationSubject(&aum), err)
		case err == nil:
			o.Unrevoked = append(o.Unrevoked, h)
		}
	case branch.Revokes(&aum):
		if o.Conflict == "" {
			o.Conflict = fmt.Sprintf("record %v revokes %s and would be discarded", h, revocationSubject(&aum))
		}
	case probe == nil:
		// Already conflicting further up; nothing more to learn.
	default:
		nextProbe, err = probe.apply(&aum, h, applyProbe)
		if err != nil && o.Conflict == "" {
			o.Conflict = fmt.Sprintf("record %v (%v) cannot be reissued on the chosen chain: %v",
				h, aum.Kind, err)
		}
	}

	children, err := childrenOf(r, c.copies, nextBranch, res)
	if err != nil {
		return err
	}
	for _, ch := range children {
		if err := walkOrphan(r, ch, nextBranch.at(*ch.aum.Prev), nextProbe, o, budget, res); err != nil {
			return err
		}
	}
	return nil
}

func revocationSubject(a *types.AUM) string {
	switch {
	case a.Kind == types.KindSetNodeRoutes && a.Subject != nil:
		return "the admin role of " + a.Subject.ShortString()
	case a.Kind == types.KindSetVouchers:
		return "vouching authority (a raised vouching threshold)"
	case a.Kind == types.KindSetHolder:
		return "authority of " + a.Holder.Name + " (fewer votes, or more keys needed)"
	case a.Kind == types.KindSetQuorum:
		return "authority of every smaller coalition (a raised quorum)"
	case a.Subject != nil:
		return a.Subject.ShortString()
	}
	return "an unnamed subject"
}
