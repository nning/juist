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

	// Unrevoked are the branch's revocations that are not in effect: they
	// lost fork choice, and could be reissued on the current head. They do
	// not stop the network, as a conflict does, and are to be reissued.
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

// walkOrphan decides whether a record on a branch that lost fork choice,
// verified against branch, merely needs reissuing or genuinely conflicts, and
// walks on to what hangs from it. Two states are carried down the branch:
// branch, which every record must verify against, since a branch of
// unauthorized records is a corrupt store rather than a fork; and probe, the
// result of replaying the branch's substance onto the chain that won.
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
		// A revocation on a losing branch is what the bias exists to prevent;
		// it gets here below a sibling that won on it too, as two concurrent
		// removals do. One that the chosen chain can take is not in effect
		// until reissued, which is said rather than stopping the network;
		// one it cannot take is a conflict.
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
