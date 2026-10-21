package log

import (
	"errors"
	"fmt"
	"slices"

	"github.com/nning/juist/types"
)

// resolution is the outcome of walking the record DAG from an anchor.
type resolution struct {
	chain     []types.Hash
	state     *State
	orphans   []Orphan
	reachable map[types.Hash]bool

	// copies are the copies of the chain's records that have several.
	copies []types.Hash

	// listed is every member the chain named from the anchor on, with the
	// signing key it last had: at most the anchor's members and one per
	// record.
	listed map[types.Identity]types.SigningKey

	// tooNew is set when the walk stopped at an authorized schema upgrade
	// this build cannot implement. The state is the one before it.
	tooNew *SchemaTooNewError

	// disabled is the first disable record the walk met, chain first.
	disabled *DisabledError
}

// resolve computes the active chain and the branches off it. It is a pure
// function of the records reachable from the anchor — no clock, no randomness,
// no dependence on arrival or storage order — which is what makes two nodes
// holding the same records reach the same state.
func resolve(st reader, anchor types.Hash) (*resolution, error) {
	r := reader(hashOrdered{st})
	anchorAUM, err := r.AUM(anchor)
	if err != nil {
		return nil, fmt.Errorf("log: reading anchor %v: %w", anchor, err)
	}
	var state *State
	switch anchorAUM.Kind {
	case types.KindGenesis:
		if err := verifySelfSigned(&anchorAUM, types.KindGenesis); err != nil {
			return nil, fmt.Errorf("log: anchor genesis record: %w", err)
		}
		if state, err = applyGenesis(&anchorAUM, anchor); err != nil {
			return nil, err
		}
	case types.KindCheckpoint:
		if err := verifySelfSigned(&anchorAUM, types.KindCheckpoint); err != nil {
			return nil, fmt.Errorf("log: anchor checkpoint: %w", err)
		}
		if state, err = stateFromCheckpoint(&anchorAUM, anchor); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("log: anchor %v is a %v record; only genesis or a checkpoint can anchor a chain",
			anchor, anchorAUM.Kind)
	}

	// The anchor stands for its content: what hangs from any copy of it is on
	// its chain.
	anchors, err := anchorCopies(r, anchor, &anchorAUM)
	if err != nil {
		return nil, err
	}
	state = state.at(anchors[0])
	res := &resolution{
		chain:     []types.Hash{anchors[0]},
		reachable: map[types.Hash]bool{},
		listed:    make(map[types.Identity]types.SigningKey, len(state.nodes)),
	}
	for _, h := range anchors {
		res.reachable[h] = true
	}
	if len(anchors) > 1 {
		res.copies = append(res.copies, anchors...)
	}
	for id, n := range state.nodes {
		if n.Signing != nil {
			res.listed[id] = *n.Signing
		}
	}
	// A branch is recorded with the state it forks from; the state it is
	// probed against is the chain's, which is not known until the walk below.
	type pendingOrphan struct {
		root   candidate
		branch *State
	}
	var orphanRoots []pendingOrphan

	cur := anchors
	for range maxChainLength {
		valid, err := childrenOf(r, cur, state, res)
		if err != nil {
			return nil, err
		}
		if len(valid) == 0 {
			break
		}
		primary, err := pickPrimary(r, valid, state)
		if err != nil {
			return nil, err
		}
		for _, c := range valid {
			if c.hash == primary.hash {
				continue
			}
			if len(orphanRoots) >= maxOrphanBranches {
				return nil, fmt.Errorf("log: more than %d forks off the chain; refusing to resolve",
					maxOrphanBranches)
			}
			orphanRoots = append(orphanRoots, pendingOrphan{root: c, branch: state.at(*c.aum.Prev)})
		}
		// The chain names the copy the record that won hangs from.
		res.chain[len(res.chain)-1] = *primary.aum.Prev
		next, err := state.at(*primary.aum.Prev).apply(&primary.aum, primary.hash, applyChain)
		if err != nil {
			var tooNew *SchemaTooNewError
			if errors.As(err, &tooNew) {
				// The chain ends here for this build. The record itself is
				// authorized and reachable, so it is kept and relayed — a
				// node that cannot apply a record must still not swallow the
				// one that explains why. What follows it is not: this build
				// does not know the rules those records are judged by, and
				// storing unverified records would let any member fill a
				// stopped node's disk.
				for _, h := range primary.copies {
					res.reachable[h] = true
				}
				res.tooNew = tooNew
				break
			}
			return nil, fmt.Errorf("log: applying record %v (%v): %w",
				primary.hash, primary.aum.Kind, err)
		}
		state = next
		res.noteListed(state, &primary.aum)
		cur = primary.copies
		res.chain = append(res.chain, primary.hash)
		for _, h := range primary.copies {
			res.reachable[h] = true
		}
		if len(primary.copies) > 1 {
			res.copies = append(res.copies, primary.copies...)
		}
	}
	if len(res.chain) >= maxChainLength {
		return nil, fmt.Errorf("log: chain exceeds %d records; refusing to resolve", maxChainLength)
	}
	res.state = state

	// Branches are analyzed after the chain is known, because the question
	// each one answers is "could this be reissued on the head that won".
	budget := maxOrphanRecords
	for _, po := range orphanRoots {
		o := Orphan{Root: po.root.hash}
		if err := walkOrphan(r, po.root, po.branch, state, &o, &budget, res); err != nil {
			return nil, err
		}
		res.orphans = append(res.orphans, o)
	}
	if err := placeDisables(st, res); err != nil {
		return nil, err
	}
	return res, nil
}

// noteListed records the member a chain record admits or rotates to, with
// its signing key in s, the state after it.
func (res *resolution) noteListed(s *State, a *types.AUM) {
	var id types.Identity
	switch {
	case a.Kind == types.KindAddNode && a.Node != nil:
		id = a.Node.Identity
	case a.Kind == types.KindRotateIdentity && a.NewIdentity != nil:
		id = *a.NewIdentity
	default:
		return
	}
	if n, ok := s.nodes[id]; ok && n.Signing != nil {
		res.listed[id] = *n.Signing
	}
}

// followsDisable reports whether a record's parent is a disable record.
func followsDisable(r reader, a *types.AUM) bool {
	if a.Prev == nil {
		return false
	}
	parent, err := r.AUM(*a.Prev)
	return err == nil && parent.Kind == types.KindDisable
}

// placeDisables takes in the disable records the walk did not reach: hung
// below the anchor, past a schema this build stopped at, or deeper on a branch
// than the walk goes. Every state holds the commitments fixed at genesis, so
// a record revealing one of the secrets ends the network wherever it hangs.
func placeDisables(r reader, res *resolution) error {
	hashes, err := r.Hashes()
	if err != nil {
		return err
	}
	slices.SortFunc(hashes, types.Hash.Compare)
	for _, h := range hashes {
		if res.reachable[h] {
			continue
		}
		aum, err := r.AUM(h)
		if err != nil {
			return fmt.Errorf("log: reading %v: %w", h, err)
		}
		if aum.Kind == types.KindDisable && res.state.ValidDisablement(aum.Secret[:]) {
			res.noteDisabled(h)
		}
	}
	return nil
}

// noteDisabled records a verified disable record, which nothing descends from.
func (res *resolution) noteDisabled(h types.Hash) {
	res.reachable[h] = true
	if res.disabled == nil {
		res.disabled = &DisabledError{At: h}
	}
}

// hashOrdered returns children in hash order, which pickPrimary's rule needs:
// it is not transitive, so its result depends on the order it is given.
type hashOrdered struct{ reader }

func (o hashOrdered) Children(h types.Hash) ([]types.Hash, error) {
	children, err := o.reader.Children(h)
	slices.SortFunc(children, types.Hash.Compare)
	return children, err
}

// candidate is a sibling record, already read and verified, with its copies:
// hash, the lowest, first.
type candidate struct {
	hash    types.Hash
	sigHash types.Hash
	aum     types.AUM
	copies  []types.Hash
}

// at returns s as it stands after h, a copy of the record s is the state
// after.
func (s *State) at(h types.Hash) *State {
	if s.head == h {
		return s
	}
	c := s.clone()
	c.head = h
	return c
}

// childrenOf reads the records hanging from parents, copies of one record,
// verifies each against state, which is the state after that record, and
// returns them with their copies gathered, in the order fork choice reads
// them. Disable records are noted, not returned.
func childrenOf(r reader, parents []types.Hash, state *State, res *resolution) ([]candidate, error) {
	var children []types.Hash
	for _, p := range parents {
		ch, err := r.Children(p)
		if err != nil {
			return nil, err
		}
		children = append(children, ch...)
	}
	slices.SortFunc(children, types.Hash.Compare)
	var out []candidate
	index := map[types.Hash]int{}
	for _, ch := range children {
		child, err := r.AUM(ch)
		if err != nil {
			return nil, fmt.Errorf("log: reading %v: %w", ch, err)
		}
		if err := verifyAgainst(&child, state.at(*child.Prev)); err != nil {
			// Validity is a function of the parent state, which is a
			// function of the parent hash, so a stored record's verdict
			// never changes. One that fails now was never storable.
			return nil, fmt.Errorf("log: record %v (%v) is not authorized: %w",
				ch, child.Kind, err)
		}
		if child.Kind == types.KindDisable {
			res.noteDisabled(ch)
			continue
		}
		sh := child.SigHash()
		if i, ok := index[sh]; ok {
			out[i].copies = append(out[i].copies, ch)
			continue
		}
		index[sh] = len(out)
		out = append(out, candidate{hash: ch, sigHash: sh, aum: child, copies: []types.Hash{ch}})
	}
	if byContent(state) {
		slices.SortFunc(out, func(x, y candidate) int { return x.sigHash.Compare(y.sigHash) })
	}
	return out, nil
}

// stateFromCheckpoint builds state from a checkpoint used as a bootstrap
// anchor.
func stateFromCheckpoint(a *types.AUM, hash types.Hash) (*State, error) {
	return adoptSnapshot(a.State, hash, "checkpoint")
}
