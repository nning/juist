// Package log implements the membership log: the hash-chained, admin-signed
// record of who belongs to the network, fully replicated and independently
// verified by every node.
//
// It is the largest piece of the trusted computing base
// (docs/04-architecture.md). Everything below it — gossip, the DHT, mDNS,
// relays, magicsock — can delay or deny connectivity but can never change who
// is a member: records are self-certifying, so the transport that moves them
// is untrusted by construction.
//
// # What is taken from tka, and what is not
//
// The design generalizes Tailscale's tailnet key authority, whose Go
// implementation is production-tested and BSD-3 licensed
// (docs/03-control-plane-options.md picks it as option E). Taken from it: the
// hash-chained record with a fixed canonical encoding, keys carrying vote
// weights with the policy checked at verification time rather than in
// threshold crypto, checkpoints as quorum-signed compactions, pre-committed
// break-glass preimages, and the discipline for evolving the schema.
//
// Not taken: the code. tka's record set describes a *key* authority — which
// keys may vouch for node keys — and authorizes a change on a single trusted
// signature, leaving ordering and distribution to the coordination server it
// was built to distrust for everything else. This log instead holds the
// members themselves, requires k-of-n on every change, and has to supply the
// ordering and anti-fork machinery tka gets from a server:
//
//   - deterministic fork choice, so every node picks the same chain;
//   - a fork alarm, so a fork that cannot be resolved deterministically is
//     escalated to an operator rather than papered over;
//   - a node-local anchor and epoch floor, so a node cannot be walked
//     backwards past a checkpoint it holds or an epoch it has seen.
//
// That is the new security-critical code docs/03-control-plane-options.md
// predicted would have to be written and audited.
//
// # Fork choice, and its limits
//
// Two records with the same parent are siblings; a linear chain can keep only
// one. The choice is deterministic so that every honest node reaches the same
// chain from the same records: a revocation beats a non-revocation ("revoked
// wins", the safety bias), and otherwise the lower record hash wins.
//
// The loser is not lost, but it is not applied either: its author has to
// reissue it against the new head. Where that reissue would fail — the two
// branches disagree about the same member, or the orphaned branch contains a
// revocation that would vanish — the fork is a genuine conflict, and this
// package raises a persistent alarm instead of choosing. Nothing prevents a
// colluding quorum from creating such a fork in the first place; cross-gossiped
// heads expose it after the fact, and global consensus is the only thing that
// would prevent it (docs/02-threat-model.md, residual weakness 3).
package log

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/types"
)

// Bounds on how much work resolving a chain may cost. A store this large means
// either a network far outside the target scale or a local compromise, and
// either way failing loudly beats grinding.
const (
	maxChainLength    = 1 << 17
	maxOrphanRecords  = 4096
	maxOrphanBranches = 64
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
}

// An Alarm is a condition an operator has to resolve. While one is raised,
// [Authority.TrustedState] refuses to hand out membership state: a node that
// cannot tell who is a member must not guess, and the fail-closed direction is
// the one that does not admit a revoked device.
type Alarm struct {
	// Forks are the conflicting branches.
	Forks []Orphan
}

func (a *Alarm) Error() string {
	var b strings.Builder
	b.WriteString("log: fork alarm: ")
	for i, f := range a.Forks {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "branch at %v (%d records): %s", f.Root, len(f.Records), f.Conflict)
	}
	b.WriteString(" — admin action required")
	return b.String()
}

// A RollbackError reports a set of records that would have moved this node to
// a chain with a lower group-secret epoch than one it has already adopted.
//
// Nothing is stored when this is returned. Reaching an older epoch through
// records that are individually valid takes admin signatures, so this is what
// a quorum rewriting history looks like from a node that saw the earlier
// version — the case docs/02-threat-model.md accepts cannot be prevented, only
// detected and refused.
type RollbackError struct {
	// Floor is the highest epoch this node has adopted.
	Floor uint64

	// Offered is the epoch the rejected chain resolves to.
	Offered uint64

	// Records are the rejected records, so a caller can preserve them as
	// evidence even though they were not stored.
	Records []types.AUM
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf(
		"log: refusing records that would move the chain from epoch %d back to epoch %d; "+
			"this requires admin signatures, so treat it as a fork or a compromised quorum",
		e.Floor, e.Offered)
}

// An Authority is a node's view of the membership log.
//
// Not safe for concurrent use; callers that share one serialize access. The
// reconciler that will drive the data plane from it (M2) is a single loop by
// design.
type Authority struct {
	storage Storage
	anchor  types.Hash
	state   *State
	orphans []Orphan
	alarm   *Alarm

	// reachable is the set of records the last adopted resolution covered.
	// Anything stored and absent from it is a leftover from an interrupted
	// compaction: harmless, since resolution never looks at it, and removed
	// by the next Compact.
	reachable map[types.Hash]bool
}

// Create initializes a new network from a genesis record and makes it the
// anchor.
//
// The storage must be empty. Refusing to re-genesis over existing state is
// deliberate (docs/04-architecture.md): a node that has lost its log must be
// recovered or re-enrolled, never quietly promoted to the founder of a new
// network that happens to share its name.
func Create(st Storage, genesis types.AUM) (*Authority, error) {
	if _, ok, err := st.Anchor(); err != nil {
		return nil, err
	} else if ok {
		return nil, errors.New("log: storage already holds a network; refusing to create another")
	}
	if stored, err := st.Hashes(); err != nil {
		return nil, err
	} else if len(stored) != 0 {
		return nil, errors.New("log: storage already holds records; refusing to create a network over them")
	}
	if err := verifyGenesis(&genesis); err != nil {
		return nil, err
	}
	// Reject a genesis whose state is unusable before it is written, so a
	// failed ceremony leaves nothing behind.
	if _, err := applyGenesis(&genesis, genesis.Hash()); err != nil {
		return nil, err
	}
	if err := st.Add(genesis); err != nil {
		return nil, err
	}
	if err := st.SetAnchor(genesis.Hash()); err != nil {
		return nil, err
	}
	return Open(st)
}

// Bootstrap initializes a node from a quorum-signed checkpoint, for joining a
// network whose history this node does not have.
//
// The checkpoint's signatures are checked against the admin keys it declares,
// which is the one place this package takes history on the signers' word —
// there is no ancestry to check it against. A node that later receives the
// ancestry verifies the checkpoint against the state the chain produces, and a
// checkpoint that does not match is rejected there.
func Bootstrap(st Storage, checkpoint types.AUM) (*Authority, error) {
	if _, ok, err := st.Anchor(); err != nil {
		return nil, err
	} else if ok {
		return nil, errors.New("log: storage already holds a network; refusing to bootstrap over it")
	}
	if err := verifyCheckpointSelfSigned(&checkpoint); err != nil {
		return nil, err
	}
	hash := checkpoint.Hash()
	if _, err := stateFromCheckpoint(&checkpoint, hash); err != nil {
		return nil, err
	}
	floor, err := st.EpochFloor()
	if err != nil {
		return nil, err
	}
	if checkpoint.State.Epoch < floor {
		return nil, &RollbackError{Floor: floor, Offered: checkpoint.State.Epoch,
			Records: []types.AUM{checkpoint}}
	}
	if err := st.Add(checkpoint); err != nil {
		return nil, err
	}
	if err := st.SetAnchor(hash); err != nil {
		return nil, err
	}
	return Open(st)
}

// Open loads the authority from storage and resolves the active chain.
func Open(st Storage) (*Authority, error) {
	anchor, ok, err := st.Anchor()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("log: storage holds no network; use Create or Bootstrap")
	}
	a := &Authority{storage: st, anchor: anchor}
	res, err := resolve(st, anchor)
	if err != nil {
		return nil, err
	}
	floor, err := st.EpochFloor()
	if err != nil {
		return nil, err
	}
	if res.state.epoch < floor {
		// Reached only if the floor was raised and the store then lost
		// records, which is corruption rather than an attack: an attacker
		// cannot remove records we already hold.
		return nil, fmt.Errorf(
			"log: stored chain resolves to epoch %d but this node has adopted epoch %d; "+
				"the log is incomplete or corrupt", res.state.epoch, floor)
	}
	a.adopt(res)
	if err := st.SetEpochFloor(res.state.epoch); err != nil {
		return nil, err
	}
	return a, nil
}

// Inform verifies records, stores them, and re-resolves the chain.
//
// Records are accepted from any transport: they carry their own proof, so
// gossip, an enrollment channel or a DHT pointer are all equally (un)trusted
// (docs/04-architecture.md). Order them oldest first — every record's parent
// must already be stored or appear earlier in the batch.
//
// Either the whole batch is stored or none of it is. Nothing is stored unless
// every record in it turned out to be a verified, reachable part of the
// resulting chain or of a branch off it.
func (a *Authority) Inform(aums ...types.AUM) error {
	if len(aums) == 0 {
		return nil
	}
	ov, err := newOverlay(a.storage, aums)
	if err != nil {
		return err
	}
	pending := ov.pending()
	if len(pending) == 0 {
		return nil // everything offered is already held
	}
	res, err := resolve(ov, a.anchor)
	if err != nil {
		return err
	}
	// Every offered record has to have been verified during resolution.
	// A record whose parent is unknown is unreachable from the anchor, and
	// accepting it into storage would leave a dangling record that a later
	// resolution would never look at — a quiet way to be told nothing.
	for i := range pending {
		h := pending[i].Hash()
		if !res.reachable[h] {
			return fmt.Errorf(
				"log: record %v (%v) does not descend from this node's anchor %v; "+
					"send its ancestors first", h, pending[i].Kind, a.anchor)
		}
	}
	floor, err := a.storage.EpochFloor()
	if err != nil {
		return err
	}
	if res.state.epoch < floor {
		return &RollbackError{Floor: floor, Offered: res.state.epoch, Records: pending}
	}
	if err := a.storage.Add(pending...); err != nil {
		return err
	}
	// Re-resolve from storage rather than adopting the overlay's result. The
	// overlay says what *would* happen if the records were stored; only this
	// says what storage can actually reproduce. A store that dropped part of
	// the batch — a crash mid-write, a full disk — must not leave the epoch
	// floor raised above a chain it can no longer produce, because that is a
	// node that refuses to start.
	committed, err := resolve(a.storage, a.anchor)
	if err != nil {
		return fmt.Errorf("log: re-reading the chain after storing records: %w", err)
	}
	if committed.state.epoch < floor {
		return fmt.Errorf(
			"log: after storing records the chain resolves to epoch %d, below the adopted %d; "+
				"storage did not durably accept the batch", committed.state.epoch, floor)
	}
	if err := a.storage.SetEpochFloor(committed.state.epoch); err != nil {
		return err
	}
	a.adopt(committed)
	return nil
}

func (a *Authority) adopt(res *resolution) {
	a.state = res.state
	a.orphans = res.orphans
	a.reachable = res.reachable
	var conflicts []Orphan
	for _, o := range res.orphans {
		if o.Conflict != "" {
			conflicts = append(conflicts, o)
		}
	}
	if len(conflicts) > 0 {
		a.alarm = &Alarm{Forks: conflicts}
	} else {
		a.alarm = nil
	}
}

// Head returns the hash of the current head record.
func (a *Authority) Head() types.Hash { return a.state.head }

// Anchor returns the record the active chain is computed from.
func (a *Authority) Anchor() types.Hash { return a.anchor }

// State returns the current authority state, for inspection. It is returned
// even while an alarm is raised, so that an operator can see what the fork
// did; use [Authority.TrustedState] for anything that grants access.
func (a *Authority) State() *State { return a.state }

// TrustedState returns the authority state, or an error while an alarm is
// raised.
//
// This is the accessor anything that grants access must use — building a peer
// set, answering "is this node a member". Failing closed on an unresolved fork
// is the same trade docs/02-threat-model.md makes for freshness: where
// security and availability conflict, deny.
func (a *Authority) TrustedState() (*State, error) {
	if a.alarm != nil {
		return nil, a.alarm
	}
	return a.state, nil
}

// Alarm returns the current alarm, or nil.
func (a *Authority) Alarm() *Alarm { return a.alarm }

// Orphans returns every branch that lost fork choice, including the benign
// ones whose records only need reissuing.
func (a *Authority) Orphans() []Orphan { return slices.Clone(a.orphans) }

// Unreachable reports how many stored records the anchor cannot reach —
// leftovers from an interrupted compaction, cleaned up by [Authority.Compact].
func (a *Authority) Unreachable() (int, error) {
	stored, err := a.storage.Hashes()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range stored {
		if !a.reachable[h] {
			n++
		}
	}
	return n, nil
}

// Chain returns the active chain's record hashes, anchor first.
func (a *Authority) Chain() ([]types.Hash, error) {
	res, err := resolve(a.storage, a.anchor)
	if err != nil {
		return nil, err
	}
	return res.chain, nil
}

// Compact advances the anchor to the newest checkpoint on the active chain and
// deletes everything the new anchor cannot reach, returning the number of
// records removed.
//
// Advancing the anchor is also a ratchet: a chain that does not descend from
// it is not considered at all afterwards, which is what "never drop a
// checkpoint you hold" means in practice. Compaction is refused while an alarm
// is raised — discarding history is the last thing to do with an unresolved
// fork.
func (a *Authority) Compact() (int, error) {
	if a.alarm != nil {
		return 0, a.alarm
	}
	res, err := resolve(a.storage, a.anchor)
	if err != nil {
		return 0, err
	}
	newAnchor := a.anchor
	for _, h := range res.chain {
		rec, err := a.storage.AUM(h)
		if err != nil {
			return 0, err
		}
		if rec.Kind == types.KindCheckpoint {
			newAnchor = h
		}
	}
	if newAnchor != a.anchor {
		if err := a.storage.SetAnchor(newAnchor); err != nil {
			return 0, err
		}
		a.anchor = newAnchor
		if res, err = resolve(a.storage, newAnchor); err != nil {
			return 0, err
		}
	}
	// Anything the anchor cannot reach is unreachable for good: resolution
	// starts there and never walks past it.
	stored, err := a.storage.Hashes()
	if err != nil {
		return 0, err
	}
	var stale []types.Hash
	for _, h := range stored {
		if !res.reachable[h] {
			stale = append(stale, h)
		}
	}
	if len(stale) > 0 {
		if err := a.storage.Delete(stale...); err != nil {
			return 0, err
		}
		if res, err = resolve(a.storage, a.anchor); err != nil {
			return 0, err
		}
	}
	a.adopt(res)
	return len(stale), nil
}

// resolution is the outcome of walking the record DAG from an anchor.
type resolution struct {
	chain     []types.Hash
	state     *State
	orphans   []Orphan
	reachable map[types.Hash]bool
}

// resolve computes the active chain and the branches off it.
//
// It is a pure function of the records reachable from the anchor: no clock, no
// randomness, no dependence on the order records arrived or the order storage
// returns children in. That is what makes two nodes holding the same records
// reach the same state, which docs/06-verification.md asserts as a
// determinism test.
func resolve(r reader, anchor types.Hash) (*resolution, error) {
	anchorAUM, err := r.AUM(anchor)
	if err != nil {
		return nil, fmt.Errorf("log: reading anchor %v: %w", anchor, err)
	}
	var state *State
	switch anchorAUM.Kind {
	case types.KindGenesis:
		if err := verifyGenesis(&anchorAUM); err != nil {
			return nil, fmt.Errorf("log: anchor genesis record: %w", err)
		}
		if state, err = applyGenesis(&anchorAUM, anchor); err != nil {
			return nil, err
		}
	case types.KindCheckpoint:
		if err := verifyCheckpointSelfSigned(&anchorAUM); err != nil {
			return nil, fmt.Errorf("log: anchor checkpoint: %w", err)
		}
		if state, err = stateFromCheckpoint(&anchorAUM, anchor); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("log: anchor %v is a %v record; only genesis or a checkpoint can anchor a chain",
			anchor, anchorAUM.Kind)
	}

	res := &resolution{
		chain:     []types.Hash{anchor},
		reachable: map[types.Hash]bool{anchor: true},
	}
	// A branch is recorded with the state it forks from; the state it is
	// probed against is the chain's, which is not known until the walk below.
	type pendingOrphan struct {
		root   types.Hash
		branch *State
	}
	var orphanRoots []pendingOrphan

	cur := anchor
	for range maxChainLength {
		children, err := r.Children(cur)
		if err != nil {
			return nil, err
		}
		valid := make([]candidate, 0, len(children))
		for _, ch := range children {
			child, err := r.AUM(ch)
			if err != nil {
				return nil, fmt.Errorf("log: reading %v: %w", ch, err)
			}
			if err := verifyAgainst(&child, state); err != nil {
				// Validity is a function of the parent state, which is a
				// function of the parent hash, so a stored record's verdict
				// never changes. One that fails now was never storable.
				return nil, fmt.Errorf("log: record %v (%v) is not authorized: %w",
					ch, child.Kind, err)
			}
			valid = append(valid, candidate{hash: ch, aum: child})
		}
		if len(valid) == 0 {
			break
		}
		primary := pickPrimary(valid)
		for _, c := range valid {
			ch := c.hash
			if ch == primary.hash {
				continue
			}
			if len(orphanRoots) >= maxOrphanBranches {
				return nil, fmt.Errorf("log: more than %d forks off the chain; refusing to resolve",
					maxOrphanBranches)
			}
			orphanRoots = append(orphanRoots, pendingOrphan{root: ch, branch: state})
		}
		next, err := state.apply(&primary.aum, primary.hash, applyChain)
		if err != nil {
			return nil, fmt.Errorf("log: applying record %v (%v): %w",
				primary.hash, primary.aum.Kind, err)
		}
		state = next
		cur = primary.hash
		res.chain = append(res.chain, primary.hash)
		res.reachable[primary.hash] = true
	}
	if len(res.chain) >= maxChainLength {
		return nil, fmt.Errorf("log: chain exceeds %d records; refusing to resolve", maxChainLength)
	}
	res.state = state

	// Branches are analyzed after the chain is known, because the question
	// each one answers is "could this be reissued on the head that won".
	budget := maxOrphanRecords
	for _, po := range orphanRoots {
		o := Orphan{Root: po.root}
		if err := walkOrphan(r, po.root, po.branch, state, &o, &budget, res.reachable); err != nil {
			return nil, err
		}
		res.orphans = append(res.orphans, o)
	}
	return res, nil
}

// candidate is a sibling record, already read and verified.
type candidate struct {
	hash types.Hash
	aum  types.AUM
}

// pickPrimary applies fork choice to a set of valid siblings.
//
// A revocation beats anything else, so a removal is never the branch that gets
// orphaned; otherwise the lower hash wins, which is arbitrary but identical
// everywhere. Deliberately *not* part of the rule: signature weight, which tka
// uses. Every change here already needs quorum, so weight would only let one
// quorum outbid another by collecting extra signatures — a tie-break that
// invites grinding and explains nothing to an operator reading the log.
func pickPrimary(candidates []candidate) candidate {
	best := candidates[0]
	for _, c := range candidates[1:] {
		rev, bestRev := c.aum.Kind.IsRevocation(), best.aum.Kind.IsRevocation()
		switch {
		case rev != bestRev:
			if rev {
				best = c
			}
		case compareHash(c.hash, best.hash) < 0:
			best = c
		}
	}
	return best
}

// walkOrphan verifies a branch that lost fork choice and decides whether it
// merely needs reissuing or genuinely conflicts.
//
// Two states are carried down the branch. branch is the real state along it,
// which every record must verify against — a branch full of unauthorized
// records is a corrupt store, not a fork. probe is the state that results from
// replaying the branch's substance onto the chain that won; where that fails,
// the two branches disagree about something concrete and no deterministic rule
// should be picking between them.
func walkOrphan(r reader, h types.Hash, branch, probe *State, o *Orphan, budget *int, reachable map[types.Hash]bool) error {
	if *budget <= 0 {
		if o.Conflict == "" {
			o.Conflict = fmt.Sprintf("branch exceeds %d records; too large to analyze", maxOrphanRecords)
		}
		return nil
	}
	*budget--

	aum, err := r.AUM(h)
	if err != nil {
		return fmt.Errorf("log: reading %v: %w", h, err)
	}
	if err := verifyAgainst(&aum, branch); err != nil {
		return fmt.Errorf("log: record %v (%v) on a branch is not authorized: %w", h, aum.Kind, err)
	}
	nextBranch, err := branch.apply(&aum, h, applyChain)
	if err != nil {
		return fmt.Errorf("log: applying branch record %v (%v): %w", h, aum.Kind, err)
	}
	o.Records = append(o.Records, h)
	reachable[h] = true

	var nextProbe *State
	switch {
	case aum.Kind.IsRevocation():
		// A revocation on a branch that lost is the one outcome fork choice
		// must never produce silently: the whole point of the bias is that a
		// removal is not quietly dropped. It can only get here below a
		// sibling that also won on that bias, i.e. in a genuine fork.
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

	children, err := r.Children(h)
	if err != nil {
		return err
	}
	for _, ch := range children {
		if err := walkOrphan(r, ch, nextBranch, nextProbe, o, budget, reachable); err != nil {
			return err
		}
	}
	return nil
}

func revocationSubject(a *types.AUM) string {
	if a.Subject != nil {
		return a.Subject.ShortString()
	}
	return "an unnamed subject"
}

// stateFromCheckpoint builds state from a checkpoint used as a bootstrap
// anchor.
func stateFromCheckpoint(a *types.AUM, hash types.Hash) (*State, error) {
	if a.State.GenesisHash == nil {
		return nil, errors.New("log: checkpoint has no genesis hash")
	}
	if err := a.State.StaticValidate(false); err != nil {
		return nil, fmt.Errorf("log: checkpoint state: %w", err)
	}
	if err := a.State.ValidateInNetwork(); err != nil {
		return nil, fmt.Errorf("log: checkpoint state: %w", err)
	}
	return stateFromSnapshot(a.State, hash)
}
