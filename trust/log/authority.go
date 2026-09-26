// Package log implements the membership log: the hash-chained, admin-signed
// record of who belongs to the network, fully replicated and independently
// verified by every node. It is the largest piece of the trusted computing
// base. Everything below it can delay or deny connectivity but never change
// who is a member, since records are self-certifying.
//
// The design generalizes Tailscale's tailnet key authority (see
// docs/08-trust-layer-notes.md). With no coordination server to order the log,
// this package also supplies deterministic fork choice, a fork alarm, and a
// node-local anchor and epoch floor so a node cannot be walked backwards.
//
// Fork choice: of two records with the same parent, a revocation wins, and
// otherwise the lower hash. The loser is kept but not applied, and its author
// reissues it against the new head; where that would fail, the fork is a
// genuine conflict and this package alarms rather than choosing.
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

	// Unrevoked are the branch's revocations that are not in effect: they
	// lost fork choice, and could be reissued on the current head. They do
	// not stop the network, as a conflict does, and are to be reissued.
	Unrevoked []types.Hash
}

// An Alarm is a condition an operator has to resolve. While one is raised,
// [Authority.TrustedState] refuses to hand out membership state: a node that
// cannot tell who is a member must not guess.
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

// A RollbackError reports records that would have moved this node to a chain
// with a lower group-secret epoch than one it has adopted. Nothing is stored.
// Reaching an older epoch through individually valid records takes admin
// signatures, so this is what a quorum rewriting history looks like.
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

// A SchemaTooNewError reports that a quorum has moved the network to a record
// schema this build does not implement. It is not a refusal of the record —
// the record is authorized and the network really has moved — but a statement
// that this node stops here. Nothing after it can be interpreted: a later
// record may carry a kind or a field this build has never heard of, and acting
// on the part it understands is the split view the closed record set exists to
// prevent.
//
// Unlike a fork alarm this does not withdraw membership state. The state the
// node holds was correct up to the upgrade, and tearing every tunnel down the
// moment an admin raises the schema would turn a planned change into an
// outage. What bounds how long that state may be acted on is the freshness
// TTL, which is M4's.
type SchemaTooNewError struct {
	// Version is the schema the network moved to, Implemented the newest this
	// build can act on, and At the record that made the change.
	Version     types.SchemaVersion
	Implemented types.SchemaVersion
	At          types.Hash
}

func (e *SchemaTooNewError) Error() string {
	return fmt.Sprintf(
		"log: the network moved to %v in record %v and this build implements %v; "+
			"this device holds the state up to that record and can apply nothing after it — "+
			"install a newer juist",
		e.Version, e.At, e.Implemented)
}

// An Authority is a node's view of the membership log. Not safe for concurrent
// use; callers that share one serialize access.
type Authority struct {
	storage Storage
	anchor  types.Hash
	state   *State
	orphans []Orphan
	alarm   *Alarm
	tooNew  *SchemaTooNewError

	// reachable is the set of records the last adopted resolution covered.
	// Anything stored and absent from it is a leftover from an interrupted
	// compaction, harmless and removed by the next Compact.
	reachable map[types.Hash]bool

	// onChain is the active chain of the last adopted resolution.
	onChain map[types.Hash]bool
}

// Create initializes a new network from a genesis record and makes it the
// anchor. The storage must be empty: a node that has lost its log must be
// recovered or re-enrolled, never promoted to the founder of a new network.
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
	if err := verifySelfSigned(&genesis, types.KindGenesis); err != nil {
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
// network whose history this node does not have. Its signatures are checked
// against the admin keys it declares — the one place this package takes
// history on the signers' word, there being no ancestry to check. A node that
// later receives the ancestry re-verifies it against what the chain produces.
func Bootstrap(st Storage, checkpoint types.AUM) (*Authority, error) {
	if _, ok, err := st.Anchor(); err != nil {
		return nil, err
	} else if ok {
		return nil, errors.New("log: storage already holds a network; refusing to bootstrap over it")
	}
	if err := verifySelfSigned(&checkpoint, types.KindCheckpoint); err != nil {
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
	if err := checkFloors(st, res); err != nil {
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
	if err := st.SetSchemaFloor(res.state.schema); err != nil {
		return nil, err
	}
	return a, nil
}

// checkFloors refuses a resolution that sits below a ratchet this node has
// already adopted. The schema floor is checked before the epoch one because a
// build too old for the network resolves to whatever came before the upgrade,
// and reporting that as a rollback would send an operator looking for a
// compromised quorum instead of for a newer binary.
func checkFloors(st Storage, res *resolution) error {
	schemaFloor, err := st.SchemaFloor()
	if err != nil {
		return err
	}
	if res.state.schema < schemaFloor {
		if res.tooNew != nil {
			return res.tooNew
		}
		return fmt.Errorf(
			"log: the chain resolves to %v but this node has adopted %v; "+
				"a schema is raised by a quorum-signed record and never lowered, "+
				"so treat this as a fork or a compromised quorum",
			res.state.schema, schemaFloor)
	}
	return nil
}

// Inform verifies records, stores them, and re-resolves the chain. Records are
// accepted from any transport, since they carry their own proof; order them
// oldest first. A refused batch stores nothing; one that fails in [Storage.Add]
// may be stored in part, which the next resolution of the store picks up.
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
	// Every offered record must have been verified during resolution: one
	// whose parent is unknown is unreachable from the anchor, and storing it
	// would leave a dangling record no later resolution looks at.
	//
	// A chain that stopped at an unreadable schema is the exception. Records
	// past the stop point are unverifiable rather than dangling, so they are
	// dropped from the batch instead of failing it: failing it would also
	// discard the upgrade record, and the node would see nothing but sync
	// going quiet.
	if res.tooNew != nil {
		kept := pending[:0]
		for i := range pending {
			if res.reachable[pending[i].Hash()] {
				kept = append(kept, pending[i])
			}
		}
		pending = kept
		if len(pending) == 0 {
			a.adopt(res)
			return nil
		}
	} else {
		for i := range pending {
			h := pending[i].Hash()
			if !res.reachable[h] {
				return reject(RuleParent, fmt.Errorf(
					"log: record %v (%v) does not descend from this node's anchor %v; "+
						"send its ancestors first", h, pending[i].Kind, a.anchor))
			}
		}
	}
	if err := checkFloors(a.storage, res); err != nil {
		return err
	}
	floor, err := a.storage.EpochFloor()
	if err != nil {
		return err
	}
	// A chain this build stopped early on resolves to whatever preceded the
	// upgrade, which is legitimately below the floor: the records are
	// authorized and storing them is right, since they are what a newer build
	// will resume from and what peers still need relayed.
	if res.state.epoch < floor && res.tooNew == nil {
		return &RollbackError{Floor: floor, Offered: res.state.epoch, Records: pending}
	}
	if err := a.storage.Add(pending...); err != nil {
		return err
	}
	// Re-resolve from storage rather than adopting the overlay's result: only
	// this says what storage can reproduce. A store that dropped part of the
	// batch must not leave the epoch floor above a chain it cannot produce,
	// which is a node that refuses to start.
	committed, err := resolve(a.storage, a.anchor)
	if err != nil {
		return fmt.Errorf("log: re-reading the chain after storing records: %w", err)
	}
	if committed.state.epoch < floor && committed.tooNew == nil {
		return fmt.Errorf(
			"log: after storing records the chain resolves to epoch %d, below the adopted %d; "+
				"storage did not durably accept the batch", committed.state.epoch, floor)
	}
	if err := a.storage.SetEpochFloor(committed.state.epoch); err != nil {
		return err
	}
	if err := a.storage.SetSchemaFloor(committed.state.schema); err != nil {
		return err
	}
	a.adopt(committed)
	return nil
}

func (a *Authority) adopt(res *resolution) {
	a.state = res.state
	a.orphans = res.orphans
	a.reachable = res.reachable
	a.onChain = make(map[types.Hash]bool, len(res.chain))
	for _, h := range res.chain {
		a.onChain[h] = true
	}
	a.tooNew = res.tooNew
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
// raised. This is the accessor anything that grants access must use: where
// security and availability conflict, deny.
func (a *Authority) TrustedState() (*State, error) {
	if a.alarm != nil {
		return nil, a.alarm
	}
	return a.state, nil
}

// Alarm returns the current fork alarm, or nil.
func (a *Authority) Alarm() *Alarm { return a.alarm }

// SchemaAlarm reports that the network has moved to a record schema this build
// does not implement, or nil. It does not gate [Authority.TrustedState]: see
// [SchemaTooNewError] for why the state a node already holds stays usable.
func (a *Authority) SchemaAlarm() *SchemaTooNewError { return a.tooNew }

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
// deletes what the new anchor cannot reach, returning how many were removed.
// The anchor is a ratchet: afterwards a chain that does not descend from it is
// not considered at all. Refused while either alarm is raised: a schema this
// build cannot read leaves records above the chain's end, and compaction
// deletes what the anchor cannot reach — which is exactly the records a newer
// build would need to resume from.
func (a *Authority) Compact() (int, error) {
	if a.alarm != nil {
		return 0, a.alarm
	}
	if a.tooNew != nil {
		return 0, a.tooNew
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

	// tooNew is set when the walk stopped at an authorized schema upgrade
	// this build cannot implement. The state is the one before it.
	tooNew *SchemaTooNewError
}

// resolve computes the active chain and the branches off it. It is a pure
// function of the records reachable from the anchor — no clock, no randomness,
// no dependence on arrival or storage order — which is what makes two nodes
// holding the same records reach the same state.
func resolve(r reader, anchor types.Hash) (*resolution, error) {
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
		primary, err := pickPrimary(r, valid, state)
		if err != nil {
			return nil, err
		}
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
			var tooNew *SchemaTooNewError
			if errors.As(err, &tooNew) {
				// The chain ends here for this build. The record itself is
				// authorized and reachable, so it is kept and relayed — a
				// node that cannot apply a record must still not swallow the
				// one that explains why. What follows it is not: this build
				// does not know the rules those records are judged by, and
				// storing unverified records would let any member fill a
				// stopped node's disk.
				res.reachable[primary.hash] = true
				res.tooNew = tooNew
				break
			}
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

// pickPrimary applies fork choice to a set of valid siblings of parent: a
// revocation beats anything else, otherwise the lower hash wins. Signature
// weight is deliberately not part of the rule — every change already needs
// quorum, so weight would only let one quorum outbid another by collecting
// extras.
//
// From [types.SchemaHolders] on, one rule comes first: a branch loses to a
// sibling whose branch removes an admin key that signed anything on it. An
// admin key removed at some point could otherwise sign a sibling rooted
// before its removal, win on the revocation bias or a ground hash, and undo
// its own removal with everything after it.
func pickPrimary(r reader, candidates []candidate, parent *State) (candidate, error) {
	var keys []branchKeys
	if parent.schema >= types.SchemaHolders {
		keys = make([]branchKeys, len(candidates))
		budget := maxOrphanRecords
		for i := range candidates {
			k, err := keysOfBranch(r, candidates[i].hash, &budget)
			if err != nil {
				return candidate{}, err
			}
			keys[i] = k
		}
	}
	// undone reports whether the branch at i signs with a key the branch at
	// j removes.
	undone := func(i, j int) bool {
		if keys == nil {
			return false
		}
		for id := range keys[i].signers {
			if keys[j].removed[id] {
				return true
			}
		}
		return false
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
		case c.hash.Compare(b.hash) < 0:
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

// keysOfBranch collects branchKeys over every stored record from root on,
// within budget: the chain ahead of a fork is at most as long as the chain.
func keysOfBranch(r reader, root types.Hash, budget *int) (branchKeys, error) {
	k := branchKeys{signers: map[types.Identity]bool{}, removed: map[types.Identity]bool{}}
	stack := []types.Hash{root}
	for len(stack) > 0 {
		if *budget -= 1; *budget < -maxChainLength {
			return k, fmt.Errorf("log: branches past %d records; refusing to resolve", maxChainLength)
		}
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		aum, err := r.AUM(h)
		if err != nil {
			return k, fmt.Errorf("log: reading %v: %w", h, err)
		}
		for i := range aum.Signatures {
			k.signers[aum.Signatures[i].KeyID] = true
		}
		if aum.Kind == types.KindRemoveAdminKey {
			k.removed[*aum.Subject] = true
		}
		children, err := r.Children(h)
		if err != nil {
			return k, err
		}
		stack = append(stack, children...)
	}
	return k, nil
}

// walkOrphan verifies a branch that lost fork choice and decides whether it
// merely needs reissuing or genuinely conflicts. Two states are carried down
// it: branch, which every record must verify against, since a branch of
// unauthorized records is a corrupt store rather than a fork; and probe, the
// result of replaying the branch's substance onto the chain that won.
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

// stateFromCheckpoint builds state from a checkpoint used as a bootstrap
// anchor.
func stateFromCheckpoint(a *types.AUM, hash types.Hash) (*State, error) {
	return adoptSnapshot(a.State, hash, "checkpoint")
}

// FromRecords builds an authority over st from a chain handed over whole,
// anchor first: a genesis, or a checkpoint taken on its signers' word as
// [Bootstrap] does, followed by the records after it. Every record is
// verified as it would be arriving one by one.
func FromRecords(st Storage, records []types.AUM) (*Authority, error) {
	if len(records) == 0 {
		return nil, errors.New("log: no records")
	}
	var auth *Authority
	var err error
	switch records[0].Kind {
	case types.KindGenesis:
		auth, err = Create(st, records[0])
	case types.KindCheckpoint:
		auth, err = Bootstrap(st, records[0])
	default:
		return nil, fmt.Errorf("log: a chain starts with a genesis or a checkpoint, not a %v", records[0].Kind)
	}
	if err != nil {
		return nil, err
	}
	if len(records) > 1 {
		if err := auth.Inform(records[1:]...); err != nil {
			return nil, err
		}
	}
	return auth, nil
}
