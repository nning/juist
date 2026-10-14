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
// genuine conflict and this package alarms rather than choosing. A disable
// record takes no part in fork choice: wherever it hangs, it ends the network.
//
// Copies of one record, siblings with one [types.AUM.SigHash] and other
// signatures, are that record: the lowest hash stands for them, and what hangs
// from any of them hangs from it. From [types.SchemaContentForkChoice] on, fork
// choice sees what a record says and the union of its copies' signatures,
// never which copies a node holds.
package log

import (
	"errors"
	"fmt"
	"maps"
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

// A RollbackError reports a checkpoint [Bootstrap] refused for an epoch below
// the one this node has adopted. Nothing is stored.
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

// A RollbackAlarm reports that fork choice over the records held picks a chain
// below the epoch floor: a branch this node applied first lost to a concurrent
// one, or a quorum rewrote history. The records are held and the floor stays;
// [Authority.TrustedState] refuses until a record on the chain, a change redone
// or a group secret rotated, brings it back to the floor.
type RollbackAlarm struct {
	// Floor is the highest epoch this node has adopted, Epoch the chain's.
	Floor, Epoch uint64

	// Branch is the root of a lost branch that reached the floor, or zero
	// where none is held, as after records were lost.
	Branch types.Hash
}

func (e *RollbackAlarm) Error() string {
	lost := ""
	if !e.Branch.IsZero() {
		lost = fmt.Sprintf(" for the branch at %v", e.Branch)
	}
	return fmt.Sprintf("log: rollback alarm: the chain went back from epoch %d to %d%s, "+
		"which this device does not follow — an admin redoes the lost changes or runs juist rotate group-secret",
		e.Floor, e.Epoch, lost)
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

// A DisabledError reports that a [types.KindDisable] record has ended the
// network. It is final: no record undoes it.
type DisabledError struct {
	// At is the disable record.
	At types.Hash
}

func (e *DisabledError) Error() string {
	return fmt.Sprintf("log: the network was disabled with a break-glass secret in record %v", e.At)
}

// An Authority is a node's view of the membership log. Not safe for concurrent
// use; callers that share one serialize access.
type Authority struct {
	storage  Storage
	anchor   types.Hash
	state    *State
	orphans  []Orphan
	alarm    *Alarm
	tooNew   *SchemaTooNewError
	disabled *DisabledError
	rollback *RollbackAlarm

	// reachable is the set of records the last adopted resolution covered.
	// Anything stored and absent from it is a leftover from an interrupted
	// compaction, harmless and removed by the next Compact.
	reachable map[types.Hash]bool

	// onChain is the active chain of the last adopted resolution.
	onChain map[types.Hash]bool

	// listed is the last adopted resolution's [resolution.listed].
	listed map[types.Identity]types.SigningKey
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
	if err := a.settle(res); err != nil {
		return nil, err
	}
	return a, nil
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

// settle adopts res and raises the floors to it, or, where it is below the
// epoch floor, adopts it under a [RollbackAlarm] and raises nothing: a fork
// switch fork choice demands cannot be told from a quorum rewriting history
// back to an epoch a removed device holds, so the node fails closed on it.
func (a *Authority) settle(res *resolution) error {
	floor, err := a.storage.EpochFloor()
	if err != nil {
		return err
	}
	if res.state.epoch < floor {
		branch, err := floorBranch(a.storage, res.orphans, floor)
		if err != nil {
			return err
		}
		// A chain this build stopped early on resolves to whatever preceded
		// the upgrade, legitimately below the floor; it excuses nothing where
		// a lost branch reached the floor.
		if res.tooNew != nil && branch.IsZero() {
			return a.raise(res)
		}
		a.adopt(res)
		a.rollback = &RollbackAlarm{Floor: floor, Epoch: res.state.epoch, Branch: branch}
		return nil
	}
	return a.raise(res)
}

// raise adopts res and raises the floors to it.
func (a *Authority) raise(res *resolution) error {
	if err := a.storage.SetEpochFloor(res.state.epoch); err != nil {
		return err
	}
	if err := a.storage.SetSchemaFloor(res.state.schema); err != nil {
		return err
	}
	a.adopt(res)
	a.rollback = nil
	return nil
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
// may be stored in part, which the next resolution of the store picks up. One
// that resolves below the epoch floor is stored and raises a [RollbackAlarm].
func (a *Authority) Inform(aums ...types.AUM) error {
	_, err := a.Learn(aums...)
	return err
}

// Learn is [Authority.Inform], reporting whether it stored any record: one
// held already, or a copy that adds nothing to those held, is no news.
func (a *Authority) Learn(aums ...types.AUM) (bool, error) {
	if len(aums) == 0 {
		return false, nil
	}
	ov, err := newOverlay(a.storage, aums)
	if err != nil {
		return false, err
	}
	pending := ov.pending()
	if len(pending) == 0 {
		return false, nil // everything offered is already held
	}
	res, err := resolve(ov, a.anchor)
	if err != nil {
		return false, err
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
			return false, nil
		}
	} else {
		for i := range pending {
			h := pending[i].Hash()
			if !res.reachable[h] && followsDisable(ov, &pending[i]) {
				return false, reject(RuleParent, fmt.Errorf("log: record %v (%v) follows a disable record, which nothing may",
					h, pending[i].Kind))
			}
			if !res.reachable[h] {
				return false, reject(RuleParent, fmt.Errorf(
					"log: record %v (%v) does not descend from this node's anchor %v; "+
						"send its ancestors first", h, pending[i].Kind, a.anchor))
			}
		}
	}
	if err := checkFloors(a.storage, res); err != nil {
		return false, err
	}
	// A chain below the epoch floor is stored too, and settles under an alarm:
	// refused, it would leave this node on a branch fork choice rejected,
	// refusing every later batch, removals included, with nothing to show.
	if err := a.storage.Add(pending...); err != nil {
		return false, err
	}
	if err := pruneCopies(a.storage, a.anchor, pending); err != nil {
		return false, err
	}
	// Re-resolve from storage rather than adopting the overlay's result: only
	// this says what storage can reproduce, and the epoch floor must never
	// be raised above a chain it cannot.
	committed, err := resolve(a.storage, a.anchor)
	if err != nil {
		return false, fmt.Errorf("log: re-reading the chain after storing records: %w", err)
	}
	if err := a.settle(committed); err != nil {
		return false, err
	}
	return true, nil
}

// Preview returns the state aums would lead to if informed now, storing
// nothing: what a change does before it does it, such as whom it removes. It
// refuses what Inform would refuse for being unreachable from the anchor; the
// storage-side checks Inform makes after that are not run.
func (a *Authority) Preview(aums ...types.AUM) (*State, error) {
	ov, err := newOverlay(a.storage, aums)
	if err != nil {
		return nil, err
	}
	res, err := resolve(ov, a.anchor)
	if err != nil {
		return nil, err
	}
	for _, p := range ov.pending() {
		if !res.reachable[p.Hash()] {
			return nil, reject(RuleParent, fmt.Errorf("log: record %v (%v) does not descend from this node's "+
				"anchor %v", p.Hash(), p.Kind, a.anchor))
		}
	}
	return res.state, nil
}

func (a *Authority) adopt(res *resolution) {
	a.state = res.state
	a.orphans = res.orphans
	a.reachable = res.reachable
	a.listed = res.listed
	a.onChain = make(map[types.Hash]bool, len(res.chain)+len(res.copies))
	for _, h := range res.chain {
		a.onChain[h] = true
	}
	for _, h := range res.copies {
		a.onChain[h] = true
	}
	a.tooNew = res.tooNew
	a.disabled = res.disabled
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

// TrustedState returns the authority state, or an error once the network is
// disabled or while a fork or rollback alarm is raised. This is the accessor
// anything that grants access must use: where security and availability
// conflict, deny.
func (a *Authority) TrustedState() (*State, error) {
	if a.disabled != nil {
		return nil, a.disabled
	}
	if a.alarm != nil {
		return nil, a.alarm
	}
	if a.rollback != nil {
		return nil, a.rollback
	}
	return a.state, nil
}

// ListedSigningKey returns the signing key the active chain last named for
// member id, listed now or not, or nil. A member removed before the anchor is
// not named.
func (a *Authority) ListedSigningKey(id types.Identity) *types.SigningKey {
	if k, ok := a.listed[id]; ok {
		return &k
	}
	return nil
}

// Alarm returns the current fork alarm, or nil.
func (a *Authority) Alarm() *Alarm { return a.alarm }

// Disabled returns the disable record that ended the network, or nil.
func (a *Authority) Disabled() *DisabledError { return a.disabled }

// Rollback returns the current rollback alarm, or nil.
func (a *Authority) Rollback() *RollbackAlarm { return a.rollback }

// SchemaAlarm reports that the network has moved to a record schema this build
// does not implement, or nil. It does not gate [Authority.TrustedState]: see
// [SchemaTooNewError] for why the state a node already holds stays usable.
func (a *Authority) SchemaAlarm() *SchemaTooNewError { return a.tooNew }

// Orphans returns every branch that lost fork choice, including the benign
// ones whose records only need reissuing.
func (a *Authority) Orphans() []Orphan { return slices.Clone(a.orphans) }

// Copies returns the stored copies of the record h, h among them, lowest hash
// first.
func (a *Authority) Copies(h types.Hash) ([]types.Hash, error) {
	aum, err := a.storage.AUM(h)
	if err != nil {
		return nil, err
	}
	if aum.Prev == nil {
		return []types.Hash{h}, nil
	}
	return copiesOf(a.storage, &aum)
}

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
// not considered at all. Refused while any alarm is raised: a schema this
// build cannot read leaves records above the chain's end, and compaction
// deletes what the anchor cannot reach — which is exactly the records a newer
// build would need to resume from. Refused once the network is disabled too,
// since the disable record may hang below the newest checkpoint.
func (a *Authority) Compact() (int, error) {
	if a.disabled != nil {
		return 0, a.disabled
	}
	if a.alarm != nil {
		return 0, a.alarm
	}
	// The anchor would move onto a chain this node does not follow, and the
	// branch its floor came from would go.
	if a.rollback != nil {
		return 0, a.rollback
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
