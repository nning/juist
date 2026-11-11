// Package log implements the membership log: the hash-chained, admin-signed
// record of who belongs to the network, verified by every node. See
// docs/08-trust-layer-notes.md.
//
// Fork choice: of two records with the same parent, a revocation wins,
// otherwise the lower hash. The loser is kept but not applied; where it
// cannot be reissued on the new head, the package alarms rather than choosing.
// A disable record ends the network wherever it hangs.
//
// Copies of one record (siblings with one [types.AUM.SigHash]) are that
// record: the lowest hash stands for them. From
// [types.SchemaContentForkChoice] on, fork choice never depends on which
// copies a node holds.
package log

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/nning/juist/types"
)

// Bounds on the work resolving a chain may cost; past them, fail loudly.
const (
	maxChainLength    = 1 << 17
	maxOrphanRecords  = 4096
	maxOrphanBranches = 64
)

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

	// reachable is the set of records the last adopted resolution covered;
	// other stored records are left over and removed by Compact.
	reachable map[types.Hash]bool

	// onChain is the active chain of the last adopted resolution.
	onChain map[types.Hash]bool

	// listed is the last adopted resolution's [resolution.listed].
	listed map[types.Identity]types.SigningKey
}

// Create initializes a new network from a genesis record and makes it the
// anchor. The storage must be empty.
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
	// Reject an unusable genesis before writing anything.
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

// Bootstrap initializes a node from a quorum-signed checkpoint, checked
// against the admin keys it declares: the one place history is taken on the
// signers' word.
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

// settle adopts res and raises the floors to it, or, below the epoch floor,
// adopts it under a [RollbackAlarm] and raises nothing: a legitimate fork
// switch cannot be told from a quorum rewriting history, so fail closed.
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
		// A schema stop legitimately resolves below the floor, unless a lost
		// branch reached it.
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

// checkFloors refuses a resolution below the schema floor. A build too old
// for the network reports [SchemaTooNewError], not a rollback.
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

// Inform verifies records, stores them, and re-resolves the chain; order them
// oldest first. A refused batch stores nothing; one that fails in
// [Storage.Add] may be stored in part. One that resolves below the epoch floor
// is stored and raises a [RollbackAlarm].
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
	// Every offered record must have been reached by resolution, or it would
	// dangle. After a schema stop, unreached records are dropped instead, so
	// the upgrade record is still stored.
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
	} else if err := checkReachable(ov, res, pending, a.anchor); err != nil {
		return false, err
	}
	if err := checkFloors(a.storage, res); err != nil {
		return false, err
	}
	// A chain below the epoch floor is stored too and settles under an alarm;
	// refusing it would strand this node on the rejected branch.
	if err := a.storage.Add(pending...); err != nil {
		return false, err
	}
	if err := pruneCopies(a.storage, a.anchor, pending); err != nil {
		return false, err
	}
	// Re-resolve from storage: the epoch floor must never be raised above a
	// chain storage cannot reproduce.
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
// nothing. It skips Inform's storage-side checks.
func (a *Authority) Preview(aums ...types.AUM) (*State, error) {
	ov, err := newOverlay(a.storage, aums)
	if err != nil {
		return nil, err
	}
	res, err := resolve(ov, a.anchor)
	if err != nil {
		return nil, err
	}
	if err := checkReachable(ov, res, ov.pending(), a.anchor); err != nil {
		return nil, err
	}
	return res.state, nil
}

// checkReachable refuses the first of pending that res did not reach from
// anchor.
func checkReachable(r reader, res *resolution, pending []types.AUM, anchor types.Hash) error {
	for i := range pending {
		h := pending[i].Hash()
		switch {
		case res.reachable[h]:
		case followsDisable(r, &pending[i]):
			return reject(RuleParent, fmt.Errorf("log: record %v (%v) follows a disable record, which nothing may",
				h, pending[i].Kind))
		default:
			return reject(RuleParent, fmt.Errorf("log: record %v (%v) does not descend from this node's anchor %v; "+
				"send its ancestors first", h, pending[i].Kind, anchor))
		}
	}
	return nil
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

// State returns the current authority state for inspection, even under an
// alarm; anything that grants access must use [Authority.TrustedState].
func (a *Authority) State() *State { return a.state }

// TrustedState returns the authority state, or an error once the network is
// disabled or while a fork or rollback alarm is raised. Anything that grants
// access must use it.
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

// SchemaAlarm returns the [SchemaTooNewError] this build stopped at, or nil.
// It does not gate [Authority.TrustedState].
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

// Held returns the records the resolution covers, in hash order.
func (a *Authority) Held() []types.Hash {
	out := slices.Collect(maps.Keys(a.reachable))
	slices.SortFunc(out, types.Hash.Compare)
	return out
}

// Record returns the stored record h.
func (a *Authority) Record(h types.Hash) (types.AUM, error) { return a.storage.AUM(h) }

// below returns the stored ancestors of the anchor, with their copies, down
// to stop (or a copy of it) or as far as stored, and the lowest of them (the
// anchor if none).
func (a *Authority) below(stop types.Hash) (map[types.Hash]bool, types.Hash, error) {
	out := map[types.Hash]bool{}
	h := a.anchor
	for !out[stop] {
		rec, err := a.storage.AUM(h)
		if err != nil {
			return nil, h, err
		}
		if rec.Prev == nil {
			break
		}
		parent, err := a.storage.AUM(*rec.Prev)
		if errors.Is(err, ErrNotFound) {
			break
		} else if err != nil {
			return nil, h, err
		}
		h = *rec.Prev
		copies := []types.Hash{h}
		if parent.Prev != nil {
			if copies, err = copiesOf(a.storage, &parent); err != nil {
				return nil, h, err
			}
		}
		for _, c := range copies {
			out[c] = true
		}
	}
	return out, h, nil
}

// Chain returns the active chain's record hashes, anchor first.
func (a *Authority) Chain() ([]types.Hash, error) {
	res, err := resolve(a.storage, a.anchor)
	if err != nil {
		return nil, err
	}
	return res.chain, nil
}

// Compact advances the anchor to the second-newest checkpoint on the active
// chain, so later forks resolve as on a device that did not compact, and
// deletes what it cannot reach except the chain up to it from the old anchor.
// It returns how many records were removed. The anchor is a ratchet. Refused
// under any alarm, a schema stop, or once disabled.
func (a *Authority) Compact() (int, error) {
	if a.disabled != nil {
		return 0, a.disabled
	}
	if a.alarm != nil {
		return 0, a.alarm
	}
	// It would delete the branch the floor came from.
	if a.rollback != nil {
		return 0, a.rollback
	}
	if a.tooNew != nil {
		return 0, a.tooNew
	}
	// It would delete the notice that a revocation is to be redone.
	if slices.ContainsFunc(a.orphans, func(o Orphan) bool { return len(o.Unrevoked) > 0 }) {
		return 0, errors.New("log: a revocation that lost fork choice is to be redone first")
	}
	res, err := resolve(a.storage, a.anchor)
	if err != nil {
		return 0, err
	}
	newAnchor, newest := a.anchor, a.anchor
	for _, h := range res.chain[1:] {
		rec, err := a.storage.AUM(h)
		if err != nil {
			return 0, err
		}
		if rec.Kind == types.KindCheckpoint {
			newAnchor, newest = newest, h
		}
	}
	var stop types.Hash
	if newAnchor != a.anchor {
		if err := a.storage.SetAnchor(newAnchor); err != nil {
			return 0, err
		}
		stop, a.anchor = a.anchor, newAnchor
		if res, err = resolve(a.storage, newAnchor); err != nil {
			return 0, err
		}
	}
	// What the anchor cannot reach is unreachable for good.
	below, _, err := a.below(stop)
	if err != nil {
		return 0, err
	}
	stored, err := a.storage.Hashes()
	if err != nil {
		return 0, err
	}
	var stale []types.Hash
	for _, h := range stored {
		if !res.reachable[h] && !below[h] {
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

// FromRecords builds an authority over st from a whole chain, anchor first:
// a genesis, or a checkpoint taken as [Bootstrap] does, then its successors.
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

// Rebase moves the log to a whole chain, as [FromRecords] takes it, at a
// later epoch and anchored at a record a quorum of this log's admins signed.
// The caller must hold something that vouches for the chain, as an
// admission does.
func (a *Authority) Rebase(records []types.AUM) error {
	if a.disabled != nil {
		return a.disabled
	}
	fresh, err := FromRecords(NewMemStorage(), records)
	if err != nil {
		return err
	}
	floor, err := a.storage.EpochFloor()
	if err != nil {
		return err
	}
	schemaFloor, err := a.storage.SchemaFloor()
	switch s := fresh.state; {
	case err != nil:
		return err
	case s.genesisHash != a.state.genesisHash || types.CountVotes(a.state.Admins(),
		func(id types.Identity) bool { return a.state.SignedBy(&records[0], id) }) < a.state.quorum:
		return errors.New("log: the chain does not start at a record this log's admins signed")
	case s.schema < schemaFloor:
		return fmt.Errorf("log: the chain is at %v, below this log's %v", s.schema, schemaFloor)
	case s.epoch <= a.state.epoch || s.epoch < floor:
		return fmt.Errorf("log: the chain does not continue this log, and is at epoch %d, not past its %d",
			s.epoch, max(a.state.epoch, floor))
	}
	keep := slices.DeleteFunc(slices.Clone(records), func(r types.AUM) bool { return !fresh.reachable[r.Hash()] })
	if err := a.storage.Add(keep...); err != nil {
		return err
	}
	if err := a.storage.SetAnchor(records[0].Hash()); err != nil {
		return err
	}
	a.anchor = records[0].Hash()
	res, err := resolve(a.storage, a.anchor)
	if err != nil {
		return err
	}
	if err := checkFloors(a.storage, res); err != nil {
		return err
	}
	return a.settle(res)
}
