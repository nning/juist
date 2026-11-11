package log

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/nning/juist/types"
)

// ErrNotFound is returned by [Storage.AUM] for a hash it does not hold.
var ErrNotFound = errors.New("log: record not found")

// Storage holds records and the node-local ratchets (anchor, epoch and schema
// floor) that protect against being walked backwards. An implementation must
// check that what it reads back hashes to its name, and report corruption
// rather than repair it.
type Storage interface {
	// AUM returns the record with the given hash, or [ErrNotFound].
	AUM(h types.Hash) (types.AUM, error)

	// Children returns the hashes of stored records whose parent is h, in
	// any order.
	Children(h types.Hash) ([]types.Hash, error)

	// Add stores records durably. A failure may leave part of the batch
	// stored, but after a crash a store must hold all of a batch or none:
	// part of one can resolve below the epoch floor the whole clears.
	// Re-adding a held record is not an error.
	Add(aums ...types.AUM) error

	// Delete removes records.
	Delete(hashes ...types.Hash) error

	// Hashes returns every stored record's hash.
	Hashes() ([]types.Hash, error)

	// Anchor returns the record the active chain is computed from: genesis,
	// or the newest checkpoint adopted. Chains not descending from it are
	// ignored.
	Anchor() (types.Hash, bool, error)

	// SetAnchor records a new anchor. Callers only move it forward, along the
	// active chain or onto the chain a rebase takes.
	SetAnchor(h types.Hash) error

	// EpochFloor returns the highest group-secret epoch this node has ever
	// adopted. A chain resolving below it is a rollback attempt.
	EpochFloor() (uint64, error)

	// SetEpochFloor raises the floor, persisted before returning.
	SetEpochFloor(epoch uint64) error

	// SchemaFloor returns the highest record schema this node has ever
	// adopted. A chain resolving below it is a schema rollback.
	SchemaFloor() (types.SchemaVersion, error)

	// SetSchemaFloor raises the schema floor, persisted before returning.
	SetSchemaFloor(v types.SchemaVersion) error
}

// reader is the read-only half of [Storage], so resolution can run over a
// proposed set of records layered on the store, before any is written.
type reader interface {
	AUM(h types.Hash) (types.AUM, error)
	Children(h types.Hash) ([]types.Hash, error)
	Hashes() ([]types.Hash, error)
}

// MemStorage is an in-memory [Storage], for tests and for callers that do not
// persist anything.
type MemStorage struct {
	aums     map[types.Hash]types.AUM
	children map[types.Hash][]types.Hash
	anchor   *types.Hash
	floor    uint64

	schemaFloor types.SchemaVersion
}

var _ Storage = (*MemStorage)(nil)

// NewMemStorage returns an empty in-memory store.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		aums:     map[types.Hash]types.AUM{},
		children: map[types.Hash][]types.Hash{},
	}
}

func (m *MemStorage) AUM(h types.Hash) (types.AUM, error) {
	a, ok := m.aums[h]
	if !ok {
		return types.AUM{}, fmt.Errorf("%w: %v", ErrNotFound, h)
	}
	return *a.Clone(), nil
}

func (m *MemStorage) Children(h types.Hash) ([]types.Hash, error) {
	return slices.Clone(m.children[h]), nil
}

func (m *MemStorage) Add(aums ...types.AUM) error {
	// Validate the whole batch first, so a rejected one changes nothing.
	for i := range aums {
		if err := aums[i].StaticValidate(); err != nil {
			return fmt.Errorf("log: refusing to store an invalid record: %w", err)
		}
	}
	for i := range aums {
		a := aums[i].Clone()
		h := a.Hash()
		if _, dup := m.aums[h]; dup {
			continue
		}
		m.aums[h] = *a
		if a.Prev != nil {
			m.children[*a.Prev] = append(m.children[*a.Prev], h)
		}
	}
	return nil
}

func (m *MemStorage) Delete(hashes ...types.Hash) error {
	for _, h := range hashes {
		a, ok := m.aums[h]
		if !ok {
			continue
		}
		delete(m.aums, h)
		if a.Prev != nil {
			m.children[*a.Prev] = slices.DeleteFunc(m.children[*a.Prev],
				func(c types.Hash) bool { return c == h })
			if len(m.children[*a.Prev]) == 0 {
				delete(m.children, *a.Prev)
			}
		}
	}
	return nil
}

func (m *MemStorage) Anchor() (types.Hash, bool, error) {
	if m.anchor == nil {
		return types.Hash{}, false, nil
	}
	return *m.anchor, true, nil
}

func (m *MemStorage) SetAnchor(h types.Hash) error {
	m.anchor = &h
	return nil
}

func (m *MemStorage) EpochFloor() (uint64, error) { return m.floor, nil }

func (m *MemStorage) SetEpochFloor(epoch uint64) error {
	if epoch > m.floor {
		m.floor = epoch
	}
	return nil
}

func (m *MemStorage) SchemaFloor() (types.SchemaVersion, error) { return m.schemaFloor, nil }

func (m *MemStorage) SetSchemaFloor(v types.SchemaVersion) error {
	if v > m.schemaFloor {
		m.schemaFloor = v
	}
	return nil
}

func (m *MemStorage) Hashes() ([]types.Hash, error) {
	out := slices.Collect(maps.Keys(m.aums))
	slices.SortFunc(out, types.Hash.Compare)
	return out, nil
}

// overlay layers proposed records on top of a store, so chain resolution can
// verify them in place before anything is written.
type overlay struct {
	base     reader
	added    map[types.Hash]types.AUM
	children map[types.Hash][]types.Hash
}

// newOverlay layers aums on base, leaving out those base holds and copies of
// a record that earn no place beside those held ([earnsPlace]), unless
// something in aums hangs from them.
func newOverlay(base reader, aums []types.AUM) (*overlay, error) {
	o := &overlay{
		base:     base,
		added:    make(map[types.Hash]types.AUM, len(aums)),
		children: map[types.Hash][]types.Hash{},
	}
	parents := make(map[types.Hash]bool, len(aums))
	for i := range aums {
		if aums[i].Prev != nil {
			parents[*aums[i].Prev] = true
		}
	}
	for i := range aums {
		if err := aums[i].StaticValidate(); err != nil {
			return nil, reject(RuleMalformed, fmt.Errorf("log: %w", err))
		}
		a := aums[i].Clone()
		h := a.Hash()
		if _, dup := o.added[h]; dup {
			continue
		}
		// Already held: leave it out so the child index lists it once.
		if _, err := base.AUM(h); err == nil {
			continue
		}
		if a.Prev != nil && !parents[h] {
			held, err := copiesOf(o, a)
			if err != nil {
				return nil, err
			}
			if earns, err := earnsPlace(o, a, h, held); err != nil {
				return nil, err
			} else if !earns {
				continue
			}
		}
		o.added[h] = *a
		if a.Prev != nil {
			o.children[*a.Prev] = append(o.children[*a.Prev], h)
		}
	}
	return o, nil
}

// earnsPlace reports whether a, hashing to h, earns a place beside others,
// copies of it: it is one of the two lowest hashes, carries a key none of
// others carries, or is a checkpoint with fewer than [maxCheckpointCopies]
// others. This bounds copies by signers while nodes keep the same lowest two.
func earnsPlace(r reader, a *types.AUM, h types.Hash, others []types.Hash) (bool, error) {
	// A peer may be anchored at any copy of a checkpoint.
	if a.Kind == types.KindCheckpoint && len(others)-count(others, h) < maxCheckpointCopies {
		return true, nil
	}
	lower := 0
	carried := map[types.Identity]bool{}
	for _, c := range others {
		if c == h {
			continue
		}
		if c.Compare(h) < 0 {
			lower++
		}
		aum, err := r.AUM(c)
		if err != nil {
			return false, fmt.Errorf("log: reading %v: %w", c, err)
		}
		for i := range aum.Signatures {
			carried[aum.Signatures[i].KeyID] = true
		}
	}
	if lower < 2 {
		return true, nil
	}
	for i := range a.Signatures {
		if !carried[a.Signatures[i].KeyID] {
			return true, nil
		}
	}
	return false, nil
}

// maxCheckpointCopies is how many checkpoint copies a store keeps whatever
// they carry.
const maxCheckpointCopies = 8

func count(hashes []types.Hash, h types.Hash) int {
	n := 0
	for _, x := range hashes {
		if x == h {
			n++
		}
	}
	return n
}

// pruneCopies deletes from st the copies of added records that no longer earn
// a place beside the others ([earnsPlace]), highest hash first, keeping the
// anchor and any copy something hangs from.
func pruneCopies(st Storage, anchor types.Hash, added []types.AUM) error {
	seen := map[types.Hash]bool{}
	for i := range added {
		a := &added[i]
		if a.Prev == nil {
			continue
		}
		copies, err := copiesOf(st, a)
		if err != nil {
			return err
		}
		if len(copies) <= 2 || seen[copies[0]] {
			continue
		}
		seen[copies[0]] = true
		for j := len(copies) - 1; j >= 2; j-- {
			h := copies[j]
			if h == anchor {
				continue
			}
			if ch, err := st.Children(h); err != nil {
				return err
			} else if len(ch) > 0 {
				continue
			}
			c, err := st.AUM(h)
			if err != nil {
				return err
			}
			if earns, err := earnsPlace(st, &c, h, copies); err != nil {
				return err
			} else if earns {
				continue
			}
			if err := st.Delete(h); err != nil {
				return err
			}
			copies = slices.Delete(copies, j, j+1)
		}
	}
	return nil
}

func (o *overlay) AUM(h types.Hash) (types.AUM, error) {
	if a, ok := o.added[h]; ok {
		return *a.Clone(), nil
	}
	return o.base.AUM(h)
}

func (o *overlay) Children(h types.Hash) ([]types.Hash, error) {
	base, err := o.base.Children(h)
	if err != nil {
		return nil, err
	}
	out := append(base, o.children[h]...)
	// Fork choice must not depend on store order.
	slices.SortFunc(out, types.Hash.Compare)
	return slices.Compact(out), nil
}

func (o *overlay) Hashes() ([]types.Hash, error) {
	base, err := o.base.Hashes()
	if err != nil {
		return nil, err
	}
	return append(base, slices.Collect(maps.Keys(o.added))...), nil
}

// pending returns the records the overlay adds.
func (o *overlay) pending() []types.AUM {
	hashes := slices.Collect(maps.Keys(o.added))
	slices.SortFunc(hashes, types.Hash.Compare)
	out := make([]types.AUM, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, o.added[h])
	}
	return out
}
