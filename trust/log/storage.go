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

// Storage holds records and the two node-local ratchets — the anchor and the
// epoch floor — that protect against being walked backwards. Records are
// content-addressed: an implementation checks what it reads back hashes to the
// name it was filed under, and reports corruption rather than repairing it.
// The ratchets are node-local, so two nodes that have seen different histories
// refuse different things, which a fork alarm surfaces.
type Storage interface {
	// AUM returns the record with the given hash, or [ErrNotFound].
	AUM(h types.Hash) (types.AUM, error)

	// Children returns the hashes of stored records whose parent is h, in
	// any order.
	Children(h types.Hash) ([]types.Hash, error)

	// Add stores records durably. A failure may leave part of the batch
	// stored, which callers re-resolve to find out, but a store that
	// outlives a crash must hold all of a batch or none of it when next
	// opened: part of one can resolve below the epoch floor the whole
	// clears. Re-adding a record already held is not an error: the name is
	// its content.
	Add(aums ...types.AUM) error

	// Delete removes records. Used only by compaction, after the anchor has
	// advanced past them.
	Delete(hashes ...types.Hash) error

	// Hashes returns every stored record's hash. Compaction needs it to find
	// records the anchor can no longer reach, and it is how "is this store
	// empty" is answered.
	Hashes() ([]types.Hash, error)

	// Anchor returns the oldest record the active chain is computed from: the
	// genesis record, or the newest checkpoint this node adopted. A chain that
	// does not descend from it is not considered at all.
	Anchor() (types.Hash, bool, error)

	// SetAnchor records a new anchor. Callers only ever move it forward,
	// along the active chain.
	SetAnchor(h types.Hash) error

	// EpochFloor returns the highest group-secret epoch this node has ever
	// adopted. A chain resolving below it is a rollback attempt.
	EpochFloor() (uint64, error)

	// SetEpochFloor raises the floor. Implementations must persist it before
	// returning, since its whole purpose is to survive a restart.
	SetEpochFloor(epoch uint64) error

	// SchemaFloor returns the highest record schema this node has ever
	// adopted. A chain resolving below it is a rollback of the schema, which
	// is how a fork that never took the upgrade would otherwise be adopted.
	SchemaFloor() (types.SchemaVersion, error)

	// SetSchemaFloor raises the schema floor, persisted before returning.
	SetSchemaFloor(v types.SchemaVersion) error
}

// reader is the read-only half of [Storage], so resolution can run over a
// proposed set of records layered on the store, before any is written.
type reader interface {
	AUM(h types.Hash) (types.AUM, error)
	Children(h types.Hash) ([]types.Hash, error)
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
	// Validate the whole batch before mutating anything, so a rejected batch
	// leaves the store as it was.
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

func newOverlay(base reader, aums []types.AUM) (*overlay, error) {
	o := &overlay{
		base:     base,
		added:    make(map[types.Hash]types.AUM, len(aums)),
		children: map[types.Hash][]types.Hash{},
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
		// A record the store already holds is not new; leaving it out of the
		// overlay keeps the child index from listing it twice.
		if _, err := base.AUM(h); err == nil {
			continue
		}
		o.added[h] = *a
		if a.Prev != nil {
			o.children[*a.Prev] = append(o.children[*a.Prev], h)
		}
	}
	return o, nil
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
	// Deterministic order: fork choice must not depend on the order the store
	// happens to return children in.
	slices.SortFunc(out, types.Hash.Compare)
	return slices.Compact(out), nil
}

// pending returns the records the overlay adds, so the caller can commit
// exactly those once resolution has approved them.
func (o *overlay) pending() []types.AUM {
	hashes := slices.Collect(maps.Keys(o.added))
	slices.SortFunc(hashes, types.Hash.Compare)
	out := make([]types.AUM, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, o.added[h])
	}
	return out
}
