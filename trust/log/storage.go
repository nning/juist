package log

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/nning/wg-p2p/types"
)

// ErrNotFound is returned by [Storage.AUM] for a hash it does not hold.
var ErrNotFound = errors.New("log: record not found")

// Storage holds records and the two node-local ratchets that protect against
// being walked backwards.
//
// Records are content-addressed, so a store cannot silently alter one: an
// implementation is expected to check that what it reads back hashes to the
// name it was filed under, and to report corruption rather than repair it
// (docs/04-architecture.md: "state file corruption ⇒ refuse to start with
// recovery instructions, never silently re-genesis").
//
// The anchor and the epoch floor are the ratchets. Both are deliberately
// node-local: two nodes that have seen different histories will refuse
// different things, and that divergence is what a fork alarm surfaces rather
// than something to be averaged away.
type Storage interface {
	// AUM returns the record with the given hash, or [ErrNotFound].
	AUM(h types.Hash) (types.AUM, error)

	// Children returns the hashes of stored records whose parent is h, in
	// any order.
	Children(h types.Hash) ([]types.Hash, error)

	// Add stores records durably. It must be atomic across the whole batch:
	// a partially-applied batch would leave records whose parents are
	// missing. Re-adding a record already held is not an error, since the
	// name is its content.
	Add(aums ...types.AUM) error

	// Delete removes records. Used only by compaction, after the anchor has
	// advanced past them.
	Delete(hashes ...types.Hash) error

	// Hashes returns every stored record's hash. Compaction needs it to find
	// records the anchor can no longer reach, and it is how "is this store
	// empty" is answered.
	Hashes() ([]types.Hash, error)

	// Anchor returns the oldest record the active chain is computed from: the
	// genesis record, or the newest checkpoint this node has adopted. A chain
	// that does not descend from it is not considered at all, which is how
	// "never drop a checkpoint you hold" is enforced.
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
}

// reader is the read-only half of [Storage], which is all that chain
// resolution needs. It exists so that resolution can run over a proposed set
// of records layered on top of the store, verifying them before any of them is
// written.
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

func (m *MemStorage) Hashes() ([]types.Hash, error) {
	out := slices.Collect(maps.Keys(m.aums))
	slices.SortFunc(out, compareHash)
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
			return nil, fmt.Errorf("log: %w", err)
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
	slices.SortFunc(out, compareHash)
	return slices.Compact(out), nil
}

// pending returns the records the overlay adds, so the caller can commit
// exactly those once resolution has approved them.
func (o *overlay) pending() []types.AUM {
	hashes := slices.Collect(maps.Keys(o.added))
	slices.SortFunc(hashes, compareHash)
	out := make([]types.AUM, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, o.added[h])
	}
	return out
}

func compareHash(a, b types.Hash) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
