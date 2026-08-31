package secrets

import (
	"slices"
	"sync"
)

// KeyringDepth is how many epochs' secrets a [Keyring] keeps.
//
// One would be enough if every member stepped to a new epoch at the same
// instant. They do not: an epoch bump reaches members over gossip, so for the
// length of a convergence round the network holds two adjacent epochs at once,
// and the node that authored the change is the one that is ahead. If it could
// only speak its own epoch, the very message that carries a revocation would
// be unreadable to precisely the members that have not yet applied it — the
// deadlock that would make revocation converge at the anti-entropy timer
// instead of at push speed (docs/05-roadmap.md M2, exit criterion 2).
//
// Four rather than two so that a node briefly offline across a couple of bumps
// still rejoins the conversation instead of having to be re-enrolled. That
// second purpose is what fixes the number, and it cuts against the first: a
// *revoked* device also holds an epoch secret, and until the network has moved
// [KeyringDepth] epochs past it, members will still open its gossip frames and
// answer its LAN queries.
//
// What that window costs is metadata — the member set and where its members
// are — and nothing else. A revoked device gets no WireGuard peer entry
// anywhere from the first moment the removal converges, because peers come
// from the log and not from anything the sync layer says. Since every
// membership change carries an epoch bump, four changes retire the window
// completely; docs/09-mesh-layer-notes.md records the trade, and the freshness
// leases in M4 are what bound it in time rather than in changes.
const KeyringDepth = 4

// A Keyring holds the epoch group secrets a node can still use.
//
// It exists for the sync layer, not for the log: the log records exactly one
// current epoch, while gossip has to survive members being a step apart.
// Nothing here decides what is authorized — a frame that opens under an old
// epoch key is still only as trustworthy as the signatures on the records
// inside it.
//
// Safe for concurrent use: the daemon reaches it from the reconcile loop and
// from every gossip session at once.
type Keyring struct {
	mu sync.Mutex

	// entries are ordered by ascending epoch and hold at most KeyringDepth
	// of them, the newest last.
	entries []keyringEntry
}

type keyringEntry struct {
	epoch  uint64
	secret Secret
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring { return &Keyring{} }

// Adopt records the secret for an epoch, evicting the oldest once the ring is
// full. Re-adopting an epoch replaces its secret, which is what happens when a
// node resolves onto a different chain at the same epoch number.
func (k *Keyring) Adopt(epoch uint64, s Secret) {
	k.mu.Lock()
	defer k.mu.Unlock()
	i, found := slices.BinarySearchFunc(k.entries, epoch, func(e keyringEntry, target uint64) int {
		switch {
		case e.epoch < target:
			return -1
		case e.epoch > target:
			return 1
		}
		return 0
	})
	if found {
		k.entries[i].secret = s
		return
	}
	k.entries = slices.Insert(k.entries, i, keyringEntry{epoch: epoch, secret: s})
	if len(k.entries) > KeyringDepth {
		k.entries = slices.Delete(k.entries, 0, len(k.entries)-KeyringDepth)
	}
}

// Secret returns the secret for an epoch, if the ring still holds it.
func (k *Keyring) Secret(epoch uint64) (Secret, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.entries {
		if k.entries[i].epoch == epoch {
			return k.entries[i].secret, true
		}
	}
	return Secret{}, false
}

// Latest returns the newest epoch the ring holds.
func (k *Keyring) Latest() (epoch uint64, s Secret, ok bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.entries) == 0 {
		return 0, Secret{}, false
	}
	last := k.entries[len(k.entries)-1]
	return last.epoch, last.secret, true
}

// Epochs returns the epochs held, ascending. For diagnostics.
func (k *Keyring) Epochs() []uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]uint64, 0, len(k.entries))
	for i := range k.entries {
		out = append(out, k.entries[i].epoch)
	}
	return out
}
