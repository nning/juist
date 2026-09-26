// Package keyring holds the epoch group secrets the sync layer can still use.
// It is outside the trusted computing base: nothing here decides what is
// authorized.
package keyring

import (
	"slices"
	"sync"

	"github.com/nning/juist/trust/secrets"
)

// Depth is how many epochs' secrets a [Keyring] keeps.
//
// More than one, because a bump reaches members over gossip: for a convergence
// round the network holds two adjacent epochs, and a node that spoke only its
// own would make the message carrying a revocation unreadable to exactly the
// members that have not applied it. Four, so a node briefly offline across a
// couple of bumps rejoins by epoch; one further behind catches up by identity.
//
// The cost is that a revoked device's frames and queries are still answered
// until the network is [Depth] epochs past it. That window leaks metadata and
// nothing else — peer entries come from the log — and every membership change
// carries a bump, so four changes retire it.
const Depth = 4

// A Keyring holds the epoch group secrets a node can still use. It exists for
// the sync layer, not the log: the log has exactly one current epoch, while
// gossip must survive members being a step apart. Safe for concurrent use.
type Keyring struct {
	mu sync.Mutex

	// entries are ordered by ascending epoch and hold at most Depth of them,
	// the newest last.
	entries []entry
}

type entry struct {
	epoch  uint64
	secret secrets.Secret
}

// New returns an empty keyring.
func New() *Keyring { return &Keyring{} }

// Adopt records the secret for an epoch, evicting the oldest once the ring is
// full. Re-adopting an epoch replaces its secret, which is what happens when a
// node resolves onto a different chain at the same epoch number.
func (k *Keyring) Adopt(epoch uint64, s secrets.Secret) {
	k.mu.Lock()
	defer k.mu.Unlock()
	i, found := slices.BinarySearchFunc(k.entries, epoch, func(e entry, target uint64) int {
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
	k.entries = slices.Insert(k.entries, i, entry{epoch: epoch, secret: s})
	if len(k.entries) > Depth {
		k.entries = slices.Delete(k.entries, 0, len(k.entries)-Depth)
	}
}

// Secret returns the secret for an epoch, if the ring still holds it.
func (k *Keyring) Secret(epoch uint64) (secrets.Secret, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.entries {
		if k.entries[i].epoch == epoch {
			return k.entries[i].secret, true
		}
	}
	return secrets.Secret{}, false
}

// Latest returns the newest epoch the ring holds.
func (k *Keyring) Latest() (epoch uint64, s secrets.Secret, ok bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.entries) == 0 {
		return 0, secrets.Secret{}, false
	}
	last := k.entries[len(k.entries)-1]
	return last.epoch, last.secret, true
}

// Held returns the epochs held and their secrets, ascending, for a node that
// keeps its keyring across a restart.
func (k *Keyring) Held() (epochs []uint64, held []secrets.Secret) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.entries {
		epochs = append(epochs, k.entries[i].epoch)
		held = append(held, k.entries[i].secret)
	}
	return epochs, held
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
