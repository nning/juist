package daemon

import (
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// saveKeyring writes the epoch secrets held, owner-only and sealed as the
// node's keys are. A failure costs the
// secrets across a rotation, which is logged, not fatal.
func (d *Daemon) saveKeyring() {
	if d.keyringPath == "" {
		return
	}
	// Serialized, and the snapshot taken inside, so a writer holding an older
	// set cannot rename over a newer one.
	d.keyringSaveMu.Lock()
	defer d.keyringSaveMu.Unlock()
	// The keyring and what was kept, newest first up to the depth: a secret
	// kept for a peer still behind stays until newer epochs displace it.
	all := map[uint64]secrets.Secret{}
	for e, s := range d.kept {
		all[e] = s
	}
	epochs, held := d.keyring.Held()
	for i := range epochs {
		all[epochs[i]] = held[i]
	}
	order := slices.Sorted(maps.Keys(all))
	if len(order) > keyring.Depth {
		order = order[len(order)-keyring.Depth:]
	}
	var b strings.Builder
	b.WriteString("# juist epoch group secrets this device holds; as secret as node.keys\n")
	for _, e := range order {
		s := all[e]
		fmt.Fprintf(&b, "%d %s\n", e, hex.EncodeToString(s[:]))
	}
	text, err := keys.SealText(b.String())
	if err != nil {
		d.logf("daemon: keeping the epoch secrets: %v", err)
		return
	}
	if err := statedir.WriteFilePrivate(d.keyringPath, []byte(text)); err != nil {
		d.logf("daemon: keeping the epoch secrets: %v", err)
	}
}

// loadKeyring reads the kept epoch secrets. They are taken back only where
// the chain's epoch record commits to them, so a damaged or planted file
// costs nothing.
func (d *Daemon) loadKeyring() map[uint64]secrets.Secret {
	out := map[uint64]secrets.Secret{}
	if d.keyringPath == "" {
		return out
	}
	b, err := os.ReadFile(d.keyringPath)
	if err != nil {
		return out
	}
	text, err := keys.OpenText(d.keyringPath, string(b))
	if err != nil {
		d.logf("daemon: reading the kept epoch secrets: %v", err)
		return out
	}
	for line := range strings.Lines(text) {
		epochText, secretText, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || strings.HasPrefix(epochText, "#") {
			continue
		}
		epoch, err := strconv.ParseUint(epochText, 10, 64)
		raw, herr := hex.DecodeString(secretText)
		var s secrets.Secret
		if err != nil || herr != nil || len(raw) != len(s) || len(out) >= keyring.Depth*2 {
			continue
		}
		copy(s[:], raw)
		out[epoch] = s
	}
	return out
}

// adoptEpoch opens this node's wrap of the current group secret and puts it in
// the keyring, so that gossip and discovery speak the epoch the log resolves
// to.
//
// A failure is reported and survived: a member that cannot open its own wrap
// keeps the data plane running on the epoch it already has.
func (d *Daemon) adoptEpoch(state *log.State) {
	epoch := state.Epoch()
	if _, held := d.keyring.Secret(epoch); held {
		return
	}
	if !state.IsMember(d.self) {
		// Not a member of the chain we resolve to: there is no wrap for us
		// and there is not supposed to be one. Nothing to report.
		return
	}
	s, err := secrets.Open(state.EpochRecord(), d.self, d.recipient)
	if err != nil {
		d.logf("daemon: cannot open the epoch %d group secret: %v", epoch, err)
		d.setStatus(func(st *ipc.Status) { st.EpochError = err.Error() })
		return
	}
	prev, _, held := d.keyring.Latest()
	d.keyring.Adopt(epoch, s)
	d.saveKeyring()
	d.setStatus(func(st *ipc.Status) { st.EpochError = "" })
	d.logf("daemon: adopted the epoch %d group secret", epoch)
	if held && epoch > prev+1 {
		// Several changes at once, as after a catch-up: the epochs skipped
		// are the ones peers still speak, and the ones held before are
		// what a removed device is answered under.
		d.backfillEpochs()
	}
}

// backfillEpochs opens this node's wraps of the epochs on the active chain,
// back from the head until the keyring is full: a node holding only the newest
// can neither read a peer that is behind nor be read by it. A wrap sealed to
// keys since rotated away is taken from the kept secrets instead, where the
// chain's epoch record commits to one.
func (d *Daemon) backfillEpochs() {
	d.authMu.Lock()
	chain, err := d.authority.Chain()
	if err != nil {
		d.authMu.Unlock()
		d.logf("daemon: reading the chain to recover past epochs: %v", err)
		return
	}
	records := make([]*types.EpochRecord, 0, keyring.Depth)
	for i := len(chain) - 1; i >= 0 && len(records) < keyring.Depth; i-- {
		aum, err := d.storage.AUM(chain[i])
		if err != nil {
			break
		}
		// Two places carry an epoch: a record's Epoch field, and a genesis or
		// checkpoint snapshot, which holds the wraps inline. Missing the
		// second skips the epoch a node that never saw a change is on.
		switch {
		case aum.Epoch != nil:
			records = append(records, aum.Epoch)
		case aum.State != nil:
			records = append(records, &types.EpochRecord{
				Epoch:  aum.State.Epoch,
				Commit: aum.State.EpochCommit,
				Wraps:  aum.State.EpochWraps,
				Suite:  aum.State.EpochSuite,
			})
		}
	}
	d.authMu.Unlock()

	for _, rec := range records {
		if _, held := d.keyring.Secret(rec.Epoch); held {
			continue
		}
		s, err := secrets.Open(rec, d.self, d.recipient)
		if err != nil {
			// Ordinary: every epoch older than this device's enrollment has
			// no wrap for it, and after a rotation the older wraps are sealed
			// to keys it no longer holds — which is what the kept secrets
			// are for, where the chain's record commits to them.
			k, ok := d.kept[rec.Epoch]
			if !ok || k.Commit() != rec.Commit {
				continue
			}
			s = k
		}
		d.keyring.Adopt(rec.Epoch, s)
		d.logf("daemon: recovered the epoch %d group secret", rec.Epoch)
	}
	d.saveKeyring()
}
