package daemon

import (
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// compaction is what decides when the log's anchor moves; under authMu.
type compaction struct {
	// lookedAt is the head and anchor the checkpoints were looked for at,
	// newest the newest on the chain to it and target the one before it past
	// the anchor, zero where there is none.
	lookedAt       [2]types.Hash
	newest, target types.Hash

	// past caches whether a record descends from a checkpoint, by both.
	past map[[2]types.Hash]bool
}

// A peerBeacon is what a member's last hello said of its log, unsigned.
type peerBeacon struct{ head, anchor types.Hash }

// onHave notes a peer's head and anchor, for compaction, and a peer holding
// the newest renumbering.
func (d *Daemon) onHave(from types.Identity, head, anchor types.Hash, have []types.Hash) {
	member := d.endpoints.IsMember(from)
	d.mu.Lock()
	defer d.mu.Unlock()
	if member {
		d.peerBeacons[from] = peerBeacon{head, anchor}
	}
	d.seenRenumbering(from, have)
}

// compactWhenSettled moves the anchor to the checkpoint before the newest on
// the chain once every other live member of state has been heard with a head
// on or past the newest, so that none is left behind what the anchor drops,
// or once a member has compacted to that checkpoint or past it, which it did
// on the same word: a policy may keep this device from hearing every member.
func (d *Daemon) compactWhenSettled(state *log.State) {
	d.mu.Lock()
	beacons := maps.Clone(d.peerBeacons)
	d.mu.Unlock()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if err := d.checkpointsLocked(); err != nil {
		return
	}
	c := &d.compacting
	if c.target.IsZero() {
		return
	}
	now := d.now().Unix()
	all, one := true, false
	for _, n := range state.Nodes() {
		if n.Identity == d.self || n.Expired(now) {
			continue
		}
		b, ok := beacons[n.Identity]
		if !ok {
			all = false
			continue
		}
		if past, err := d.descendsLocked(b.head, c.newest); err != nil || !past {
			all = false
		}
		if past, err := d.descendsLocked(b.anchor, c.target); err == nil && past {
			one = true
		}
	}
	if !all && !one {
		return
	}
	target := c.target
	removed, err := d.authority.Compact()
	if err != nil {
		d.logOnce(fmt.Sprintf("daemon: moving the log's anchor to a checkpoint: %v", err))
		return
	}
	d.logf("daemon: the log starts at checkpoint %s now; %d older records dropped", target.String()[:12], removed)
}

// checkpointsLocked finds the newest checkpoint on the chain and the one
// before it past the anchor, once per head. The caller holds authMu.
func (d *Daemon) checkpointsLocked() error {
	c := &d.compacting
	head, anchor := d.authority.Head(), d.authority.Anchor()
	if c.lookedAt == [2]types.Hash{head, anchor} {
		return nil
	}
	at, err := d.storage.AUM(anchor)
	if err != nil {
		return err
	}
	var found []types.Hash
	for h := head; h != anchor && len(found) < 2; {
		aum, err := d.storage.AUM(h)
		if err != nil {
			return err
		}
		// A copy of the anchor is where its chain starts, as the anchor is.
		if at.Prev != nil && aum.Prev != nil && *aum.Prev == *at.Prev && aum.SigHash() == at.SigHash() {
			break
		}
		if aum.Kind == types.KindCheckpoint {
			found = append(found, h)
		}
		if aum.Prev == nil {
			break
		}
		h = *aum.Prev
	}
	c.lookedAt, c.newest, c.target = [2]types.Hash{head, anchor}, types.Hash{}, types.Hash{}
	if len(found) == 2 {
		c.newest, c.target = found[0], found[1]
	}
	if c.past == nil {
		c.past = map[[2]types.Hash]bool{}
	}
	return nil
}

// descendsLocked reports whether h, a record this node may not hold, is cp
// or descends from it. The caller holds authMu.
func (d *Daemon) descendsLocked(h, cp types.Hash) (bool, error) {
	c := &d.compacting
	key := [2]types.Hash{h, cp}
	if past, ok := c.past[key]; ok {
		return past, nil
	}
	anchor := d.authority.Anchor()
	past := false
	for x := h; ; {
		if x == cp {
			past = true
			break
		}
		if x == anchor {
			break
		}
		aum, err := d.storage.AUM(x)
		if errors.Is(err, log.ErrNotFound) {
			// Not held yet: asked again once it is.
			return false, nil
		} else if err != nil {
			return false, err
		}
		if aum.Prev == nil {
			break
		}
		x = *aum.Prev
	}
	if len(c.past) < maxPastHeads {
		c.past[key] = past
	}
	return past, nil
}

// maxPastHeads bounds the heads [Daemon.descendsLocked] remembers.
const maxPastHeads = 4096

// Rebase moves the log to the chain an invite brought where it does not
// descend from this log's anchor: for a device further behind than its peers
// keep. The caller vouches for the chain, as an admission does.
func (d *Daemon) Rebase(records []types.AUM) error {
	d.authMu.Lock()
	err := d.authority.Rebase(records)
	d.authMu.Unlock()
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.behindSince = time.Time{}
	d.mu.Unlock()
	if err := d.Reconcile(); err != nil {
		d.logf("daemon: reconcile after a rebase: %v", err)
	}
	d.MarkDirty()
	return nil
}

// noteBehind follows whether peers answer this device from a checkpoint it
// cannot reach, as one that compacted past all it holds does: a batch that
// starts at a checkpoint whose parent this log lacks, refused, and none since
// that brought news. The caller holds authMu.
func (d *Daemon) noteBehind(records []types.AUM, news bool, err error) {
	switch {
	case news:
		d.mu.Lock()
		d.behindSince = time.Time{}
		d.mu.Unlock()
	case belowAnchor(err) && records[0].Kind == types.KindCheckpoint && records[0].Prev != nil &&
		records[0].State.Epoch > d.authority.State().Epoch():
		if _, err := d.storage.AUM(*records[0].Prev); !errors.Is(err, log.ErrNotFound) {
			return
		}
		d.mu.Lock()
		if d.behindSince.IsZero() {
			d.behindSince = d.now()
		}
		d.mu.Unlock()
	}
}

// overtaken reports whether peers have answered this device only from beyond
// its log for longer than a few rounds of sync take.
func (d *Daemon) overtaken() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.behindSince.IsZero() && d.now().Sub(d.behindSince) > overtakenAfter
}

// overtakenAfter is how long peers answer only from beyond this log before it
// is said to be overtaken: a peer that kept what it needs may yet answer.
const overtakenAfter = 10 * time.Minute

// AnchorRecord returns the record the log's chain is resolved from.
func (d *Daemon) AnchorRecord() (types.AUM, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.storage.AUM(d.authority.Anchor())
}

// belowAnchor reports whether err refuses records for not descending from
// the log's anchor.
func belowAnchor(err error) bool {
	var r *log.RejectError
	return errors.As(err, &r) && r.Rule == log.RuleParent
}
