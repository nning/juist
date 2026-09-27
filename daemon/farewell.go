package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// farewellWait bounds handing a change to the members it removes, which the
// removal waits for: well inside the time a revocation has to converge in.
const farewellWait = 3 * time.Second

// farewell hands records that end members' membership, under their identity,
// to those members before this node applies them and drops their tunnels,
// best effort, and returns whom it tried. A removed device not told keeps
// believing it is a member.
func (d *Daemon) farewell(ctx context.Context, records []types.AUM) []types.Identity {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	var next *log.State
	if err == nil {
		next, err = d.authority.Preview(records...)
	}
	d.authMu.Unlock()
	if err != nil {
		return nil // Inform will say why
	}
	var gone []types.Identity
	for _, n := range state.Nodes() {
		if n.Identity != d.self && !next.IsMember(n.Identity) && !d.seenDown(n.Identity) {
			gone = append(gone, n.Identity)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	raw := make([][]byte, 0, len(records))
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return nil
		}
		raw = append(raw, b)
	}
	ctx, cancel := context.WithTimeout(ctx, farewellWait)
	defer cancel()
	var wg sync.WaitGroup
	for _, id := range gone {
		wg.Go(func() {
			if err := d.gossip.PushTo(ctx, id, raw); err != nil {
				d.logf("daemon: handing %v the change that ends its membership: %v", id.ShortString(), err)
				return
			}
			d.logf("daemon: handed %v the change that ends its membership", id.ShortString())
		})
	}
	wg.Wait()
	return gone
}

// seenDown reports whether the last tunnel check found the member's tunnel
// down.
func (d *Daemon) seenDown(id types.Identity) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.status.Reach {
		if r.Identity == id {
			return !r.Live
		}
	}
	return false
}
