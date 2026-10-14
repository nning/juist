package daemon

import (
	"cmp"
	"slices"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A renumbering is what this node knows of who holds the newest renumbering
// record, while one keeps old addresses working.
type renumbering struct {
	head types.Hash // the chain head it was found from

	// since holds the record and every one after it on the chain: a peer
	// holding any of them holds the renumbering, as one that started from a
	// later checkpoint does.
	since map[types.Hash]bool
	seen  map[types.Identity]bool
}

// followRenumbering returns the names of the live members other than this one
// not yet seen holding the newest renumbering, while any member's old address
// is still recorded: working until its deadline, or held after it, when a
// member not told yet reaches the moved one over IPv6 alone.
func (d *Daemon) followRenumbering(state *log.State, live map[types.Identity]bool) []string {
	_, moving := state.V4Retiring()
	for _, n := range state.Nodes() {
		moving = moving || n.Retiring != nil
	}
	d.mu.Lock()
	cur := d.moving
	if !moving {
		d.moving = nil
	}
	d.mu.Unlock()
	if !moving {
		return nil
	}
	if cur == nil || cur.head != state.Head() {
		next, record, err := d.renumberingAt(state.Head())
		if err != nil {
			d.logOnce("daemon: finding the renumbering record: " + err.Error())
			return nil
		}
		d.mu.Lock()
		if cur != nil && cur.since[record] {
			next.seen = cur.seen
		}
		d.moving = next
		d.mu.Unlock()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, n := range state.Nodes() {
		if n.Identity != d.self && live[n.Identity] && !d.moving.seen[n.Identity] {
			out = append(out, cmp.Or(n.Name, n.Identity.ShortString()))
		}
	}
	slices.Sort(out)
	return out
}

// renumberingAt walks back from head to the newest renumbering record, or to
// the start of the stored chain where none is stored.
func (d *Daemon) renumberingAt(head types.Hash) (*renumbering, types.Hash, error) {
	r := &renumbering{head: head, since: map[types.Hash]bool{}, seen: map[types.Identity]bool{}}
	d.authMu.Lock()
	defer d.authMu.Unlock()
	anchors, err := d.authority.Copies(d.authority.Anchor())
	if err != nil {
		return nil, types.Hash{}, err
	}
	h := head
	for {
		aum, err := d.storage.AUM(h)
		if err != nil {
			return nil, types.Hash{}, err
		}
		r.since[h] = true
		if aum.Kind == types.KindRenumberNetwork || aum.Kind == types.KindRenumberNode ||
			aum.Prev == nil || slices.Contains(anchors, h) {
			return r, h, nil
		}
		h = *aum.Prev
	}
}

// onHave notes a peer holding the newest renumbering.
func (d *Daemon) onHave(from types.Identity, have []types.Hash) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.moving == nil || d.moving.seen[from] {
		return
	}
	for _, h := range have {
		if d.moving.since[h] {
			d.moving.seen[from] = true
			return
		}
	}
}
