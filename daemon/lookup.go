package daemon

import (
	"cmp"
	"slices"
	"time"

	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/types"
)

// wanted returns the members worth a DHT lookup. Those this node holds no
// announcement for come first and alone, since a round looks up only a few
// and a member just admitted is among them. Otherwise it is those whose tunnel
// does not answer: an announcement held can name a disco key its member has
// since replaced, as every restart does. Each of these is asked after in
// fewer rounds the longer it stays down, since a member gone for good would
// otherwise be looked up, and seen to be, every round for ever. A stale node
// looks up the members it keeps no tunnel to on the same schedule: their
// relays are in its map, and a relay's announcement can only reach it there.
//
// At most one round's worth is returned, those due longest first and the
// unheard among equals, members set aside only after every other one due,
// and only those returned are rescheduled: a member left out keeps its turn
// for the next round.
func (d *Daemon) wanted() []types.Identity {
	unheard := d.unheard()
	aside := d.setAside()
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	seeks := make(map[types.Identity]*lookupPlan, len(unheard))
	for _, id := range unheard {
		p := d.unheardPlan[id]
		if p == nil {
			p = &lookupPlan{lookAt: now}
		}
		seeks[id] = p
	}
	d.unheardPlan = seeks
	asides := make(map[types.Identity]*lookupPlan, len(aside))
	for _, id := range aside {
		if d.down[id] != nil || slices.ContainsFunc(d.installed, func(p namedPeer) bool { return p.id == id }) {
			continue
		}
		p := d.asidePlan[id]
		if p == nil {
			p = &lookupPlan{lookAt: now}
		}
		asides[id] = p
	}
	d.asidePlan = asides
	type due struct {
		id      types.Identity
		p       *lookupPlan
		unheard bool
		aside   bool
	}
	var all []due
	for id, p := range seeks {
		if !now.Before(p.lookAt) {
			all = append(all, due{id, p, true, false})
		}
	}
	for id, p := range d.down {
		if !now.Before(p.lookAt) {
			all = append(all, due{id, &p.lookupPlan, false, false})
		}
	}
	for id, p := range asides {
		if !now.Before(p.lookAt) {
			all = append(all, due{id, p, false, true})
		}
	}
	slices.SortFunc(all, func(a, b due) int {
		if a.aside != b.aside {
			return cmp.Compare(boolInt(a.aside), boolInt(b.aside))
		}
		if c := a.p.lookAt.Compare(b.p.lookAt); c != 0 {
			return c
		}
		if a.unheard != b.unheard {
			return cmp.Compare(boolInt(b.unheard), boolInt(a.unheard))
		}
		return a.id.Compare(b.id)
	})
	out := make([]types.Identity, 0, min(len(all), dht.MaxLookupsPerRound))
	settle := d.settles()
	for _, w := range all[:min(len(all), dht.MaxLookupsPerRound)] {
		out = append(out, w.id)
		// Until a sign of life could have come, the lookups that would find
		// it stay close together.
		most := maxLookupGap
		if p := d.down[w.id]; p != nil && now.Before(p.since.Add(settle)) {
			most = seekLookupGap
		}
		w.p.reschedule(now, most)
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// unheard returns the live members this node holds no announcement for.
func (d *Daemon) unheard() []types.Identity {
	state, err := d.TrustedState()
	if err != nil {
		return nil
	}
	now := d.now().Unix()
	nodes := state.Nodes()
	out := make([]types.Identity, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if n.Identity == d.self || n.Expired(now) {
			continue
		}
		if _, held := d.endpoints.Get(n.Identity); !held {
			out = append(out, n.Identity)
		}
	}
	return out
}

// setAside returns the live members a stale node holds an announcement for:
// none of them has a tunnel, so none is ever found down.
func (d *Daemon) setAside() []types.Identity {
	if !d.Status().Stale {
		return nil
	}
	state, err := d.TrustedState()
	if err != nil {
		return nil
	}
	now := d.now().Unix()
	nodes := state.Nodes()
	var out []types.Identity
	for i := range nodes {
		n := &nodes[i]
		if n.Identity == d.self || n.Expired(now) {
			continue
		}
		if _, held := d.endpoints.Get(n.Identity); held {
			out = append(out, n.Identity)
		}
	}
	return out
}

// A lookupPlan is when a member is next looked up in the DHT.
type lookupPlan struct {
	lookAt    time.Time // when a lookup is due
	lookEvery time.Duration
	looked    time.Time // when one was last asked for
}

// reschedule moves the next lookup on from the one due, not from now, so a
// lookup a check finds due just late keeps the schedule.
func (p *lookupPlan) reschedule(now time.Time, most time.Duration) {
	p.looked = now
	p.lookEvery = min(max(2*p.lookEvery, firstLookupGap), most)
	p.lookAt = p.lookAt.Add(p.lookEvery)
	if !p.lookAt.After(now) {
		p.lookAt = now.Add(p.lookEvery)
	}
}

// A member whose tunnel goes down is looked up in the DHT at once, then after
// firstLookupGap, doubling up to maxLookupGap: a peer that restarted or moved
// is found within a minute, and one gone for good costs a lookup an hour.
const (
	firstLookupGap = 30 * time.Second
	maxLookupGap   = time.Hour
)
