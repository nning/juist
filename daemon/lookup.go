package daemon

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/relay/forward"
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

// seeksInDHT reports whether this device asks the public DHT after members:
// where it reaches none, is stale, or holds the lowest identity among those
// it reaches. What one device of a group finds, gossip hands the others, so
// storage nodes link the members sought to one address rather than to each.
func (d *Daemon) seeksInDHT() bool {
	if d.Status().Stale {
		return true
	}
	r := d.reachable.Load()
	if r == nil {
		return true
	}
	for id, live := range *r {
		if live && id.Compare(d.self) < 0 && !d.peerRests(id) {
			return false
		}
	}
	return true
}

// joinsDHT reports whether a device that rests takes part in the public DHT:
// not before its first check, nor while a member that does not rest answers
// it, which publishes and looks there itself and hands on by gossip what
// this device announces and finds.
func (d *Daemon) joinsDHT() bool {
	r := d.reachable.Load()
	if r == nil {
		return false
	}
	for id, live := range *r {
		if live && !d.peerRests(id) {
			return false
		}
	}
	return true
}

// askTimeout bounds one relay's answer, at each of its addresses.
const askTimeout = 5 * time.Second

// askRelays asks the member relays, the home relay's first, for id's
// announcement under the newest epoch, and reports whether one held one
// newer than this device's.
func (d *Daemon) askRelays(ctx context.Context, id types.Identity) bool {
	epoch, secret, ok := d.keyring.Latest()
	if !ok {
		return false
	}
	key := dht.RendezvousKey(secret.TopicSeed(epoch, dht.Window(d.now()), id))
	held, _ := d.endpoints.Get(id)
	for _, r := range d.askable() {
		raw, err := d.askRelay(ctx, r, key)
		if err != nil {
			continue
		}
		e, err := dht.OpenAnnouncement(d.keyring, epoch, raw)
		if err != nil || e.Identity != id || e.Seq <= held.Seq {
			continue
		}
		d.discovered(e, "at a member relay")
		return true
	}
	return false
}

// askable are the relays worth asking: not this device's own, the home
// relay's first, a few.
func (d *Daemon) askable() []conn.Relay {
	home := d.manager.HomeRelay()
	d.mu.Lock()
	own := relayRegion(d.status.Network, d.self)
	relays := slices.DeleteFunc(slices.Clone(d.relays), func(r conn.Relay) bool { return r.Region == own })
	d.mu.Unlock()
	slices.SortStableFunc(relays, func(a, b conn.Relay) int { return cmp.Compare(boolInt(a.Region != home), boolInt(b.Region != home)) })
	return relays[:min(len(relays), maxRendezvousRelays)]
}

// askRelay asks one relay for the item at key: at its addresses, by the
// certificate its announcement pins, then at its name on 443.
func (d *Daemon) askRelay(ctx context.Context, r conn.Relay, key [32]byte) ([]byte, error) {
	err := errors.New("daemon: the relay has no address to ask")
	if len(r.Addrs) > 0 {
		hc := &http.Client{Timeout: askTimeout, CheckRedirect: noRedirect, Transport: &http.Transport{
			DialContext:         underlay.Dialer(askTimeout).DialContext,
			TLSClientConfig:     forward.PinnedConfig(r.HostName, r.CertHash),
			TLSHandshakeTimeout: askTimeout,
			DisableKeepAlives:   true,
		}}
		for _, ap := range r.Addrs {
			var v []byte
			if v, err = relay.GetAnnouncement(ctx, hc, ap.String(), key); err == nil || errors.Is(err, relay.ErrNotHeld) {
				return v, err
			}
		}
	}
	if r.Name != "" {
		return relay.GetAnnouncement(ctx, d.httpsClient(), r.Name, key)
	}
	return nil, err
}
