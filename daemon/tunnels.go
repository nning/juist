package daemon

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/types"
)

// tunnelFresh is how long a completed handshake proves a tunnel: WireGuard's
// RejectAfterTime, past which the session's keys are no longer used.
const tunnelFresh = 180 * time.Second

// probeWait bounds how long a check waits for a quiet tunnel to answer.
const probeWait = 3 * time.Second

// A peer that has missed probeMissesBeforeBackoff checks in a row is probed
// in every probeBackoff-th check only.
const (
	probeMissesBeforeBackoff = 3
	probeBackoff             = 10
)

// pathSettle is how long a check waits for a direct path to be confirmed
// where a probe was answered without one.
const pathSettle = time.Second

// reachEvery is how often the tunnels are checked in the background. Its
// probes keep the NAT mappings towards a quiet peer open where no relay could
// bring the tunnel back.
const reachEvery = 30 * time.Second

// quietProbeEvery is how often a peer that answered is probed where a relay
// can bring its tunnel back: each probe keeps magicsock pinging it every 3 s
// for 45 s, so probing every reachEvery keeps a laptop's radio awake.
const quietProbeEvery = 5 * time.Minute

// recheckGap is the least time between two checks, however often a new
// announcement asks for one.
const recheckGap = 5 * time.Second

// relayUnreachedAfter is how long this device's relay may go unused, while a
// live peer is homed at no member relay, before its port is blamed: a peer
// measures the relays and announces its home within a minute or two.
const relayUnreachedAfter = 3 * time.Minute

// syncRetryGap is how often a sync that keeps failing through a live tunnel
// is tried again before the status blames a firewall for it.
const syncRetryGap = 5 * time.Minute

// A running device signs its announcement again every announceRenewal, and
// for each DHT publication, though nothing in it changed: its sequence number
// is its clock, so a signature made after a peer's tunnel went down is what
// shows the peer running. Only such a signature lets the status blame the
// way; without one it calls the peer offline once one could have arrived:
// published within a DHT interval, found within a lookup gap, allowing for
// clocks that disagree by clockSkew.
const (
	announceRenewal = 5 * time.Minute
	seekLookupGap   = 5 * time.Minute
	clockSkew       = 2 * time.Minute
)

// A downPeer is an installed member the checks find down.
type downPeer struct {
	lookupPlan
	since   time.Time // when a check first found it down
	renewed bool      // an announcement saying something new arrived since
}

// A downState is what can be said about why a peer's tunnel is down.
type downState int

const (
	// stateSeeking: not yet known whether it is offline or the way to it
	// is blocked.
	stateSeeking downState = iota
	// stateBlocked: it has signed or changed its announcement since, so it
	// runs, and the way to it is to blame.
	stateBlocked
	// stateAbsent: no sign of it running since, where one had time to come:
	// it is offline.
	stateAbsent
)

// state says why a peer is down at now, given when its newest announcement
// held was signed, how long a sign of life may take to arrive — zero where
// none is to be expected — and whether its home relay, this device's, finds
// it disconnected.
func (p *downPeer) state(now, signed time.Time, settle time.Duration, relayGone bool) downState {
	switch {
	case p.renewed || signed.After(p.since.Add(clockSkew)):
		// Signed since, as the signer's clock has it: clockSkew ahead, a
		// record signed just before the peer went quiet would pass.
		return stateBlocked
	case relayGone && !now.Before(p.since.Add(firstLookupGap)), settle > 0 && !now.Before(p.since.Add(settle)):
		return stateAbsent
	}
	return stateSeeking
}

// settles is how long after a peer goes down a sign of it running has had
// time to arrive: through the DHT where there is one, else on the LAN.
func (d *Daemon) settles() time.Duration {
	if d.dht == nil {
		return announceRenewal + 2*clockSkew + reachEvery
	}
	return dht.DefaultInterval + seekLookupGap + 2*clockSkew
}

// signedAt reads an announcement's sequence number as the signer's clock.
func signedAt(e gossip.Endpoint) time.Time { return time.Unix(int64(min(e.Seq, 1<<62)), 0) }

// A namedPeer is an installed peer under its member name, and what its
// handshakes mix in.
type namedPeer struct {
	name  string
	id    types.Identity
	wg    types.WGKey
	peer  conn.Peer
	stage pairkey.Stage
}

// setInstalled records the peer set about to be installed. Set before
// SetPeers, a failed install leaves probes aimed at peers that may lack an
// entry, which they then report as down.
func (d *Daemon) setInstalled(peers []namedPeer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.installed = peers
}

// Tunnels reports how many installed peers' tunnels are live and names the
// rest, sorted. Each is probed and waited for up to wait; a handshake within
// [tunnelFresh] counts as live too.
func (d *Daemon) Tunnels(wait time.Duration) (live int, down []string) {
	for _, c := range d.checkTunnels(wait) {
		if c.reach.Live {
			live++
		} else {
			down = append(down, c.name)
		}
	}
	slices.Sort(down)
	return live, down
}

// A probeAnswer is the last probe a peer answered.
type probeAnswer struct {
	at     time.Time // wall clock, so that a suspend ages it
	direct bool
}

// standsAt reports whether a needs no new probe at at.
func (a probeAnswer) standsAt(at time.Time) bool {
	age := at.Sub(a.at)
	return age >= 0 && age < quietProbeEvery
}

// A tunnelCheck is one installed peer and what checking it found.
type tunnelCheck struct {
	namedPeer
	reach ipc.PeerReach
}

// checkTunnels checks every installed peer's tunnel. Each is probed, fresh
// handshake or not, unless both ends have a relay and it answered within
// [quietProbeEvery], when its last answer stands: the path is read after the
// probes, since magicsock names a direct path only for a few seconds after its
// last pong, and a quiet tunnel would otherwise read as relayed.
func (d *Daemon) checkTunnels(wait time.Duration) []tunnelCheck {
	d.probeMu.Lock()
	defer d.probeMu.Unlock()
	d.mu.Lock()
	peers := d.installed
	now := d.probeNow
	d.probeNow = nil
	d.mu.Unlock()
	at := d.now().Round(0)
	homed := d.manager.HomeRelay() != 0

	out := make([]tunnelCheck, len(peers))
	probed, answered, kept := make([]bool, len(peers)), make([]bool, len(peers)), make([]bool, len(peers))
	answers := make(map[types.Identity]probeAnswer, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		out[i] = tunnelCheck{namedPeer: p, reach: ipc.PeerReach{Identity: p.id}}
		if len(p.peer.Addrs) == 0 {
			continue
		}
		if a, ok := d.answered[p.id]; ok && homed && p.peer.HomeRelay != 0 && !now[p.id] && a.standsAt(at) {
			out[i].reach.Live, out[i].reach.Direct, kept[i] = true, a.direct, true
			answers[p.id] = a
			continue
		}
		// A peer that has not answered for a while is probed in only every
		// few checks: every device probing every one gone for good costs
		// traffic through the relays and battery on laptops, for nothing.
		// One with a new announcement is probed at once.
		if n := d.probeMisses[p.id]; !now[p.id] && n >= probeMissesBeforeBackoff && n%probeBackoff != 0 {
			continue
		}
		probed[i] = true
		wg.Add(1)
		d.manager.Probe(p.peer.Addrs[0].Addr(), wait, func(ok bool) {
			defer wg.Done()
			out[i].reach.Live, answered[i] = ok, ok
		})
	}
	wg.Wait()
	tunnels := d.manager.Tunnels()
	settle := false
	for i := range out {
		t := tunnels[out[i].peer.ID]
		// A handshake stands in for a probe not sent, and for one lost on
		// the way: a probe is one packet. Two unanswered in a row outweigh
		// all but a handshake just now, since a peer that restarted leaves
		// the last one looking fresh for minutes.
		fresh := tunnelFresh
		if probed[i] && d.unanswered[out[i].id] > 0 {
			fresh = reachEvery
		}
		if hs := t.LastHandshake; !hs.IsZero() && time.Since(hs) < fresh {
			out[i].reach.Live = true
		}
		out[i].reach.Direct = out[i].reach.Direct || out[i].reach.Live && t.Direct.IsValid()
		settle = settle || !kept[i] && out[i].reach.Live && !out[i].reach.Direct
	}
	misses := make(map[types.Identity]int, len(out))
	for _, c := range out {
		if !c.reach.Live {
			misses[c.id] = d.probeMisses[c.id] + 1
		}
	}
	d.probeMisses = misses // a peer that answers, or is gone, starts over
	unanswered := make(map[types.Identity]int, len(out))
	for i, c := range out {
		switch {
		case probed[i] && !answered[i]:
			unanswered[c.id] = d.unanswered[c.id] + 1
		case !probed[i] && d.unanswered[c.id] > 0:
			unanswered[c.id] = d.unanswered[c.id]
		}
	}
	d.unanswered = unanswered
	if settle && d.pathSettle > 0 {
		// A probe's answer can arrive through the relay before the pong
		// that confirms the direct path does.
		time.Sleep(d.pathSettle)
		tunnels = d.manager.Tunnels()
		for i := range out {
			if t := tunnels[out[i].peer.ID]; out[i].reach.Live && t.Direct.IsValid() {
				out[i].reach.Direct = true
			}
		}
	}
	for i, c := range out {
		if answered[i] {
			answers[c.id] = probeAnswer{at: at, direct: c.reach.Direct}
		}
	}
	d.answered = answers
	handshakes := make(map[uint64]time.Time, len(tunnels))
	for id, t := range tunnels {
		handshakes[id] = t.LastHandshake
	}
	d.probePairs(out, probed, handshakes)
	return out
}

// refreshReach checks the tunnels and keeps the result for status requests
// and the DHT, so neither waits for a probe.
func (d *Daemon) refreshReach(ctx context.Context) {
	d.mu.Lock()
	gen := d.reachGen
	d.mu.Unlock()
	checks := d.checkTunnels(probeWait)
	reach := make([]ipc.PeerReach, len(checks))
	now := d.now()
	var live int
	var down, seeking, absent, syncFailing []string
	var resync []types.Identity
	lookup := false
	failing := map[types.Identity]bool{}
	for _, c := range checks {
		failing[c.id] = d.gossip.Failing(c.id)
	}
	held := make(map[types.Identity]gossip.Endpoint, len(checks))
	for _, c := range checks {
		if !c.reach.Live {
			held[c.id], _ = d.endpoints.Get(c.id)
		}
	}
	settle := d.settles()
	// Asked before d.mu is taken: the relay asks the daemon who may use it
	// under its own lock.
	d.mu.Lock()
	region := uint16(relayRegion(d.status.Network, d.self))
	srv := d.relay
	if !d.ownRegion {
		srv = nil
	}
	d.mu.Unlock()
	gone := map[types.Identity]bool{}
	for _, c := range checks {
		ep, down := held[c.id]
		gone[c.id] = down && srv != nil && ep.HomeRelay == region && !srv.Connected(c.wg)
	}
	// A peer connected to this relay, or homed at it, reached it; a live one
	// homed at no member relay would have, were its port open.
	var relayedFor int
	var relayPort uint16
	stranded := false
	if srv != nil {
		relayPort = srv.Port()
		for _, c := range checks {
			ep, _ := d.endpoints.Get(c.id)
			switch {
			case srv.Connected(c.wg) || ep.HomeRelay == region:
				relayedFor++
			case c.reach.Live && ep.HomeRelay == 0:
				stranded = true
			}
		}
	}
	d.mu.Lock()
	if d.reachGen != gen {
		d.mu.Unlock()
		return
	}
	downs := make(map[types.Identity]*downPeer, len(checks))
	reachable := make(map[types.Identity]bool, len(checks))
	for _, c := range checks {
		reachable[c.id] = c.reach.Live
	}
	d.reachable.Store(&reachable)
	for i, c := range checks {
		reach[i] = c.reach
		if c.reach.Live {
			live++
			// Back up, or up with a sync that failed: sync now, so the log
			// and the announcements catch up, and so that a failure the
			// status reports is one through the tunnel as it is.
			if _, was := d.down[c.id]; was || failing[c.id] && now.Sub(d.syncRetried[c.id]) >= syncRetryGap {
				resync = append(resync, c.id)
			}
			continue
		}
		down = append(down, c.name)
		p := d.down[c.id]
		if p == nil {
			p = &downPeer{since: now, lookupPlan: lookupPlan{lookAt: now}}
		}
		downs[c.id] = p
		lookup = lookup || !now.Before(p.lookAt)
		ep := held[c.id]
		reach[i].Since, reach[i].Heard = p.since.Unix(), signedAt(ep).Unix()
		// A device never seen renewing may be on a build that does not: the
		// window says nothing about it.
		window := settle
		if !d.endpoints.Renews(c.id) {
			window = 0
		}
		switch p.state(now, signedAt(ep), window, gone[c.id]) {
		case stateSeeking:
			reach[i].Seeking = true
			seeking = append(seeking, c.name)
		case stateAbsent:
			reach[i].Absent = true
			absent = append(absent, c.name)
		}
	}
	d.down = downs
	if d.syncRetried == nil {
		d.syncRetried = map[types.Identity]time.Time{}
	}
	for _, id := range resync {
		d.syncRetried[id] = now
	}
	d.mu.Unlock()
	if lookup && d.dht != nil {
		d.dht.Kick()
	}
	if len(resync) > 0 {
		d.gossip.Sync(ctx, resync)
	}
	for _, c := range checks {
		// The tunnel carries traffic, yet the session through it did not
		// come up: a firewall drops the sync port on juist0 on one side.
		if c.reach.Live && d.tunName != "" && d.gossip.Failing(c.id) {
			syncFailing = append(syncFailing, c.name)
		}
	}
	var firewalled string
	var firewallUnsure bool
	// A network stack of its own has no host firewall before it.
	if d.tunName != "" {
		if blocked, unsure := d.firewalled(ctx, d.tunName, d.gossipPort); blocked {
			firewalled, firewallUnsure = d.tunName, unsure
		}
	}
	slices.Sort(down)
	slices.Sort(seeking)
	slices.Sort(absent)
	slices.Sort(syncFailing)
	home := d.homeRelayName()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reachGen == gen {
		switch {
		case srv == nil || relayedFor > 0 || !stranded:
			d.relayUnreachedSince = time.Time{}
		case d.relayUnreachedSince.IsZero():
			d.relayUnreachedSince = now
		}
		unreached := !d.relayUnreachedSince.IsZero() && now.Sub(d.relayUnreachedSince) >= relayUnreachedAfter
		d.status.Tunnels = ipc.Tunnels{
			TunnelsChecked: true, TunnelsLive: live, TunnelsDown: down,
			Reach: reach, ReachChecked: now.Unix(), HomeRelay: home,
			Seeking: seeking, Absent: absent, SyncFailing: syncFailing,
			Firewalled: firewalled, FirewallUnsure: firewallUnsure,
			RelayedFor: relayedFor, RelayUnreached: unreached, RelayPort: relayPort,
		}
	}
}

// noteNewAnnouncements compares the peers about to be installed with those
// installed: one whose announcement says something new runs, and is probed
// now rather than when its backoff allows, so its tunnel is known to be back
// as soon as it is. One that only renewed its signature changes nothing here.
func (d *Daemon) noteNewAnnouncements(next []namedPeer) {
	d.mu.Lock()
	changed := false
	for _, n := range next {
		i := slices.IndexFunc(d.installed, func(p namedPeer) bool { return p.id == n.id })
		if i >= 0 && samePeerPath(d.installed[i].peer, n.peer) {
			continue
		}
		if p := d.down[n.id]; p != nil {
			p.renewed = true
		}
		if d.probeNow == nil {
			d.probeNow = map[types.Identity]bool{}
		}
		d.probeNow[n.id] = true
		changed = changed || i >= 0
	}
	d.mu.Unlock()
	if changed {
		d.checkSoon()
	}
}

// samePeerPath reports whether two peer entries reach the peer the same way.
func samePeerPath(a, b conn.Peer) bool {
	return a.DiscoKey == b.DiscoKey && a.HomeRelay == b.HomeRelay && slices.Equal(a.Endpoints, b.Endpoints)
}

// checkSoon asks for a tunnel check ahead of the next one due.
func (d *Daemon) checkSoon() {
	select {
	case d.recheck <- struct{}{}:
	default:
	}
}

// homeRelayName is the member whose relay the data plane keeps its home
// connection to, empty where it has none.
func (d *Daemon) homeRelayName() string {
	region := d.manager.HomeRelay()
	if region == 0 {
		return ""
	}
	state, err := d.TrustedState()
	if err != nil {
		return ""
	}
	// Of two members deriving one region, the lower identity holds it; see
	// [Daemon.relaySet].
	var name string
	var holder types.Identity
	for _, n := range state.NodesWithRole(types.RoleRelayCapable) {
		if relayRegion(state.GenesisHash(), n.Identity) == region &&
			(name == "" || n.Identity.Compare(holder) < 0) {
			name, holder = n.Name, n.Identity
		}
	}
	return name
}
