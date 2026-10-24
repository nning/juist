package daemon

import (
	"cmp"
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

// outdatedAfter is how long a live peer may announce no epoch, or an older
// schema than the network's, before it is called outdated: one back from
// sleeping through an upgrade announces it a sync round after it catches up.
const outdatedAfter = 3 * time.Minute

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

// A namedPeer is an installed peer under its member name, what its
// handshakes mix in, and whether its announcement says it rests.
type namedPeer struct {
	name  string
	id    types.Identity
	wg    types.WGKey
	peer  conn.Peer
	stage pairkey.Stage
	rests bool
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
	psk    [32]byte  // installed then: a quiet ping proves no other
	pinged time.Time // when it was last pinged quietly since
}

// quietPingGap is the least time between two quiet pings of a peer, or one
// and its probe: longer than the 45 s magicsock keeps the heartbeat a packet
// started going after the last, which a ping sooner would keep going.
const quietPingGap = 50 * time.Second

// standsAt reports whether a needs no new probe at at, standing for as long
// as stands.
func (a probeAnswer) standsAt(at time.Time, stands time.Duration) bool {
	return within(a.at, at, stands)
}

// within reports whether at lies in the span from since, a clock set back
// leaving it out.
func within(since, at time.Time, span time.Duration) bool {
	age := at.Sub(since)
	return age >= 0 && age < span
}

// probeState is what one tunnel check leaves the next; mu serializes the
// checks, so asking twice does not probe twice.
type probeState struct {
	mu         sync.Mutex
	misses     map[types.Identity]int // checks in a row each peer missed
	unanswered map[types.Identity]int // probes in a row a peer left unanswered
	answered   map[types.Identity]probeAnswer
}

// A tunnelCheck is one installed peer and what checking it found.
type tunnelCheck struct {
	namedPeer
	reach ipc.PeerReach
}

// checkTunnels checks every installed peer's tunnel. Each is probed, fresh
// handshake or not, unless both ends have a relay, this device reaches the
// peer's, and it answered within [quietProbeEvery]: its last answer then
// stands. A relay not reached wakes nothing, and only a probe finds a peer
// homed there down, to be looked up for its next home.
//
// A peer that rests, or any while this device saves battery, is checked
// quietly: an answer stands for [savingProbeStands], and where no relay could
// wake the peer a quiet ping, which starts no heartbeat, holds the way open
// meanwhile, [quietPingGap] apart; one unanswered is followed by a probe. The path is read after
// the probes, since magicsock names a direct path only for a few seconds
// after its last pong, and a quiet tunnel would otherwise read as relayed.
func (d *Daemon) checkTunnels(wait time.Duration) []tunnelCheck {
	d.probes.mu.Lock()
	defer d.probes.mu.Unlock()
	d.mu.Lock()
	peers := d.installed
	now := d.probeNow
	d.probeNow = nil
	d.mu.Unlock()
	at := d.now().Round(0)
	homed := d.manager.HomeRelay() != 0
	saving := d.pace.Saving()

	out := make([]tunnelCheck, len(peers))
	probed, answered, kept := make([]bool, len(peers)), make([]bool, len(peers)), make([]bool, len(peers))
	pinged, pingAnswered := make([]bool, len(peers)), make([]bool, len(peers))
	doubted := make([]bool, len(peers))
	answers := make(map[types.Identity]probeAnswer, len(peers))
	var wg sync.WaitGroup
	probe := func(i int) {
		probed[i] = true
		wg.Add(1)
		d.manager.Probe(peers[i].peer.Addrs[0].Addr(), wait, func(ok bool) {
			defer wg.Done()
			out[i].reach.Live, answered[i] = ok, ok
		})
	}
	for i, p := range peers {
		out[i] = tunnelCheck{namedPeer: p, reach: ipc.PeerReach{Identity: p.id}}
		if len(p.peer.Addrs) == 0 {
			continue
		}
		// Neither an answer standing nor a backoff spares it a probe.
		doubted[i] = d.doubted(p)
		quiet := saving || p.rests
		stands := quietProbeEvery
		if quiet {
			stands = savingProbeStands
		}
		wakes := homed && d.manager.ReachesRelay(p.peer.HomeRelay)
		// An answer proves the key it was given under alone.
		if a, ok := d.probes.answered[p.id]; ok && !now[p.id] && !doubted[i] && a.psk == p.peer.PSK && a.standsAt(at, stands) {
			switch {
			case wakes, quiet && (within(a.at, at, quietPingGap) || within(a.pinged, at, quietPingGap)):
				out[i].reach.Live, out[i].reach.Direct, kept[i] = true, a.direct, true
				answers[p.id] = a
				continue
			case quiet:
				pinged[i] = true
				a.pinged = at
				answers[p.id] = a
				wg.Add(1)
				d.manager.ProbeQuietly(p.peer.Addrs[0].Addr(), wait, func(ok bool) {
					defer wg.Done()
					pingAnswered[i] = ok
				})
				continue
			}
		}
		// A peer that has not answered for a while is probed in only every
		// few checks: every device probing every one gone for good costs
		// traffic through the relays and battery on laptops, for nothing.
		// One with a new announcement is probed at once.
		if n := d.probes.misses[p.id]; !now[p.id] && !doubted[i] && n >= probeMissesBeforeBackoff && n%probeBackoff != 0 {
			continue
		}
		probe(i)
	}
	wg.Wait()
	// A quiet ping is lost as one packet is: only a probe finds its peer down.
	for i := range peers {
		switch {
		case pinged[i] && pingAnswered[i]:
			out[i].reach.Live, out[i].reach.Direct, kept[i] = true, answers[peers[i].id].direct, true
		case pinged[i]:
			delete(answers, peers[i].id)
			probe(i)
		}
	}
	wg.Wait()
	tunnels := d.manager.Tunnels()
	settle := d.liveByHandshake(out, tunnels, probed, doubted, kept)
	d.countMisses(out, probed, answered, doubted)
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
	keepAnswers(answers, out, tunnels, answered, at)
	d.probes.answered = answers
	handshakes := make(map[uint64]time.Time, len(tunnels))
	for id, t := range tunnels {
		handshakes[id] = t.LastHandshake
	}
	d.probePairs(out, probed, handshakes)
	return out
}

// liveByHandshake takes a fresh handshake for a live tunnel and reads each
// live one's path, and reports whether one answered through a relay where a
// direct path may yet be confirmed.
func (d *Daemon) liveByHandshake(out []tunnelCheck, tunnels map[uint64]conn.Tunnel, probed, doubted, kept []bool) (settle bool) {
	for i := range out {
		t := tunnels[out[i].peer.ID]
		// A handshake stands in for a probe not sent, and for one lost on
		// the way: a probe is one packet. Two unanswered in a row outweigh
		// all but a handshake just now, since a peer that restarted leaves
		// the last one looking fresh for minutes.
		fresh := tunnelFresh
		if probed[i] && d.probes.unanswered[out[i].id] > 0 {
			fresh = reachEvery
			if doubted[i] {
				fresh = 0
			}
		}
		if hs := t.LastHandshake; !hs.IsZero() && time.Since(hs) < fresh {
			out[i].reach.Live = true
		}
		out[i].reach.Direct = out[i].reach.Direct || out[i].reach.Live && t.Direct.IsValid()
		settle = settle || !kept[i] && out[i].reach.Live && !out[i].reach.Direct
	}
	return settle
}

// countMisses counts the checks each peer has been down for, and the probes
// in a row it left unanswered. Called with d.probes.mu held.
func (d *Daemon) countMisses(out []tunnelCheck, probed, answered, doubted []bool) {
	misses := make(map[types.Identity]int, len(out))
	for _, c := range out {
		if !c.reach.Live {
			misses[c.id] = d.probes.misses[c.id] + 1
		}
	}
	d.probes.misses = misses // a peer that answers, or is gone, starts over
	unanswered := make(map[types.Identity]int, len(out))
	for i, c := range out {
		switch {
		case probed[i] && !answered[i]:
			unanswered[c.id] = d.probes.unanswered[c.id] + 1
			if doubted[i] && unanswered[c.id] == 1 {
				d.checkSoon() // the second miss decides
			}
		case !probed[i] && d.probes.unanswered[c.id] > 0:
			unanswered[c.id] = d.probes.unanswered[c.id]
		}
	}
	d.probes.unanswered = unanswered
}

// keepAnswers records in answers each answer this check had at at, and each
// handshake since one under the same key.
func keepAnswers(answers map[types.Identity]probeAnswer, out []tunnelCheck, tunnels map[uint64]conn.Tunnel,
	answered []bool, at time.Time) {
	for i, c := range out {
		a, held := answers[c.id]
		switch hs := tunnels[c.peer.ID].LastHandshake; {
		case answered[i]:
			answers[c.id] = probeAnswer{at: at, direct: c.reach.Direct, psk: c.peer.PSK}
		case held && a.psk == c.peer.PSK && hs.After(a.at) && !hs.After(at):
			// A handshake under the key since, as the peer's own probe
			// brings, answers for both ends: one burst of heartbeat a
			// pair rather than one each.
			a.at = hs
			answers[c.id] = a
		}
	}
}

// refreshReach checks the tunnels and keeps the result for status requests
// and the DHT, so neither waits for a probe.
func (d *Daemon) refreshReach(ctx context.Context) {
	d.mu.Lock()
	gen := d.reachGen
	d.mu.Unlock()
	start := d.now()
	checks := d.checkTunnels(probeWait)
	now := d.now()
	var syncFailing, syncNewer, syncBroken []string
	failed := make(map[types.Identity]gossip.Failure, len(checks))
	for _, c := range checks {
		failed[c.id] = d.gossip.Failed(c.id)
	}
	held := make(map[types.Identity]gossip.Endpoint, len(checks))
	announced := make(map[types.Identity]types.SchemaVersion, len(checks))
	for _, c := range checks {
		if !c.reach.Live {
			held[c.id], _ = d.endpoints.Get(c.id)
		} else if ep, ok := d.endpoints.Get(c.id); ok && !ep.HintAlone() {
			announced[c.id] = ep.Schema
		}
	}
	settle := d.settles()
	relays := d.relayOwners()
	notAt := d.manager.NotAtHome()
	// A walled device sends to a peer homed where it does not reach at its
	// own home.
	via := map[int]int{}
	if d.manager.Walled() {
		for _, c := range checks {
			if r := c.peer.HomeRelay; r != 0 && !d.manager.ReachesRelay(r) {
				via[r] = d.manager.HomeRelay()
			}
		}
	}
	// Asked before d.mu is taken: the relay asks the daemon who may use it
	// under its own lock.
	d.mu.Lock()
	region := uint16(relayRegion(d.status.Network, d.self))
	srv := d.ownRelay.server
	if !d.ownRelay.region {
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
	reachable := make(map[types.Identity]bool, len(checks))
	for _, c := range checks {
		reachable[c.id] = c.reach.Live
	}
	d.reachable.Store(&reachable)
	v := classifyReach(checks, reachFacts{
		now: now, schema: d.status.Schema, settle: settle, relays: relays, via: via,
		failed: failed, held: held, announced: announced, gone: gone,
	}, reachPast{down: d.down, behind: d.behind, olderBuild: d.olderBuild, syncRetried: d.syncRetried})
	d.down, d.behind, d.olderBuild = v.past.down, v.past.behind, v.past.olderBuild
	if d.syncRetried == nil {
		d.syncRetried = map[types.Identity]time.Time{}
	}
	for _, id := range v.resync {
		d.syncRetried[id] = now
	}
	reach, resync := v.reach, v.resync
	// What the check's own probes brought counts for a peer it found down.
	var notAtRelay []string
	for _, c := range checks {
		if p, at := v.past.down[c.id], notAt[c.peer.ID]; p != nil && (!at.Before(p.since) || !at.Before(start)) {
			notAtRelay = append(notAtRelay, c.name)
		}
	}
	d.mu.Unlock()
	slices.Sort(notAtRelay)
	// A peer found down is installed on the disco key a newer hint names,
	// which every member hears of from the hint itself.
	for _, c := range checks {
		if k, ok := d.endpoints.HintDisco(c.id); ok && !c.reach.Live && c.peer.DiscoKey != conn.DiscoPublicFromRaw32(k) {
			d.reconcileSoon()
			break
		}
	}
	if v.lookup && d.dht != nil {
		d.dht.Kick()
	}
	if len(resync) > 0 {
		d.gossip.Sync(ctx, resync)
	}
	for i, c := range checks {
		if !c.reach.Live || reach[i].Outdated {
			continue
		}
		switch syncVerdict(d.gossip.Failed(c.id), d.tunName != "") {
		case syncFirewalled:
			syncFailing = append(syncFailing, c.name)
		case syncNewerBuild:
			syncNewer = append(syncNewer, c.name)
		case syncBrokenElse:
			syncBroken = append(syncBroken, c.name)
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
	slices.Sort(syncFailing)
	slices.Sort(syncNewer)
	slices.Sort(syncBroken)
	home := relays[d.manager.HomeRelay()]
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reachGen == gen {
		switch {
		case srv == nil || relayedFor > 0 || !stranded:
			d.ownRelay.unreachedSince = time.Time{}
		case d.ownRelay.unreachedSince.IsZero():
			d.ownRelay.unreachedSince = now
		}
		unreached := !d.ownRelay.unreachedSince.IsZero() && now.Sub(d.ownRelay.unreachedSince) >= relayUnreachedAfter
		d.status.Tunnels = ipc.Tunnels{
			TunnelsChecked: true, TunnelsLive: v.live, TunnelsDown: v.down,
			Reach: reach, ReachChecked: now.Unix(), HomeRelay: home,
			Seeking: v.seeking, Absent: v.absent, NotAtRelay: notAtRelay, SyncFailing: syncFailing, SyncNewer: syncNewer,
			SyncBroken: syncBroken, Outdated: v.outdated, OlderBuild: v.olderBuild,
			Firewalled: firewalled, FirewallUnsure: firewallUnsure,
			RelayedFor: relayedFor, RelayUnreached: unreached, RelayPort: relayPort,
		}
	}
}

// reachPast is what one tunnel check leaves the next.
type reachPast struct {
	down               map[types.Identity]*downPeer
	behind, olderBuild map[types.Identity]time.Time
	syncRetried        map[types.Identity]time.Time // read alone
}

// reachFacts are what refreshReach gathers for classifyReach.
type reachFacts struct {
	now       time.Time
	schema    types.SchemaVersion
	settle    time.Duration
	relays    map[int]string
	via       map[int]int // the region sent to for a peer's home, where not that
	failed    map[types.Identity]gossip.Failure
	held      map[types.Identity]gossip.Endpoint // the down's announcements
	announced map[types.Identity]types.SchemaVersion
	gone      map[types.Identity]bool
}

// A reachVerdict is what classifyReach makes of a tunnel check.
type reachVerdict struct {
	reach                                       []ipc.PeerReach
	live                                        int
	down, seeking, absent, outdated, olderBuild []string
	resync                                      []types.Identity
	lookup                                      bool
	past                                        reachPast
}

// classifyReach says what checks show of each peer, given f and what the
// last check left: whether it is down and why, behind or on an older build,
// and whom to sync with again. It changes nothing; refreshReach applies it
// under d.mu.
func classifyReach(checks []tunnelCheck, f reachFacts, past reachPast) reachVerdict {
	v := reachVerdict{reach: make([]ipc.PeerReach, len(checks)), past: reachPast{
		down:   make(map[types.Identity]*downPeer, len(checks)),
		behind: map[types.Identity]time.Time{}, olderBuild: map[types.Identity]time.Time{},
	}}
	for i, c := range checks {
		v.reach[i] = c.reach
		if c.reach.Live {
			v.live++
			if !c.reach.Direct {
				v.reach[i].Relay = f.relays[cmp.Or(f.via[c.peer.HomeRelay], c.peer.HomeRelay)]
			}
			// Back up, or up with a sync that failed: sync now, so the log
			// and the announcements catch up, and so that a failure the
			// status reports is one through the tunnel as it is.
			if _, was := past.down[c.id]; was || f.failed[c.id] != 0 && f.now.Sub(past.syncRetried[c.id]) >= syncRetryGap {
				v.resync = append(v.resync, c.id)
			}
			// Its tunnel carries juist's own traffic alone. Only a sync that
			// works shows it is not catching up.
			if c.stage == pairkey.StageNone {
				since, was := past.behind[c.id]
				if !was {
					since = f.now
				}
				v.past.behind[c.id] = since
				if f.now.Sub(since) >= outdatedAfter && f.failed[c.id] == 0 {
					v.reach[i].Outdated = true
					v.outdated = append(v.outdated, c.name)
				}
			}
			// It reaches this device, and applies no change past what its
			// build implements.
			if build, ok := f.announced[c.id]; ok && !v.reach[i].Outdated && build < f.schema {
				since, was := past.olderBuild[c.id]
				if !was {
					since = f.now
				}
				v.past.olderBuild[c.id] = since
				if f.now.Sub(since) >= outdatedAfter && f.failed[c.id] == 0 {
					v.reach[i].OlderBuild = true
					v.olderBuild = append(v.olderBuild, c.name)
				}
			}
			continue
		}
		v.down = append(v.down, c.name)
		p := past.down[c.id]
		if p == nil {
			p = &downPeer{since: f.now, lookupPlan: lookupPlan{lookAt: f.now}}
		}
		v.past.down[c.id] = p
		v.lookup = v.lookup || !f.now.Before(p.lookAt)
		ep := f.held[c.id]
		v.reach[i].Since, v.reach[i].Heard = p.since.Unix(), signedAt(ep).Unix()
		switch p.state(f.now, signedAt(ep), f.settle, f.gone[c.id]) {
		case stateSeeking:
			v.reach[i].Seeking = true
			v.seeking = append(v.seeking, c.name)
		case stateAbsent:
			v.reach[i].Absent = true
			v.absent = append(v.absent, c.name)
		case stateBlocked:
			// Running a build from before the network's upgrade, which knows
			// no member that joined after it. Given longer than a live peer:
			// its announcement from after the upgrade comes by the DHT.
			if c.stage == pairkey.StageNone || !ep.HintAlone() && ep.Schema < f.schema {
				since, was := past.behind[c.id]
				if !was {
					since = f.now
				}
				v.past.behind[c.id] = since
				if f.now.Sub(since) >= max(outdatedAfter, f.settle) {
					v.reach[i].Outdated = true
					v.outdated = append(v.outdated, c.name)
				}
			}
		}
	}
	for _, names := range [][]string{v.down, v.seeking, v.absent, v.outdated, v.olderBuild} {
		slices.Sort(names)
	}
	return v
}

// What a failing log sync through a live tunnel is put down to.
const (
	syncNone = iota
	syncFirewalled
	syncNewerBuild
	syncBrokenElse
)

// syncVerdict is what the last round's failure f with a live peer is put
// down to, tun saying a host firewall stands before the tunnel.
func syncVerdict(f gossip.Failure, tun bool) int {
	switch {
	case f == 0 || f == gossip.FailRefused:
		// A refusal is the network's word on this device, said apart.
		return syncNone
	case f == gossip.FailNewer:
		return syncNewerBuild
	case f == gossip.FailUnconnected && tun:
		// The tunnel carries traffic, yet no session through it came up:
		// a firewall drops the sync port on juist0 on one side.
		return syncFirewalled
	}
	return syncBrokenElse
}

// noteNewAnnouncements compares the peers about to be installed with those
// installed: one whose announcement says something new runs, and is probed
// now rather than when its backoff allows, so its tunnel is known to be back
// as soon as it is. One that only renewed its signature changes nothing here,
// and one checked quietly and not down that only moved its addresses is left
// to its next check: a probe would start a heartbeat on both ends.
func (d *Daemon) noteNewAnnouncements(next []namedPeer) {
	saving := d.pace.Saving()
	d.mu.Lock()
	changed := false
	for _, n := range next {
		i := slices.IndexFunc(d.installed, func(p namedPeer) bool { return p.id == n.id })
		if i >= 0 && samePeerPath(d.installed[i].peer, n.peer) {
			continue
		}
		p := d.down[n.id]
		if p != nil {
			p.renewed = true
		}
		if i >= 0 && p == nil && (saving || n.rests) && movedAlone(d.installed[i].peer, n.peer) {
			continue
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

// doubted reports whether a hint newer than p's announcement names another
// disco key than p is installed on: its member restarted, or the hint is
// forged. A probe tells which, two missed in a row; a
// handshake from before the restart says nothing.
func (d *Daemon) doubted(p namedPeer) bool {
	k, ok := d.endpoints.HintDisco(p.id)
	return ok && p.peer.DiscoKey != conn.DiscoPublicFromRaw32(k)
}

// checkDoubted asks for a check at once where a member in peers is newly
// doubted, so a restarted one moves to its new disco key within seconds.
func (d *Daemon) checkDoubted(peers []namedPeer) {
	kick := false
	d.mu.Lock()
	seen := make(map[types.Identity]gossip.DiscoKey, len(d.doubtedOn))
	for _, p := range peers {
		k, ok := d.endpoints.HintDisco(p.id)
		if !ok || p.peer.DiscoKey == conn.DiscoPublicFromRaw32(k) {
			continue
		}
		seen[p.id] = k
		kick = kick || d.doubtedOn[p.id] != k
	}
	d.doubtedOn = seen
	d.mu.Unlock()
	if kick {
		d.checkSoon()
	}
}

// samePeerPath reports whether two peer entries reach the peer the same way.
func samePeerPath(a, b conn.Peer) bool {
	return a.DiscoKey == b.DiscoKey && a.HomeRelay == b.HomeRelay && slices.Equal(a.Endpoints, b.Endpoints)
}

// movedAlone reports whether b differs from a in its addresses alone.
func movedAlone(a, b conn.Peer) bool { return a.DiscoKey == b.DiscoKey && a.HomeRelay == b.HomeRelay }

// checkSoon asks for a tunnel check ahead of the next one due.
func (d *Daemon) checkSoon() {
	select {
	case d.recheck <- struct{}{}:
	default:
	}
}

// relayOwners names each relay region by the member whose relay it is.
func (d *Daemon) relayOwners() map[int]string {
	state, err := d.TrustedState()
	if err != nil {
		return nil
	}
	// Of two members deriving one region, the lower identity holds it; see
	// [Daemon.relaySet].
	names := map[int]string{}
	holders := map[int]types.Identity{}
	for _, n := range state.NodesWithRole(types.RoleRelayCapable) {
		region := relayRegion(state.GenesisHash(), n.Identity)
		if h, ok := holders[region]; !ok || n.Identity.Compare(h) < 0 {
			names[region], holders[region] = n.Name, n.Identity
		}
	}
	return names
}
