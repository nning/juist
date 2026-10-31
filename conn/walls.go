package conn

import (
	"context"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// meetEvery is how often a member writes to a walled peer's home: magicsock
// closes a connection to a region other than its home once nothing was
// written on it for 60 s, checking every 15 s.
const meetEvery = 45 * time.Second

// lookAgain is how soon a node asks for another report where the last one
// left undecided whether it is walled, or whether names come first.
const lookAgain = 10 * time.Second

// derpNotHere is magicsock's line for a relay's answer that a peer sent to is
// not connected to it; a test holds it to the pinned module's.
const derpNotHere = "magicsock: derp-%d does not know about peer %s, removing route"

// walls holds what makes this node walled, and whom it has been told is not
// at its home.
type walls struct {
	// unreached are the member relays out of reach while walled, nil
	// otherwise, and home the home what goes to a peer homed at one of them
	// is sent to; out is unreached for readers without apply. Guarded by the
	// manager's apply.
	unreached map[int]bool
	home      int
	out       atomic.Pointer[map[int]bool]
	// missed is how many reports in a row, of those up to counted, did not
	// reach each member relay while homed; decisive whether the last one
	// measured anything, homed whether it was counted with a home. Guarded
	// by apply.
	missed   map[int]int
	decisive bool
	homed    bool
	// nameFirst is whether relays' names come first in the map, as where
	// reports without UDP reached none; blind is how many did in a row.
	// Guarded by apply.
	nameFirst bool
	blind     int
	// namedFirst is how many reports were counted since names came first,
	// each taken with them first. Guarded by apply.
	namedFirst int
	counted    *netcheck.Report
	// asked is the report counted when another was last asked for, once
	// each, as none comes while the link is down; waited the one the wait
	// before asking began at. Guarded by apply.
	asked, waited *netcheck.Report
	// stunAside is whether the map leaves the STUN servers out, as where
	// they answered and no relay did; unanswered is how many reports in a
	// row, up to stunCounted, did so; asideAgain when they may be left out
	// again after HTTPS reached no relay either, asideGap the wait after
	// the next such. Guarded by apply, stunAside written under it.
	stunAside   atomic.Bool
	unanswered  int
	stunCounted *netcheck.Report
	asideAgain  time.Time
	asideGap    time.Duration
	emptyAside  int // reports in a row that measured nothing, without them

	noRelay atomic.Bool // blind is above 0, for readers without apply

	kick chan struct{} // the meeting loop is to look again
	due  atomic.Bool   // a look after a report is due
	// met is when each home a connection is kept at was last needed, kept
	// the homes last kept. Guarded by apply.
	met  map[int]time.Time
	kept []int
	// keepKey is what the writes keeping a connection at a walled peer's
	// home are addressed to: no client holds it, so the relay drops them.
	keepKey key.NodePublic

	goneMu sync.Mutex
	gone   map[key.NodePublic]time.Time
}

func (m *tsManager) Walled() bool { return m.walled.Load() }

func (m *tsManager) ReachesNoRelay() bool { return m.walls.noRelay.Load() }

func (m *tsManager) NotAtHome() map[uint64]time.Time {
	m.walls.goneMu.Lock()
	defer m.walls.goneMu.Unlock()
	st := m.state.Load()
	out := make(map[uint64]time.Time, len(m.walls.gone))
	for nk, at := range m.walls.gone {
		if p, ok := st.peers[nk]; ok {
			out[p.ID] = at
		}
	}
	return out
}

// noteNotHere records that region, if it is this node's home, said the peer
// whose key reads as short is not connected to it.
func (m *tsManager) noteNotHere(region tailcfg.DERPRegionID, short string) {
	if int(region) != m.HomeRelay() {
		return
	}
	now := time.Now()
	m.walls.goneMu.Lock()
	defer m.walls.goneMu.Unlock()
	st := m.state.Load()
	for nk := range st.peers {
		if nk.ShortString() == short {
			if m.walls.gone == nil {
				m.walls.gone = map[key.NodePublic]time.Time{}
			}
			m.walls.gone[nk] = now
		}
	}
	for nk := range m.walls.gone {
		if _, ok := st.peers[nk]; !ok {
			delete(m.walls.gone, nk)
		}
	}
}

// unreachedIn says which of relays a node homed at home does not reach, as
// r measured them, nil where it is not walled; ok is false where r says
// nothing either way, as one that measured nothing. Without UDP, netcheck
// pings a relay too, which says nothing of TCP: a relay in pinged, reached
// by ICMP alone, is not reached.
func unreachedIn(relays []Relay, home int, r *netcheck.Report, httpsOnly bool, pinged map[int]bool) (unreached map[int]bool, ok bool) {
	if home == 0 || len(relays) == 0 {
		return nil, true
	}
	if r == nil || len(r.RegionLatency) == 0 {
		return nil, false
	}
	if r.UDP && !httpsOnly {
		return nil, true
	}
	for _, rel := range relays {
		_, measured := r.RegionLatency[tailcfg.DERPRegionID(rel.Region)]
		if rel.Region != home && (!measured || pinged[rel.Region]) {
			if unreached == nil {
				unreached = map[int]bool{}
			}
			unreached[rel.Region] = true
		}
	}
	return unreached, true
}

// blindAfter is how many reports in a row, r last, had no UDP and reached
// no relay but by ICMP alone, those in pinged, before was.
func blindAfter(r *netcheck.Report, relays []Relay, pinged map[int]bool, before int) int {
	if r == nil || r.UDP || !slices.ContainsFunc(relays, func(rel Relay) bool { return rel.Name != "" }) {
		return 0
	}
	for _, rel := range relays {
		_, ok := r.RegionLatency[tailcfg.DERPRegionID(rel.Region)]
		if ok && !pinged[rel.Region] {
			return 0
		}
	}
	return before + 1
}

// missedAfter counts, per relay, the reports in a row that left it out of
// reach of a node homed at home, r last, before was; a report that says
// nothing either way leaves them.
func missedAfter(r *netcheck.Report, relays []Relay, home int, httpsOnly bool, pinged map[int]bool, before map[int]int) (after map[int]int, decisive bool) {
	u, ok := unreachedIn(relays, home, r, httpsOnly, pinged)
	if !ok {
		return before, false
	}
	for region := range u {
		if after == nil {
			after = map[int]int{}
		}
		after[region] = before[region] + 1
	}
	return after, true
}

// missesToWall is how many reports in a row must miss a relay before it
// counts as out of reach, as one may miss a far relay in the time netcheck
// leaves HTTPS. On --https-only, a relay without a name is not in the map.
func missesToWall(rel Relay, httpsOnly bool) int {
	if httpsOnly && rel.Name == "" {
		return 1
	}
	return 2
}

// follow takes report r, once, into what makes this node walled, and
// reports whether it was new. The home a report leads to comes after it, so
// the report is counted for what it missed again once there is one.
func (w *walls) follow(r *netcheck.Report, relays []Relay, home int, httpsOnly bool, pinged map[int]bool) bool {
	switch {
	case r != w.counted:
		w.counted = r
		w.blind = blindAfter(r, relays, pinged, w.blind)
		if w.nameFirst {
			w.namedFirst++
		}
	case home != 0 && !w.homed:
		w.asked = nil
	default:
		return false
	}
	w.homed = home != 0
	w.missed, w.decisive = missedAfter(r, relays, home, httpsOnly, pinged, w.missed)
	return true
}

// unreachedAt is which of relays a node homed at home does not reach, by
// the reports followed: nil where it is not walled.
func (w *walls) unreachedAt(relays []Relay, home int, httpsOnly bool) map[int]bool {
	if home == 0 {
		return nil
	}
	var out map[int]bool
	for _, rel := range relays {
		if rel.Region != home && w.missed[rel.Region] >= missesToWall(rel, httpsOnly) {
			if out == nil {
				out = map[int]bool{}
			}
			out[rel.Region] = true
		}
	}
	return out
}

// waitFor reports whether to wait [lookAgain] and ask for another report,
// as the last left something undecided and none was asked for since, and
// notes the wait began.
func (w *walls) waitFor(relays []Relay, home int, httpsOnly bool) bool {
	if w.asked == w.counted || !w.undecided(relays, home, httpsOnly) {
		return false
	}
	w.waited = w.counted
	return true
}

// askFor reports whether to ask for another report now, a wait for it
// over, and notes it asked: once per report, and not sooner than
// [lookAgain] after it.
func (w *walls) askFor(relays []Relay, home int, httpsOnly bool) bool {
	if w.waited != w.counted || w.asked == w.counted || !w.undecided(relays, home, httpsOnly) {
		return false
	}
	w.asked = w.counted
	return true
}

// undecided reports whether one more report would decide what one left
// open: whether names come first, or a relay is out of reach.
func (w *walls) undecided(relays []Relay, home int, httpsOnly bool) bool {
	if w.blind == 1 && !w.nameFirst && !httpsOnly {
		return true
	}
	return w.missing(relays, home, httpsOnly)
}

// saysWalled reports whether a node homed at home says it is walled after
// report r: a relay is out of reach, or r had no UDP and one more report has
// to decide whether one is.
func (w *walls) saysWalled(r *netcheck.Report, unreached map[int]bool, relays []Relay, home int, httpsOnly bool) bool {
	return len(unreached) > 0 || r != nil && !r.UDP && w.missing(relays, home, httpsOnly)
}

// missing reports whether a relay, homed at home, was missed by fewer
// reports in a row than make it out of reach.
func (w *walls) missing(relays []Relay, home int, httpsOnly bool) bool {
	if home == 0 || !w.decisive {
		return false
	}
	return slices.ContainsFunc(relays, func(rel Relay) bool {
		n := w.missed[rel.Region]
		return rel.Region != home && n > 0 && n < missesToWall(rel, httpsOnly)
	})
}

// nameFirstAfter is whether relays' names on 443 come first in the map after
// report r, was before: two reports in a row without UDP that reached no
// relay may have spent their time on the relays' own ports, which a network
// passing 443 alone drops, before netcheck ends them; one alone may be the
// first after a link change. A report that measured one of relays by UDP puts
// the ports first again; UDP a STUN server alone answered says nothing of
// them, as in a report taken before the STUN servers were left out.
func nameFirstAfter(r *netcheck.Report, relays []Relay, httpsOnly bool, blind int, was bool) bool {
	switch {
	case httpsOnly || r == nil:
		return was
	case r.UDP && measuresRelay(r, relays, nil):
		return false
	case r.UDP:
		return was
	case blind >= 2:
		return true
	}
	return was
}

// unansweredAfter is how many reports in a row, r last, had UDP answered and
// measured no relay, before was: netcheck measures by HTTPS only where no UDP
// is answered, so STUN servers answering alone leave every relay unmeasured.
func unansweredAfter(r *netcheck.Report, relays []Relay, before int) int {
	if r == nil || len(r.RegionLatency) == 0 || len(relays) == 0 {
		return before
	}
	if !r.UDP || measuresRelay(r, relays, nil) {
		return 0
	}
	return before + 1
}

// measuresRelay reports whether r measured any of relays, but by ICMP alone,
// those in pinged.
func measuresRelay(r *netcheck.Report, relays []Relay, pinged map[int]bool) bool {
	return r != nil && slices.ContainsFunc(relays, func(rel Relay) bool {
		_, ok := r.RegionLatency[tailcfg.DERPRegionID(rel.Region)]
		return ok && !pinged[rel.Region]
	})
}

// reachesNoneAside reports whether r, taken without the STUN servers,
// reached no relay with every way tried: with the relays' names on 443
// first, where there are any, which come first only after two such reports;
// namesTried is whether r was taken so.
func reachesNoneAside(r *netcheck.Report, relays []Relay, pinged map[int]bool, namesTried bool) bool {
	if r == nil || r.UDP || measuresRelay(r, relays, pinged) {
		return false
	}
	return namesTried || !slices.ContainsFunc(relays, func(rel Relay) bool { return rel.Name != "" })
}

// followSTUN leaves the STUN servers out of the map after two reports in a
// row that only they answered, so that netcheck measures the relays by
// HTTPS, until the link changes; where HTTPS reaches none either, as with
// the relays gone, they come back, to be left out again no sooner than
// [relayRetryFirst] later, doubling up to [relayRetryMost].
func (m *tsManager) followSTUN() {
	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed || len(m.stun) == 0 || m.httpsOnly {
		return
	}
	r := m.magic.GetLastNetcheckReport(context.Background())
	if r == m.walls.stunCounted || r == nil {
		return
	}
	m.walls.stunCounted = r
	if m.walls.stunAside.Load() {
		pinged := m.pinged.lastAlone()
		if r.UDP || measuresRelay(r, m.relays, pinged) {
			m.walls.emptyAside = 0
		} else if m.walls.emptyAside++; m.walls.emptyAside >= 2 {
			// Without the STUN servers no report names one for the nearest
			// region, which is what makes a node whose relays went homeless;
			// two in a row, as one alone may follow a link change.
			if !m.relayMissing.Swap(true) {
				m.relayLost.Add(1)
			}
			m.followHome()
		}
		switch {
		case r.UDP && measuresRelay(r, m.relays, nil):
			// A relay's own port answered: they were not measured for
			// another reason, as while they started, and the STUN servers
			// are what tell this node its public address.
			m.walls.stunAside.Store(false)
			m.walls.unanswered, m.walls.asideAgain, m.walls.asideGap = 0, time.Time{}, 0
			m.logf("conn: a relay answered UDP; the STUN servers are asked again")
			m.installDERPMapAsking(m.relays, false)
		case measuresRelay(r, m.relays, pinged):
			m.walls.asideGap = 0
		case reachesNoneAside(r, m.relays, pinged, m.walls.nameFirst && m.walls.namedFirst > 0):
			m.walls.asideGap = min(max(2*m.walls.asideGap, relayRetryFirst), relayRetryMost)
			m.walls.asideAgain = time.Now().Add(m.walls.asideGap)
			m.walls.stunAside.Store(false)
			m.walls.unanswered = 0
			if !m.relayMissing.Swap(true) {
				m.relayLost.Add(1)
			}
			m.logf("conn: no relay reached without the STUN servers either; they are asked again")
			// At the next report: one asked now would cost a homeless
			// node, as with every relay down, another round.
			m.installDERPMapAsking(m.relays, false)
		}
		return
	}
	m.walls.unanswered = unansweredAfter(r, m.relays, m.walls.unanswered)
	if m.walls.unanswered < 2 || time.Now().Before(m.walls.asideAgain) {
		return
	}
	m.walls.stunAside.Store(true)
	m.walls.emptyAside = 0
	m.logf("conn: STUN servers answered and no relay did; the relays are measured without them until the link changes")
	// Their own ports went unanswered, so their names on 443 come first at
	// once rather than after two reports reaching none.
	if !m.walls.nameFirst && slices.ContainsFunc(m.relays, func(rel Relay) bool { return rel.Name != "" }) {
		m.walls.nameFirst, m.walls.namedFirst = true, 0
		m.logf("conn: relays' names on 443 first: true")
	}
	m.installDERPMap(m.relays)
}

// sendHome is the region what goes to a peer homed at region is sent to.
// The caller holds m.apply.
func (m *tsManager) sendHome(region int) int {
	if m.walls.unreached[region] {
		return m.walls.home
	}
	return region
}

// rerouteLocked has the data plane send what goes to a peer homed where this
// node does not reach to its own home, where the peer, told this node is
// walled, keeps a connection; and back to the peer's home once it reaches
// that again. The caller holds m.apply.
func (m *tsManager) rerouteLocked() {
	if m.closed {
		return
	}
	home := m.HomeRelay()
	r := m.magic.GetLastNetcheckReport(context.Background())
	if m.walls.follow(r, m.relays, home, m.httpsOnly, m.pinged.lastAlone()) {
		m.walls.noRelay.Store(m.walls.blind > 0)
		if first := nameFirstAfter(r, m.relays, m.httpsOnly, m.walls.blind, m.walls.nameFirst); first != m.walls.nameFirst {
			m.walls.nameFirst, m.walls.namedFirst = first, 0
			m.logf("conn: relays' names on 443 first: %v", first)
			m.installDERPMap(m.relays)
		}
		if m.walls.undecided(m.relays, home, m.httpsOnly) {
			m.meetSoon()
		}
	}
	unreached := m.walls.unreachedAt(m.relays, home, m.httpsOnly)
	// Homed without UDP, it says it is walled while a report still has to
	// decide: said otherwise, members stop keeping its home open, and hear
	// the walls that follow only at their next sync.
	walled := m.walls.saysWalled(r, unreached, m.relays, home, m.httpsOnly)
	if !maps.Equal(unreached, m.walls.unreached) || len(unreached) > 0 && home != m.walls.home {
		m.walls.unreached, m.walls.home = unreached, home
		m.walls.out.Store(&unreached)
		// Walled off from fewer relays, it may be to keep a connection to one.
		m.meetSoon()
		st := m.state.Load()
		next, nodes := newPeerState(m.self.NodeKey.Public(), slices.Collect(maps.Values(st.peers)), m.sendHome)
		m.state.Store(next)
		m.magic.SetNetworkMap(m.selfNV, nodes)
		if len(unreached) > 0 {
			m.logf("conn: walled: relays %v are out of reach, their peers are sent to at %d", slices.Sorted(maps.Keys(unreached)), home)
		}
	}
	if m.walled.Swap(walled) != walled {
		switch {
		case len(unreached) > 0: // said above, as they moved
		case walled:
			m.logf("conn: walled until a report decides it, homed at %d without UDP", home)
		default:
			m.logf("conn: no longer walled")
		}
		m.notifyChange()
	}
}

// reroute is [tsManager.rerouteLocked] taking m.apply.
func (m *tsManager) reroute() {
	m.apply.Lock()
	defer m.apply.Unlock()
	m.rerouteLocked()
}

// meetSoon has the meeting loop look again now.
func (m *tsManager) meetSoon() {
	select {
	case m.walls.kick <- struct{}{}:
	default:
	}
}

// meetLoop keeps the connections walled peers are reached by, and asks for
// another report where the last left undecided whether this node is walled.
// It sleeps while there is neither. Not one of m.warm, which Close waits
// for holding m.apply.
func (m *tsManager) meetLoop() {
	t := time.NewTimer(meetEvery)
	t.Stop()
	defer t.Stop()
	for {
		timed := false
		select {
		case <-m.done:
			return
		case <-m.walls.kick:
		case <-t.C:
			timed = true
		}
		if next := m.meet(timed); next > 0 {
			t.Reset(next)
		} else {
			t.Stop()
		}
	}
}

// meet keeps a connection at each walled peer's home, asks for a report
// where one is undecided and timed says the wait for it is over, and says
// when to do so again, or 0.
func (m *tsManager) meet(timed bool) time.Duration {
	m.apply.Lock()
	if m.closed {
		m.apply.Unlock()
		return 0
	}
	m.rerouteLocked()
	home := m.HomeRelay()
	wait, ask := false, false
	if timed {
		ask = m.walls.askFor(m.relays, home, m.httpsOnly)
	} else {
		wait = m.walls.waitFor(m.relays, home, m.httpsOnly)
	}
	var at []int
	if !m.saving.Load() {
		reaches := func(region int) bool {
			return m.sendHome(region) == region && m.dm != nil && m.dm.Regions[tailcfg.DERPRegionID(region)] != nil
		}
		at = meetingHomes(slices.Collect(maps.Values(m.state.Load().peers)), m.relays, home, reaches)
		at = m.walls.lingering(at, time.Now(), func(region int) bool { return region != home && reaches(region) })
	} else {
		m.walls.met = nil
	}
	if !slices.Equal(at, m.walls.kept) {
		m.walls.kept = at
		m.logf("conn: keeping relays %v open for walled peers", at)
	}
	m.apply.Unlock()
	if ask {
		m.magic.ReSTUN("walls")
	}
	for _, region := range at {
		// One byte, not disco: the relay answers a disco packet for no
		// client, and passes nothing to the walled peer either way.
		if _, err := m.magic.SendDERPPacketTo(m.walls.keepKey, tailcfg.DERPRegionID(region), []byte{0}); err != nil {
			m.logf("conn: keeping a connection at relay %d: %v", region, err)
		}
	}
	switch {
	case wait:
		return lookAgain
	case len(at) > 0:
		return meetEvery
	}
	return 0
}

// meetLinger is how long a connection is kept at a walled peer's home after
// it was last needed: a walled device that restarts announces itself
// homeless, then not walled, before it is walled at the same home again.
const meetLinger = 2 * time.Minute

// lingering is homes, noted as needed at now, and the homes needed within
// [meetLinger] before that still reached. The caller holds m.apply.
func (w *walls) lingering(homes []int, now time.Time, reaches func(int) bool) []int {
	if w.met == nil {
		w.met = map[int]time.Time{}
	}
	for _, h := range homes {
		w.met[h] = now
	}
	out := slices.Clone(homes)
	for h, at := range w.met {
		switch {
		case now.Sub(at) >= meetLinger || !reaches(h):
			delete(w.met, h)
		case !slices.Contains(out, h):
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return out
}

// meetingHomes are the homes of walled peers a node homed at home keeps a
// connection at, each once: none where its own home has a name on 443, which
// a walled peer reaches, and none that is its home or out of its reach.
func meetingHomes(peers []Peer, relays []Relay, home int, reaches func(region int) bool) []int {
	if home != 0 && slices.ContainsFunc(relays, func(r Relay) bool { return r.Region == home && r.Name != "" }) {
		return nil
	}
	var out []int
	for _, p := range peers {
		if p.Walled && p.HomeRelay != 0 && p.HomeRelay != home && !slices.Contains(out, p.HomeRelay) && reaches(p.HomeRelay) {
			out = append(out, p.HomeRelay)
		}
	}
	slices.Sort(out)
	return out
}

// netcheckReport is the line netcheck ends each report with, before
// magicsock stores it; a test holds it to the pinned module's.
const netcheckReport = "netcheck: [v1] report: %v"

// rerouteAfterReport looks again at what this node reaches a moment after a
// report, which magicsock stores after its line: what onNetInfo is called
// for leaves out a relay reached or lost.
func (m *tsManager) rerouteAfterReport() {
	if m.walls.due.Swap(true) {
		return
	}
	time.AfterFunc(time.Second, func() {
		m.walls.due.Store(false)
		m.holdHome()
		// After reroute, which counts the report for the names first.
		m.reroute()
		m.followSTUN()
		if m.walls.stunAside.Load() {
			// The engine passes on no report whose home is the one it
			// fell back to while homeless, as the first to reach a relay
			// without the STUN servers often is.
			m.followReport()
		}
	})
}
