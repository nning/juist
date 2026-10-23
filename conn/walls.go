package conn

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// meetEvery is how often a walled peer is pinged at its home: magicsock
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
	counted   *netcheck.Report
	// asked is the report counted when another was last asked for, once
	// each, as none comes while the link is down; waited the one the wait
	// before asking began at. Guarded by apply.
	asked, waited *netcheck.Report

	kick chan struct{} // the meeting loop is to look again
	due  atomic.Bool   // a look after a report is due

	goneMu sync.Mutex
	gone   map[key.NodePublic]time.Time
}

func (m *tsManager) Walled() bool { return m.walled.Load() }

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
// pings a relay too, which says nothing of its TCP port: a report that has
// ICMP counts a relay reached by its name on 443 alone.
func unreachedIn(relays []Relay, home int, r *netcheck.Report, httpsOnly bool) (unreached map[int]bool, ok bool) {
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
		if rel.Region != home && (!measured || r.ICMPv4 && rel.Name == "") {
			if unreached == nil {
				unreached = map[int]bool{}
			}
			unreached[rel.Region] = true
		}
	}
	return unreached, true
}

// blindAfter is how many reports in a row, r last, had no UDP and reached
// no relay, before was. ICMP measures a region's first node, so with names
// first, only a named relay, whose first node is its name with no STUN
// port, counts as reached by HTTPS.
func blindAfter(r *netcheck.Report, relays []Relay, nameFirst bool, before int) int {
	if r == nil || r.UDP || !slices.ContainsFunc(relays, func(rel Relay) bool { return rel.Name != "" }) {
		return 0
	}
	for _, rel := range relays {
		_, ok := r.RegionLatency[tailcfg.DERPRegionID(rel.Region)]
		if ok && (!r.ICMPv4 || nameFirst && rel.Name != "") {
			return 0
		}
	}
	return before + 1
}

// missedAfter counts, per relay, the reports in a row that left it out of
// reach of a node homed at home, r last, before was; a report that says
// nothing either way leaves them.
func missedAfter(r *netcheck.Report, relays []Relay, home int, httpsOnly bool, before map[int]int) (after map[int]int, decisive bool) {
	u, ok := unreachedIn(relays, home, r, httpsOnly)
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
func (w *walls) follow(r *netcheck.Report, relays []Relay, home int, httpsOnly bool) bool {
	switch {
	case r != w.counted:
		w.counted = r
		w.blind = blindAfter(r, relays, w.nameFirst, w.blind)
	case home != 0 && !w.homed:
		w.asked = nil
	default:
		return false
	}
	w.homed = home != 0
	w.missed, w.decisive = missedAfter(r, relays, home, httpsOnly, w.missed)
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
// first after a link change. A report with UDP puts the ports first again.
func nameFirstAfter(r *netcheck.Report, httpsOnly bool, blind int, was bool) bool {
	switch {
	case httpsOnly || r == nil:
		return was
	case r.UDP:
		return false
	case blind >= 2:
		return true
	}
	return was
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
	if m.walls.follow(r, m.relays, home, m.httpsOnly) {
		if first := nameFirstAfter(r, m.httpsOnly, m.walls.blind, m.walls.nameFirst); first != m.walls.nameFirst {
			m.walls.nameFirst = first
			m.logf("conn: relays' names on 443 first: %v", first)
			m.installDERPMap(m.relays)
		}
		if m.walls.undecided(m.relays, home, m.httpsOnly) {
			m.meetSoon()
		}
	}
	unreached := m.walls.unreachedAt(m.relays, home, m.httpsOnly)
	if maps.Equal(unreached, m.walls.unreached) && (len(unreached) == 0 || home == m.walls.home) {
		return
	}
	m.walls.unreached, m.walls.home = unreached, home
	m.walls.out.Store(&unreached)
	// Walled off from fewer relays, it may be to keep a connection to one.
	m.meetSoon()
	st := m.state.Load()
	next, nodes := newPeerState(m.self.NodeKey.Public(), slices.Collect(maps.Values(st.peers)), m.sendHome)
	m.state.Store(next)
	m.magic.SetNetworkMap(m.selfNV, nodes)
	walled := len(unreached) > 0
	if m.walled.Swap(walled) != walled {
		if walled {
			m.logf("conn: walled: relays %v are out of reach, their peers are sent to at %d", slices.Sorted(maps.Keys(unreached)), home)
		} else {
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

// meet pings each walled peer at its home, unless that is this node's own
// or out of its reach, asks for a report where one is undecided and timed
// says the wait for it is over, and says when to do so again, or 0.
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
	var at []netip.Addr
	for _, p := range m.state.Load().peers {
		if !p.Walled || p.HomeRelay == 0 || len(p.Addrs) == 0 {
			continue
		}
		if p.HomeRelay != home && m.sendHome(p.HomeRelay) == p.HomeRelay && m.dm != nil &&
			m.dm.Regions[tailcfg.DERPRegionID(p.HomeRelay)] != nil {
			at = append(at, p.Addrs[0].Addr())
		}
	}
	m.apply.Unlock()
	if ask {
		m.magic.ReSTUN("walls")
	}
	if !m.saving.Load() {
		for _, ip := range at {
			m.ProbeQuietly(ip, meetEvery/3, func(bool) {})
		}
	} else {
		at = nil
	}
	switch {
	case wait:
		return lookAgain
	case len(at) > 0:
		return meetEvery
	}
	return 0
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
		m.reroute()
	})
}
