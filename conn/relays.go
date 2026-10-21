package conn

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
)

// SetRelays installs the relay set. It is separate from SetPeers because the
// two change for different reasons: a relay set moves when a role is granted
// or a relay restarts, and installing it re-runs the data plane's latency
// probes, which an unchanged set must not.
func (m *tsManager) SetRelays(relays []Relay) error {
	if err := validateRelays(relays); err != nil {
		return err
	}
	relays = slices.Clone(relays)
	for i := range relays {
		relays[i].Addrs = slices.Clone(relays[i].Addrs)
	}
	slices.SortFunc(relays, func(a, b Relay) int { return a.Region - b.Region })

	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return errors.New("conn: manager is closed")
	}
	if sameRelays(m.relays, relays) {
		return nil
	}
	m.relays = relays
	// Names dropped are kept, up to a bound: a dial begun under the old
	// map still asks the proxy hook, which must not send it direct.
	named := slices.Clone(*m.named.Load())
	for _, r := range relays {
		if r.Name != "" && !slices.Contains(named, r.Name) {
			named = append(named, r.Name)
		}
	}
	if len(named) > maxProxiedNames {
		named = named[len(named)-maxProxiedNames:]
	}
	m.named.Store(&named)
	// Relays of their own are tried for a home again, whatever the last
	// report reached.
	m.relayMissing.Store(false)
	m.installDERPMap(relays)
	if len(relays) == 0 {
		// Nothing will report a home region again, and a stale one would be
		// announced to peers as a path that no longer exists.
		if m.homeRelay.Swap(0) != 0 {
			m.notifyChange()
		}
	}
	return nil
}

func (m *tsManager) HomeRelay() int { return int(m.homeRelay.Load()) }

// SetSaving stops, or resumes, magicsock pinging every peer it sent to in
// the last 45 s every 3 s: while saving battery a path is trusted while the
// peer's traffic arrives on it, and probed when sending finds it stale.
func (m *tsManager) SetSaving(saving bool) {
	m.silentMu.Lock()
	defer m.silentMu.Unlock()
	m.saving.Store(saving)
	m.magic.SetSilentDisco(saving)
}

func (m *tsManager) ReachesRelay(region int) bool {
	if region == 0 {
		return false
	}
	if region == m.HomeRelay() {
		return true
	}
	if m.magic == nil {
		return false
	}
	r := m.magic.GetLastNetcheckReport(context.Background())
	if r == nil {
		return false
	}
	_, ok := r.RegionLatency[tailcfg.DERPRegionID(region)]
	return ok
}

// publicHeld is how long a public address of this host's counts after it
// was last reported.
const publicHeld = 30 * time.Minute

// followNetworks installs the relays again where this host's networks moved,
// which order their addresses.
func (m *tsManager) followNetworks() {
	m.apply.Lock()
	defer m.apply.Unlock()
	local := Networks{Prefixes: hostNetworks(m.skip)}
	now := time.Now()
	m.epsMu.Lock()
	for _, ap := range m.localEps {
		if !isPrivateAddr(ap.Addr()) {
			m.publicSeen[ap.Addr()] = now
		}
	}
	// Held a while past the last report of them: netcheck reports a
	// public address only some rounds, and an order that came and went
	// with it would drop the home relay's connection each time. A server
	// may report any address; it moves only where a relay's own come first.
	for a, seen := range m.publicSeen {
		if now.Sub(seen) > publicHeld {
			delete(m.publicSeen, a)
			continue
		}
		local.Public = append(local.Public, a)
	}
	m.epsMu.Unlock()
	slices.SortFunc(local.Public, netip.Addr.Compare)
	if local.equal(*m.local.Load()) {
		return
	}
	m.local.Store(&local)
	if !m.closed && len(m.relays) > 0 {
		m.installDERPMap(m.relays)
	}
}

// watchEngine drops what magicsock says at each netcheck of a homeless node:
// that its home moves to the nearest STUN server, which it then does not
// take. It has a connection magicsock opens to a STUN server's region
// dropped, at most once per [stunDropEvery].
func (m *tsManager) watchEngine(logf logger.Logf) logger.Logf {
	return func(format string, args ...any) {
		if format == addingDERPConn {
			r, ok := tailcfg.DERPRegionID(0), len(args) == 2
			if ok {
				r, ok = args[0].(tailcfg.DERPRegionID)
			}
			if !ok {
				m.unreadLine.Do(func() { logf("conn: magicsock's new relay connections are no longer read: %q %T", format, args) })
			} else if (*m.stunRegions.Load())[r] && !m.stunDrop.Swap(true) {
				go m.dropSTUNConnSoon()
			}
		}
		if m.homeless.Load() && strings.HasPrefix(format, homeDERPChanging) {
			return
		}
		logf(format, args...)
	}
}

// homeDERPChanging begins magicsock's line for a new home, and addingDERPConn
// is its line for a new relay connection; a test holds both to the pinned
// module's.
const (
	homeDERPChanging = "magicsock: home DERP changing"
	addingDERPConn   = "magicsock: adding connection to derp-%v for %v"
)

// stunDropEvery bounds how often dropSTUNConn installs the map twice, as a
// peer whose home has the STUN region's number would have each packet open
// the connection again.
const stunDropEvery = time.Second

func (m *tsManager) dropSTUNConnSoon() {
	t := time.NewTimer(time.Until(time.Unix(0, m.stunDropped.Load()).Add(stunDropEvery)))
	defer t.Stop()
	select {
	case <-m.done:
		return
	case <-t.C:
	}
	m.stunDrop.Store(false)
	m.dropSTUNConn()
	m.stunDropped.Store(time.Now().UnixNano())
}

// dropSTUNConn closes magicsock's connection to the STUN servers' region,
// which never comes up. magicsock opens it where it takes that region for a
// home, at times just after it was told it has none, and then measures again
// at each failed reconnect until it drops idle connections a minute later.
func (m *tsManager) dropSTUNConn() {
	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed || m.dm == nil {
		return
	}
	// magicsock drops the connections of a region whose definition changed.
	renamed := m.dm.Clone()
	for r := range *m.stunRegions.Load() {
		if reg := renamed.Regions[r]; reg != nil {
			reg.RegionName += " (dropped)"
		}
	}
	m.magic.SetDERPMapWithoutReSTUN(renamed)
	m.magic.SetDERPMapWithoutReSTUN(m.dm)
}

// installDERPMap renders the relays and the STUN servers as one map. The STUN
// regions are recorded first, so a report naming one is never mistaken for a
// relay to be reached through.
func (m *tsManager) installDERPMap(relays []Relay) {
	dm, stunRegions := derpMap(relays, m.stun, m.httpsOnly, *m.local.Load())
	m.dm = dm
	m.stunRegions.Store(&stunRegions)
	m.stunOnly.Store(dm != nil && len(dm.Regions) == len(stunRegions))
	// Homeless before the map, so that it homes nowhere; homed after it, so
	// that the netcheck leaving homelessness starts measures the map.
	if m.stunOnly.Load() || m.relayMissing.Load() {
		m.followHome()
		m.magic.SetDERPMap(dm)
		return
	}
	m.magic.SetDERPMap(dm)
	m.followHome()
}

// followReport takes the last netcheck's choice of the nearest region: a
// STUN server's means it measured no relay, by STUN, HTTPS or ICMP alike. A
// report that measured nothing, as the first after a link change, says
// nothing either way.
func (m *tsManager) followReport() {
	r := m.magic.GetLastNetcheckReport(context.Background())
	if r == nil || len(r.RegionLatency) == 0 {
		return
	}
	missing := (*m.stunRegions.Load())[r.PreferredDERP]
	if !m.relayMissing.Swap(missing) && missing {
		m.relayLost.Add(1)
	}
	m.followHome()
	if missing {
		// A report differing only in what it measured is not passed on,
		// and the one that measures a relay must be.
		m.magic.ResetNetInfoLast()
	}
}

// followHome tells the engine whether it has a home to take. With no relay
// it reaches, the engine takes the nearest STUN server for its home and,
// failing to connect to it, asks every STUN server again every few seconds,
// idle or not.
func (m *tsManager) followHome() {
	m.homeMu.Lock()
	defer m.homeMu.Unlock()
	homeless := m.stunOnly.Load() || m.relayMissing.Load()
	if m.homeless.Swap(homeless) != homeless {
		m.magic.SetHomeless(homeless)
		if !homeless {
			select {
			case m.homed <- struct{}{}:
			default:
			}
		}
	}
}

// stunEvery is how often a homeless node asks STUN while its tunnels carry
// traffic, as the engine does for a node with a home; one whose relays went
// unreached asks from relayRetryFirst apart up to relayRetryMost, saving or
// idle as well: homeless, the engine neither keeps reconnecting to a relay
// nor measures again by itself, and a node with relays and no home is
// reached by none.
const (
	stunEvery       = 25 * time.Second
	relayRetryFirst = 25 * time.Second
	relayRetryMost  = 10 * time.Minute
	homedAgain      = netcheck.ReportTimeout + time.Second
)

// stunWhileHomeless asks STUN every [stunEvery] while homeless, active and
// not saving battery, which the engine stops doing for a homeless node: an
// idle one asks again once traffic resumes or the network changes. A peer's
// probes keep it active. Once homed again it asks once more after
// [homedAgain], since magicsock's SetHomeless update races its queue and may
// fail or report before the relays, and has its NetInfo passed on, as one from
// before the return may be taken after the home's; saving, that is one
// netcheck per return.
func (m *tsManager) stunWhileHomeless() {
	defer m.warm.Done()
	t := time.NewTicker(stunEvery)
	defer t.Stop()
	again := time.NewTimer(homedAgain)
	again.Stop()
	defer again.Stop()
	gap := relayRetryFirst
	var retryAt time.Time
	lost := m.relayLost.Load()
	for {
		select {
		case <-m.done:
			return
		case <-m.homed:
			again.Reset(homedAgain)
			continue
		case <-again.C:
			m.magic.ResetNetInfoLast()
			m.magic.ReSTUN("juist-homed")
			continue
		case <-t.C:
		}
		if l := m.relayLost.Load(); l != lost {
			lost, gap, retryAt = l, relayRetryFirst, time.Time{}
		}
		switch now := time.Now(); {
		case m.relayMissing.Load() && !m.stunOnly.Load():
			// Half a tick early: the tick a gap later is the one meant.
			if now.Before(retryAt.Add(-stunEvery / 2)) {
				continue
			}
			m.magic.ReSTUN("juist-relay-unreached")
			retryAt, gap = now.Add(gap), min(2*gap, relayRetryMost)
		case m.homeless.Load() && !m.saving.Load() && m.tun.IdleDuration() < 45*time.Second:
			m.magic.ReSTUN("juist-homeless")
			fallthrough
		default:
			gap, retryAt = relayRetryFirst, time.Time{}
		}
	}
}

func (m *tsManager) LocalEndpoints() []netip.AddrPort {
	m.epsMu.Lock()
	defer m.epsMu.Unlock()
	return slices.Clone(m.localEps)
}

// onStatus records the endpoint set the data plane believes this node is
// reachable at. Without a relay it is empty: magicsock reports no endpoints of
// its own with neither a STUN result nor a DERP map, which is why the
// announcement is built from an interface scan as well and these are added to
// it rather than substituted for it.
func (m *tsManager) onStatus(st *wgengine.Status, err error) {
	if err != nil || st == nil {
		return
	}
	eps := make([]netip.AddrPort, 0, len(st.LocalAddrs))
	for _, e := range st.LocalAddrs {
		ap := e.Addr
		if !ap.IsValid() || ap.Port() == 0 {
			continue
		}
		eps = append(eps, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	slices.SortFunc(eps, func(a, b netip.AddrPort) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return int(a.Port()) - int(b.Port())
	})
	eps = slices.Compact(eps)

	m.epsMu.Lock()
	changed := !slices.Equal(m.localEps, eps)
	m.localEps = eps
	m.epsMu.Unlock()
	if changed {
		m.notifyChange()
		// The public addresses among them say which relays share a site.
		go m.followNetworks()
	}
}

// onNetInfo records the relay region the data plane chose for itself.
func (m *tsManager) onNetInfo(ni *tailcfg.NetInfo) {
	if ni == nil {
		return
	}
	stunRegions := *m.stunRegions.Load()
	if len(stunRegions) > 0 {
		m.followReport()
	}
	home := ni.PreferredDERP
	if stunRegions[home] || m.homeless.Load() {
		// Nearest, but nothing to be reached through; or left.
		home = 0
	}
	if m.homeRelay.Swap(int64(home)) != int64(home) {
		m.notifyChange()
	}
}
