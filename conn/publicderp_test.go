package conn

import (
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"tailscale.com/net/netcheck"

	"tailscale.com/tailcfg"
)

// Tailscale's public regions join the map only where asked, numbered apart,
// scored as homes below any member relay and above STUN servers, behind a
// member relay deriving one of their numbers, and on HTTPS alone too.
func TestPublicDERPRegionsJoinTheMapBelowMemberRelays(t *testing.T) {
	public := tailscaleRegions()
	if len(public) == 0 {
		t.Fatal("the build embeds no public region")
	}
	if dm, _ := derpMap(nil, nil, false, false, Networks{}, false); dm != nil {
		t.Errorf("no relay and no public DERP make a map of %d regions", len(dm.Regions))
	}
	first := public[0]
	clash := testRelay()
	clash.Region = int(first.RegionID)
	dm, stun := derpMap([]Relay{testRelay(), clash}, []string{"stun.example:3478"}, false, false, Networks{}, true)
	for _, r := range public[1:] {
		got := dm.Regions[r.RegionID]
		if got == nil || got.RegionCode != r.RegionCode || len(got.Nodes) == 0 || got.Nodes[0].RegionID != r.RegionID {
			t.Errorf("region %d: %+v", r.RegionID, got)
		}
		if s := dm.HomeParams.RegionScore[r.RegionID]; s != publicRegionScore {
			t.Errorf("region %d scores %v", r.RegionID, s)
		}
	}
	if got := dm.Regions[first.RegionID]; got.RegionCode != "j"+strconv.Itoa(clash.Region) {
		t.Errorf("a member relay deriving a public region's number lost it to %s", got.RegionCode)
	}
	if _, scored := dm.HomeParams.RegionScore[tailcfg.DERPRegionID(testRelay().Region)]; scored {
		t.Error("a member relay is scored down")
	}
	for id := range stun {
		if dm.HomeParams.RegionScore[id] <= publicRegionScore {
			t.Error("a STUN server scores above a public region")
		}
	}
	if dm, _ := derpMap(nil, nil, true, false, Networks{}, true); dm == nil || len(dm.Regions) != len(public) {
		t.Error("HTTPS alone drops the public regions")
	}
	// On HTTPS alone a relay without a name is left out, and its region
	// stays its: its peers send to it there.
	if dm, _ := derpMap([]Relay{clash}, nil, true, false, Networks{}, true); dm.Regions[first.RegionID] != nil {
		t.Errorf("region %d, a member relay's, is %s on HTTPS alone", first.RegionID, dm.Regions[first.RegionID].RegionCode)
	}
	names := PublicRegions()
	if names[int(first.RegionID)] == "" || len(names) != len(public) {
		t.Errorf("PublicRegions names %v", names)
	}
}

// The setting reaches the data plane: the map holds the public regions, their
// names go through the proxy however many relays' names come after, a home
// at one survives the member relays going, and turning it off takes both.
func TestPublicDERPReachesTheDataPlane(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	m := a.mgr.(*tsManager)
	public := tailscaleRegions()
	host := public[0].Nodes[0].HostName
	regions := func() []tailcfg.DERPRegionID {
		m.apply.Lock()
		defer m.apply.Unlock()
		var out []tailcfg.DERPRegionID
		if m.dm != nil {
			for id := range m.dm.Regions {
				out = append(out, id)
			}
		}
		return out
	}
	if err := m.SetPublicDERP(true); err != nil {
		t.Fatal(err)
	}
	for _, r := range public {
		if !slices.Contains(regions(), r.RegionID) {
			t.Fatalf("region %d is not in the map", r.RegionID)
		}
	}
	for i := range maxProxiedNames + 5 {
		r := namedRelay()
		r.Name = fmt.Sprintf("r%d.example.org", i)
		if err := m.SetRelays([]Relay{r}); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Contains(*m.named.Load(), host) {
		t.Errorf("%s fell off the names dialled through the proxy", host)
	}
	m.homeRelay.Store(int64(public[0].RegionID))
	if err := m.SetRelays(nil); err != nil {
		t.Fatal(err)
	}
	if m.HomeRelay() != int(public[0].RegionID) {
		t.Errorf("the home at a public region went with the member relays: %d", m.HomeRelay())
	}
	if err := m.SetPublicDERP(false); err != nil {
		t.Fatal(err)
	}
	if got := regions(); len(got) != 0 {
		t.Errorf("off, the map holds %v", got)
	}
	if m.HomeRelay() != 0 {
		t.Errorf("off, the home stays at %d", m.HomeRelay())
	}
}

// Tailscale's regions are the pinned module's; a bump that changes them
// leaves members on older builds without a new one, a peer homed there
// unreachable to them: say so in the changelog, and update the cities.
func TestTailscalesRegionsAreThePinnedOnes(t *testing.T) {
	var got []string
	for _, r := range tailscaleRegions() {
		for _, n := range r.Nodes {
			got = append(got, fmt.Sprintf("%d %s", r.RegionID-publicRegionBase, n.HostName))
		}
	}
	want := []string{"1 derp1c.tailscale.com", "1 derp1d.tailscale.com", "1 derp1e.tailscale.com",
		"2 derp2d.tailscale.com", "2 derp2e.tailscale.com", "2 derp2f.tailscale.com", "3 derp3.tailscale.com",
		"4 derp4c.tailscale.com", "4 derp4d.tailscale.com", "4 derp4e.tailscale.com", "5 derp5.tailscale.com",
		"6 derp6.tailscale.com", "7 derp7.tailscale.com", "8 derp8b.tailscale.com", "8 derp8c.tailscale.com",
		"8 derp8d.tailscale.com", "9 derp9.tailscale.com", "9 derp9b.tailscale.com", "9 derp9c.tailscale.com",
		"10 derp10.tailscale.com", "11 derp11.tailscale.com", "12 derp12.tailscale.com",
		"12 derp12b.tailscale.com", "12 derp12c.tailscale.com"}
	if !slices.Equal(got, want) {
		t.Errorf("Tailscale's embedded DERP regions changed: %q", got)
	}
	for _, r := range tailscaleRegions() {
		if _, ok := publicRegionCities[int(r.RegionID-publicRegionBase)]; !ok {
			t.Errorf("region %s has no city", r.RegionCode)
		}
	}
	if got := PublicRegions()[publicRegionBase+4]; got != "Tailscale Frankfurt" {
		t.Errorf("region 4 is named %q", got)
	}
}

// Relay names keep their bound of maxProxiedNames beside Tailscale's.
func TestRelayNamesKeepTheirBoundWithPublicOn(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	m := a.mgr.(*tsManager)
	if err := m.SetPublicDERP(true); err != nil {
		t.Fatal(err)
	}
	for i := range maxProxiedNames {
		r := namedRelay()
		r.Name = fmt.Sprintf("r%d.example.org", i)
		if err := m.SetRelays([]Relay{r}); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Contains(*m.named.Load(), "r0.example.org") {
		t.Errorf("r0.example.org fell off within %d relay names", maxProxiedNames)
	}
	// Turned off, Tailscale's names stay proxied: a dial begun under the old
	// map still asks the proxy hook.
	if err := m.SetPublicDERP(false); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRelays([]Relay{namedRelay()}); err != nil {
		t.Fatal(err)
	}
	if host := tailscaleRegions()[0].Nodes[0].HostName; !slices.Contains(*m.named.Load(), host) {
		t.Errorf("turned off, %s is no longer dialled through the proxy", host)
	}
}

// Beside a member relay it does not measure, a node homed at Tailscale's
// region keeps it through a report without UDP that measured it on 443,
// rather than going homeless as with no relay reached.
func TestTailscaleHomesWhenUDPLapsesBesideAnUnreachedRelay(t *testing.T) {
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	if err := m.SetPublicDERP(true); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRelays([]Relay{testRelay()}); err != nil {
		t.Fatal(err)
	}
	m.apply.Lock()
	var stunRegion tailcfg.DERPRegionID
	for r := range *m.stunRegions.Load() {
		stunRegion = r
	}
	m.apply.Unlock()
	ts := tailscaleRegions()[3].RegionID
	at := time.Now().Add(time.Hour)
	report := func(r *netcheck.Report) {
		at = at.Add(time.Second)
		r.Now = at
		m.apply.Lock()
		dm := m.dm
		m.apply.Unlock()
		m.magic.AddNetcheckReportForTest(dm, r, at)
		m.followSTUN()
	}
	for range 2 {
		report(&netcheck.Report{UDP: true, IPv4: true, PreferredDERP: ts,
			RegionLatency: map[tailcfg.DERPRegionID]time.Duration{stunRegion: 5 * time.Millisecond, ts: 10 * time.Millisecond}})
	}
	if !m.walls.stunAside.Load() {
		t.Fatal("the STUN servers are not set aside")
	}
	for range 2 {
		report(&netcheck.Report{PreferredDERP: ts, RegionLatency: map[tailcfg.DERPRegionID]time.Duration{ts: 20 * time.Millisecond}})
	}
	if m.relayMissing.Load() || m.homeless.Load() {
		t.Errorf("homeless (relayMissing %v, homeless %v) after reports that measured Tailscale's region on 443",
			m.relayMissing.Load(), m.homeless.Load())
	}
	// Measured on 443 alone, Tailscale's region keeps the home, and the
	// STUN servers, which tell the node its public address, come back.
	if m.walls.stunAside.Load() {
		t.Error("the STUN servers stay aside though nothing answers UDP without them")
	}
	// With the setting off, no relay reached is homeless, as before.
	if err := m.SetPublicDERP(false); err != nil {
		t.Fatal(err)
	}
	m.apply.Lock()
	m.walls.stunAside.Store(true)
	m.apply.Unlock()
	for range 2 {
		report(&netcheck.Report{PreferredDERP: ts, RegionLatency: map[tailcfg.DERPRegionID]time.Duration{ts: 20 * time.Millisecond}})
	}
	if !m.relayMissing.Load() {
		t.Error("with Tailscale's servers off, a report reaching only theirs is a home")
	}
}

// A home held while a relay is reached by ICMP alone is weighed as netcheck
// weighs homes, by the map's scores: Tailscale's a thousand times below a
// member relay, and a member relay deriving one of their numbers as a
// member relay.
func TestAHeldHomeRanksTailscaleBelowMemberRelays(t *testing.T) {
	ts := tailscaleRegions()[3].RegionID
	nine := testRelay()
	nine.Region = 9
	dm, _ := derpMap([]Relay{nine}, nil, false, false, Networks{}, true)
	scores := dm.HomeParams.RegionScore
	r := &netcheck.Report{PreferredDERP: 7, RegionLatency: map[tailcfg.DERPRegionID]time.Duration{
		7: 10 * time.Millisecond, 9: 80 * time.Millisecond, ts: 20 * time.Millisecond}}
	if got, hold := homeToHold(r, map[int]bool{7: true}, nil, scores); !hold || got != 9 {
		t.Errorf("held at %d, want the member relay 9", got)
	}
	r.RegionLatency = map[tailcfg.DERPRegionID]time.Duration{7: 10 * time.Millisecond, ts: 20 * time.Millisecond}
	if got, _ := homeToHold(r, map[int]bool{7: true}, nil, scores); got != int(ts) {
		t.Errorf("held at %d, want Tailscale's %d where no member relay is reached", got, ts)
	}
	colliding := testRelay()
	colliding.Region = int(ts)
	dm, _ = derpMap([]Relay{nine, colliding}, nil, false, false, Networks{}, true)
	r.RegionLatency = map[tailcfg.DERPRegionID]time.Duration{
		7: 5 * time.Millisecond, 9: 80 * time.Millisecond, ts: 10 * time.Millisecond}
	if got, _ := homeToHold(r, map[int]bool{7: true}, nil, dm.HomeParams.RegionScore); got != int(ts) {
		t.Errorf("held at %d, want the nearer member relay at %d, a number of Tailscale's", got, ts)
	}
}

// Beside a member relay, in every mode and with the STUN servers set aside,
// Tailscale's regions stay measurable and answer STUN, so that a device
// whose member relays are down still finds a home there: holding them
// back from netcheck left devices without one (reviews 9 and 10).
func TestTailscalesRegionsStayMeasurableBesideMemberRelays(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"stun", func(o *Options) { o.STUN = []string{newSTUNCounter(t).addr()} }},
		{"no-stun", func(o *Options) { o.STUN = nil }},
		{"https-only", func(o *Options) { o.HTTPSOnly = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", c.mutate)
			m := n.mgr.(*tsManager)
			if err := m.SetPublicDERP(true); err != nil {
				t.Fatal(err)
			}
			unnamed := testRelay()
			unnamed.Region = 9
			if err := m.SetRelays([]Relay{namedRelay(), unnamed}); err != nil {
				t.Fatal(err)
			}
			for _, aside := range []bool{false, true} {
				m.apply.Lock()
				m.walls.stunAside.Store(aside)
				m.installDERPMapAsking(m.relays, false)
				for _, r := range tailscaleRegions() {
					got := m.dm.Regions[r.RegionID]
					switch {
					case got == nil:
						t.Errorf("aside %v: region %s is not in the map", aside, r.RegionCode)
					case got.NoMeasureNoHome:
						t.Errorf("aside %v: region %s is held back from netcheck", aside, r.RegionCode)
					case slices.ContainsFunc(got.Nodes, func(n *tailcfg.DERPNode) bool { return n.STUNPort < 0 }):
						t.Errorf("aside %v: region %s answers no STUN", aside, r.RegionCode)
					}
				}
				m.apply.Unlock()
			}
		})
	}
}
