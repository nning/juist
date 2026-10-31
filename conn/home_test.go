package conn

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"

	"github.com/nning/juist/relay"
)

// deadUDP is a UDP port on this host's address nothing answers at.
func deadUDP(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(hostAddr(t), 0)))
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	pc.Close()
	return ap
}

// startRelay starts a relay on port, or on any port, with its STUN responder
// on it too: a test's other sockets may hold the UDP port, and netcheck
// measures a relay without STUN only where UDP is blocked.
func startRelay(t *testing.T, port uint16) *relay.Server {
	t.Helper()
	cert, err := relay.NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		s, err := relay.New(relay.Options{Port: port, Certificate: cert, Admit: func([32]byte) bool { return true }, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		if s.STUNPort() != 0 {
			t.Cleanup(func() { s.Close() })
			return s
		}
		s.Close()
		if port != 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.Fatalf("no STUN responder for the relay on port %d", port)
	return nil
}

// TestStartRelayWantsSTUNOnAFixedPort: a relay restarted on its port without
// STUN would be measured by HTTPS alone, failing its test by chance.
func TestStartRelayWantsSTUNOnAFixedPort(t *testing.T) {
	if os.Getenv("JUIST_TEST_RELAY_PORT_HELD") == "" {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestStartRelayWantsSTUNOnAFixedPort$", "-test.count", "1")
		cmd.Env = append(os.Environ(), "JUIST_TEST_RELAY_PORT_HELD=1")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "no STUN responder for the relay") {
			t.Fatalf("a relay on a port whose UDP is held was taken: %v\n%s", err, out)
		}
		return
	}
	held, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	startRelay(t, uint16(held.LocalAddr().(*net.UDPAddr).Port))
}

// With UDP blocked, netcheck measures the relays by HTTPS alone, which fills
// the report's RegionLatency but not RegionV4Latency/RegionV6Latency, from
// which NetInfo.DERPLatency is built: the relay reached is a home still.
func TestARelayReachedByHTTPSAloneIsAHome(t *testing.T) {
	t.Parallel()
	dead := deadUDP(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{dead.String()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: dead.Port(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 45*time.Second, "a home at the relay reached by HTTPS alone", func() bool {
		m.magic.ReSTUN("test")
		return m.HomeRelay() == 8 && !m.homeless.Load()
	})
}

// A report that measured nothing, as the first after a link change, says
// nothing about the relays: the home stays, as magicsock keeps it
// (pickDERPFallback returns myDerp), and what peers are told agrees with
// whether the node is on the relay.
func TestAReportMeasuringNothingKeepsTheHome(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
	// What updateNetInfo delivers when no probe was answered: DERPLatency
	// empty, PreferredDERP the home kept, WorkingUDP false so that it is
	// not de-duplicated against the last.
	ni := &tailcfg.NetInfo{DERPLatency: map[string]float64{}, PreferredDERP: 8}
	ni.WorkingUDP.Set(false)
	m.onNetInfo(ni) // synchronous: followHome ran before it returned
	homeless, home := m.homeless.Load(), m.HomeRelay()
	if homeless && home != 0 {
		t.Errorf("homeless, its DERP connection closed, yet peers are told home relay %d", home)
	}
	if homeless {
		t.Fatal("homeless after a report that measured nothing")
	}
}

// magicsock passes each NetInfo on in a goroutine of its own, so one from
// before a return home may be taken after the one saying the home: the
// netcheck asked after the return passes its NetInfo on, the same or not.
func TestAHomeTakenOutOfOrderIsSetRight(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
	m.onNetInfo(&tailcfg.NetInfo{PreferredDERP: 0}) // from while homeless
	if m.HomeRelay() != 0 {
		t.Fatal("a NetInfo with no home taken for none")
	}
	m.homed <- struct{}{}
	waitUntil(t, homedAgain+netcheck.ReportTimeout+5*time.Second, "the home said again", func() bool { return m.HomeRelay() == 8 })
}

// A saving node whose relay went and came back homes there again: nothing
// else makes it ask STUN while homeless and saving, and magicsock, homeless,
// neither keeps the DERP connection nor schedules a periodic netcheck.
func TestASavingNodeHomesAgainWhenItsRelayReturns(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
	m.SetSaving(true)
	s.Close()
	m.magic.ReSTUN("test")
	waitUntil(t, 30*time.Second, "homeless with the relay gone", m.homeless.Load)
	time.Sleep(8 * time.Second) // the endpoint updates the broken connection queued drain
	if !m.homeless.Load() {
		t.Fatal("homed with the relay still gone")
	}
	startRelay(t, live.Addrs[0].Port())
	waitUntil(t, 40*time.Second, "a home at the relay back, saving", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
}

// With more STUN servers than netcheck measures regions in a report, a relay
// is measured still, and homed at again when it returns: the servers share
// one region.
func TestARelayIsMeasuredBesideThreeSTUNServers(t *testing.T) {
	t.Parallel()
	s1, s2, s3 := newSTUNCounter(t), newSTUNCounter(t), newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{s1.addr(), s2.addr(), s3.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
	s.Close()
	m.magic.ReSTUN("test")
	waitUntil(t, 30*time.Second, "homeless with the relay gone", m.homeless.Load)
	startRelay(t, live.Addrs[0].Port())
	waitUntil(t, 40*time.Second, "a home at the relay back", func() bool {
		m.magic.ReSTUN("test")
		return m.HomeRelay() == 8 && !m.homeless.Load()
	})
}

// Where a STUN server answers and no relay's port does, netcheck measured no
// relay by HTTPS, which it does only where no UDP is answered, and the node
// stayed homeless: after two such reports the STUN servers are left out, and
// the relay HTTPS reaches is the home, until the link changes.
func TestARelayReachedByHTTPSBesideAnAnsweringSTUNServerIsAHome(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	dead := deadUDP(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: dead.Port(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 60*time.Second, "a home at the relay reached by HTTPS beside the STUN server", func() bool {
		m.magic.ReSTUN("test")
		return m.HomeRelay() == 8 && !m.homeless.Load()
	})
	if !m.walls.stunAside.Load() {
		t.Fatal("homed with the STUN servers in the map")
	}
	m.local.Store(&Networks{})
	m.followNetworks()
	if m.walls.stunAside.Load() {
		t.Error("the STUN servers stayed out after the link changed")
	}

	// The relay gone, HTTPS reaches it no more: the STUN servers come back,
	// to be left out again no sooner than a while later, and it is homeless.
	waitUntil(t, 60*time.Second, "the STUN servers left out again", func() bool {
		m.magic.ReSTUN("test")
		return m.walls.stunAside.Load()
	})
	s.Close()
	waitUntil(t, 60*time.Second, "homeless with the STUN servers back", func() bool {
		m.magic.ReSTUN("test")
		m.apply.Lock()
		again := !m.walls.asideAgain.IsZero()
		m.apply.Unlock()
		return again && !m.walls.stunAside.Load() && m.homeless.Load()
	})
}

// Reports in a row count where UDP was answered and no relay measured; a
// relay measured, or no UDP, starts over, and one that measured nothing
// counts for nothing.
func TestReportsAnsweredByTheSTUNServersAloneAreCounted(t *testing.T) {
	relays := []Relay{{Region: 8}}
	alone := &netcheck.Report{UDP: true, RegionLatency: map[tailcfg.DERPRegionID]time.Duration{100: time.Millisecond}}
	relay := &netcheck.Report{UDP: true, RegionLatency: map[tailcfg.DERPRegionID]time.Duration{8: time.Millisecond, 100: time.Millisecond}}
	https := &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{8: time.Millisecond}}
	n := unansweredAfter(alone, relays, 0)
	n = unansweredAfter(&netcheck.Report{}, relays, n)
	if n = unansweredAfter(alone, relays, n); n != 2 {
		t.Errorf("two reports by STUN alone counted %d", n)
	}
	if unansweredAfter(relay, relays, n) != 0 || unansweredAfter(https, relays, n) != 0 {
		t.Error("a relay measured did not start over")
	}
	if unansweredAfter(alone, nil, 0) != 0 {
		t.Error("counted without a relay to measure")
	}
}

// Without the STUN servers, a report reaching no relay brings them back only
// once the relays' names on 443 were tried first, which a network passing
// 443 alone needs, or where no relay has a name.
func TestTheSTUNServersComeBackOnceTheNamesWereTried(t *testing.T) {
	named := []Relay{{Region: 8, Name: "relay.example.org"}, {Region: 9}}
	plain := []Relay{{Region: 9}}
	none := &netcheck.Report{}
	if reachesNoneAside(none, named, nil, false) {
		t.Error("back before the names came first")
	}
	if !reachesNoneAside(none, named, nil, true) {
		t.Error("not back with the names first and nothing reached")
	}
	if !reachesNoneAside(none, plain, nil, false) {
		t.Error("not back where no relay has a name")
	}
	reached := &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{8: time.Millisecond}}
	if !reachesNoneAside(reached, named, map[int]bool{8: true}, true) {
		t.Error("not back where the relay answered ICMP alone")
	}
	if reachesNoneAside(reached, named, nil, true) || reachesNoneAside(&netcheck.Report{UDP: true}, plain, nil, false) {
		t.Error("back though a relay was reached, or UDP answered")
	}
}

// Without the STUN servers, a report reaching no relay leaves the node
// homeless at once, as a STUN server taken for the nearest region would: a
// saving node asks for no other report soon.
func TestARelayGoneWithoutTheSTUNServersLeavesTheNodeHomeless(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	dead := deadUDP(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: dead.Port(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 60*time.Second, "a home at the relay without the STUN servers", func() bool {
		m.magic.ReSTUN("test")
		return m.HomeRelay() == 8 && !m.homeless.Load() && m.walls.stunAside.Load()
	})
	m.SetSaving(true)
	s.Close()
	m.magic.ReSTUN("test")
	waitUntil(t, 4*time.Second, "homeless with the relay gone, after the one report asked", m.homeless.Load)
}

// The report that has the STUN servers left out names theirs for the nearest
// region, which the map no longer holds: followed again, it keeps the node
// homeless, not homed at a region it does not know.
func TestTheReportThatLeavesTheSTUNServersOutKeepsTheNodeHomeless(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
	s.Close()
	waitUntil(t, 30*time.Second, "homeless with the relay gone", func() bool {
		m.magic.ReSTUN("test")
		return m.homeless.Load()
	})
	m.apply.Lock()
	m.walls.unanswered, m.walls.stunCounted = 1, nil
	m.apply.Unlock()
	m.followSTUN()
	if !m.walls.stunAside.Load() {
		t.Fatal("the STUN servers were not left out")
	}
	m.followReport()
	if !m.homeless.Load() {
		t.Error("homed by the report naming the STUN servers' region, left out of the map")
	}
}

// Without the STUN servers, a report that measured a relay by UDP brings them
// back: the relays were not measured for another reason, as while they
// started, and the STUN servers tell the node its public address.
func TestARelayAnsweringUDPBringsTheSTUNServersBack(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	n := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.STUN = []string{srv.addr()} })
	m := n.mgr.(*tsManager)
	s := startRelay(t, 0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: s.STUNPort(), CertHash: s.CertHash()}
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "a home at the relay", func() bool { return m.HomeRelay() == 8 && !m.homeless.Load() })
	m.apply.Lock()
	m.walls.stunAside.Store(true)
	m.installDERPMap(m.relays)
	m.apply.Unlock()
	waitUntil(t, 30*time.Second, "the STUN servers back once the relay answered UDP", func() bool {
		m.magic.ReSTUN("test")
		return !m.walls.stunAside.Load()
	})
}

// A home is announced where the last report measured it, or it is the one
// announced already: where a report measured no relay, the engine picks one
// by its number, which peers would send to in vain.
func TestAHomeNoReportMeasuredIsNotAnnounced(t *testing.T) {
	measured := &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{8: time.Millisecond}}
	none := &netcheck.Report{}
	for _, c := range []struct {
		home, held int
		r          *netcheck.Report
		want       bool
	}{
		{8, 0, measured, true},
		{9, 0, none, false},
		{9, 0, measured, false},
		{9, 9, none, true},
		{0, 0, none, true},
		{9, 0, nil, false},
	} {
		if got := measuredOrHeld(c.home, c.held, c.r); got != c.want {
			t.Errorf("home %d, held %d: %v, want %v", c.home, c.held, got, c.want)
		}
	}
}

// Where a report measured no relay, the engine picks one for its home by
// number, which is not announced; the report that measures it names the
// same home, which the engine passes on only where told to, and it is
// announced then.
func TestAHomePickedUnmeasuredIsTakenOnceMeasured(t *testing.T) {
	t.Parallel()
	n := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	m := n.mgr.(*tsManager)
	cert, err := relay.NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	start := func(port uint16) *relay.Server {
		s, err := relay.New(relay.Options{Port: port, Certificate: cert, Admit: func([32]byte) bool { return true }, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	// Its STUN unanswered, as behind a network passing TCP alone, so that
	// both reports say the same of UDP.
	dead := deadUDP(t)
	s := start(0)
	live := Relay{Region: 8, HostName: s.HostName(), Addrs: []netip.AddrPort{netip.AddrPortFrom(hostAddr(t), s.Port())},
		STUNPort: dead.Port(), CertHash: s.CertHash()}
	s.Close()
	if err := m.SetRelays([]Relay{live}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		m.magic.ReSTUN("test")
		time.Sleep(time.Second)
	}
	if got := m.HomeRelay(); got != 0 {
		t.Fatalf("home %d announced with no relay measured", got)
	}
	start(live.Addrs[0].Port())
	waitUntil(t, 30*time.Second, "a home at the relay once measured", func() bool {
		m.magic.ReSTUN("test")
		return m.HomeRelay() == 8
	})
}
