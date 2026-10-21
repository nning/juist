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
