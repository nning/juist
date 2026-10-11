package conn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/backoff"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// The tests in this file assert behaviour of the pinned Tailscale module that
// this package depends on and nothing else checks. A failure after an upgrade
// names an assumption to revisit; see docs/07-embedding-notes.md, "Upgrading
// the pinned Tailscale".

// upstreamSource reads a file of the tailscale.com module this build uses.
func upstreamSource(t *testing.T, rel string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("reads the pinned module's source, which a host without Go has not")
	}
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "tailscale.com").Output()
	if err != nil {
		t.Fatalf("locating the tailscale.com module: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Skip("reads the pinned module's source, which a test run outside the module has not")
	}
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("reading upstream %s: %v", rel, err)
	}
	return string(b)
}

// filtered runs one line through the STUN-home filter, reporting whether it
// was kept.
func filtered(format string, args ...any) bool {
	m := &tsManager{}
	m.stunRegions.Store(&map[tailcfg.DERPRegionID]bool{65534: true})
	kept := false
	m.withoutSTUNHomeNoise(func(string, ...any) { kept = true })(format, args...)
	return kept
}

// The filter's first rule matches what util/backoff logs, under the name
// magicsock gives a relay region's backoff.
func TestUpstreamBackoffLineIsTheOneFiltered(t *testing.T) {
	src := upstreamSource(t, "wgengine/magicsock/derp.go")
	if !strings.Contains(src, `backoff.NewBackoff(fmt.Sprintf("derp-%d", regionID), c.logf,`) {
		t.Fatal(`magicsock no longer names a region's backoff "derp-<region>" with its own logf`)
	}
	var lines []string
	for _, region := range []int{65534, 7} {
		bo := backoff.NewBackoff(fmt.Sprintf("derp-%d", region), func(format string, args ...any) {
			if filtered(format, args...) {
				lines = append(lines, fmt.Sprintf(format, args...))
			}
		}, time.Second)
		bo.BackOff(t.Context(), errors.New("connect failed"))
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "derp-7: ") {
		t.Fatalf("kept %q; want only the real relay's backoff", lines)
	}
}

// The second matches the error derphttp gives for a region with no relay in
// it, which is what a STUN-only region is.
func TestUpstreamSTUNOnlyRegionErrorIsTheOneFiltered(t *testing.T) {
	dm, stunRegions := derpMap(nil, []string{"192.0.2.1:3478"}, false, Networks{})
	var reg *tailcfg.DERPRegion
	for id := range stunRegions {
		reg = dm.Regions[id]
	}
	if reg == nil {
		t.Fatal("the map holds no STUN region")
	}
	c := derphttp.NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(), func() *tailcfg.DERPRegion { return reg })
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := c.Connect(ctx)
	if err == nil {
		t.Fatal("connected to a STUN-only region")
	}
	if filtered("magicsock: [%p] derp.Recv(derp-%d): %v", c, reg.RegionID, err) {
		t.Fatalf("derphttp's error for a STUN-only region is no longer the one filtered: %v", err)
	}
}

// magicsock moves its home relay only while the health tracker says a map
// poll is open, which conn sets for good. Under test magicsock skips the
// check, so only its source can show it is still made.
func TestUpstreamHomeRelayWaitsForAMapPoll(t *testing.T) {
	src := upstreamSource(t, "wgengine/magicsock/derp.go")
	if !strings.Contains(src, "connectedToControl = c.health.GetInPollNetMap()") {
		t.Fatal("magicsock no longer gates a home relay change on GetInPollNetMap; " +
			"conn's GotStreamedMapResponse may be unneeded, or no longer enough")
	}
}

// flakyRouter fails Set while fail is true, and records what it took.
type flakyRouter struct {
	mu   sync.Mutex
	fail bool
	took []*router.Config
}

func (r *flakyRouter) Up() error { return nil }
func (r *flakyRouter) Set(c *router.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c != nil && r.fail {
		return errors.New("router: netlink is busy")
	}
	if c != nil {
		r.took = append(r.took, c)
	}
	return nil
}
func (r *flakyRouter) Close() error { return nil }

func (r *flakyRouter) set(fail bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = fail
	return len(r.took)
}

// newRouterEngine starts a real engine on r, listening where the OS picks.
func newRouterEngine(t *testing.T, r router.Router) wgengine.Engine {
	t.Helper()
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	eng, err := wgengine.NewUserspaceEngine(t.Logf, wgengine.Config{
		Router:        r,
		EventBus:      bus,
		Metrics:       new(usermetric.Registry),
		HealthTracker: new(health.Tracker),
	})
	if err != nil {
		t.Fatalf("starting the engine: %v", err)
	}
	t.Cleanup(eng.Close)
	return eng
}

// The real engine records a router config before programming it, so after a
// failure it does not hand the same config to the router again: it reports
// ErrNoChanges, or nothing at all where something else moved, such as the
// listen port of an engine that was given none.
func TestUpstreamEngineSkipsARouterItFailedToProgram(t *testing.T) {
	r := &flakyRouter{fail: true}
	eng := newRouterEngine(t, r)
	nk := key.NewNode()
	wg := &wgcfg.Config{PrivateKey: nk, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}
	rt := &router.Config{LocalAddrs: wg.Addresses}
	if err := eng.Reconfig(wg, rt, &dns.Config{}); err == nil || errors.Is(err, wgengine.ErrNoChanges) {
		t.Fatalf("a failing router gave %v", err)
	}
	before := r.set(false)
	err := eng.Reconfig(wg, rt, &dns.Config{})
	if err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		t.Fatalf("the same config again: %v", err)
	}
	if r.set(false) != before {
		t.Fatal("the engine retried a config its router failed; reconfig's forced retry may be unneeded")
	}
}

// And reconfig reaches the router anyway, whatever the engine answers.
func TestReconfigReprogramsAFailedRouterOnTheRealEngine(t *testing.T) {
	r := &flakyRouter{fail: true}
	m := &tsManager{logf: t.Logf, eng: newRouterEngine(t, r), osRouter: r,
		self: Self{ID: 1, NodeKey: key.NewNode(), Addrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}}
	m.state.Store(&peerState{})
	if err := m.reconfig(); err == nil {
		t.Fatal("a failing router did not surface an error")
	}
	before := r.set(false)
	if err := m.reconfig(); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.took) == before {
		t.Fatal("the retry never reached the router: the host keeps the routes it had when it failed")
	}
	if last := r.took[len(r.took)-1]; !samePrefixSet(last.LocalAddrs, m.self.Addrs) {
		t.Fatalf("the router ended at %v, want %v", last.LocalAddrs, m.self.Addrs)
	}
	// Never by an empty config, which takes every address and route off
	// the device for a call.
	for _, c := range r.took {
		if len(c.LocalAddrs) == 0 {
			t.Fatal("the retry handed the router an empty config")
		}
	}
}

// HTTPS alone rests on magicsock sending no UDP once SetOnlyTCP443 is set:
// disco and netcheck's sends refuse, a peer's UDP path is taken only from a
// pong to a ping that was sent, or from a peer relay the self node's
// capability turns off, and netcheck measures relays over HTTPS alone.
func TestUpstreamOnlyTCP443SendsNoUDP(t *testing.T) {
	for file, wants := range map[string][]string{
		"wgengine/magicsock/magicsock.go": {
			"func (c *Conn) sendUDPStd(addr netip.AddrPort, b []byte) (sent bool, err error) {\n\tif c.onlyTCP443.Load() {\n\t\treturn false, nil",
			"if !hasUDPTransport || c.onlyTCP443.Load() {\n\t\treturn 0, errors.ErrUnsupported",
			"!self.HasCap(nodecap.OnlyTCP443)",
			"OnlyTCP443:          c.onlyTCP443.Load(),",
		},
		"wgengine/magicsock/endpoint.go": {
			"de.setBestAddrLocked(thisPong)",
			"determined maybeBest is functional via [disco.Pong] reception",
		},
		"net/netcheck/netcheck.go": {
			"if buildfeatures.HasNATTraversal && (opts == nil || !opts.OnlyTCP443) {\n\t\tplan = makeProbePlan",
			`"https://"+node.HostName+"/derp/latency-check"`,
		},
	} {
		src := upstreamSource(t, file)
		for _, want := range wants {
			if !strings.Contains(src, want) {
				t.Errorf("%s no longer holds %q", file, want)
			}
		}
		// Two set it, from a pong and from a peer relay, and two clear it.
		if n := strings.Count(src, "de.setBestAddrLocked("); file == "wgengine/magicsock/endpoint.go" && n != 4 {
			t.Errorf("%s sets a peer's UDP path in %d places, not the 4 read for HTTPS alone", file, n)
		}
	}
}

// A relay's name on 443 rests on derphttp dialling a node's DERPPort, at its
// host name resolved in DNS where an address is left empty, verifying a node
// with no CertName by WebPKI against that name, and asking the proxy hook,
// with the name, for each dial.
func TestUpstreamANamedNodeIsDialledByNameThroughTheProxy(t *testing.T) {
	src := upstreamSource(t, "derp/derphttp/derphttp_client.go")
	for _, want := range []string{
		"if proxyFromEnv, ok := feature.HookProxyFromEnvironment.GetOk(); ok {",
		"Host:   c.tlsServerName(n),",
		"if n.DERPPort != 0 {\n\t\t\t\tport = fmt.Sprint(n.DERPPort)",
		"func shouldDialProto(s string, pred func(netip.Addr) bool) bool {\n\tif s == \"\" {\n\t\treturn true",
		"dst := cmp.Or(dstPrimary, n.HostName)",
		"tlsConf.ServerName = c.tlsServerName(node)",
		"if node.CertName != \"\" {",
		"if getAuthHeader, ok := feature.HookProxyGetAuthHeader.GetOk(); ok {",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("derphttp no longer holds %q", want)
		}
	}
}

// Nothing in juistd maps ports or probes for captive portals, which would
// send outside TLS on 443 whatever magicsock is told.
func TestUpstreamNoPortMapperOrCaptivePortalIsLinked(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("lists the build's packages, which a host without Go cannot")
	}
	out, err := exec.Command("go", "list", "-deps", "github.com/nning/juist/cmd/juistd").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range strings.Fields(string(out)) {
		if p == "tailscale.com/feature/portmapper" || p == "tailscale.com/net/portmapper" ||
			strings.HasPrefix(p, "tailscale.com/feature/captiveportal") || p == "tailscale.com/net/captivedetection" {
			t.Errorf("juistd links %s", p)
		}
	}
}
