package resolved

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"

	"github.com/nning/juist/internal/firewalld/firewalldtest"
)

// fake answers as resolved does, recording each call; old leaves out
// SetLinkDNSEx, and refuse answers every call as polkit's refusal.
type fake struct {
	mu     sync.Mutex
	calls  []string
	old    bool
	refuse bool
}

func (f *fake) record(s string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
	if f.refuse {
		return &dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied", Body: []any{"no"}}
	}
	return nil
}

func (f *fake) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func startResolved(t *testing.T, f *fake) *dbus.Conn {
	t.Helper()
	return startResolvedBus(t, f).Connect(t)
}

// startResolvedBus is a bus with f on it as resolved.
func startResolvedBus(t *testing.T, f *fake) *firewalldtest.Bus {
	t.Helper()
	bus := firewalldtest.Start(t)
	conn := bus.Connect(t)
	methods := map[string]any{
		"SetLinkDomains": func(i int32, d []domain) *dbus.Error {
			return f.record(fmt.Sprintf("domains %d %v", i, d))
		},
		"SetLinkDefaultRoute": func(i int32, on bool) *dbus.Error {
			return f.record(fmt.Sprintf("default-route %d %v", i, on))
		},
		"RevertLink": func(i int32) *dbus.Error { return f.record(fmt.Sprintf("revert %d", i)) },
		"SetLinkDNSSECNegativeTrustAnchors": func(i int32, names []string) *dbus.Error {
			return f.record(fmt.Sprintf("nta %d %v", i, names))
		},
	}
	if !f.old {
		methods["SetLinkDNSEx"] = func(i int32, s []server) *dbus.Error {
			var addrs []string
			for _, x := range s {
				a, _ := netip.AddrFromSlice(x.Address)
				addrs = append(addrs, fmt.Sprintf("%d %v", x.Family, netip.AddrPortFrom(a, x.Port)))
			}
			return f.record(fmt.Sprintf("dns %d %v", i, addrs))
		}
	}
	if err := conn.ExportMethodTable(methods, objPath, manager); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	return bus
}

// A bus that accepts a connection and never answers holds DialContext no
// longer than its context.
func TestDialContextEndsWithItsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+path)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := DialContext(ctx)
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a silent bus was dialled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialContext outlives its context on a silent bus")
	}
}

// Without a system bus to connect to, resolved is not running.
func TestNoBusIsNoResolved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+path)
	if _, err := DialContext(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("no socket: %v", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := Dial(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("a socket no one listens on: %v", err)
	}
}

// A client dialled on the system bus routes, as the daemon's does: its
// connection outlives the dialling.
func TestADialledClientRoutes(t *testing.T) {
	f := &fake{}
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", startResolvedBus(t, f).Addr)
	c, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Route(7, []netip.AddrPort{netip.MustParseAddrPort("198.18.4.2:41646")}); err != nil {
		t.Fatalf("routing: %v", err)
	}
	if got := f.asked(); len(got) != 4 {
		t.Errorf("asked %q", got)
	}
}

// A link's servers are made resolved's for every name, and reverted.
func TestRouteAndRevert(t *testing.T) {
	f := &fake{}
	c, err := Open(startResolved(t, f))
	if err != nil {
		t.Fatal(err)
	}
	servers := []netip.AddrPort{netip.MustParseAddrPort("198.18.4.2:41646"), netip.MustParseAddrPort("[fd12::2]:41646")}
	if err := c.Route(7, servers); err != nil {
		t.Fatal(err)
	}
	if err := c.Revert(7); err != nil {
		t.Fatal(err)
	}
	want := []string{"dns 7 [2 198.18.4.2:41646 10 [fd12::2]:41646]", "domains 7 [{. true}]", "default-route 7 true",
		"nta 7 []", "revert 7"}
	if got := f.asked(); !slices.Equal(got, want) {
		t.Errorf("asked %q, want %q", got, want)
	}
}

// A refusal, a resolved too old for ports and one that does not run are
// each said as what they are.
func TestWhatResolvedCannotDoIsSaid(t *testing.T) {
	c, err := Open(startResolved(t, &fake{refuse: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Route(7, []netip.AddrPort{netip.MustParseAddrPort("198.18.4.2:41646")}); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("refused: %v", err)
	}
	c, err = Open(startResolved(t, &fake{old: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Route(7, []netip.AddrPort{netip.MustParseAddrPort("198.18.4.2:41646")}); !errors.Is(err, ErrTooOld) {
		t.Errorf("too old: %v", err)
	}
	bus := firewalldtest.Start(t)
	if _, err := Open(bus.Connect(t)); !errors.Is(err, ErrNotRunning) {
		t.Errorf("not running: %v", err)
	}
}

// A refusal on a host without polkit says so, since no rule turns it there.
func TestARefusalSaysWherePolkitIsMissing(t *testing.T) {
	bus := startResolvedBus(t, &fake{refuse: true})
	c, err := Open(bus.Connect(t))
	if err != nil {
		t.Fatal(err)
	}
	route := func() error { return c.Route(7, []netip.AddrPort{netip.MustParseAddrPort("198.18.4.2:41646")}) }
	if err := route(); !errors.Is(err, ErrNoPolkit) {
		t.Errorf("without polkit: %v", err)
	}
	bus.Polkit(t)
	if err := route(); !errors.Is(err, ErrNotAuthorized) || errors.Is(err, ErrNoPolkit) {
		t.Errorf("with polkit: %v", err)
	}
}

// A link routed for some domains alone takes them, a search domain among
// them, and is no default route; with everything, "." is added once. Its
// own domains are kept from DNSSEC validation, which answers from juistd
// would fail.
func TestConfigureDomains(t *testing.T) {
	f := &fake{}
	c, err := Open(startResolved(t, f))
	if err != nil {
		t.Fatal(err)
	}
	servers := []netip.AddrPort{netip.MustParseAddrPort("[fd12::5]:41647")}
	if err := c.Configure(7, servers, []Domain{{Name: "home.juist", Search: true}, {Name: "mx.example.net"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Configure(7, servers, []Domain{{Name: "home.juist", Search: true}}, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"dns 7 [10 [fd12::5]:41647]", "domains 7 [{home.juist false} {mx.example.net true}]", "default-route 7 false",
		"nta 7 [home.juist mx.example.net]",
		"dns 7 [10 [fd12::5]:41647]", "domains 7 [{home.juist false} {. true}]", "default-route 7 true", "nta 7 [home.juist]",
	}
	if got := f.asked(); !slices.Equal(got, want) {
		t.Errorf("asked %q, want %q", got, want)
	}
}

type srv struct {
	Ifindex int32
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

type dom struct {
	Ifindex   int32
	Domain    string
	RouteOnly bool
}

// A fakeDelegate is a delegate of resolved's, in dns-delegate.d.
type fakeDelegate struct {
	id           string
	servers      []srv
	domains      []string
	defaultRoute bool
}

// resolvedBus is a resolved with servers, each a link's or, at ifindex 0,
// global, and domains alike, which its manager reports as systemd 255 does,
// a loopback server at the loopback's ifindex; fallback, where it has
// FallbackDNSEx; and delegates, listed where it has ListDelegates. links
// say whether each link is a default route, overTLS which speak DNS over
// TLS, noScope which have no DNS scope; others are no links of its.
type resolvedBus struct {
	servers   []srv
	domains   []dom
	links     map[int32]bool
	overTLS   map[int32]bool
	noScope   map[int32]bool
	delegates []fakeDelegate
	listing   bool
	fallback  []srv
	candidate []int
	asked     *int // how often the candidates were asked for
	churn     int  // GetLink calls that change the manager's servers
	own       int
}

func (b resolvedBus) routing(t *testing.T, skip int) (Routing, error) {
	t.Helper()
	if _, ok := b.links[1]; !ok {
		// The loopback is a link of resolved's, with no scope.
		b.links = maps.Clone(b.links)
		if b.links == nil {
			b.links = map[int32]bool{}
		}
		b.noScope = maps.Clone(b.noScope)
		if b.noScope == nil {
			b.noScope = map[int32]bool{}
		}
		b.links[1], b.noScope[1] = false, true
	}
	bus := firewalldtest.Start(t)
	conn := bus.Connect(t)
	var managerProps *prop.Properties
	churn := b.churn
	methods := map[string]any{
		"GetLink": func(i int32) (dbus.ObjectPath, *dbus.Error) {
			if churn > 0 {
				churn--
				now := managerProps.GetMust(manager, "DNSEx").([]srv)
				managerProps.SetMust(manager, "DNSEx", append(slices.Clone(now), srv{0, 2, a4("10.250.0.1"), 0, ""}))
			}
			if _, ok := b.links[i]; !ok {
				return "", dbus.NewError(busName+".NoSuchLink", []any{"no"})
			}
			return dbus.ObjectPath(fmt.Sprintf("%s/link/_%d", objPath, i)), nil
		},
	}
	type listed struct {
		ID   string
		Path dbus.ObjectPath
	}
	var list []listed
	for _, d := range b.delegates {
		path := dbus.ObjectPath(objPath + "/dns_delegate/" + d.id)
		list = append(list, listed{d.id, path})
		type ddom struct {
			Domain    string
			RouteOnly bool
		}
		var domains []ddom
		for _, n := range d.domains {
			domains = append(domains, ddom{n, true})
		}
		if _, err := prop.Export(conn, path, prop.Map{busName + ".DnsDelegate": {
			"DNS": {Value: d.servers}, "Domains": {Value: domains}, "DefaultRoute": {Value: d.defaultRoute}}}); err != nil {
			t.Fatal(err)
		}
	}
	if b.listing {
		methods["ListDelegates"] = func() ([]listed, *dbus.Error) { return list, nil }
	}
	if err := conn.ExportMethodTable(methods, objPath, manager); err != nil {
		t.Fatal(err)
	}
	reported := []srv{}
	for _, s := range b.servers {
		if a, _ := netip.AddrFromSlice(s.Address); a.IsLoopback() {
			s.Ifindex = 1
		}
		reported = append(reported, s)
	}
	props := map[string]*prop.Prop{"DNSEx": {Value: reported}, "Domains": {Value: append([]dom{}, b.domains...)}, "DNSOverTLS": {Value: "no"}}
	if b.fallback != nil {
		props["FallbackDNSEx"] = &prop.Prop{Value: b.fallback}
	}
	for _, p := range props {
		p.Writable = true
	}
	var err error
	if managerProps, err = prop.Export(conn, objPath, prop.Map{manager: props}); err != nil {
		t.Fatal(err)
	}
	type lsrv struct {
		Family  int32
		Address []byte
		Port    uint16
		Name    string
	}
	type ldom struct {
		Domain    string
		RouteOnly bool
	}
	for i, on := range b.links {
		own, domains := []lsrv{}, []ldom{}
		for _, s := range b.servers {
			if s.Ifindex == i {
				own = append(own, lsrv{s.Family, s.Address, s.Port, s.Name})
			}
		}
		for _, d := range b.domains {
			if d.Ifindex == i {
				domains = append(domains, ldom{d.Domain, d.RouteOnly})
			}
		}
		tls := map[bool]string{true: "opportunistic", false: "no"}[b.overTLS[i]]
		mask := map[bool]uint64{true: 0, false: 1 | 2}[b.noScope[i]]
		if _, err := prop.Export(conn, dbus.ObjectPath(fmt.Sprintf("%s/link/_%d", objPath, i)),
			prop.Map{busName + ".Link": {"DefaultRoute": {Value: on}, "DNSOverTLS": {Value: tls}, "DNSEx": {Value: own},
				"Domains": {Value: domains}, "ScopesMask": {Value: mask}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	c, err := Open(bus.Connect(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.Routing(cmp.Or(b.own, skip), func() []int {
		if b.asked != nil {
			*b.asked++
		}
		return b.candidate
	})
}

var a4 = func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

// Routing reads resolved's servers, domains and DNS over TLS of every link
// but the one skipped, an IPv6 link-local server keeping its link, and
// routes a name as resolved does: to the links whose domain matching it is
// longest, else to those that take every name.
func TestRouting(t *testing.T) {
	a := a4
	r, err := resolvedBus{
		servers: []srv{{0, 2, a("10.0.0.1"), 0, ""}, {2, 2, a("10.0.2.3"), 53, ""}, {5, 2, a("10.99.2.2"), 0, ""},
			{7, 10, a("fd12::1"), 41647, ""}, {9, 10, a("fd99::53"), 5353, ""}, {11, 10, a("fe80::1"), 0, ""},
			{12, 2, a("10.12.0.1"), 0, "dns.example"}},
		domains: []dom{{2, "lan", false}, {5, "lab.example.", true}, {7, "svc.lab.example", true},
			{7, "home.juist", false}, {9, "corp.example", true}, {11, "v6.example", true}, {12, "tls.example", true}},
		links:   map[int32]bool{2: true, 5: false, 7: false, 9: false, 11: false, 12: false},
		overTLS: map[int32]bool{12: true},
	}.routing(t, 7)
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort
	for name, want := range map[string][]netip.AddrPort{
		"svc.lab.example.":  {ap("10.99.2.2:53")},
		"a.b.lab.example":   {ap("10.99.2.2:53")},
		"nas.lan":           {ap("10.0.2.3:53")},
		"git.corp.example":  {ap("[fd99::53]:5353")},
		"a.v6.example":      {ap("[fe80::1%11]:53")},
		"example.org":       {ap("10.0.0.1:53"), ap("10.0.2.3:53")},
		"mailer.home.juist": {ap("10.0.0.1:53"), ap("10.0.2.3:53")},
	} {
		if got, tls, err := r.Route(name, typeA); err != nil || !slices.Equal(got, want) || tls {
			t.Errorf("%s is asked of %v, over TLS %v, %v; want %v", name, got, tls, err, want)
		}
	}
	if ups, tls, err := r.Route("www.tls.example", typeA); err != nil || !tls || !slices.Equal(ups, []netip.AddrPort{ap("10.12.0.1:53")}) {
		t.Errorf("a name routed to a link speaking DNS over TLS: %v, %v, %v", ups, tls, err)
	}
}

// Routing takes systemd 258's delegates as scopes of their own, none where
// resolved cannot list them, and resolved's fallback servers where nothing
// else would take a name; with no server at all, a name is refused as such.
func TestRoutingTakesDelegatesAndFallback(t *testing.T) {
	a, ap := a4, netip.MustParseAddrPort
	link := resolvedBus{
		servers: []srv{{2, 2, a("10.0.2.3"), 0, ""}}, domains: []dom{{2, "lan", true}}, links: map[int32]bool{2: false},
		delegates: []fakeDelegate{{id: "corp", servers: []srv{{0, 2, a("10.77.0.1"), 0, ""}}, domains: []string{"corp.example"}}},
		listing:   true, fallback: []srv{{0, 2, a("9.9.9.9"), 0, ""}},
	}
	r, err := link.routing(t, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]netip.AddrPort{
		"x.corp.example": {ap("10.77.0.1:53")}, "nas.lan": {ap("10.0.2.3:53")}, "example.org": {ap("9.9.9.9:53")},
	} {
		if got, _, err := r.Route(name, typeA); err != nil || !slices.Equal(got, want) {
			t.Errorf("%s is asked of %v, %v; want %v", name, got, err, want)
		}
	}
	old := link
	old.listing, old.fallback = false, nil
	if r, err = old.routing(t, 0); err != nil {
		t.Fatalf("a resolved without delegates or fallback: %v", err)
	}
	if _, _, err := r.Route("example.org", typeA); !errors.Is(err, ErrNotUnicast) {
		t.Errorf("without a default route or fallback, example.org: %v", err)
	}
	if _, _, err := (resolvedBus{}).mustRoute(t).Route("example.org", typeA); !errors.Is(err, ErrNoServers) {
		t.Errorf("without servers, example.org: %v", err)
	}
}

// Global servers on the loopback, which the manager files under the
// loopback's ifindex, stay global with the global domains, so that resolved's
// "~." keeps a link's and its fallback's from them; a link on the loopback
// alone is found where it is named; a link without a DNS scope routes
// nothing, and its servers are no global ones.
func TestLoopbackServersStayWhereTheyAre(t *testing.T) {
	a, ap := a4, netip.MustParseAddrPort
	stub := resolvedBus{
		servers: []srv{{0, 2, a("127.0.0.1"), 0, ""}, {2, 2, a("192.168.1.1"), 0, ""}},
		domains: []dom{{0, ".", true}}, links: map[int32]bool{2: true},
	}
	if got, _, err := stub.mustRoute(t).Route("example.org", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("127.0.0.1:53")}) {
		t.Errorf("global 127.0.0.1 with ~. and a DHCP link: example.org is asked of %v, %v", got, err)
	}
	alone := resolvedBus{servers: []srv{{0, 2, a("127.0.0.1"), 0, ""}}, fallback: []srv{{0, 2, a("1.1.1.1"), 0, ""}}}
	if got, _, err := alone.mustRoute(t).Route("example.org", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("127.0.0.1:53")}) {
		t.Errorf("global 127.0.0.1 and a fallback: example.org is asked of %v, %v", got, err)
	}
	linked := resolvedBus{
		servers: []srv{{0, 2, a("10.0.0.1"), 0, ""}, {4, 2, a("127.0.0.2"), 5353, ""}},
		domains: []dom{{4, "vpn.example", true}}, links: map[int32]bool{4: false}, candidate: []int{4},
	}
	r := linked.mustRoute(t)
	for name, want := range map[string]netip.AddrPort{"a.vpn.example": ap("127.0.0.2:5353"), "example.org": ap("10.0.0.1:53")} {
		if got, _, err := r.Route(name, typeA); err != nil || !slices.Equal(got, []netip.AddrPort{want}) {
			t.Errorf("a link on the loopback: %s is asked of %v, %v; want %v", name, got, err, want)
		}
	}
	gone := resolvedBus{
		servers: []srv{{0, 2, a("10.0.0.1"), 0, ""}, {6, 2, a("10.6.0.1"), 0, ""}},
		domains: []dom{{6, "old.example", true}}, links: map[int32]bool{6: false}, noScope: map[int32]bool{6: true},
	}
	if got, _, err := gone.mustRoute(t).Route("a.old.example", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("10.0.0.1:53")}) {
		t.Errorf("a link without a DNS scope: a.old.example is asked of %v, %v", got, err)
	}
}

// A link resolved no longer has makes none of its servers global, a read
// during which resolved's servers change is read again, and refused where
// they keep changing; the host's interfaces are asked for only where a
// server is on the loopback.
func TestALinkGoneMakesNoServerGlobal(t *testing.T) {
	a, ap := a4, netip.MustParseAddrPort
	asked := 0
	gone := resolvedBus{
		servers: []srv{{2, 2, a("192.168.1.1"), 0, ""}, {5, 2, a("10.8.0.53"), 0, ""}},
		domains: []dom{{5, "corp.example", true}}, links: map[int32]bool{2: true}, asked: &asked,
	}
	if got, _, err := gone.mustRoute(t).Route("www.public.org", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("192.168.1.1:53")}) {
		t.Errorf("a VPN link gone, www.public.org is asked of %v, %v", got, err)
	}
	if asked != 0 {
		t.Errorf("no server on the loopback, the interfaces were asked for %d times", asked)
	}
	churning := gone
	churning.churn = 1
	if _, err := churning.routing(t, 0); err != nil {
		t.Errorf("servers changing once: %v", err)
	}
	churning.churn = 100
	if _, err := churning.routing(t, 0); !errors.Is(err, errChanging) {
		t.Errorf("servers changing on: %v", err)
	}
}

// juistd's own link is asked nothing, but its "~." takes every name from
// the default route, and its being one keeps resolved from its fallback;
// its other domains route nothing.
func TestJuistdsOwnLinkIsAskedNothing(t *testing.T) {
	a, ap := a4, netip.MustParseAddrPort
	exit := resolvedBus{
		servers: []srv{{9, 2, a("100.64.0.9"), 0, ""}}, domains: []dom{{9, ".", true}},
		links: map[int32]bool{9: true}, fallback: []srv{{0, 2, a("1.1.1.1"), 0, ""}}, own: 9,
	}
	if got, _, err := exit.mustRoute(t).Route("example.org", typeA); !errors.Is(err, ErrOwn) {
		t.Errorf("juistd's link the only default route, example.org is asked of %v, %v", got, err)
	}
	offline := Routing{Scopes: []Scope{{Ifindex: 9, Servers: []netip.AddrPort{ap("100.64.0.9:53")}, Domains: []string{"home.juist"}, Own: true}}}
	if got, _, err := offline.Route("example.org", typeA); !errors.Is(err, ErrNoServers) {
		t.Errorf("juistd's link's servers alone, example.org: %v, %v", got, err)
	}
	named := resolvedBus{
		servers: []srv{{2, 2, a("192.168.1.1"), 0, ""}, {9, 2, a("100.64.0.9"), 0, ""}},
		domains: []dom{{9, "mx.example.net", true}}, links: map[int32]bool{2: true, 9: false}, own: 9,
	}
	if got, _, err := named.mustRoute(t).Route("mx.example.net", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("192.168.1.1:53")}) {
		t.Errorf("a name juistd's link routes is asked of %v, %v", got, err)
	}
}

// A domain's \DDD escapes are its bytes, compared as resolved compares
// names: A to Z alone folded.
func TestADomainsEscapedBytesAreCompared(t *testing.T) {
	ap := netip.MustParseAddrPort
	r := Routing{Scopes: []Scope{
		{Ifindex: 3, Servers: []netip.AddrPort{ap("10.0.3.1:53")}, Domains: []string{`\195\137.corp`}},
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.1:53")}, DefaultRoute: true},
	}}
	if got, _, err := r.Route("\xc3\x89.CORP", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("10.0.3.1:53")}) {
		t.Errorf("É.corp is asked of %v, %v", got, err)
	}
}

// A domain's escaped dot is within a label, as resolved writes it.
func TestAnEscapedDotIsWithinALabel(t *testing.T) {
	ap := netip.MustParseAddrPort
	r := Routing{Scopes: []Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.1:53")}, Domains: []string{`a\.b.example`}},
		{Ifindex: 3, Servers: []netip.AddrPort{ap("10.0.3.1:53")}, Domains: []string{"b.example"}},
	}}
	if got, _, err := r.Route("x.a.b.example", typeA); err != nil || !slices.Equal(got, []netip.AddrPort{ap("10.0.3.1:53")}) {
		t.Errorf("x.a.b.example is asked of %v, %v", got, err)
	}
	if n := matches(`x.a\b.example`, `a\\b.example`); n != 2 {
		t.Errorf(`a\\b.example matches x.a\b.example by %d labels, want 2`, n)
	}
}

func (b resolvedBus) mustRoute(t *testing.T) Routing {
	t.Helper()
	r, err := b.routing(t, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Route keeps from DNS servers what resolved does: names it answers itself
// or never resolves, single-label addresses, .local and link-local reverse
// names; a link's own subnet's reverse names go to that link, and a "~."
// route takes every name from the default route.
func TestRouteKeepsWhatResolvedKeeps(t *testing.T) {
	ap := netip.MustParseAddrPort
	lan := Scope{Ifindex: 2, Servers: []netip.AddrPort{ap("192.168.1.1:53")}, Search: true, Domains: []string{"lan"},
		Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24"), netip.MustParsePrefix("fd00:1::20/64")}}
	wan := Scope{Ifindex: 3, Servers: []netip.AddrPort{ap("9.9.9.9:53")}, DefaultRoute: true}
	r := Routing{Scopes: []Scope{lan, wan}}
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  error
	}{
		{"x.invalid", typeA, ErrNeverResolved}, {"a.b.alt", typeA, ErrNeverResolved},
		{"5.0.0.0.in-addr.arpa", 12, ErrNeverResolved}, {"255.255.255.255.in-addr.arpa", 12, ErrNeverResolved},
		{"localhost", typeA, ErrNotUnicast}, {"a.localhost", typeAAAA, ErrNotUnicast},
		{"1.0.0.127.in-addr.arpa", 12, ErrNotUnicast}, {"_gateway", typeA, ErrNotUnicast},
		{"x.resolver.arpa", 16, ErrNotUnicast}, {"printer.local", typeA, ErrNotUnicast},
		{"nas", typeA, ErrNotUnicast}, {"", typeA, ErrNotUnicast},
		{"4.3.254.169.in-addr.arpa", 12, ErrNotUnicast},
		{"1." + strings.Repeat("0.", 15) + "0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", 12, ErrNotUnicast},
	} {
		if ups, _, err := r.Route(tc.name, tc.qtype); !errors.Is(err, tc.want) {
			t.Errorf("%q type %d: %v, %v; want %v", tc.name, tc.qtype, ups, err, tc.want)
		}
	}
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  []netip.AddrPort
	}{
		{"7.1.168.192.in-addr.arpa", 12, lan.Servers},
		{"1." + strings.Repeat("0.", 23) + "1.0.0.0.0.0.d.f.ip6.arpa", 12, lan.Servers},
		{"7.2.168.192.in-addr.arpa", 12, wan.Servers},
		{"nas", 16, lan.Servers},
		{"com", 43, lan.Servers},
		{"", 48, wan.Servers},
		{"_dns.resolver.arpa", typeSVCB, wan.Servers},
	} {
		if ups, _, err := r.Route(tc.name, tc.qtype); err != nil || !slices.Equal(ups, tc.want) {
			t.Errorf("%q type %d: %v, %v; want %v", tc.name, tc.qtype, ups, err, tc.want)
		}
	}
	if ups, _, err := (Routing{Scopes: []Scope{wan}}).Route("com", 43); err != nil || !slices.Equal(ups, wan.Servers) {
		t.Errorf("without a search domain, com's DS is asked of %v, %v", ups, err)
	}
	for _, qtype := range []uint16{16, 12, 5, 255} {
		if ups, _, err := (Routing{Scopes: []Scope{wan}}).Route("nas", qtype); !errors.Is(err, ErrNotUnicast) {
			t.Errorf("without a search domain, LLMNR's nas type %d is asked of %v, %v", qtype, ups, err)
		}
	}
	ts := Scope{Ifindex: 7, Servers: []netip.AddrPort{ap("100.100.100.100:53")}, Domains: []string{""}, DefaultRoute: true}
	if ups, _, err := (Routing{Scopes: []Scope{wan, ts}}).Route("example.org", typeA); err != nil || !slices.Equal(ups, ts.Servers) {
		t.Errorf("with a ~. route, example.org is asked of %v, %v", ups, err)
	}
	if _, _, err := (Routing{}).Route("example.org", typeA); !errors.Is(err, ErrNoServers) {
		t.Errorf("no links: %v", err)
	}
}
