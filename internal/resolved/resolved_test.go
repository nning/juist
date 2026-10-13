package resolved

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

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

// Routing reads resolved's servers and domains of every link but the one
// skipped, and routes a name as resolved does: to the links whose domain
// matching it is longest, else to those that take every name.
func TestRouting(t *testing.T) {
	bus := firewalldtest.Start(t)
	conn := bus.Connect(t)
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
	a := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	servers := []srv{{0, 2, a("10.0.0.1"), 0, ""}, {2, 2, a("10.0.2.3"), 53, ""}, {5, 2, a("10.99.2.2"), 0, ""},
		{7, 10, a("fd12::1"), 41647, ""}, {9, 10, a("fd99::53"), 5353, ""}}
	domains := []dom{{2, "lan", false}, {5, "lab.example.", true}, {7, "svc.lab.example", true},
		{7, "home.juist", false}, {9, "corp.example", true}}
	links := map[int32]bool{2: true, 5: false, 7: false, 9: false}
	if err := conn.ExportMethodTable(map[string]any{
		"GetLink": func(i int32) (dbus.ObjectPath, *dbus.Error) {
			return dbus.ObjectPath(fmt.Sprintf("%s/link/_%d", objPath, i)), nil
		},
	}, objPath, manager); err != nil {
		t.Fatal(err)
	}
	if _, err := prop.Export(conn, objPath, prop.Map{manager: {
		"DNSEx":   {Value: servers},
		"Domains": {Value: domains},
	}}); err != nil {
		t.Fatal(err)
	}
	for i, on := range links {
		if _, err := prop.Export(conn, dbus.ObjectPath(fmt.Sprintf("%s/link/_%d", objPath, i)),
			prop.Map{busName + ".Link": {"DefaultRoute": {Value: on}}}); err != nil {
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
	r, err := c.Routing(7)
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort
	for name, want := range map[string][]netip.AddrPort{
		"svc.lab.example.":  {ap("10.99.2.2:53")},
		"a.b.lab.example":   {ap("10.99.2.2:53")},
		"nas.lan":           {ap("10.0.2.3:53")},
		"git.corp.example":  {ap("[fd99::53]:5353")},
		"example.org":       {ap("10.0.0.1:53"), ap("10.0.2.3:53")},
		"mailer.home.juist": {ap("10.0.0.1:53"), ap("10.0.2.3:53")},
	} {
		if got := r.Servers(name); !slices.Equal(got, want) {
			t.Errorf("%s is asked of %v, want %v", name, got, want)
		}
	}
	if got := (Routing{}).Servers("example.org"); got == nil || len(got) != 0 {
		t.Errorf("no links ask %v", got)
	}
}
