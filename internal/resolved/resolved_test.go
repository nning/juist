package resolved

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"

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
	if got := f.asked(); len(got) != 3 {
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
	want := []string{"dns 7 [2 198.18.4.2:41646 10 [fd12::2]:41646]", "domains 7 [{. true}]", "default-route 7 true", "revert 7"}
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
