package conn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// Each engine's port mapper takes the switch of the engine it was built
// for, and one built outside New asks the router for nothing.
func TestPortMapperTakesItsEnginesSwitch(t *testing.T) {
	var mu sync.Mutex
	built := map[*atomic.Bool]bool{}
	portMapperBuilt = func(off *atomic.Bool) {
		mu.Lock()
		defer mu.Unlock()
		built[off] = off.Load()
	}
	t.Cleanup(func() { portMapperBuilt = func(*atomic.Bool) {} })

	on := startNode(t, 1, "100.64.0.1/32", "fd00::1/128", nil)
	off := startNode(t, 2, "100.64.0.2/32", "fd00::2/128", func(o *Options) { o.PortMapOff = true })
	mu.Lock()
	for _, c := range []struct {
		n   *node
		off bool
	}{{on, false}, {off, true}} {
		m := c.n.mgr.(*tsManager)
		got, ok := built[&m.portMapOff]
		if !ok || got != c.off {
			t.Errorf("node %d: port mapper built with off=%v (built: %v), want %v", c.n.id, got, ok, c.off)
		}
		if u := m.Underlay(); u.PortMapOff != c.off {
			t.Errorf("node %d: the underlay says off=%v", c.n.id, u.PortMapOff)
		}
	}
	mu.Unlock()

	bus := eventbus.New()
	defer bus.Close()
	nm, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer nm.Close()
	pm := newPortMapper(logger.Discard, bus, nm, nil, nil)
	defer pm.Close()
	if _, err := pm.Probe(context.Background()); !errors.Is(err, portmapper.ErrPortMappingDisabled) {
		t.Errorf("a port mapper built outside New probes: %v", err)
	}
}

// On HTTPS alone the port mapper sends nothing, though mapping is on.
func TestPortMapperSendsNothingOnHTTPSAlone(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	nm, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer nm.Close()
	engineMu.Lock()
	on := new(atomic.Bool)
	buildingOff = on
	pm := newPortMapper(logger.Discard, bus, nm, nil, func() bool { return true })
	buildingOff = nil
	engineMu.Unlock()
	defer pm.Close()
	if _, err := pm.Probe(context.Background()); !errors.Is(err, portmapper.ErrPortMappingDisabled) {
		t.Errorf("on HTTPS alone the port mapper probes: %v", err)
	}
	if _, ok := pm.GetCachedMappingOrStartCreatingOne(); ok {
		t.Error("on HTTPS alone the port mapper maps")
	}
}

// The address the router maps is the portmapped endpoint's, unmapped from
// IPv6; none where no endpoint is.
func TestPortMappedIsThePortmappedEndpoint(t *testing.T) {
	stun := tailcfg.Endpoint{Type: tailcfg.EndpointSTUN, Addr: netip.MustParseAddrPort("198.51.100.4:41641")}
	mapped := tailcfg.Endpoint{Type: tailcfg.EndpointPortmapped, Addr: netip.MustParseAddrPort("[::ffff:203.0.113.7]:41641")}
	if got := portMapped([]tailcfg.Endpoint{stun, mapped}); got != netip.MustParseAddrPort("203.0.113.7:41641") {
		t.Errorf("mapped: %v", got)
	}
	if got := portMapped([]tailcfg.Endpoint{stun}); got.IsValid() {
		t.Errorf("nothing mapped, yet %v", got)
	}
}
