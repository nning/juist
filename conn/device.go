package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/router"
)

// openDevice opens the device and its OS router and hands both to the
// engine's config. newOSRouter wants the device and the engine wants the
// router, fixing the order: netmon, TUN, router, engine. The MTU must be
// DefaultTUNMTU() — 1280, the IPv6 minimum; lower and the kernel drops IPv6
// silently.
func (m *tsManager) openDevice(opts Options, cfg *wgengine.Config, undo *cleanups, logf logger.Logf) error {
	mon, err := netmon.New(m.bus, logf)
	if err != nil {
		return fmt.Errorf("conn: starting the network monitor: %w", err)
	}
	// The engine never closes a monitor it was handed.
	undo.push(func() { mon.Close() })
	var dev tun.Device
	var osRtr router.Router
	if vp, ok := opts.Plumber.(*vpnPlumber); ok {
		dev, osRtr = newVPNPlumbed(vp, opts.TunName, int(tstun.DefaultTUNMTU()), logf)
		undo.push(func() { dev.Close() })
	} else if opts.Plumber != nil {
		if dev, osRtr, err = newPlumbed(opts.Plumber, opts.TunName, opts.Instance, int(tstun.DefaultTUNMTU()), logf); err != nil {
			return fmt.Errorf("conn: creating TUN device %q: %w", opts.TunName, err)
		}
		undo.push(func() { dev.Close() })
	} else {
		if dev, err = tun.CreateTUN(opts.TunName, int(tstun.DefaultTUNMTU())); err != nil {
			// Lists what creation needs; does not claim to be the cause,
			// since a name already in use comes back as EBUSY.
			return fmt.Errorf("conn: creating TUN device %q: %w (needs %s, and the name must be free)",
				opts.TunName, err, tunNeeds)
		}
		undo.push(func() { dev.Close() })
		if osRtr, err = newOSRouter(logf, dev, mon, m.health, m.bus, opts.Instance); err != nil {
			return fmt.Errorf("conn: creating the OS router: %w", err)
		}
	}
	// The engine's own cleanup closes the device, and neither closes the
	// router on failure; the router may already hold the policy rules its
	// Up installed.
	undo.pop()
	undo.push(func() { closeUnstartedRouter(osRtr) })
	// One monitor for both, rather than letting the engine start a second.
	cfg.Tun = dev
	cfg.Router = osRtr
	m.osRouter = osRtr
	if version.IsMobile() {
		// What the engine hands Android's VPN.
		m.osRouter = router.ConsolidatingRoutes(m.logf, osRtr)
	}
	m.exits, _ = osRtr.(exitRouter)
	m.hostRouter, _ = osRtr.(hostRouter)
	m.inGuard, _ = osRtr.(overlayGuard)
	if m.hostRouter != nil && opts.OnHostRoutesChange != nil {
		m.hostRouter.watchHostRoutes(opts.OnHostRoutesChange)
	}
	m.tunName = opts.TunName
	cfg.NetMon = mon
	m.netMon = mon
	// What an exit node serves leaves out the networks it is on, which
	// change under it.
	ec := m.bus.Client("juist-serve")
	eventbus.SubscribeFunc(ec, func(d netmon.ChangeDelta) {
		// Not on the bus's goroutine: Close holds apply while it closes
		// the bus, which waits for this callback.
		if d.InterfaceIPsChanged {
			go m.refilter()
			go m.followNetworks()
			if opts.OnInterfacesChange != nil {
				go opts.OnInterfacesChange()
			}
		}
	})
	return nil
}

// overlayGuard is an OS router that drops what reaches the overlay's
// addresses by another device than the tunnel.
type overlayGuard interface {
	guardOverlay(own, peers []netip.Addr) error
}

// unguardedRouter is an overlay guard that may run unguarded, and says why.
type unguardedRouter interface {
	unguardedBy() string
}

// A hostRouter is an OS router that reads the host's own routes, and says
// when they change.
type hostRouter interface {
	hostRoutes() []netip.Prefix
	watchHostRoutes(changed func())
}

// exitRouter is what an OS router does for egress and serving beside
// [router.Router].
type exitRouter interface {
	setEgress(e Egress, t tunnelled) error
	setServe(s Serve) error
	// lans is the networks the host is on but through this node's device,
	// and its own addresses in them.
	lans() ([]netip.Prefix, []netip.Addr)
	// answersThrough is why answers to what comes in by another device
	// would go into the tunnel though not isolated, "" where they leave by
	// it.
	answersThrough() string
}

// maxTunNameLen is IFNAMSIZ-1, the longest name Linux and the BSDs accept.
const maxTunNameLen = 15

// checkTunName rejects device names the OS would mishandle, which TUNSETIFF
// reports as a bare EINVAL. '%' matters most: the kernel treats it as a
// template, so "juist%d" creates a device the caller never named.
func checkTunName(name string) error {
	if name == "" {
		return errors.New("must not be empty")
	}
	if len(name) > maxTunNameLen {
		return fmt.Errorf("%q is %d bytes; the OS accepts at most %d", name, len(name), maxTunNameLen)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%q is not a usable interface name", name)
	}
	if strings.ContainsAny(name, "%") {
		return fmt.Errorf("%q contains %%, which the kernel expands to a different name", name)
	}
	if strings.ContainsAny(name, "/: \t\n") {
		return fmt.Errorf("%q contains a character an interface name may not hold", name)
	}
	return nil
}
