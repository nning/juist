package plumber

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/tailscale/wireguard-go/tun"
)

// Darwin is the helper's Host on macOS: wireguard-go's utun device,
// ifconfig(8) and the route socket, pf for the guard and the exit node's
// egress, and scutil(8) for DNS through it. It does not serve.
type Darwin struct {
	// Daemon is the uid of the daemon this helper serves.
	Daemon int
}

// errNotOnMac is what macOS's helper does not do yet.
var errNotOnMac = errors.New("not on macOS")

func (d Darwin) OpenTUN(name string, mtu int) (*os.File, func() error, error) {
	lock, err := lockDevice(name)
	if err != nil {
		return nil, nil, err
	}
	// A utun lives while a descriptor of it is open: one of this name
	// still there is held by a process the lock no longer covers.
	if _, err := net.InterfaceByName(name); err == nil {
		lock.Close()
		return nil, nil, fmt.Errorf("%s is held by another program: %w", name, syscall.EBUSY)
	}
	// What a helper killed left in /etc/resolver or guarded for the
	// device goes.
	if err := errors.Join(writeResolvers(resolverDir, name, nil, 0, nil, nil), unguard(name)); err != nil {
		lock.Close()
		return nil, nil, err
	}
	if err := loadAnchor(daemonAnchor(name), macDaemonRules(name, d.Daemon)); err != nil {
		lock.Close()
		return nil, nil, err
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		lock.Close()
		return nil, nil, fmt.Errorf("creating %s: %w", name, err)
	}
	go func() {
		for range dev.Events() {
		}
	}()
	f, err := dup(dev.File())
	if err != nil {
		dev.Close()
		lock.Close()
		return nil, nil, err
	}
	if err := run("/sbin/ifconfig", name, "up"); err != nil {
		f.Close()
		dev.Close()
		lock.Close()
		return nil, nil, err
	}
	// The device goes once the daemon's descriptor closes too. The egress
	// anchor stays where it refuses: traffic stays in while juistd restarts.
	return f, func() error {
		defer forgetCapture(name)
		return errors.Join(unguard(name), flushAnchor(daemonAnchor(name)), dev.Close(), lock.Close())
	}, nil
}

func (Darwin) Free(name string) bool { return deviceFree(name) }

func (Darwin) AddAddr(dev string, p netip.Prefix) error {
	a := p.Addr()
	switch {
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("a link-local address, %v: %w", p, errNotOnMac)
	case a.Is4():
		return run("/sbin/ifconfig", dev, "inet", a.String()+"/32", a.String(), "alias")
	}
	// A point-to-point address to itself, as Tailscale sets it on macOS.
	return run("/sbin/ifconfig", dev, "inet6", p.String(), a.String())
}

func (Darwin) DelAddr(dev string, p netip.Prefix) error {
	fam := "inet"
	if p.Addr().Is6() {
		fam = "inet6"
	}
	if !holds(dev, p.Addr()) {
		return nil
	}
	return run("/sbin/ifconfig", dev, fam, p.Addr().String(), "-alias")
}

func (Darwin) AddRoute(dev string, p netip.Prefix, src netip.Addr) error {
	return addRoute(dev, p, src)
}

func (Darwin) DelRoute(dev string, p netip.Prefix, src netip.Addr) error {
	return delRoute(dev, p, src)
}

func (Darwin) SetServe(dev string, s ServeSpec) error {
	if len(s.Sources) > 0 {
		return fmt.Errorf("serving: %w", errNotOnMac)
	}
	return nil
}

func (Darwin) HostAddrs() []netip.Addr { return hostAddrs() }

// Answers is why answers to what comes in by another device go into the
// tunnel: the anchor never passes them over the host's own pf rules.
func (Darwin) Answers() string {
	return "on macOS the host's own pf rules decide what comes in, and their answers go by the routes, into the tunnel"
}

func (Darwin) ListenHTTPS(netip.Addr) (*os.File, error) {
	return nil, fmt.Errorf("a relay: %w", errNotOnMac)
}

func (Darwin) ListenDNS(a netip.Addr, proto string) (*os.File, error) { return listenDNS(a, proto) }
