package plumber

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

// FreeBSD is the helper's Host on FreeBSD: wireguard-go's device, and
// ifconfig(8) and route(8) for the rest.
type FreeBSD struct{}

func (FreeBSD) OpenTUN(name string, mtu int) (*os.File, func() error, error) {
	lock, err := lockDevice(name)
	if err != nil {
		return nil, nil, err
	}
	// What a helper gone left served or guarded for the device, it does
	// no longer.
	if err := errors.Join(unserve(name), unguard(name)); err != nil {
		lock.Close()
		return nil, nil, err
	}
	f, destroy, err := openTUN(name, mtu)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	// The egress anchor stays where it refuses: traffic stays in while
	// juistd restarts. The routes into the device go with it.
	return f, func() error {
		defer forgetCapture(name)
		return errors.Join(unserve(name), unguard(name), destroy(), lock.Close())
	}, nil
}

// RelayGrant is root's file whose presence lets the helper bind 443 for the
// relay, as the package's relay.sh on leaves it.
var RelayGrant = "/usr/local/etc/juist/relay-443"

// ListenHTTPS binds 443/tcp at a, where root granted the relay 443 and no
// program answers there yet: root's socket at an address would take the
// clients of another server's on the wildcard.
func (FreeBSD) ListenHTTPS(a netip.Addr) (*os.File, error) {
	if err := relayGranted(); err != nil {
		return nil, err
	}
	at := netip.AddrPortFrom(a, 443)
	switch c, err := net.DialTimeout("tcp", at.String(), time.Second); {
	case err == nil:
		c.Close()
		return nil, fmt.Errorf("listen tcp %v: another program answers there", at)
	case !errors.Is(err, syscall.ECONNREFUSED):
		return nil, fmt.Errorf("listen tcp %v: whether another program answers there: %w", at, err)
	}
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.File()
}

// relayGranted says whether RelayGrant is in place, and root's alone.
func relayGranted() error {
	fi, err := os.Lstat(RelayGrant)
	if err != nil {
		return errors.New("root has not granted the relay 443")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not root's alone", RelayGrant)
	}
	return nil
}

func (FreeBSD) Free(name string) bool { return deviceFree(name) }

func openTUN(name string, mtu int) (*os.File, func() error, error) {
	// if_tuntap may be built in, or loaded already.
	_ = run("/sbin/kldload", "-n", "if_tuntap")
	if _, err := net.InterfaceByName(name); err == nil {
		// What a juistd gone left, whose lock is free. Destroying waits for
		// whoever still holds the device, as a daemon on its way out may.
		if err := run("/sbin/ifconfig", name, "destroy"); err != nil {
			return nil, nil, err
		}
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", name, err)
	}
	// Its events are the daemon's to see; unread, they would stop the
	// device's own watch of its link, which then never lets go.
	go func() {
		for range dev.Events() {
		}
	}()
	f, err := dup(dev.File())
	if err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := run("/sbin/ifconfig", name, "group", DeviceGroup, "up"); err != nil {
		f.Close()
		dev.Close()
		return nil, nil, err
	}
	return f, dev.Close, nil
}

func (FreeBSD) AddAddr(dev string, p netip.Prefix) error {
	a := p.Addr().String()
	if p.Addr().Is4() {
		// A point-to-point address to itself, as Tailscale sets it.
		return run("/sbin/ifconfig", dev, "inet", a+"/32", a, "alias")
	}
	if p.Addr().IsLinkLocalUnicast() {
		return onlyLinkLocal(dev, p.Addr())
	}
	return run("/sbin/ifconfig", dev, "inet6", a, "prefixlen", strconv.Itoa(p.Bits()), "alias")
}

func (FreeBSD) DelAddr(dev string, p netip.Prefix) error {
	fam, a := "inet", p.Addr().String()
	if p.Addr().Is6() {
		fam = "inet6"
	}
	if p.Addr().IsLinkLocalUnicast() {
		// Gone already where another took its place.
		if !holds(dev, p.Addr()) {
			return nil
		}
		a += "%" + dev
	}
	return run("/sbin/ifconfig", dev, fam, a, "-alias")
}

// onlyLinkLocal has dev hold ll as its one link-local address, on-link for
// the members' others: the kernel gives it one of its own otherwise, which
// the host would send from. Without DAD, which a tunnel has no use for and
// which leaves the address unusable until done.
func onlyLinkLocal(dev string, ll netip.Addr) error {
	if err := run("/sbin/ifconfig", dev, "inet6", "-auto_linklocal", "no_dad"); err != nil {
		return err
	}
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return err
	}
	for _, ad := range addrs {
		ipn, ok := ad.(*net.IPNet)
		if !ok {
			continue
		}
		if a, ok := netip.AddrFromSlice(ipn.IP); ok && a.IsLinkLocalUnicast() && a != ll {
			if err := run("/sbin/ifconfig", dev, "inet6", a.String()+"%"+dev, "-alias"); err != nil {
				return err
			}
		}
	}
	return run("/sbin/ifconfig", dev, "inet6", ll.String()+"%"+dev, "prefixlen", "64", "alias")
}

func (FreeBSD) AddRoute(dev string, p netip.Prefix, src netip.Addr) error {
	return addRoute(dev, p, src)
}

func (FreeBSD) DelRoute(dev string, p netip.Prefix, src netip.Addr) error {
	return delRoute(dev, p, src)
}
