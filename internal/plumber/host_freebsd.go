package plumber

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// FreeBSD is the helper's Host on FreeBSD: wireguard-go's device, and
// ifconfig(8) and route(8) for the rest.
type FreeBSD struct{}

// lockDir holds a lock per device, which its helper holds while it lives.
const lockDir = "/var/run"

// runTimeout bounds a command, which a device held elsewhere can block.
const runTimeout = 30 * time.Second

func (FreeBSD) OpenTUN(name string, mtu int) (*os.File, func() error, error) {
	lock, err := os.OpenFile(filepath.Join(lockDir, "juistd."+name+".lock"), os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, fmt.Errorf("%s is another juistd's: %w", name, syscall.EBUSY)
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

// Free reports whether no helper holds name's lock, which one holds while
// its device lives.
func (FreeBSD) Free(name string) bool {
	lock, err := os.OpenFile(filepath.Join(lockDir, "juistd."+name+".lock"), os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return false
	}
	defer lock.Close()
	return syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

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

func dup(f *os.File) (*os.File, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var derr error
	if err := rc.Control(func(fd uintptr) { nfd, derr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return nil, err
	}
	if derr != nil {
		return nil, derr
	}
	return os.NewFile(uintptr(nfd), f.Name()), nil
}

func (FreeBSD) AddAddr(dev string, p netip.Prefix) error {
	a := p.Addr().String()
	if p.Addr().Is4() {
		// A point-to-point address to itself, as Tailscale sets it.
		return run("/sbin/ifconfig", dev, "inet", a+"/32", a, "alias")
	}
	return run("/sbin/ifconfig", dev, "inet6", a, "prefixlen", strconv.Itoa(p.Bits()), "alias")
}

func (FreeBSD) DelAddr(dev string, p netip.Prefix) error {
	fam := "inet"
	if p.Addr().Is6() {
		fam = "inet6"
	}
	return run("/sbin/ifconfig", dev, fam, p.Addr().String(), "-alias")
}

// AddRoute routes p into dev by a message to the routing socket, which a
// large network's route set needs: route(8) costs a process a route.
func (FreeBSD) AddRoute(dev string, p netip.Prefix, src netip.Addr) error {
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	m := &route.RouteMessage{Type: syscall.RTM_ADD, Flags: syscall.RTF_UP | syscall.RTF_STATIC}
	viaDevice(m, ifc, src)
	if err := routeMsg(m, p); err != nil {
		return fmt.Errorf("adding a route to %v into %s: %w", p, dev, err)
	}
	return nil
}

// viaDevice has m's route go into ifc, from src where valid.
func viaDevice(m *route.RouteMessage, ifc *net.Interface, src netip.Addr) {
	m.Addrs = make([]route.Addr, syscall.RTAX_IFA+1)
	if src.IsValid() {
		// The source is pinned by making it the gateway: -ifa beside -iface
		// is ignored for what the host sends.
		m.Flags |= syscall.RTF_GATEWAY
		m.Addrs[syscall.RTAX_GATEWAY] = inetAddr(src)
		m.Addrs[syscall.RTAX_IFP] = &route.LinkAddr{Index: ifc.Index, Name: ifc.Name}
		m.Addrs[syscall.RTAX_IFA] = inetAddr(src)
		return
	}
	m.Addrs[syscall.RTAX_GATEWAY] = &route.LinkAddr{Index: ifc.Index}
}

// DelRoute deletes the route AddRoute made, by its gateway too: beside a
// route of the host's to p, as multipath routing allows, that one stays.
func (FreeBSD) DelRoute(dev string, p netip.Prefix, src netip.Addr) error {
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return nil // gone with the device
	}
	m := &route.RouteMessage{Type: syscall.RTM_DELETE}
	viaDevice(m, ifc, src)
	err = routeMsg(m, p)
	if errors.Is(err, syscall.ESRCH) {
		// The kernel takes a route with the address it came from.
		return nil
	}
	if err != nil {
		return fmt.Errorf("deleting the route to %v: %w", p, err)
	}
	return nil
}

// routeMsg sends m for the destination p, whose answer is the write's error.
func routeMsg(m *route.RouteMessage, p netip.Prefix) error {
	m.Version, m.ID, m.Seq = syscall.RTM_VERSION, uintptr(os.Getpid()), 1
	m.Addrs[syscall.RTAX_DST] = inetAddr(p.Addr())
	if p.IsSingleIP() {
		m.Flags |= syscall.RTF_HOST
	} else {
		mask := net.CIDRMask(p.Bits(), p.Addr().BitLen())
		a, _ := netip.AddrFromSlice(mask)
		m.Addrs[syscall.RTAX_NETMASK] = inetAddr(a)
	}
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	// Nothing is read: what every route change says would fill it.
	syscall.Shutdown(fd, syscall.SHUT_RD)
	_, err = syscall.Write(fd, b)
	return err
}

func inetAddr(a netip.Addr) route.Addr {
	if a.Is4() {
		return &route.Inet4Addr{IP: a.As4()}
	}
	return &route.Inet6Addr{IP: a.As16()}
}

func run(name string, args ...string) error { return runIn("", name, args...) }

// runIn runs name with stdin, within runTimeout.
func runIn(stdin, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, bytes.TrimSpace(out))
	}
	return nil
}
