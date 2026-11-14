//go:build freebsd || darwin

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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nning/juist/internal/instance"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// lockDir holds a lock per device, which its helper holds while it lives.
const lockDir = "/var/run"

// runTimeout bounds a command, which a device held elsewhere can block.
const runTimeout = 30 * time.Second

// deviceFree reports whether no helper holds name's lock, which one holds
// while its device lives.
func deviceFree(name string) bool {
	lock, err := os.OpenFile(filepath.Join(lockDir, "juistd."+name+".lock"), os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return false
	}
	defer lock.Close()
	return syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

// lockDevice takes name's lock, which a helper holds while its device lives.
func lockDevice(name string) (*os.File, error) {
	lock, err := os.OpenFile(filepath.Join(lockDir, "juistd."+name+".lock"), os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%s is another juistd's: %w", name, syscall.EBUSY)
	}
	return lock, nil
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

// holds reports whether dev holds a.
func holds(dev string, a netip.Addr) bool {
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		return false
	}
	addrs, _ := ifc.Addrs()
	for _, ad := range addrs {
		if ipn, ok := ad.(*net.IPNet); ok {
			if b, ok := netip.AddrFromSlice(ipn.IP); ok && b.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// addRoute routes p into dev by a message to the routing socket, which a
// large network's route set needs: route(8) costs a process a route.
func addRoute(dev string, p netip.Prefix, src netip.Addr) error {
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

// delRoute deletes the route addRoute made, by its gateway too: beside a
// route of the host's to p, as multipath routing allows, that one stays.
func delRoute(dev string, p netip.Prefix, src netip.Addr) error {
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
	// No SOCK_CLOEXEC on macOS.
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
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

// hostAddrs is the addresses of the host's devices but juist's and the
// loopback, and the gateways of its routes by them.
func hostAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	theHosts := map[int]bool{}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || instance.IsDevice(ifc.Name) {
			continue
		}
		theHosts[ifc.Index] = true
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return out
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return out
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || !theHosts[rm.Index] || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		var gw netip.Addr
		switch a := rm.Addrs[syscall.RTAX_GATEWAY].(type) {
		case *route.Inet4Addr:
			gw = netip.AddrFrom4(a.IP)
		case *route.Inet6Addr:
			gw = netip.AddrFrom16(a.IP)
		}
		if gw.IsValid() && !slices.Contains(out, gw) {
			out = append(out, gw)
		}
	}
	return out
}

// listenDNS binds 53 at a by proto, for the daemon's resolver, which the
// host's resolver asks there.
func listenDNS(a netip.Addr, proto string) (*os.File, error) {
	at := netip.AddrPortFrom(a, 53)
	if proto == "udp" {
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(at))
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.File()
	}
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.File()
}
