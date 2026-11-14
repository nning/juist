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
	"strings"
	"sync"
	"syscall"

	"github.com/nning/juist/internal/instance"
	"golang.org/x/net/route"
)

var loaded struct {
	sync.Mutex
	rules map[string]string // the anchor last loaded, by device
}

// loadAnchor loads name's anchor with rules where they changed, or where pf no
// longer holds them, as after its rules were reloaded: every reconcile gives
// them again, which must put back what someone took.
func loadAnchor(name, rules string) error {
	loaded.Lock()
	defer loaded.Unlock()
	if loaded.rules[name] == rules {
		if held, err := pfOutput("-a", anchorPath(name), "-s", "rules"); err == nil && strings.TrimSpace(held) != "" {
			return nil
		}
	}
	if err := pfctl(rules, "-a", anchorPath(name), "-f", "-"); err != nil {
		return err
	}
	if loaded.rules == nil {
		loaded.rules = map[string]string{}
	}
	loaded.rules[name] = rules
	return nil
}

func flushAnchor(name string) error {
	loaded.Lock()
	defer loaded.Unlock()
	delete(loaded.rules, name)
	if err := pfctl("", "-s", "info"); err != nil {
		return nil // no pf, so no anchor
	}
	anchor := anchorPath(name)
	errs := []error{pfctl("", "-a", anchor, "-F", "rules"), pfctl("", "-a", anchor, "-F", "nat")}
	// -F all and -F Tables fail in an anchor on FreeBSD 15.1, so its tables go one by one.
	tables, err := pfOutput("-a", anchor, "-s", "Tables")
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) && bytes.Contains(ee.Stderr, []byte("Anchor does not exist")) {
		err = nil
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("pfctl -a %s -s Tables: %w", anchor, err))
	}
	for _, t := range strings.Fields(tables) {
		errs = append(errs, pfctl("", "-a", anchor, "-t", t, "-T", "kill"))
	}
	return errors.Join(errs...)
}

func removeIfThere(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func pfctl(stdin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %v: %v: %s", args, err, bytes.TrimSpace(out))
	}
	return nil
}

func pfOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/pfctl", args...).Output()
	return string(out), err
}

// captured is what each device has routed into it for the internet.
var captured struct {
	sync.Mutex
	routes map[string]map[netip.Prefix]bool
}

// setCapture routes exactly want into dev for the internet.
func setCapture(dev string, want []netip.Prefix) error {
	captured.Lock()
	defer captured.Unlock()
	if captured.routes == nil {
		captured.routes = map[string]map[netip.Prefix]bool{}
	}
	have := captured.routes[dev]
	if have == nil {
		have = map[netip.Prefix]bool{}
		captured.routes[dev] = have
	}
	wanted := map[netip.Prefix]bool{}
	for _, p := range want {
		wanted[p.Masked()] = true
	}
	var errs []error
	for p := range have {
		if !wanted[p] {
			if err := delRoute(dev, p, netip.Addr{}); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(have, p)
		}
	}
	for p := range wanted {
		if have[p] {
			continue
		}
		if err := addRoute(dev, p, netip.Addr{}); err != nil {
			errs = append(errs, err)
			continue
		}
		have[p] = true
	}
	return errors.Join(errs...)
}

// forgetCapture forgets dev's routes, which went with the device.
func forgetCapture(dev string) {
	captured.Lock()
	defer captured.Unlock()
	delete(captured.routes, dev)
}

// gateways are the host's default routes, by family, but through juist's
// devices.
func gateways() (gw4, gw6 gateway) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || rm.Flags&scopedRoute != 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		ifc, err := net.InterfaceByIndex(rm.Index)
		if err != nil || instance.IsDevice(ifc.Name) {
			continue
		}
		dst, hop := addrOf(rm.Addrs[syscall.RTAX_DST]), addrOf(rm.Addrs[syscall.RTAX_GATEWAY])
		if !dst.IsValid() || !dst.IsUnspecified() || !hop.IsValid() || !isDefault(rm) {
			continue
		}
		g := gateway{dev: ifc.Name, hop: hop.WithZone(""), addr: firstAddr(ifc, hop.Is6())}
		if hop.Is4() && !gw4.hop.IsValid() {
			gw4 = g
		} else if hop.Is6() && !gw6.hop.IsValid() {
			gw6 = g
		}
	}
	return
}

// isDefault reports whether rm's netmask, absent or all zero, makes it a
// default route.
func isDefault(rm *route.RouteMessage) bool {
	if len(rm.Addrs) <= syscall.RTAX_NETMASK || rm.Addrs[syscall.RTAX_NETMASK] == nil {
		return true
	}
	m := addrOf(rm.Addrs[syscall.RTAX_NETMASK])
	return !m.IsValid() || m.IsUnspecified()
}

func addrOf(a route.Addr) netip.Addr {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP)
	}
	return netip.Addr{}
}

// firstAddr is ifc's first address of the family, a global one for IPv6.
func firstAddr(ifc *net.Interface, v6 bool) netip.Addr {
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is6() == v6 && !ip.IsLinkLocalUnicast() {
			return ip
		}
	}
	return netip.Addr{}
}

// guardAnchor is the pf anchor guarding dev's overlay.
func guardAnchor(dev string) string { return dev + "_in" }

// egressAnchor is the anchor of dev's egress, which outlasts the device where
// it refuses: traffic stays in while juistd restarts.
func egressAnchor(dev string) string { return dev + "_egress" }
