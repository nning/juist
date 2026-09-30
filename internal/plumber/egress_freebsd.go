package plumber

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/net/route"
)

// captured is what each device has routed into it for the internet.
var captured struct {
	sync.Mutex
	routes map[string]map[netip.Prefix]bool
}

// egressAnchor is the anchor of dev's egress, which outlasts the device where
// it refuses: traffic stays in while juistd restarts.
func egressAnchor(dev string) string { return dev + "_egress" }

// SetEgress sends the host's traffic outside the overlay as e asks.
func (FreeBSD) SetEgress(dev string, e EgressSpec, uid int) error {
	if e.Mode == EgressDirect {
		return errors.Join(setCapture(dev, nil), flushAnchor(egressAnchor(dev)), release(egressAnchor(dev)))
	}
	if err := hold(egressAnchor(dev), false); err != nil {
		return err
	}
	gw4, gw6 := gateways()
	// Answers pass what comes in, which only juist's own ruleset, passing
	// everything, leaves them nothing to open; the host's own decides else.
	rules := e
	rules.Isolate = e.Isolate || !onlyJuists()
	// The guard first, so that nothing leaves outside the tunnel meanwhile.
	if err := loadAnchor(egressAnchor(dev), egressRules(dev, rules, uid, gw4, gw6)); err != nil {
		return err
	}
	return setCapture(dev, e.Capture)
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
			if err := (FreeBSD{}).DelRoute(dev, p, netip.Addr{}); err != nil {
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
		if err := (FreeBSD{}).AddRoute(dev, p, netip.Addr{}); err != nil {
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
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		ifc, err := net.InterfaceByIndex(rm.Index)
		if err != nil || devicePattern.MatchString(ifc.Name) {
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
