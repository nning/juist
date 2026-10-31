package plumber

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/net/route"
)

// guardAnchor is the pf anchor guarding dev's overlay.
func guardAnchor(dev string) string { return dev + "_in" }

// SetGuard keeps dev's overlay to it in pf, which it has run, as Linux's
// in table does; where g holds no address, no longer.
func (FreeBSD) SetGuard(dev string, g GuardSpec) error {
	if len(g.Own) == 0 && len(g.Overlay) == 0 {
		return unguard(dev)
	}
	name := guardAnchor(dev)
	if err := hold(name, false); err != nil {
		return err
	}
	return loadAnchor(name, guardRules(dev, g))
}

// unguard flushes dev's guard and lets go of pf for it.
func unguard(dev string) error {
	name := guardAnchor(dev)
	return errors.Join(flushAnchor(name), release(name))
}

// HostAddrs is the addresses of the host's devices but juist's and the
// loopback, and the gateways of its routes by them.
func (FreeBSD) HostAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	theHosts := map[int]bool{}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || devicePattern.MatchString(ifc.Name) {
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
