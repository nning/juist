package conn

import (
	"net"
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/net/route"
)

// InstanceHoldings lists what the host's juist instances other than self
// hold, leaving out the device named own, which is self's. FreeBSD has one
// table for them all: an instance is known by its device's name, and holds
// the routes into it. Reading the table needs no privilege.
func InstanceHoldings(self int, own string) ([]Holding, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	held := map[int]*Holding{}
	byIndex := map[int]*Holding{}
	for _, ifc := range ifs {
		inst, ok := deviceInstance(ifc.Name)
		if !ok || inst == self || ifc.Name == own {
			continue
		}
		h := &Holding{Instance: inst, Device: ifc.Name}
		held[inst], byIndex[ifc.Index] = h, h
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok || ip.IsLinkLocalUnicast() {
				continue
			}
			ip = ip.Unmap()
			h.Prefixes = append(h.Prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	if len(held) > 0 {
		rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			rm, ok := m.(*route.RouteMessage)
			if !ok {
				continue
			}
			h := byIndex[rm.Index]
			if h == nil {
				continue
			}
			if p, ok := routeDst(rm); ok && !slices.Contains(h.Prefixes, p) {
				h.Prefixes = append(h.Prefixes, p)
			}
		}
	}
	out := make([]Holding, 0, len(held))
	for _, h := range held {
		out = append(out, *h)
	}
	slices.SortFunc(out, func(a, b Holding) int { return a.Instance - b.Instance })
	return out, nil
}
