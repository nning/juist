//go:build linux && !android

package conn

import (
	"net/netip"
	"slices"

	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/nning/juist/internal/instance"
)

// InstanceHoldings lists what the host's juist instances other than self
// hold, leaving out the device named own, which is self's. An instance is
// known by the table its routes are in, or, where it routes nothing yet, by
// its device's name. Reading the kernel's tables needs no privilege; the
// tables are read in one dump, whatever else the host routes.
func InstanceHoldings(self int, own string) ([]Holding, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	byIndex := make(map[int]netlink.Link, len(links))
	for _, l := range links {
		byIndex[l.Attrs().Index] = l
	}
	// Table 0 with the table filter set is every table.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	held := map[int]*Holding{}
	holding := func(inst int, dev string) *Holding {
		h := held[inst]
		if h == nil {
			h = &Holding{Instance: inst, Device: dev}
			held[inst] = h
		}
		return h
	}
	routedBy := map[int]int{} // link index → the instance whose table routes into it
	for _, rt := range routes {
		inst := rt.Table - juistRouteTable
		if inst < 0 || inst > instance.Max || inst == self {
			continue
		}
		l, ok := byIndex[rt.LinkIndex]
		if !ok || l.Attrs().Name == own {
			continue
		}
		h := holding(inst, l.Attrs().Name)
		routedBy[rt.LinkIndex] = inst
		h.Prefixes = append(h.Prefixes, routeDst(rt))
	}
	for _, l := range links {
		name := l.Attrs().Name
		inst, ok := routedBy[l.Attrs().Index]
		if !ok {
			inst, ok = deviceInstance(name)
		}
		if !ok || inst == self || name == own {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ip, ok := netip.AddrFromSlice(a.IP)
			if !ok || ip.IsLinkLocalUnicast() {
				continue
			}
			ip = ip.Unmap()
			h := holding(inst, name)
			h.Prefixes = append(h.Prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	out := make([]Holding, 0, len(held))
	for _, h := range held {
		out = append(out, *h)
	}
	slices.SortFunc(out, func(a, b Holding) int { return a.Instance - b.Instance })
	return out, nil
}

// routeDst is a route's destination. The kernel sends none for a default
// route, whose destination is then the whole family.
func routeDst(rt netlink.Route) netip.Prefix {
	if rt.Dst != nil {
		if p, ok := netipx.FromStdIPNet(rt.Dst); ok {
			return p.Masked()
		}
	}
	if rt.Family == netlink.FAMILY_V6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

// deviceInstance reads the instance a device's name says it is.
func deviceInstance(name string) (int, bool) {
	if name == instance.Name(0) {
		return 0, true
	}
	n, err := instance.Parse(name)
	return n, err == nil
}
