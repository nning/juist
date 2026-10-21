// Package underlay reads the host addresses another device might reach this
// one at, leaving out those only this host's own containers, VMs and VPNs can.
package underlay

import (
	"net"
	"net/netip"
	"strings"

	"go4.org/netipx"
	"tailscale.com/net/netmon"
)

// Scan returns the addresses of every up, non-loopback interface: in addrs
// those a device elsewhere might reach this host at, in internal those it
// cannot, which callers use to tell an interface address from a reflexive one.
func Scan() (addrs, internal []netip.Addr) {
	for _, ifc := range Interfaces(Filter{Up: true, NoLoopback: true}) {
		hidden := InternalInterface(ifc.Name)
		for _, p := range ifc.Prefixes {
			if hidden || tailscaleV6.Contains(p.Addr()) {
				internal = append(internal, p.Addr())
			} else {
				addrs = append(addrs, p.Addr())
			}
		}
	}
	return addrs, internal
}

// Filter says which interfaces [Interfaces] lists: Up those up alone,
// NoLoopback none that is loopback, and never the one named Skip.
type Filter struct {
	Up, NoLoopback bool
	Skip           string
}

// Interface is one of the host's interfaces and its addresses, each with its
// network's length.
type Interface struct {
	Name     string
	Prefixes []netip.Prefix
}

// Interfaces lists the host's interfaces f lets through, or none where they
// cannot be read. They are netmon's: net.Interfaces is denied to an Android
// app, which registers its own lister there.
func Interfaces(f Filter) []Interface {
	ifaces, err := netmon.GetInterfaceList()
	if err != nil {
		return nil
	}
	var out []Interface
	for _, ifi := range ifaces {
		if ifi.Interface == nil || ifi.Name == f.Skip ||
			f.Up && ifi.Flags&net.FlagUp == 0 || f.NoLoopback && ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		ifc := Interface{Name: ifi.Name}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if p, ok := netipx.FromStdIPNet(ipn); ok && p.IsValid() {
				ifc.Prefixes = append(ifc.Prefixes, p)
			}
		}
		out = append(out, ifc)
	}
	return out
}

// tailscaleV6 is Tailscale's overlay, named here for hosts whose Tailscale
// interface is not called tailscale0; its IPv4 range is types.CGNAT.
var tailscaleV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

// internalPrefixes name interfaces that lead only into this host: juist's own
// tunnel, other VPNs' tunnels, and the bridges and veth pairs of container and
// VM runtimes.
var internalPrefixes = []string{
	"juist", "tailscale", "zt", "docker", "veth", "virbr", "lxcbr", "lxdbr",
	"podman", "cni", "flannel", "cali", "vnet",
}

// InternalInterface reports whether an interface of that name leads only into
// this host. A bridge such as br0 may hold the host's LAN address and is kept;
// Docker's own bridges are br- and twelve hex digits.
func InternalInterface(name string) bool {
	for _, p := range internalPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	id, ok := strings.CutPrefix(name, "br-")
	return ok && len(id) == 12 && strings.Trim(id, "0123456789abcdef") == ""
}
