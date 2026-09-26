// Package underlay reads the host addresses another device might reach this
// one at, leaving out those only this host's own containers, VMs and VPNs can.
package underlay

import (
	"net"
	"net/netip"
	"strings"
)

// Scan returns the addresses of every up, non-loopback interface: in addrs
// those a device elsewhere might reach this host at, in internal those it
// cannot, which callers use to tell an interface address from a reflexive one.
func Scan() (addrs, internal []netip.Addr) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifAddrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		hidden := InternalInterface(ifi.Name)
		for _, a := range ifAddrs {
			pfx, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(pfx.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if hidden || tailscaleV6.Contains(ip) {
				internal = append(internal, ip)
			} else {
				addrs = append(addrs, ip)
			}
		}
	}
	return addrs, internal
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
