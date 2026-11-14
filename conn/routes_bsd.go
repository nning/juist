//go:build freebsd || darwin

package conn

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// routeDst is a route message's destination, a single host where it names
// no netmask.
func routeDst(rm *route.RouteMessage) (netip.Prefix, bool) {
	if len(rm.Addrs) <= syscall.RTAX_DST {
		return netip.Prefix{}, false
	}
	var dst netip.Addr
	switch a := rm.Addrs[syscall.RTAX_DST].(type) {
	case *route.Inet4Addr:
		dst = netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		dst = netip.AddrFrom16(a.IP)
	default:
		return netip.Prefix{}, false
	}
	if dst.IsLinkLocalUnicast() || dst.IsMulticast() {
		return netip.Prefix{}, false
	}
	bits := dst.BitLen()
	if rm.Flags&syscall.RTF_HOST == 0 && len(rm.Addrs) > syscall.RTAX_NETMASK {
		switch m := rm.Addrs[syscall.RTAX_NETMASK].(type) {
		case *route.Inet4Addr:
			bits, _ = net.IPMask(m.IP[:]).Size()
		case *route.Inet6Addr:
			bits, _ = net.IPMask(m.IP[:]).Size()
		}
	}
	return netip.PrefixFrom(dst, bits).Masked(), true
}

// hostsOwn reports whether a route of flags is the host's own: none an ICMP
// redirect made or changed, nor one that drops what it takes, nor one the
// kernel cloned for a single neighbour or destination, as macOS keeps them.
func hostsOwn(flags int) bool { return flags&notHostsOwn == 0 }
