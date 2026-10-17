package plumber

import (
	"net"
	"net/netip"
	"os"
	"strings"
)

// SetDNS has resolvconf(8) take servers as the host's resolvers, and them
// alone, by dev, with search its search domains, or forget dev's.
func (FreeBSD) SetDNS(dev string, servers []netip.Addr, search []string) error {
	if len(servers) == 0 {
		err := runIn("", "/sbin/resolvconf", "-d", dev)
		if err != nil && strings.Contains(err.Error(), "No resolv.conf for ") {
			return nil
		}
		return err
	}
	var b strings.Builder
	for _, s := range servers {
		b.WriteString("nameserver " + s.String() + "\n")
	}
	if len(search) > 0 {
		b.WriteString("search " + strings.Join(search, " ") + "\n")
	}
	// Exclusive: every name goes to the exit node or juistd, as resolved's
	// "~." has it on Linux.
	return runIn(b.String(), "/sbin/resolvconf", "-x", "-a", dev)
}

// ListenDNS binds 53 at a by proto, for the daemon's resolver, which the
// host's resolver asks there.
func (FreeBSD) ListenDNS(a netip.Addr, proto string) (*os.File, error) {
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
