package conn

import (
	"errors"
	"net/netip"
	"slices"

	"go4.org/netipx"
	"tailscale.com/types/key"

	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/types"
)

// specialV4 and specialV6 are the ranges an exit node carries for nobody:
// private, shared, loopback, link-local, multicast, documentation and
// reserved space. Private ranges are a subnet router's to carry (M6b), and an
// exit node carrying them would open its own LAN to every member.
var (
	specialV4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
	globalV6  = netip.MustParsePrefix("2000::/3")
	specialV6 = prefixes("2001:db8::/32")
)

// localSpace is what a client leaves to the host's own routes while it uses
// an exit node: special space, which no exit node carries, private and
// link-local among it, and other overlays such as tailscaled's.
var localSpace = slices.Concat(specialV4, specialV6, prefixes("fc00::/7", "fe80::/10", "ff00::/8"))

// attached is the prefixes of the networks the host's interfaces but skip
// are on, and the host's own addresses in them. Single addresses are no
// network.
func attached(skip string) (nets []netip.Prefix, hosts []netip.Addr) {
	for _, ifc := range underlay.Interfaces(underlay.Filter{NoLoopback: true, Skip: skip}) {
		for _, p := range ifc.Prefixes {
			if !p.IsSingleIP() {
				nets, hosts = append(nets, p.Masked()), append(hosts, p.Addr())
			}
		}
	}
	return nets, hosts
}

// served is what an exit node forwards of routes: all of it but the networks
// it is attached to, where only its own addresses stay, so that it never
// opens its LAN, public addresses or not.
func served(routes, nets []netip.Prefix, hosts []netip.Addr) []netip.Prefix {
	if len(routes) == 0 {
		return nil
	}
	var b netipx.IPSetBuilder
	for _, p := range routes {
		b.AddPrefix(p)
	}
	for _, p := range nets {
		b.RemovePrefix(p)
	}
	for _, h := range hosts {
		if slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Contains(h) }) {
			b.Add(h)
		}
	}
	s, err := b.IPSet()
	if err != nil {
		return nil
	}
	return s.Prefixes()
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Internet is the address space an exit node carries, of the families asked
// for: every public IPv4 address, and global unicast IPv6, without overlay,
// which the caller names and which must never reach an exit node.
func Internet(v4, v6 bool, overlay []netip.Prefix) []netip.Prefix {
	var b netipx.IPSetBuilder
	if v4 {
		b.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
		for _, p := range specialV4 {
			b.RemovePrefix(p)
		}
	}
	if v6 {
		b.AddPrefix(globalV6)
		for _, p := range specialV6 {
			b.RemovePrefix(p)
		}
	}
	for _, p := range overlay {
		b.RemovePrefix(p)
	}
	s, err := b.IPSet()
	if err != nil {
		return nil
	}
	return s.Prefixes()
}

// Egress is where this node sends traffic bound outside the overlay.
type Egress int

const (
	// EgressDirect leaves it to the host's routes.
	EgressDirect Egress = iota
	// EgressTunnel sends it into the tunnel, to the peer whose routes carry
	// it; what no peer carries is refused.
	EgressTunnel
	// EgressRefused refuses it: an exit node is chosen and cannot be used,
	// and the traffic must not leave directly instead.
	EgressRefused
)

func (e Egress) String() string {
	switch e {
	case EgressDirect:
		return "direct"
	case EgressTunnel:
		return "tunnel"
	case EgressRefused:
		return "refused"
	}
	return "egress?"
}

// tunnelled is what the peers carry outside the overlay, which the guard lets
// into the tunnel: the families of an exit node's routes, and the subnets
// routers route. What else goes in is refused at once, not dropped unsaid.
type tunnelled struct {
	v4, v6  bool
	subnets []netip.Prefix
	// answers sends the answers to connections that came in by another
	// device into the tunnel too, isolating the host; else they leave by
	// the way the connection came.
	answers bool
}

func tunnelledBy(peers map[key.NodePublic]Peer) tunnelled {
	var t tunnelled
	for _, p := range peers {
		for _, r := range p.Routes {
			t.v4, t.v6 = t.v4 || r.Addr().Is4(), t.v6 || r.Addr().Is6()
		}
		t.subnets = append(t.subnets, p.Subnets...)
	}
	slices.SortFunc(t.subnets, types.ComparePrefix)
	return t
}

func (t tunnelled) equal(o tunnelled) bool {
	return t.v4 == o.v4 && t.v6 == o.v6 && slices.Equal(t.subnets, o.subnets) && t.answers == o.answers
}

// ErrForwardingOff reports a host that does not forward a family an exit node
// carries, which would drop its peers' traffic without a word.
var ErrForwardingOff = errors.New("IP forwarding is off on this host")

// ErrEgressTaken reports that another network's juistd on this host routes
// the internet already, which would take this one's traffic as well.
var ErrEgressTaken = errors.New("another network on this host uses an exit node")

// Serve is what this node forwards for its peers out of the overlay: Routes,
// the internet it carries as an exit node, less the networks the host is on;
// and Subnets, which it routes as a subnet router. Peers' traffic from
// Sources, the overlay ranges, leaves with this host's own address. Where DNS
// is set, peers' DNS on port 53 of this node's own addresses goes to the
// forwarder on port DNS, which a resolver without ports, as FreeBSD's, needs.
// The zero value forwards nothing.
type Serve struct {
	Routes  []netip.Prefix
	Subnets []netip.Prefix
	Sources []netip.Prefix
	DNS     uint16
}

// serving reports whether s forwards anything.
func (s Serve) serving() bool { return len(s.Routes)+len(s.Subnets) > 0 }

// offTunnel is where traffic may go outside the tunnel while an exit node is
// used: what no exit node carries. A LAN in public space is not among it: a
// network could claim any public prefix for itself, by DHCP or router
// advertisement, and so take it out of the tunnel.
func offTunnel() []netip.Prefix {
	var b netipx.IPSetBuilder
	for _, p := range localSpace {
		b.AddPrefix(p)
	}
	s, _ := b.IPSet()
	return s.Prefixes()
}
