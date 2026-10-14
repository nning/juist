package conn

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"tailscale.com/tailcfg"

	"github.com/nning/juist/types"
)

// A Relay is one member-run relay, as the reconciler derived it: the role
// comes from the log, and where it listens from that member's own signed
// announcement.
//
// Region is the relay's network-wide identifier. It must be the same number
// on every member — a peer says which region it can be reached through, and a
// packet sent to another one is dropped — and must fit 16 bits, which is what
// the data plane keeps a peer's home region in.
type Relay struct {
	Region   int
	HostName string

	// Addrs are the relay's DERP endpoints: underlay addresses with the
	// relay's TCP port.
	Addrs []netip.AddrPort

	// STUNPort is where the relay answers binding requests, or zero if it
	// does not. It is a UDP port at each of Addrs' addresses.
	STUNPort uint16

	// CertHash is the SHA-256 of the relay's TLS certificate, which is what
	// authenticates it: the relays are member-run, so there is no authority
	// to ask and the announcement carries the pin.
	CertHash [32]byte

	// Name, where set, is a public DNS name the relay also serves on
	// 443/tcp, resolved in DNS and verified by WebPKI rather than the pin.
	Name string

	// Own says the relay is this device's, which it reaches first at the
	// addresses this host holds: behind a NAT that does not hairpin, its own
	// public address answers it nothing.
	Own bool
}

// HTTPSPort is where a relay's [Relay.Name] is served.
const HTTPSPort = 443

// MaxRegionID is the largest usable relay region. The data plane narrows a
// peer's home region to 16 bits, so a larger one would alias another relay's.
const MaxRegionID = 65535

// stunRegionScore makes a STUN-only region the least preferred home by far:
// the data plane picks its home by latency, and a public STUN server is often
// nearer than any member relay while being nothing to reach a peer through.
const stunRegionScore = 1e6

// derpMap renders relays and STUN servers as the map the data plane consumes,
// and returns the regions the STUN servers took. Nothing at all returns nil,
// which is how the engine is told there are no relays. httpsOnly keeps the
// relays' names on 443 alone, and no STUN server; local orders each relay's
// addresses.
func derpMap(relays []Relay, stun []string, httpsOnly bool, local Networks) (*tailcfg.DERPMap, map[tailcfg.DERPRegionID]bool) {
	stunRegions := map[tailcfg.DERPRegionID]bool{}
	if httpsOnly {
		relays = slices.DeleteFunc(slices.Clone(relays), func(r Relay) bool { return r.Name == "" })
		stun = nil
	}
	if len(relays) == 0 && len(stun) == 0 {
		return nil, stunRegions
	}
	dm := &tailcfg.DERPMap{
		Regions: make(map[tailcfg.DERPRegionID]*tailcfg.DERPRegion, len(relays)),
		// Nothing would add Tailscale's own regions here, since this map is
		// built whole. Stated because a relay reached through a third party
		// is the thing this design exists to avoid.
		OmitDefaultRegions: true,
	}
	for _, r := range relays {
		id := tailcfg.DERPRegionID(r.Region)
		reg := &tailcfg.DERPRegion{
			RegionID:   id,
			RegionCode: fmt.Sprintf("j%d", r.Region),
			RegionName: r.HostName,
		}
		ordered := relayDialOrder(r.Addrs, local)
		if r.Own {
			slices.SortStableFunc(ordered, func(a, b netip.AddrPort) int {
				return boolRank(!local.holds(a.Addr())) - boolRank(!local.holds(b.Addr()))
			})
		}
		public := slices.DeleteFunc(slices.Clone(ordered), func(ap netip.AddrPort) bool { return isPrivateAddr(ap.Addr()) })
		if !httpsOnly {
			reg.Nodes = pinnedNodes(r, ordered, 0)
		}
		if r.Name != "" {
			reg.Nodes = append(reg.Nodes, namedNodes(r, public)...)
		}
		dm.Regions[id] = reg
	}
	// STUN servers take the highest free regions, below which member relays
	// derive theirs; a collision gives the relay the region.
	next := tailcfg.DERPRegionID(MaxRegionID)
	for i, s := range stun {
		hp, err := parseSTUNServer(s)
		if err != nil {
			continue // checked when the manager was built
		}
		for dm.Regions[next] != nil {
			next--
		}
		dm.Regions[next] = &tailcfg.DERPRegion{
			RegionID:   next,
			RegionCode: fmt.Sprintf("stun%d", i),
			RegionName: hp.host,
			Nodes: []*tailcfg.DERPNode{{
				Name:     fmt.Sprintf("stun%d", i),
				RegionID: next,
				HostName: hp.host,
				STUNPort: int(hp.port),
				STUNOnly: true,
			}},
		}
		stunRegions[next] = true
		if dm.HomeParams == nil {
			dm.HomeParams = &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{}}
		}
		dm.HomeParams.RegionScore[next] = stunRegionScore
		next--
	}
	return dm, stunRegions
}

// pinnedNodes are r's nodes at addrs on its own port, its certificate
// pinned, numbered from first.
func pinnedNodes(r Relay, addrs []netip.AddrPort, first int) []*tailcfg.DERPNode {
	var out []*tailcfg.DERPNode
	for i, ap := range addrs {
		n := &tailcfg.DERPNode{
			Name:     fmt.Sprintf("j%d-%d", r.Region, first+i),
			RegionID: tailcfg.DERPRegionID(r.Region),
			HostName: r.HostName,
			CertName: fmt.Sprintf("sha256-raw:%x", r.CertHash),
			DERPPort: int(ap.Port()),
			STUNPort: -1,
		}
		// Never resolved: HostName is a TLS server name and the addresses
		// come from the announcement.
		n.IPv4, n.IPv6 = familyOf(ap.Addr())
		if r.STUNPort != 0 {
			n.STUNPort = int(r.STUNPort)
		}
		out = append(out, n)
	}
	return out
}

// namedNodes are r's name on 443, verified by WebPKI against the system's
// roots, since a public CA issued its certificate: resolved in DNS, then at
// each of public, for where DNS fails, as when an exit node routes it
// through a tunnel not up yet. They come after every address on the relay's
// own port: a member that reaches that uses it, one whose network passes 443
// alone falls back, and netcheck, which sends STUN to a region's first three
// nodes alone, still finds them.
func namedNodes(r Relay, public []netip.AddrPort) []*tailcfg.DERPNode {
	out := []*tailcfg.DERPNode{{
		Name:     fmt.Sprintf("j%d-https", r.Region),
		RegionID: tailcfg.DERPRegionID(r.Region),
		HostName: r.Name,
		DERPPort: HTTPSPort,
		STUNPort: -1,
	}}
	for i, ap := range public {
		n := &tailcfg.DERPNode{
			Name:     fmt.Sprintf("j%d-https%d", r.Region, i),
			RegionID: tailcfg.DERPRegionID(r.Region),
			HostName: r.Name,
			DERPPort: HTTPSPort,
			STUNPort: -1,
		}
		n.IPv4, n.IPv6 = familyOf(ap.Addr())
		out = append(out, n)
	}
	return out
}

// familyOf is a node's IPv4 and IPv6 fields for a, "none" for the other
// family, which would otherwise be looked up in DNS.
func familyOf(a netip.Addr) (v4, v6 string) {
	if a.Is4() {
		return a.String(), "none"
	}
	return "none", a.String()
}

type hostPort struct {
	host string
	port uint16
}

// parseSTUNServer reads a STUN server as host:port.
func parseSTUNServer(s string) (hostPort, error) {
	host, portText, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return hostPort{}, fmt.Errorf("conn: STUN server %q is not host:port", s)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return hostPort{}, fmt.Errorf("conn: STUN server %q has no usable port", s)
	}
	return hostPort{host: host, port: uint16(port)}, nil
}

// relayDialOrder puts the addresses a relay is most likely to be reachable at
// first: where the relay is seen from one of local's public addresses, as
// behind the same router, those on a network of local's, then public ones,
// then the other private ones. The data plane tries a region's nodes in
// order with a short timeout each, and a relay-capable member announces
// every address it holds, so a private one no other member can reach would
// otherwise cost every connection the seconds it takes to fail; and
// netcheck, once it has measured, sends STUN to a region's first node or two
// alone. A private network elsewhere is often numbered as this host's own.
func relayDialOrder(addrs []netip.AddrPort, local Networks) []netip.AddrPort {
	site := slices.ContainsFunc(addrs, func(ap netip.AddrPort) bool { return slices.Contains(local.Public, ap.Addr()) })
	rank := func(a netip.Addr) int {
		switch {
		case site && local.onLink(a):
			return 0
		case !isPrivateAddr(a):
			return 1
		}
		return 2
	}
	out := slices.Clone(addrs)
	slices.SortStableFunc(out, func(a, b netip.AddrPort) int { return rank(a.Addr()) - rank(b.Addr()) })
	return out
}

// Networks are this host's own addresses, with their networks, and the
// public addresses it is seen from.
type Networks struct {
	Prefixes []netip.Prefix
	Public   []netip.Addr
}

func (n Networks) equal(o Networks) bool {
	return slices.Equal(n.Prefixes, o.Prefixes) && slices.Equal(n.Public, o.Public)
}

// holds reports whether a is one of this host's own addresses.
func (n Networks) holds(a netip.Addr) bool {
	return slices.ContainsFunc(n.Prefixes, func(p netip.Prefix) bool { return p.Addr() == a })
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// onLink reports whether a is on one of n's networks and none of n's own
// addresses: another host's on a shared link, never one this host holds,
// as every Docker host holds 172.17.0.1.
func (n Networks) onLink(a netip.Addr) bool {
	in := false
	for _, p := range n.Prefixes {
		if p.Addr() == a {
			return false
		}
		in = in || p.Contains(a) && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast()
	}
	return in
}

// hostNetworks are the networks of this host's interfaces but skip's.
func hostNetworks(skip string) []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, ifc := range ifs {
		if ifc.Name == skip || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					bits, _ := ipn.Mask.Size()
					out = append(out, netip.PrefixFrom(ip.Unmap(), bits))
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

func isPrivateAddr(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback() || unrouted.Contains(a) || sharedV4.Contains(a)
}

// unrouted is IPv6's deprecated site-local range and sharedV4 the carriers'
// shared range, neither routed between networks: netcheck sends STUN to a
// region's first three nodes alone, which such an address would take.
var (
	unrouted = netip.MustParsePrefix("fec0::/10")
	sharedV4 = netip.MustParsePrefix("100.64.0.0/10")
)

// validateRelays checks a relay set before any of it reaches the data plane,
// so a bad one leaves the map as it was.
func validateRelays(relays []Relay) error {
	seen := make(map[int]bool, len(relays))
	for _, r := range relays {
		switch {
		case r.Region <= 0 || r.Region > MaxRegionID:
			return fmt.Errorf("conn: relay region %d is outside 1..%d", r.Region, MaxRegionID)
		case seen[r.Region]:
			return fmt.Errorf("conn: two relays claim region %d", r.Region)
		case r.HostName == "":
			return fmt.Errorf("conn: relay region %d has no host name", r.Region)
		case r.CertHash == [32]byte{}:
			return fmt.Errorf("conn: relay region %d has no certificate hash, so nothing would authenticate it", r.Region)
		case len(r.Addrs) == 0 && r.Name == "":
			return fmt.Errorf("conn: relay region %d has no addresses", r.Region)
		case r.Name != "" && !validRelayName(r.Name):
			return fmt.Errorf("conn: relay region %d has unusable name %q", r.Region, r.Name)
		}
		for _, ap := range r.Addrs {
			if !ap.IsValid() || ap.Port() == 0 || ap.Addr().Is4In6() {
				return fmt.Errorf("conn: relay region %d has unusable address %v", r.Region, ap)
			}
		}
		seen[r.Region] = true
	}
	return nil
}

// validRelayName is a public DNS name, as the announcement already checked;
// here so that nothing else, such as an address, a port or a line break,
// ever reaches a dial or a proxy's CONNECT line.
func validRelayName(name string) bool { return types.ValidateHostName(name) == nil }

// sameRelays reports whether two relay sets are identical, so that an
// unchanged one does not make the data plane re-run its latency probes.
func sameRelays(a, b []Relay) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Region != b[i].Region || a[i].HostName != b[i].HostName ||
			a[i].STUNPort != b[i].STUNPort || a[i].CertHash != b[i].CertHash || a[i].Name != b[i].Name || a[i].Own != b[i].Own ||
			!slices.Equal(a[i].Addrs, b[i].Addrs) {
			return false
		}
	}
	return true
}
