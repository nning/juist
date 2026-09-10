package conn

import (
	"fmt"
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
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
}

// MaxRegionID is the largest usable relay region. The data plane narrows a
// peer's home region to 16 bits, so a larger one would alias another relay's.
const MaxRegionID = 65535

// derpMap renders relays as the map the data plane consumes. Empty returns
// nil, which is how the engine is told there are no relays at all.
func derpMap(relays []Relay) *tailcfg.DERPMap {
	if len(relays) == 0 {
		return nil
	}
	dm := &tailcfg.DERPMap{
		Regions: make(map[int]*tailcfg.DERPRegion, len(relays)),
		// Nothing would add Tailscale's own regions here, since this map is
		// built whole. Stated because a relay reached through a third party
		// is the thing this design exists to avoid.
		OmitDefaultRegions: true,
	}
	for _, r := range relays {
		reg := &tailcfg.DERPRegion{
			RegionID:   r.Region,
			RegionCode: fmt.Sprintf("j%d", r.Region),
			RegionName: r.HostName,
		}
		for i, ap := range relayDialOrder(r.Addrs) {
			n := &tailcfg.DERPNode{
				Name:     fmt.Sprintf("j%d-%d", r.Region, i),
				RegionID: r.Region,
				HostName: r.HostName,
				CertName: fmt.Sprintf("sha256-raw:%x", r.CertHash),
				DERPPort: int(ap.Port()),
				// Never resolved: HostName is a TLS server name and the
				// addresses come from the announcement. Both families are
				// stated so that the unused one is not looked up in DNS.
				IPv4:     "none",
				IPv6:     "none",
				STUNPort: -1,
			}
			if ap.Addr().Is4() {
				n.IPv4 = ap.Addr().String()
			} else {
				n.IPv6 = ap.Addr().String()
			}
			if r.STUNPort != 0 {
				n.STUNPort = int(r.STUNPort)
			}
			reg.Nodes = append(reg.Nodes, n)
		}
		dm.Regions[r.Region] = reg
	}
	return dm
}

// relayDialOrder puts the addresses a relay is most likely to be reachable at
// first. The data plane tries a region's nodes in order with a short timeout
// each, and a relay-capable member announces every address it holds — so a
// private one, which no other member can reach, would otherwise cost every
// connection the seconds it takes to fail.
func relayDialOrder(addrs []netip.AddrPort) []netip.AddrPort {
	out := slices.Clone(addrs)
	slices.SortStableFunc(out, func(a, b netip.AddrPort) int {
		ap, bp := isPrivateAddr(a.Addr()), isPrivateAddr(b.Addr())
		switch {
		case ap == bp:
			return 0
		case ap:
			return 1
		default:
			return -1
		}
	})
	return out
}

func isPrivateAddr(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback()
}

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
		case len(r.Addrs) == 0:
			return fmt.Errorf("conn: relay region %d has no addresses", r.Region)
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

// sameRelays reports whether two relay sets are identical, so that an
// unchanged one does not make the data plane re-run its latency probes.
func sameRelays(a, b []Relay) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Region != b[i].Region || a[i].HostName != b[i].HostName ||
			a[i].STUNPort != b[i].STUNPort || a[i].CertHash != b[i].CertHash ||
			!slices.Equal(a[i].Addrs, b[i].Addrs) {
			return false
		}
	}
	return true
}
