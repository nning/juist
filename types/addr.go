package types

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// CGNAT is Tailscale's IPv4 range (RFC 6598): tailscaled drops packets from it
// that arrive on any interface but its own, so juist assigns no address there
// unless a network chooses it as its own prefix.
var CGNAT = netip.MustParsePrefix("100.64.0.0/10")

// OverlayV4 is the overlay IPv4 range of a network without a prefix of its
// own: RFC 2544's benchmarking block, which no public network routes and neither LANs nor
// Tailscale use. Unlike the v6 address a v4 one is assigned explicitly in the
// record, since 17 host bits are too few for hash-derived addresses.
var OverlayV4 = netip.MustParsePrefix("198.18.0.0/15")

// v4Choosable are the ranges a network's own IPv4 prefix may lie in.
var v4Choosable = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	CGNAT,
	OverlayV4,
}

// Bounds on a network's own IPv4 prefix length.
const (
	MinV4PrefixBits = 8
	MaxV4PrefixBits = 28
)

// ValidateV4Prefix checks a network's own IPv4 prefix: canonical, private or
// one of juist's ranges, and between [MinV4PrefixBits] and [MaxV4PrefixBits].
func ValidateV4Prefix(p netip.Prefix) error {
	switch {
	case !p.IsValid() || !p.Addr().Is4():
		return fmt.Errorf("IPv4 prefix %v is not an IPv4 prefix", p)
	case p.Masked() != p:
		return fmt.Errorf("IPv4 prefix %v is not masked; did you mean %v?", p, p.Masked())
	case p.Bits() < MinV4PrefixBits || p.Bits() > MaxV4PrefixBits:
		return fmt.Errorf("IPv4 prefix %v must be between /%d and /%d", p, MinV4PrefixBits, MaxV4PrefixBits)
	}
	for _, r := range v4Choosable {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return nil
		}
	}
	return fmt.Errorf("IPv4 prefix %v is not private address space (10/8, 172.16/12, 192.168/16) "+
		"or %v", p, OverlayV4)
}

// V4Range returns the range new overlay IPv4 addresses are assigned from: the
// network's own prefix where it has one, else [OverlayV4].
func V4Range(own *netip.Prefix) netip.Prefix {
	if own != nil {
		return *own
	}
	return OverlayV4
}

// V4Ranges returns every range an overlay IPv4 address may hold.
func V4Ranges(own *netip.Prefix) []netip.Prefix {
	return []netip.Prefix{V4Range(own)}
}

// IsOverlayV4 reports whether a lies in juist's or Tailscale's overlay IPv4
// range, and so is never an underlay address.
func IsOverlayV4(a netip.Addr) bool {
	return CGNAT.Contains(a) || OverlayV4.Contains(a)
}

// Prefixes an advertised route may never cover, on top of the network's own
// overlay space: a grant covering loopback, link-local or multicast would
// point a client's own local traffic at another member's host. The full-tunnel
// case has its own form — the default route plus the exit role.
var forbiddenRoutes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ULA returns the network's overlay IPv6 prefix, a unique-local /48 derived
// from the genesis record's hash, so no coordination is needed to pick a range
// and two networks do not collide. The 40 bits are a labelled hash of the
// genesis hash rather than a slice of it, keeping the address space and the
// chain's hashes independent derivations.
func ULA(genesis Hash) netip.Prefix {
	h := hashLabeled(LabelULA, genesis[:])
	var b [16]byte
	b[0] = 0xfd
	copy(b[1:6], h[:5])
	return netip.PrefixFrom(netip.AddrFrom16(b), 48)
}

// Addr6 returns a node's overlay IPv6 address: the network's [ULA] prefix
// followed by 80 bits derived from the node's identity key. Derived, never
// carried in the record, so no record can claim an address that does not
// follow from its key. It is not a security boundary — cryptokey routing binds
// each address to a 256-bit key — but allocation without coordination, made
// safe by the log's collision check. The genesis hash is mixed in so one key
// in two networks gets two unrelated addresses.
func Addr6(genesis Hash, id Identity) netip.Addr {
	h := hashLabeled(LabelAddr6, genesis[:], id[:])
	prefix := ULA(genesis).Addr().As16()
	var b [16]byte
	copy(b[:6], prefix[:6])
	copy(b[6:], h[:10])
	return netip.AddrFrom16(b)
}

// validateAddrForm rejects address encodings that are not the canonical form
// for the address they denote: netip.Addr can carry a zone, and IPv4 in either
// 4-byte or IPv4-mapped form, which would give one address two encodings.
func validateAddrForm(a netip.Addr) error {
	if !a.IsValid() {
		return errors.New("address is invalid")
	}
	if a.Zone() != "" {
		return fmt.Errorf("address %v carries a zone", a)
	}
	if a.Is4In6() {
		return fmt.Errorf("address %v is IPv4-mapped IPv6; use the 4-byte form", a)
	}
	if a.IsUnspecified() {
		return fmt.Errorf("address %v is unspecified", a)
	}
	return nil
}

// ValidateV4 checks a node's optional explicit overlay IPv4 address against
// the ranges it may lie in.
func ValidateV4(a netip.Addr, ranges []netip.Prefix) error {
	if err := validateAddrForm(a); err != nil {
		return err
	}
	if !a.Is4() {
		return fmt.Errorf("overlay v4 address %v is not IPv4", a)
	}
	for _, r := range ranges {
		if r.Contains(a) {
			return nil
		}
	}
	names := make([]string, len(ranges))
	for i, r := range ranges {
		names[i] = r.String()
	}
	return fmt.Errorf("overlay v4 address %v is outside %s", a, strings.Join(names, " and "))
}

// ValidateRoute checks one advertised prefix from a route grant. ula is the
// network's overlay prefix, v4 its [V4Ranges], and exitNode whether the
// granted node holds the exit role.
//
//   - Canonical form: masked, no zone, no IPv4-mapped-IPv6.
//   - No overlap with the overlay's own space, which is what stops a grant
//     becoming a way to intercept member-to-member traffic.
//   - Nothing in [forbiddenRoutes].
//   - The default route only with the exit role, and exempt from the
//     overlap rules it would otherwise fail by construction; the consumer
//     subtracts the overlay space when rendering AllowedIPs.
func ValidateRoute(pfx netip.Prefix, ula netip.Prefix, v4 []netip.Prefix, exitNode bool) error {
	if !pfx.IsValid() {
		return errors.New("route prefix is invalid")
	}
	if pfx.Addr().Zone() != "" {
		return fmt.Errorf("route %v carries a zone", pfx)
	}
	if pfx.Addr().Is4In6() {
		return fmt.Errorf("route %v is IPv4-mapped IPv6; use the 4-byte form", pfx)
	}
	if pfx.Masked() != pfx {
		return fmt.Errorf("route %v is not masked (host bits set)", pfx)
	}
	if pfx.Bits() == 0 {
		if !exitNode {
			return fmt.Errorf("default route %v requires the %s role", pfx, RoleExit)
		}
		return nil
	}
	if pfx.Addr().IsUnspecified() {
		return fmt.Errorf("route %v starts at the unspecified address", pfx)
	}
	if pfx.Overlaps(ula) {
		return fmt.Errorf("route %v overlaps the overlay prefix %v", pfx, ula)
	}
	for _, r := range v4 {
		if pfx.Overlaps(r) {
			return fmt.Errorf("route %v overlaps the overlay v4 range %v", pfx, r)
		}
	}
	for _, bad := range forbiddenRoutes {
		if pfx.Overlaps(bad) {
			return fmt.Errorf("route %v overlaps reserved prefix %v", pfx, bad)
		}
	}
	for _, other := range overlaySpaces {
		if pfx.Overlaps(other) {
			return fmt.Errorf("route %v overlaps %v, which overlays on a member's host may hold", pfx, other)
		}
	}
	// Any other juist network's overlay prefix is a /48 of fc00::/7.
	if uniqueLocal.Contains(pfx.Addr()) && pfx.Bits() < 48 {
		return fmt.Errorf("route %v spans unique-local /48s, one of which another network's overlay may be", pfx)
	}
	return nil
}

// overlaySpaces are what overlays on a member's host may hold, another juist
// network's or tailscaled's, which a route through a member would take from
// them.
var overlaySpaces = []netip.Prefix{CGNAT, OverlayV4, netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

var uniqueLocal = netip.MustParsePrefix("fc00::/7")

// ComparePrefix orders prefixes by address, then length: the order every
// prefix set in a record is sorted in, so that one set has one encoding.
func ComparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), a.Bits()-b.Bits())
}
