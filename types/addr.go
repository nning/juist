package types

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// CGNAT is Tailscale's IPv4 range (RFC 6598). tailscaled drops packets from it
// arriving on other interfaces, so juist uses it only if a network chooses it.
var CGNAT = netip.MustParsePrefix("100.64.0.0/10")

// OverlayV4 is the default overlay IPv4 range (RFC 2544 benchmarking, unused
// by LANs and Tailscale). v4 addresses are assigned in the record, not
// derived: 17 host bits are too few to hash into.
var OverlayV4 = netip.MustParsePrefix("198.18.0.0/15")

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

// V4Range returns the range new overlay IPv4 addresses come from: own, or
// [OverlayV4] if nil.
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

// forbiddenRoutes may never be granted: they would send a client's own local
// traffic to another member's host.
var forbiddenRoutes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ULA returns the network's overlay IPv6 prefix, a unique-local /48 from a
// labelled hash of the genesis hash.
func ULA(genesis Hash) netip.Prefix {
	h := hashLabeled(LabelULA, genesis[:])
	var b [16]byte
	b[0] = 0xfd
	copy(b[1:6], h[:5])
	return netip.PrefixFrom(netip.AddrFrom16(b), 48)
}

// Addr6 returns a node's overlay IPv6 address: [ULA] plus 80 bits hashed from
// the genesis hash and identity. Never carried in a record, so none can claim
// an address its key does not yield. Not a security boundary; the log checks
// collisions.
func Addr6(genesis Hash, id Identity) netip.Addr {
	h := hashLabeled(LabelAddr6, genesis[:], id[:])
	prefix := ULA(genesis).Addr().As16()
	var b [16]byte
	copy(b[:6], prefix[:6])
	copy(b[6:], h[:10])
	return netip.AddrFrom16(b)
}

// ResolverAddr is ula::53, where a device answering its host's DNS in the
// tunnel (the Android app) takes lookups. An [Addr6] hits it only after about
// 2^80 keys.
func ResolverAddr(ula netip.Prefix) netip.Addr {
	b := ula.Masked().Addr().As16()
	b[15] = 0x53
	return netip.AddrFrom16(b)
}

// validateAddrForm rejects zones and IPv4-mapped IPv6, which would give one
// address two encodings.
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

// ValidateV4 checks an overlay IPv4 address lies in ranges.
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

// ValidateRoute checks one granted prefix: canonical, and clear of the overlay
// (ula, v4 [V4Ranges]) so no grant intercepts member traffic, and of reserved
// and foreign-overlay space. The default route needs exitNode and skips the
// overlap checks; consumers must subtract the overlay from AllowedIPs.
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

// overlaySpaces are other overlays (juist, tailscaled) a member's host may
// run; a route over them would hijack their traffic.
var overlaySpaces = []netip.Prefix{CGNAT, OverlayV4, netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

var uniqueLocal = netip.MustParsePrefix("fc00::/7")

// ComparePrefix orders prefixes by address, then length: the canonical order
// of every prefix set in a record.
func ComparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), a.Bits()-b.Bits())
}
