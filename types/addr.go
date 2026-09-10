package types

import (
	"errors"
	"fmt"
	"net/netip"
)

// CGNAT is the IPv4 range overlay v4 addresses are assigned from (RFC 6598),
// matching Tailscale's choice. Unlike the v6 address it is assigned explicitly
// in the record: 22 host bits is too few for hash-derived addresses to avoid
// birthday collisions.
var CGNAT = netip.MustParsePrefix("100.64.0.0/10")

// Prefixes an advertised route may never cover, on top of the network's own
// overlay space: a grant covering loopback, link-local or multicast would
// point a client's own local traffic at another member's host. The full-tunnel
// case has its own form — the default route plus the exit-node role.
var forbiddenRoutes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
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
	h := hashLabeled(labelULA, genesis[:])
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
	h := hashLabeled(labelAddr6, genesis[:], id[:])
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

// ValidateV4 checks a node's optional explicit overlay IPv4 address.
func ValidateV4(a netip.Addr) error {
	if err := validateAddrForm(a); err != nil {
		return err
	}
	if !a.Is4() {
		return fmt.Errorf("overlay v4 address %v is not IPv4", a)
	}
	if !CGNAT.Contains(a) {
		return fmt.Errorf("overlay v4 address %v is outside %v", a, CGNAT)
	}
	return nil
}

// ValidateRoute checks one advertised prefix from a route grant. ula is the
// network's overlay prefix and exitNode whether the granted node holds the
// exit-node role.
//
//   - Canonical form: masked, no zone, no IPv4-mapped-IPv6.
//   - No overlap with the overlay's own space, which is what stops a grant
//     becoming a way to intercept member-to-member traffic.
//   - Nothing in [forbiddenRoutes].
//   - The default route only with the exit-node role, and exempt from the
//     overlap rules it would otherwise fail by construction; the consumer
//     subtracts the overlay space when rendering AllowedIPs.
func ValidateRoute(pfx netip.Prefix, ula netip.Prefix, exitNode bool) error {
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
			return fmt.Errorf("default route %v requires the %s role", pfx, RoleExitNode)
		}
		return nil
	}
	if pfx.Addr().IsUnspecified() {
		return fmt.Errorf("route %v starts at the unspecified address", pfx)
	}
	if pfx.Overlaps(ula) {
		return fmt.Errorf("route %v overlaps the overlay prefix %v", pfx, ula)
	}
	if pfx.Overlaps(CGNAT) {
		return fmt.Errorf("route %v overlaps the overlay v4 range %v", pfx, CGNAT)
	}
	for _, bad := range forbiddenRoutes {
		if pfx.Overlaps(bad) {
			return fmt.Errorf("route %v overlaps reserved prefix %v", pfx, bad)
		}
	}
	return nil
}

// comparePrefix orders prefixes deterministically: by address family, then
// address, then prefix length. Route sets are sorted by it so that one set has
// one encoding.
func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	switch {
	case a.Bits() < b.Bits():
		return -1
	case a.Bits() > b.Bits():
		return 1
	}
	return 0
}
