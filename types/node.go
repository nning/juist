package types

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// A Role is a capability granted by quorum in the log, never asserted by the
// node itself.
type Role string

// The set is closed: [validateRoles] rejects anything else, so all nodes agree
// on what is authorized. Adding a role is a schema change.
const (
	// RoleAdmin marks an admin device, whose daemon signs freshness leases.
	// It has no authority over membership; that is the admin keys', which the
	// daemon never holds.
	RoleAdmin Role = "admin"

	// RoleRelayCapable marks a node that relays for others.
	RoleRelayCapable Role = "relay-capable"

	// RoleExit permits a default route, carrying members' internet traffic.
	RoleExit Role = "exit"

	// RoleIngress marks a public member that splices connections for
	// published names to their targets, terminating nothing. Never beside
	// admin or exit, so a compromised ingress holds no other authority.
	RoleIngress Role = "ingress"

	// RoleService marks a juistd beside a published service, which every
	// member confines with no port open to it. Alone, and routing nothing.
	RoleService Role = "service"

	// RolePublish lets a member publish under its own name's label without a
	// vote each time. Never beside ingress.
	RolePublish Role = "publish"
)

// NameBytes is the size of n's names and published labels, which
// [MaxNameBytes] caps.
func (n *NodeRecord) NameBytes() int {
	total := 0
	for _, name := range n.Names {
		total += len(name)
	}
	for _, p := range n.Published {
		total += len(p.Label)
	}
	return total
}

// A NodeRecord is a member device. The [Identity] is the member; everything
// else may change without making it another member.
type NodeRecord struct {
	// Identity is the node's Ed25519 identity key; its IPv6 address derives
	// from it ([Addr6]) and is never stored.
	Identity Identity `cbor:"1,keyasint"`

	// Name is a human label; the trust layer never reads it.
	Name string `cbor:"2,keyasint,omitempty"`

	// WireGuard is the static public key the node's overlay addresses are
	// bound to.
	WireGuard WGKey `cbor:"3,keyasint"`

	// X25519 and MLKEM are the node's HPKE recipient key, to which epoch
	// group secrets are sealed.
	X25519 X25519Key `cbor:"4,keyasint"`
	MLKEM  MLKEMKey  `cbor:"5,keyasint"`

	// V4 is an optional overlay IPv4 address inside [V4Ranges], assigned
	// rather than derived.
	V4 *netip.Addr `cbor:"6,keyasint,omitempty"`

	Roles []Role `cbor:"7,keyasint,omitempty"`

	// Routes are the prefixes this node may forward for ([ValidateRoute]).
	Routes []netip.Prefix `cbor:"8,keyasint,omitempty"`

	// Expiry is when the membership goes stale, in Unix seconds; 0 never. A
	// backstop only: revocation is [KindRemoveNode].
	Expiry uint64 `cbor:"9,keyasint,omitempty"`

	// Retiring is the IPv4 address a renumbering moved the node from, still
	// held until the deadline.
	Retiring *RetiringV4 `cbor:"10,keyasint,omitempty"`

	// Names are public DNS names quorum points at this node. Sorted, and held
	// by no other node ([ValidateHostName]).
	Names []string `cbor:"11,keyasint,omitempty"`

	// Published are labels this node publishes under the network's domain,
	// each held by no other node.
	Published []PublishedName `cbor:"12,keyasint,omitempty"`

	// Signing is the node's ML-DSA key.
	Signing *SigningKey `cbor:"13,keyasint,omitempty"`
}

// A RetiringV4 is an overlay IPv4 address a renumbering replaced, live until
// Until, in Unix seconds. No other member may hold it while it is recorded.
type RetiringV4 struct {
	Addr  netip.Addr `cbor:"1,keyasint"`
	Until uint64     `cbor:"2,keyasint"`
}

// Live reports whether the address is still in use at unix time now.
func (r *RetiringV4) Live(now int64) bool { return r != nil && liveUntil(r.Until, now) }

// RetireAtOnce is the deadline of a move that ends the old address at once,
// distinguishable from a transition that ran out.
const RetireAtOnce uint64 = 1

// RetiringRanges are the IPv4 ranges a network renumbering moved away from,
// live until Until, in Unix seconds.
type RetiringRanges struct {
	Prefixes []netip.Prefix `cbor:"1,keyasint"`
	Until    uint64         `cbor:"2,keyasint"`
}

// Live reports whether the ranges are still in use at unix time now.
func (r *RetiringRanges) Live(now int64) bool { return r != nil && liveUntil(r.Until, now) }

func liveUntil(until uint64, now int64) bool { return now < 0 || uint64(now) < until }

// V4Addrs returns the node's overlay IPv4 address and any it is retiring.
func (n *NodeRecord) V4Addrs() []netip.Addr {
	var out []netip.Addr
	if n.V4 != nil {
		out = append(out, *n.V4)
	}
	if n.Retiring != nil {
		out = append(out, n.Retiring.Addr)
	}
	return out
}

func (n *NodeRecord) HasRole(r Role) bool { return slices.Contains(n.Roles, r) }

// Expired reports whether the membership has passed its expiry at unix time
// now. A zero Expiry never expires.
func (n *NodeRecord) Expired(now int64) bool {
	return n.Expiry != 0 && now >= 0 && uint64(now) >= n.Expiry
}

// Clone returns a deep copy.
func (n *NodeRecord) Clone() *NodeRecord {
	out := *n
	if n.V4 != nil {
		v4 := *n.V4
		out.V4 = &v4
	}
	if n.Retiring != nil {
		r := *n.Retiring
		out.Retiring = &r
	}
	out.Roles = slices.Clone(n.Roles)
	out.Routes = slices.Clone(n.Routes)
	out.Names = slices.Clone(n.Names)
	out.Published = slices.Clone(n.Published)
	if n.Signing != nil {
		k := *n.Signing
		out.Signing = &k
	}
	return &out
}

// StaticValidate checks what does not depend on the network; the rest is
// [NodeRecord.ValidateInNetwork].
func (n *NodeRecord) StaticValidate() error {
	if err := n.Identity.Validate(); err != nil {
		return fmt.Errorf("node identity: %w", err)
	}
	if err := ValidateName(n.Name); err != nil {
		return fmt.Errorf("node %v name: %w", n.Identity.ShortString(), err)
	}
	if n.WireGuard.IsZero() {
		return fmt.Errorf("node %v has no WireGuard key", n.Identity.ShortString())
	}
	if n.X25519.IsZero() {
		return fmt.Errorf("node %v has no X25519 key", n.Identity.ShortString())
	}
	if n.MLKEM.IsZero() {
		return fmt.Errorf("node %v has no ML-KEM key", n.Identity.ShortString())
	}
	if n.V4 != nil {
		if err := ValidateV4(*n.V4, v4Choosable); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	if r := n.Retiring; r != nil {
		switch {
		case n.V4 == nil:
			return fmt.Errorf("node %v retires an IPv4 address and holds none", n.Identity.ShortString())
		case r.Addr == *n.V4:
			return fmt.Errorf("node %v retires the address it holds", n.Identity.ShortString())
		case r.Until == 0:
			return fmt.Errorf("node %v retires an address with no deadline", n.Identity.ShortString())
		}
		if err := ValidateV4(r.Addr, v4Choosable); err != nil {
			return fmt.Errorf("node %v retiring: %w", n.Identity.ShortString(), err)
		}
	}
	if err := validateGrant(n.Roles, n.Routes); err != nil {
		return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
	}
	if len(n.Routes) > MaxRoutesPerNode {
		return fmt.Errorf("node %v advertises %d routes, over the %d limit",
			n.Identity.ShortString(), len(n.Routes), MaxRoutesPerNode)
	}
	for i, pfx := range n.Routes {
		if i > 0 && ComparePrefix(n.Routes[i-1], pfx) >= 0 {
			return fmt.Errorf("node %v routes are not sorted and unique at %v",
				n.Identity.ShortString(), pfx)
		}
	}
	if err := validateNames(n.Names); err != nil {
		return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
	}
	if err := validatePublished(n.Published); err != nil {
		return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
	}
	if n.Signing != nil {
		if err := n.Signing.Validate(); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	return n.ValidatePublishing()
}

// ValidateInNetwork checks the node's IPv4 addresses and routes against the
// network's ula and v4 [V4Ranges].
func (n *NodeRecord) ValidateInNetwork(ula netip.Prefix, v4 []netip.Prefix) error {
	if n.V4 != nil {
		if err := ValidateV4(*n.V4, v4); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	if n.Retiring != nil {
		if err := ValidateV4(n.Retiring.Addr, v4); err != nil {
			return fmt.Errorf("node %v retiring: %w", n.Identity.ShortString(), err)
		}
	}
	exit := n.HasRole(RoleExit)
	for _, pfx := range n.Routes {
		if err := ValidateRoute(pfx, ula, v4, exit); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	subnets := n.SubnetRoutes()
	for i := range subnets {
		for _, q := range subnets[i+1:] {
			if subnets[i].Overlaps(q) {
				return fmt.Errorf("node %v: routes %v and %v overlap", n.Identity.ShortString(), subnets[i], q)
			}
		}
	}
	return nil
}

// SubnetRoutes is n's routes without the default ones.
func (n *NodeRecord) SubnetRoutes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range n.Routes {
		if p.Bits() > 0 {
			out = append(out, p)
		}
	}
	return out
}

// validateUnder checks n's names fit [MaxNameBytes] and publishes only under a
// domain.
func (n *NodeRecord) validateUnder(domain string) error {
	if b := n.NameBytes(); b > MaxNameBytes {
		return fmt.Errorf("node %v's names take %d bytes, over the %d limit", n.Identity.ShortString(), b, MaxNameBytes)
	}
	if len(n.Published) > 0 && domain == "" {
		return fmt.Errorf("node %v publishes names, and the network has no domain", n.Identity.ShortString())
	}
	return nil
}

// validateGrant checks roles, and that an ingress routes nothing: its peers
// confine it by its overlay addresses alone.
func validateGrant(roles []Role, routes []netip.Prefix) error {
	if err := validateRoles(roles); err != nil {
		return err
	}
	if slices.Contains(roles, RoleIngress) && len(routes) > 0 {
		return errors.New("an ingress routes nothing")
	}
	if slices.Contains(roles, RoleService) && (len(roles) > 1 || len(routes) > 0) {
		return errors.New("a service member holds no other role and routes nothing")
	}
	return nil
}

var knownRoles = []Role{RoleAdmin, RoleExit, RoleRelayCapable, RoleIngress, RoleService, RolePublish}

func validateRoles(roles []Role) error {
	if len(roles) > MaxRolesPerNode {
		return fmt.Errorf("%d roles, over the %d limit", len(roles), MaxRolesPerNode)
	}
	for i, r := range roles {
		if !slices.Contains(knownRoles, r) {
			return fmt.Errorf("unknown role %q", r)
		}
		if i > 0 && roles[i-1] >= r {
			return fmt.Errorf("roles are not sorted and unique at %q", r)
		}
	}
	if slices.Contains(roles, RoleIngress) && (slices.Contains(roles, RoleAdmin) || slices.Contains(roles, RoleExit)) {
		return errors.New("an ingress is neither a voucher nor an exit node")
	}
	if slices.Contains(roles, RoleIngress) && slices.Contains(roles, RolePublish) {
		return errors.New("an ingress publishes nothing under its own name, whose port it holds")
	}
	return nil
}
