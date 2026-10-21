package types

import (
	"fmt"
	"net/netip"
	"slices"
)

// A NetworkSpace is what a member is admitted to besides the other members:
// the network's genesis, domain and IPv4 ranges.
type NetworkSpace struct {
	Genesis    Hash
	Domain     string
	V4Prefix   *netip.Prefix
	V4Retiring *RetiringRanges
}

// ValidateIn checks n against what [NodeRecord.StaticValidate] cannot know:
// the network and the members but n, which others indexes. It is the one rule
// for a member, whether a record or a whole state brings it.
func (n *NodeRecord) ValidateIn(others *MemberIndex) error {
	sp := &others.space
	ranges := V4Ranges(sp.V4Prefix)
	if sp.V4Retiring != nil {
		ranges = append(ranges, sp.V4Retiring.Prefixes...)
	}
	if err := n.ValidateInNetwork(ULA(sp.Genesis), ranges); err != nil {
		return err
	}
	// Only an address a member is retiring may lie in a retiring range: one
	// it holds there would be left outside the network once it retires.
	if n.V4 != nil && sp.V4Retiring != nil {
		if err := ValidateV4(*n.V4, V4Ranges(sp.V4Prefix)); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	if err := n.validateUnder(sp.Domain); err != nil {
		return err
	}
	if err := n.ValidatePublishing(); err != nil {
		return err
	}
	return others.Check(n)
}

// A MemberIndex holds what a set of members claims — derived and IPv4 overlay
// addresses, and keys — so one more can be checked against all of them.
// Rejecting derived-address collisions deterministically is what makes
// coordination-free allocation safe; a shared key collides where it is used,
// in the data plane for WireGuard and in the epoch fan-out for the others.
type MemberIndex struct {
	space  NetworkSpace
	addr6  map[netip.Addr]Identity
	addr4  map[netip.Addr]Identity
	wg     map[WGKey]Identity
	x25519 map[X25519Key]Identity
	mlkem  map[MLKEMKey]Identity
	routes []routeClaim
	names  map[string]Identity
	labels map[string]Identity

	// public holds each public TCP port's member, and held the ports
	// ingresses' own names go to, which every ingress's public ports bar.
	public map[uint16]Identity
	held   map[uint16]Identity
}

// A routeClaim is a subnet route a member is granted: one member routes each
// address, or two peers would each be sent some of its traffic.
type routeClaim struct {
	prefix netip.Prefix
	by     Identity
}

// NewMemberIndex returns an empty index for a network, sized for n members.
func NewMemberIndex(space NetworkSpace, n int) *MemberIndex {
	return &MemberIndex{
		space:  space,
		addr6:  make(map[netip.Addr]Identity, n),
		addr4:  make(map[netip.Addr]Identity, 2*n),
		wg:     make(map[WGKey]Identity, n),
		x25519: make(map[X25519Key]Identity, n),
		mlkem:  make(map[MLKEMKey]Identity, n),
		names:  map[string]Identity{},
		labels: map[string]Identity{},
		public: map[uint16]Identity{},
		held:   map[uint16]Identity{},
	}
}

// Check reports what n shares with a member added before. It must stay
// symmetric, n refused beside m exactly where m is beside n, or a whole state
// and the records reaching it part ([Snapshot.ValidateInNetwork]).
func (ix *MemberIndex) Check(n *NodeRecord) error {
	id, domain := n.Identity.ShortString(), ix.space.Domain
	if other, dup := ix.wg[n.WireGuard]; dup {
		return fmt.Errorf("nodes %v and %v share a WireGuard key", other.ShortString(), id)
	}
	if other, dup := ix.x25519[n.X25519]; dup {
		return fmt.Errorf("nodes %v and %v share an X25519 key", other.ShortString(), id)
	}
	if other, dup := ix.mlkem[n.MLKEM]; dup {
		return fmt.Errorf("nodes %v and %v share an ML-KEM key", other.ShortString(), id)
	}
	a6 := Addr6(ix.space.Genesis, n.Identity)
	if other, dup := ix.addr6[a6]; dup {
		return fmt.Errorf("nodes %v and %v derive the same overlay address %v", other.ShortString(), id, a6)
	}
	for _, a := range n.V4Addrs() {
		if other, dup := ix.addr4[a]; dup {
			return fmt.Errorf("nodes %v and %v both claim overlay v4 address %v", other.ShortString(), id, a)
		}
	}
	for _, p := range n.SubnetRoutes() {
		if c, ok := ix.overlapping(p); ok {
			return fmt.Errorf("nodes %v and %v both route %v", c.by.ShortString(), id, p.Masked())
		}
	}
	// A name resolves to one member alone.
	for _, name := range n.Names {
		if other, dup := ix.names[name]; dup {
			return fmt.Errorf("nodes %v and %v both answer for %s", other.ShortString(), id, name)
		}
		if label, ok := publishedLabel(name, domain); ok {
			if other, dup := ix.labels[label]; dup {
				return fmt.Errorf("node %v publishes %s, which node %v answers for", other.ShortString(), name, id)
			}
		}
	}
	if l, ok := n.ShareLabel(); ok && n.HasRole(RolePublish) {
		if other, dup := ix.labels[l]; dup {
			return fmt.Errorf("node %v publishes under its name %s, which node %v publishes", id, l, other.ShortString())
		}
		if slices.ContainsFunc(n.Published, func(p PublishedName) bool { return p.Label == l }) {
			return fmt.Errorf("node %v publishes %s, the label its own name gives", id, l)
		}
		if domain != "" {
			name := l + "." + domain
			if other, dup := ix.names[name]; dup || slices.Contains(n.Names, name) {
				if !dup {
					other = n.Identity
				}
				return fmt.Errorf("node %v publishes under its name %s, which node %v answers for", id, name, other.ShortString())
			}
			if len(name) > MaxHostNameLen {
				return fmt.Errorf("node %v publishes under a name of %d bytes, over the %d limit", id, len(name), MaxHostNameLen)
			}
		}
	}
	ingress := n.HasRole(RoleIngress)
	for _, p := range n.Published {
		if other, dup := ix.labels[p.Label]; dup {
			return fmt.Errorf("nodes %v and %v both publish %s", other.ShortString(), id, p.shown())
		}
		if other, dup := ix.public[p.Public]; dup && p.Public != 0 {
			return fmt.Errorf("nodes %v and %v both publish on port %d", other.ShortString(), id, p.Public)
		}
		if other, dup := ix.held[p.Public]; dup && p.Public != 0 {
			return fmt.Errorf("node %v publishes on port %d, where ingress %v serves a name of its own", id, p.Public, other.ShortString())
		}
		if other, dup := ix.public[p.Port]; dup && ingress {
			return fmt.Errorf("node %v is an ingress, which holds port %d for node %v, and publishes %s on it",
				id, p.Port, other.ShortString(), p.shown())
		}
		if domain == "" {
			continue
		}
		name := p.Under(domain)
		if len(name) > MaxHostNameLen {
			return fmt.Errorf("node %v publishes a name of %d bytes, over the %d limit", id, len(name), MaxHostNameLen)
		}
		if other, dup := ix.names[name]; dup || slices.Contains(n.Names, name) {
			if !dup {
				other = n.Identity
			}
			return fmt.Errorf("node %v publishes %s, which node %v answers for", id, name, other.ShortString())
		}
	}
	return nil
}

// overlapping is a claim overlapping p. Claims are disjoint and kept sorted
// by their first address, so only the one starting at or before p and the one
// after it can overlap it.
func (ix *MemberIndex) overlapping(p netip.Prefix) (routeClaim, bool) {
	i, _ := slices.BinarySearchFunc(ix.routes, p.Addr(), func(c routeClaim, a netip.Addr) int {
		return c.prefix.Addr().Compare(a)
	})
	for _, j := range []int{i - 1, i} {
		if j >= 0 && j < len(ix.routes) && ix.routes[j].prefix.Overlaps(p) {
			return ix.routes[j], true
		}
	}
	return routeClaim{}, false
}

// Add records what n claims, unchecked.
func (ix *MemberIndex) Add(n *NodeRecord) {
	ix.wg[n.WireGuard] = n.Identity
	ix.x25519[n.X25519] = n.Identity
	ix.mlkem[n.MLKEM] = n.Identity
	ix.addr6[Addr6(ix.space.Genesis, n.Identity)] = n.Identity
	for _, a := range n.V4Addrs() {
		ix.addr4[a] = n.Identity
	}
	for _, p := range n.SubnetRoutes() {
		i, _ := slices.BinarySearchFunc(ix.routes, p.Addr(), func(c routeClaim, a netip.Addr) int {
			return c.prefix.Addr().Compare(a)
		})
		ix.routes = slices.Insert(ix.routes, i, routeClaim{p, n.Identity})
	}
	for _, name := range n.Names {
		ix.names[name] = n.Identity
	}
	for _, p := range n.Published {
		ix.labels[p.Label] = n.Identity
		if p.Public != 0 {
			ix.public[p.Public] = n.Identity
		}
		if n.HasRole(RoleIngress) {
			ix.held[p.Port] = n.Identity
		}
	}
	if l, ok := n.ShareLabel(); ok && n.HasRole(RolePublish) {
		ix.labels[l] = n.Identity
	}
}
