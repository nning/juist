package policy

import (
	"net/netip"
	"slices"

	"github.com/nning/juist/types"
)

// A Member is what a policy's meaning depends on of a member.
type Member struct {
	ID types.Identity

	// Exit is whether it may serve the internet, by its role.
	Exit bool

	// Subnets are the routes it may serve.
	Subnets []netip.Prefix

	// Carrier is whether it carries the log to every member: a relay or a
	// voucher.
	Carrier bool

	// Service is whether it is a service member, which opens nothing.
	Service bool

	// Ingress is whether it is an ingress, and Publishes whether the ingress
	// passes it connections.
	Ingress, Publishes bool

	// Addrs are its overlay addresses.
	Addrs []netip.Addr

	// Names are the names it publishes by TLS.
	Names []Name
}

// A Name is a name published by TLS: its label under the network's domain,
// "" for the domain itself, its port, and whether it is for members alone.
type Name struct {
	Label   string
	Port    uint16
	Members bool
}

// A Network is what a policy is evaluated against: the policy, nil for
// none, and the live members.
type Network struct {
	Policy  *types.Policy
	Members []Member
}

// Access is what one member may open on another: on its own addresses, to
// the internet through it, and to its subnets. A nil port set is nothing; a
// set holding the zero [types.PortRange] is everything.
type Access struct {
	Own    []types.PortRange
	Exit   []types.PortRange
	Routes []Route
	// Names are the labels of the names it may open there, as TLS asks for
	// them, sorted.
	Names []string
	// Multicast is the UDP ports it may send group datagrams to the other
	// on.
	Multicast []types.PortRange
}

// A Route is ports on a prefix behind a subnet router.
type Route struct {
	Prefix netip.Prefix
	Ports  []types.PortRange
}

// Empty reports whether a grants nothing.
func (a Access) Empty() bool {
	return len(a.Own) == 0 && len(a.Exit) == 0 && len(a.Routes) == 0 && len(a.Names) == 0 && len(a.Multicast) == 0
}

// Everything is the port set that is every protocol and port.
var Everything = []types.PortRange{{}}

// A View is what a policy means for one member.
type View struct {
	// Restricted is false where the network has no policy, and nothing below
	// applies: every member peers every other and opens anything on it.
	Restricted bool

	// Out is what this member may open on each other, In what each may
	// open on this one. Members granted nothing either way are absent.
	Out, In map[types.Identity]Access

	// Peers are the members this one keeps a tunnel with, Control those of
	// them that pass juist's own traffic alone, granted nothing either way.
	Peers, Control map[types.Identity]bool
}

// Lists reports whether a member whose view v is lists, and resolves by
// name, the member id: itself and its peers, every member without a policy.
func (v View) Lists(self, id types.Identity) bool { return !v.Restricted || id == self || v.Peers[id] }

// View evaluates the policy for self.
func (n *Network) View(self types.Identity) View {
	v := View{
		Restricted: n.Policy != nil,
		Out:        map[types.Identity]Access{},
		In:         map[types.Identity]Access{},
		Peers:      map[types.Identity]bool{},
		Control:    map[types.Identity]bool{},
	}
	if !v.Restricted {
		for _, m := range n.Members {
			if m.ID != self {
				v.Peers[m.ID] = true
			}
		}
		return v
	}
	c := n.compile()
	me, ok := c.byID[self]
	if !ok {
		return v
	}
	for _, r := range c.rules {
		if r.from[self] && !me.Service {
			for _, m := range n.Members {
				if m.ID != self {
					v.Out[m.ID] = merge(v.Out[m.ID], r.grant(m))
				}
			}
		}
		g := r.grant(*me)
		if g.Empty() {
			continue
		}
		for _, m := range n.Members {
			if m.ID != self && r.from[m.ID] && !m.Service {
				v.In[m.ID] = merge(v.In[m.ID], g)
			}
		}
	}
	for id, a := range v.Out {
		if a.Empty() {
			delete(v.Out, id)
		}
	}
	carriers := slices.ContainsFunc(n.Members, func(m Member) bool { return m.Carrier })
	for _, m := range n.Members {
		if m.ID == self {
			continue
		}
		_, out := v.Out[m.ID]
		_, in := v.In[m.ID]
		published := me.Ingress && m.Publishes || m.Ingress && me.Publishes
		switch {
		case out || in || published:
			v.Peers[m.ID] = true
		case !carriers || me.Carrier || m.Carrier:
			v.Peers[m.ID] = true
			v.Control[m.ID] = true
		}
	}
	return v
}

type compiled struct {
	byID  map[types.Identity]*Member
	rules []compiledRule
}

type compiledRule struct {
	from, to map[types.Identity]bool
	internet bool
	via      map[types.Identity]bool // nil: every exit node
	prefixes []netip.Prefix
	ports    []types.PortRange
	names    []string
	// multicast passes group datagrams on ports and nothing else.
	multicast bool
}

func (n *Network) compile() *compiled {
	c := &compiled{byID: map[types.Identity]*Member{}}
	for i := range n.Members {
		c.byID[n.Members[i].ID] = &n.Members[i]
	}
	tables := map[string]*types.PolicyTable{}
	for i := range n.Policy.Tables {
		tables[n.Policy.Tables[i].Name] = &n.Policy.Tables[i]
	}
	services := map[string][]types.PortRange{}
	for _, s := range n.Policy.Services {
		services[s.Name] = s.Ports
	}
	expand := func(any bool, nodes []types.Identity, names []string) map[types.Identity]bool {
		set := map[types.Identity]bool{}
		if any {
			for id := range c.byID {
				set[id] = true
			}
		}
		for _, id := range nodes {
			set[id] = true
		}
		seen := map[string]bool{}
		var walk func(string)
		walk = func(name string) {
			t := tables[name]
			if t == nil || seen[name] {
				return
			}
			seen[name] = true
			for _, id := range t.Nodes {
				set[id] = true
			}
			for _, inner := range t.Tables {
				walk(inner)
			}
		}
		for _, name := range names {
			walk(name)
		}
		return set
	}
	for _, r := range n.Policy.Rules {
		cr := compiledRule{
			from:     expand(r.From.Any, r.From.Nodes, r.From.Tables),
			to:       expand(r.To.Any, r.To.Nodes, r.To.Tables),
			internet: r.To.Internet,
			prefixes: r.To.Prefixes,
			ports:    slices.Clone(r.Ports),
			names:    r.To.Names,

			multicast: r.Multicast,
		}
		if len(r.To.ViaNodes)+len(r.To.ViaTables) > 0 {
			cr.via = expand(false, r.To.ViaNodes, r.To.ViaTables)
		}
		for _, s := range r.Services {
			cr.ports = append(cr.ports, services[s]...)
		}
		switch {
		case r.Multicast && len(r.Ports) == 0:
			cr.ports = []types.PortRange{{Proto: types.ProtoUDP}}
		case len(r.Ports)+len(r.Services) == 0:
			cr.ports = Everything
		}
		cr.ports = normalize(cr.ports)
		c.rules = append(c.rules, cr)
	}
	return c
}

// grant is what r lets its sources open on m.
func (r *compiledRule) grant(m Member) Access {
	var a Access
	if r.multicast {
		if r.to[m.ID] {
			a.Multicast = r.ports
		}
		return a
	}
	if r.to[m.ID] {
		a.Own = r.ports
	}
	if r.internet && m.Exit && (r.via == nil || r.via[m.ID]) {
		a.Exit = r.ports
	}
	for _, n := range m.Names {
		if slices.Contains(r.names, n.Label) {
			a.Own = normalize(append(slices.Clone(a.Own),
				types.PortRange{Proto: types.ProtoTCP, First: n.Port, Last: n.Port},
				types.PortRange{Proto: types.ProtoUDP, First: n.Port, Last: n.Port}))
			a.Names = append(a.Names, n.Label)
		}
	}
	for _, p := range r.prefixes {
		for _, s := range m.Subnets {
			if in, ok := intersect(p, s); ok {
				a.Routes = append(a.Routes, Route{Prefix: in, Ports: r.ports})
			}
		}
	}
	return a
}

// intersect is the smaller of two prefixes where one holds the other.
func intersect(a, b netip.Prefix) (netip.Prefix, bool) {
	switch {
	case a.Addr().Is4() != b.Addr().Is4():
		return netip.Prefix{}, false
	case a.Bits() >= b.Bits() && b.Contains(a.Addr()):
		return a, true
	case b.Bits() > a.Bits() && a.Contains(b.Addr()):
		return b, true
	}
	return netip.Prefix{}, false
}

func merge(a, b Access) Access {
	if len(b.Names) > 0 {
		a.Names = slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(a.Names), b.Names...))))
	}
	a.Own = normalize(append(slices.Clone(a.Own), b.Own...))
	a.Multicast = normalize(append(slices.Clone(a.Multicast), b.Multicast...))
	a.Exit = normalize(append(slices.Clone(a.Exit), b.Exit...))
	for _, r := range b.Routes {
		i := slices.IndexFunc(a.Routes, func(x Route) bool { return x.Prefix == r.Prefix })
		if i < 0 {
			a.Routes = append(a.Routes, Route{Prefix: r.Prefix, Ports: r.Ports})
			continue
		}
		a.Routes = slices.Clone(a.Routes)
		a.Routes[i].Ports = normalize(append(slices.Clone(a.Routes[i].Ports), r.Ports...))
	}
	slices.SortFunc(a.Routes, func(x, y Route) int { return types.ComparePrefix(x.Prefix, y.Prefix) })
	return a
}

// normalize sorts ports and merges what overlaps or touches; everything
// takes in every other range, and a protocol's every port, which sorts
// first, its ranges.
func normalize(ports []types.PortRange) []types.PortRange {
	if len(ports) == 0 {
		return nil
	}
	if slices.Contains(ports, types.PortRange{}) {
		return Everything
	}
	sorted := slices.SortedFunc(slices.Values(ports), types.ComparePorts)
	var out []types.PortRange
	for _, p := range sorted {
		if n := len(out); n > 0 && out[n-1].Proto == p.Proto {
			last := &out[n-1]
			if last.First == 0 {
				continue
			}
			if int(p.First) <= int(last.Last)+1 {
				last.Last = max(last.Last, p.Last)
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// Allows reports whether ports pass proto on port, or anything of proto
// where port is zero.
func Allows(ports []types.PortRange, proto uint8, port uint16) bool {
	for _, p := range ports {
		switch {
		case p.Proto == types.ProtoAny:
			return true
		case p.Proto != proto:
		case p.First == 0 || port == 0 || p.First <= port && port <= p.Last:
			return true
		}
	}
	return false
}
