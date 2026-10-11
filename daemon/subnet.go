package daemon

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"go4.org/netipx"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// SetSubnetConsent records whether this device's operator agrees to route
// the subnets the log grants it for the network's members.
func (d *Daemon) SetSubnetConsent(on bool) {
	d.mu.Lock()
	d.subnetConsent = on
	d.mu.Unlock()
	d.MarkDirty()
}

// SetSubnetsOff records whether this device's owner turned off routing its
// peers' subnets into the tunnel.
func (d *Daemon) SetSubnetsOff(off bool) {
	d.mu.Lock()
	d.subnetsOff = off
	d.mu.Unlock()
	d.MarkDirty()
}

// A subnetPlan is what one reconcile decides about subnet routes: what this
// device routes for its peers, and the peers' prefixes it sends into the
// tunnel, which no exit node's routes may hold as well.
type subnetPlan struct {
	serve  []netip.Prefix
	taken  []netip.Prefix
	status ipc.Subnets
}

// planSubnets decides this device's subnet routes, and gives each router's
// peer entry the prefixes it routes here: those it was granted, agreed to
// route and can be reached for, less what the host reaches by routes of its
// own inside them, which a route into the tunnel would take away from it. A
// stale view routes none, so that a withdrawn grant ends at the freshness
// TTL.
func (d *Daemon) planSubnets(s snapshot, fresh bool, held map[types.Identity]gossip.Endpoint, peers []conn.Peer,
	named []namedPeer) subnetPlan {
	d.mu.Lock()
	consent, off := d.subnetConsent, d.subnetsOff
	d.mu.Unlock()
	var p subnetPlan
	p.status.Consent, p.status.Off = consent, off

	self, _ := s.state.Node(d.self)
	own := self.SubnetRoutes()
	for _, pfx := range own {
		p.status.Routes = append(p.status.Routes, ipc.SubnetRoute{Prefix: pfx, Router: d.self, Name: self.Name})
	}
	if consent {
		// Without overlay IPv4 no peer's IPv4 reaches it from a source it
		// accepts.
		carried := own
		if d.noV4.Load() {
			carried = slices.DeleteFunc(slices.Clone(own), func(p netip.Prefix) bool { return p.Addr().Is4() })
		}
		switch {
		case len(own) == 0:
			p.status.NotServing = "the network routes no subnet through this device"
		case !fresh:
			p.status.NotServing = "this device's view of the network is stale"
		case len(carried) == 0:
			p.status.NotServing = "this device has no IPv4 in the network"
		default:
			p.serve = carried
		}
	}

	// Only where a member routes some subnet: the host's routes may be a
	// full table.
	var host []netip.Prefix
	if !off && slices.ContainsFunc(s.members, func(n types.NodeRecord) bool {
		return n.Identity != d.self && len(n.SubnetRoutes()) > 0
	}) {
		host = d.manager.HostRoutes()
	}
	for _, n := range s.members {
		if n.Identity == d.self || !s.live[n.Identity] {
			continue
		}
		i := slices.IndexFunc(named, func(np namedPeer) bool { return np.id == n.Identity })
		var carried []netip.Prefix
		for _, pfx := range n.SubnetRoutes() {
			r := ipc.SubnetRoute{Prefix: pfx, Router: n.Identity, Name: n.Name}
			parts := allowedRoutes(s.view, n.Identity, pfx)
			switch {
			case off:
				r.Why = "subnets are off on this device"
			case !fresh:
				r.Why = "this device's view of the network is stale"
			case pfx.Addr().Is4() && d.noV4.Load():
				r.Why = "this device has no IPv4 in the network"
			case i < 0:
				r.Why = "its router cannot be reached"
			case pfx.Addr().Is4() && held[n.Identity].NoV4:
				r.Why = "its router has no IPv4 in the network"
			case !held[n.Identity].Subnets:
				r.Why = "its router's operator has not agreed to route it"
			case notPQ(s.state, named[i].stage):
				r.Why = "its router " + errNotPQ
			case len(parts) == 0:
				r.Why = "the access policy passes none of it to this device"
			default:
				var left, kept, wider []netip.Prefix
				for _, part := range parts {
					l, k, w := without(part, host)
					left, kept, wider = append(left, l...), append(kept, k...), append(wider, w...)
				}
				switch {
				case len(left) == 0:
					r.Why = "this device reaches it by a route of its own"
				case len(kept) > 0:
					r.InUse, r.Why = true, "but for "+joinPrefixes(kept)+", which this device reaches by a route of its own"
				case len(wider) > 0:
					r.InUse, r.Why = true, "taken from this device's own route to "+joinPrefixes(wider)
				default:
					r.InUse = true
				}
				if r.InUse && (len(parts) != 1 || parts[0] != pfx) {
					r.Why = strings.TrimPrefix(r.Why+"; ", "; ") + "the access policy passes " + joinPrefixes(parts) + " alone"
				}
				carried = append(carried, left...)
			}
			p.status.Routes = append(p.status.Routes, r)
		}
		if len(carried) > 0 {
			peers[slices.IndexFunc(peers, func(pe conn.Peer) bool { return pe.NodeKey == named[i].peer.NodeKey })].Subnets = carried
			p.taken = append(p.taken, carried...)
		}
	}
	slices.SortFunc(p.status.Routes, func(x, y ipc.SubnetRoute) int {
		return cmp.Or(x.Prefix.Addr().Compare(y.Prefix.Addr()), x.Prefix.Bits()-y.Prefix.Bits())
	})
	return p
}

// without is pfx less what host routes of it, what of pfx they do, and the
// wider host routes holding it. Only a route inside pfx counts: a wider one,
// as a DHCP server's /8 netmask or a router advertisement's short prefix
// would give, takes no subnet away.
func without(pfx netip.Prefix, host []netip.Prefix) (left, kept, wider []netip.Prefix) {
	var b netipx.IPSetBuilder
	b.AddPrefix(pfx)
	for _, h := range host {
		switch {
		case pfx.Contains(h.Addr()) && h.Bits() >= pfx.Bits():
			b.RemovePrefix(h)
		case h.Contains(pfx.Addr()) && !slices.Contains(wider, h):
			// An interface's network is listed by its route too.
			wider = append(wider, h)
		}
	}
	l, _ := b.IPSet()
	var k netipx.IPSetBuilder
	k.AddPrefix(pfx)
	if l != nil {
		k.RemoveSet(l)
	}
	ks, _ := k.IPSet()
	return l.Prefixes(), ks.Prefixes(), wider
}

func joinPrefixes(ps []netip.Prefix) string {
	s := ""
	for i, p := range ps {
		if i > 0 {
			s += ", "
		}
		s += p.String()
	}
	return s
}

// lessTaken is routes without what the subnet routes send elsewhere.
func lessTaken(routes, taken []netip.Prefix) []netip.Prefix {
	if len(taken) == 0 {
		return routes
	}
	var b netipx.IPSetBuilder
	for _, r := range routes {
		b.AddPrefix(r)
	}
	for _, t := range taken {
		b.RemovePrefix(t)
	}
	s, _ := b.IPSet()
	return s.Prefixes()
}

// subnetsNow is a copy of what the last reconcile made of subnet routes, nil
// where there are none, and nothing is agreed or turned off.
func (d *Daemon) subnetsNow() *ipc.Subnets {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.subnetStatus
	if len(s.Routes) == 0 && !s.Consent && !s.Off {
		return nil
	}
	s.Routes = slices.Clone(s.Routes)
	s.Serving = slices.Clone(s.Serving)
	return &s
}
