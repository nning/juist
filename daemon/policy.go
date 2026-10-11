package daemon

import (
	"net/netip"
	"slices"

	"go4.org/netipx"
	"tailscale.com/types/ipproto"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// An accessPlan is what one reconcile gives every peer's [conn.Access].
type accessPlan struct {
	view policy.View

	// stale is a view past the freshness TTL under a policy: juist's own
	// traffic alone, with the vouchers it keeps.
	stale bool

	// ingress is what an ingress may open on this device.
	ingress []conn.Ports

	// internet is what this device serves as an exit node, less its subnets;
	// nil where it is none.
	internet []netip.Prefix

	self       types.NodeRecord
	gossipPort uint16
}

func (d *Daemon) accessPlan(s snapshot, stale bool, ingress []conn.Ports) accessPlan {
	self, _ := s.state.Node(d.self)
	ap := accessPlan{view: s.view, stale: stale && s.view.Restricted, ingress: ingress, self: self, gossipPort: d.gossipPort}
	if serves := exitRoutesOf(s.state, self, false); serves != nil {
		var b netipx.IPSetBuilder
		for _, p := range serves {
			b.AddPrefix(p)
		}
		for _, p := range self.SubnetRoutes() {
			b.RemovePrefix(p)
		}
		if set, err := b.IPSet(); err == nil {
			ap.internet = set.Prefixes()
		}
	}
	return ap
}

// access is what peer n may open on this device and this device on it, by
// its role and the policy; nil where it may open anything, as every member
// may without a policy.
func (ap *accessPlan) access(n *types.NodeRecord, ep gossip.Endpoint) *conn.Access {
	if ap.stale {
		return ap.ownOnly(n, ep)
	}
	own := []conn.Ports{{Proto: ipproto.TCP, First: ap.gossipPort, Last: ap.gossipPort}}
	theirs := []conn.Ports{{Proto: ipproto.TCP, First: ep.GossipPort, Last: ep.GossipPort}}
	if !ap.view.Restricted {
		switch {
		case n.HasRole(types.RoleIngress):
			return &conn.Access{Open: ap.ingress, Sends: everything}
		case n.HasRole(types.RoleService):
			return &conn.Access{Sends: everything}
		}
		return nil
	}
	in, out := ap.view.In[n.Identity], ap.view.Out[n.Identity]
	a := &conn.Access{Open: append(ports(in.Own), own...), Sends: append(ports(out.Own), theirs...)}
	if len(in.Exit) > 0 && ap.internet != nil {
		for _, p := range ap.internet {
			a.Through = append(a.Through, conn.Through{Prefix: p, Ports: ports(in.Exit)})
		}
		// Its DNS, which this device answers on its own addresses, at the
		// port it announces and at 53, which it redirects there.
		a.Open = append(a.Open, dnsPorts(53)...)
		a.Open = append(a.Open, dnsPorts(DefaultDNSPort)...)
	}
	if len(out.Exit) > 0 && ep.DNS != 0 {
		a.Sends = append(a.Sends, dnsPorts(ep.DNS)...)
	}
	for _, r := range in.Routes {
		a.Through = append(a.Through, conn.Through{Prefix: r.Prefix, Ports: ports(r.Ports)})
	}
	switch {
	case n.HasRole(types.RoleIngress):
		a.Open, a.Through = ap.ingress, nil
	case n.HasRole(types.RoleService):
		a.Open, a.Through = nil, nil
	}
	if ap.self.HasRole(types.RoleIngress) && (len(n.Published) > 0 || n.HasRole(types.RolePublish)) {
		// What it publishes, which is the ingress's whole purpose; the
		// member keeps the ingress to it.
		a.Sends = everything
	}
	return a
}

// ownOnly keeps peer n, whose announcement is ep, to juist's own traffic:
// log sync, which a service member does not open.
func (ap *accessPlan) ownOnly(n *types.NodeRecord, ep gossip.Endpoint) *conn.Access {
	a := &conn.Access{
		Open:  []conn.Ports{{Proto: ipproto.TCP, First: ap.gossipPort, Last: ap.gossipPort}},
		Sends: []conn.Ports{{Proto: ipproto.TCP, First: ep.GossipPort, Last: ep.GossipPort}},
	}
	if n.HasRole(types.RoleService) {
		a.Open = nil
	}
	return a
}

var everything = []conn.Ports{{}}

// dnsPorts is DNS on port, by UDP and TCP.
func dnsPorts(port uint16) []conn.Ports {
	return []conn.Ports{{Proto: ipproto.UDP, First: port, Last: port}, {Proto: ipproto.TCP, First: port, Last: port}}
}

// ports is a policy's port set as the data plane passes it.
func ports(rs []types.PortRange) []conn.Ports {
	var out []conn.Ports
	for _, r := range rs {
		switch r.Proto {
		case types.ProtoAny:
			return everything
		case types.ProtoICMP:
			out = append(out, conn.Ports{Proto: ipproto.ICMPv4}, conn.Ports{Proto: ipproto.ICMPv6})
		default:
			out = append(out, conn.Ports{Proto: ipproto.Proto(r.Proto), First: r.First, Last: r.Last})
		}
	}
	return out
}

// allowedRoutes is what of a router's subnet pfx the policy lets this device
// reach through it: all of it without a policy.
func allowedRoutes(view policy.View, router types.Identity, pfx netip.Prefix) []netip.Prefix {
	if !view.Restricted {
		return []netip.Prefix{pfx}
	}
	var out []netip.Prefix
	for _, r := range view.Out[router].Routes {
		if pfx.Contains(r.Prefix.Addr()) && r.Prefix.Bits() >= pfx.Bits() {
			out = append(out, r.Prefix)
		}
	}
	// A narrower prefix inside a wider one the policy passes too adds nothing.
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Bits() - b.Bits() })
	var kept []netip.Prefix
	for _, p := range out {
		if !slices.ContainsFunc(kept, func(k netip.Prefix) bool { return k.Contains(p.Addr()) }) {
			kept = append(kept, p)
		}
	}
	return kept
}

// setGossipPeers restricts log sync to the members a policy lets this device
// keep a tunnel with, the vouchers alone where its view is stale; without a
// policy every member, as the data plane decides.
func (d *Daemon) setGossipPeers(view policy.View, stale bool, admit func(types.Identity) bool) {
	var to func(types.Identity) bool
	if view.Restricted {
		to = func(id types.Identity) bool { return view.Peers[id] && (!stale || admit(id)) }
	}
	d.mu.Lock()
	d.gossipTo = to
	d.mu.Unlock()
}

// closeToIngresses narrows what every ingress may open on this device to log
// sync's port, in the peer set last installed.
func (d *Daemon) closeToIngresses() {
	d.mu.Lock()
	peers, ingresses := slices.Clone(d.lastPeers), d.lastIngresses
	d.mu.Unlock()
	for i := range peers {
		if ingresses[peers[i].NodeKey] {
			peers[i].Access = &conn.Access{Open: []conn.Ports{{Proto: ipproto.TCP, First: d.gossipPort, Last: d.gossipPort}},
				Sends: peers[i].Access.Clone().Sends}
		}
	}
	if err := d.manager.SetPeers(peers); err != nil {
		d.logOnce("daemon: closing published ports to the ingresses: " + err.Error())
	}
}

// peerDevices is devs as this device lists them.
func peerDevices(devs []ipc.Device, self types.Identity, view policy.View) []ipc.Device {
	return slices.DeleteFunc(devs, func(d ipc.Device) bool { return !view.Lists(self, d.Identity) })
}
