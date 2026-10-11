package daemon

import (
	"cmp"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/internal/dnsfwd"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A NamesServer answers the host's DNS at addr: what answer has a word on,
// the rest from the resolvers upstream names for each query, until closed.
type NamesServer func(addr netip.AddrPort, answer func([]byte) []byte, upstream func([]byte) []netip.AddrPort) (io.Closer, error)

// NamesPort is where juistd answers the host's own DNS, on an overlay
// address of the device's.
const NamesPort = DefaultDNSPort + 1

// namesAddrNow is where juistd's resolver is to answer the host: an address
// the device holds, which resolved, asking a link's servers through the
// link, reaches before systemd 252.20 too; IPv6, which no renumbering moves,
// unless the device holds none, as on a host without IPv6.
func (d *Daemon) namesAddrNow() (netip.AddrPort, error) {
	if d.namesFixed.IsValid() {
		return d.namesFixed, nil
	}
	held := func(netip.Addr) bool { return true }
	if d.tunName != "" {
		ifc, err := net.InterfaceByName(d.tunName)
		if err != nil {
			return netip.AddrPort{}, err
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return netip.AddrPort{}, err
		}
		held = func(a netip.Addr) bool {
			return slices.ContainsFunc(addrs, func(x net.Addr) bool {
				n, ok := x.(*net.IPNet)
				if !ok {
					return false
				}
				h, _ := netip.AddrFromSlice(n.IP)
				return h.Unmap() == a
			})
		}
	}
	if at, ok := namesAddrOf(d.heldAddrs(), held); ok {
		return at, nil
	}
	return netip.AddrPort{}, errors.New("juist's device holds no overlay address yet")
}

// namesAddrOf is the first of addrs held says the device holds on
// [NamesPort]: IPv6 first, then the current IPv4 address before one
// retiring, which addrs lists before it.
func namesAddrOf(addrs []netip.Prefix, held func(netip.Addr) bool) (netip.AddrPort, bool) {
	var v6, v4 []netip.Addr
	for _, p := range addrs {
		if p.Addr().Is6() {
			v6 = append(v6, p.Addr())
		} else {
			v4 = append([]netip.Addr{p.Addr()}, v4...)
		}
	}
	for _, a := range append(v6, v4...) {
		if held(a) {
			return netip.AddrPortFrom(a, NamesPort), true
		}
	}
	return netip.AddrPort{}, false
}

// defaultNamesServer answers the host alone, on the device named dev: what
// comes from the host's own address or the loopback, which nothing through
// the tunnel does, and bound to the device, which the host's own traffic to
// it is taken to come in by, and nothing sent by another's.
func defaultNamesServer(dev string) NamesServer {
	return func(addr netip.AddrPort, answer func([]byte) []byte, upstream func([]byte) []netip.AddrPort) (io.Closer, error) {
		own := func(a netip.Addr) bool { return a == addr.Addr() || a.IsLoopback() }
		// Never the host's resolv.conf, whose stub would route it back here.
		none := func() []netip.AddrPort { return nil }
		return dnsfwd.Start(dnsfwd.Options{Addrs: []netip.Addr{addr.Addr()}, Port: addr.Port(), Device: dev,
			Allowed: own, Local: true, Answer: answer, Upstream: none, UpstreamFor: upstream,
			// A public name newly pointed at a member replaces its public
			// address in the host's cache as soon as its own answers expire.
			MaxTTL: names.TTL})
	}
}

// noZone is the zone of a device that cannot tell who is a member.
var noZone = &names.Zone{}

// A heldOverride is a public name the log points at target, whose name is
// device; published, where the network publishes it under its domain.
type heldOverride struct {
	name      string
	target    types.Identity
	device    string
	published bool
	members   bool // a name for members alone
}

// namesZone is what the host resolves of state's network: each member by its
// name as a DNS label under the network's, and none of a label two members'
// names share, or where the network's name is no label; and, where fresh at
// now, the public names pointed at members, where accepted too, each
// answered while the view stays fresh and its member is reachable. It also
// returns every public name the log holds, and until when the view is fresh.
//
// The network's own domain goes to juistd whole on every member: a name
// published there on port 443, or by TCP on its own port, or shared, is
// resolved to its member where serves says the member serves it, which
// members then reach directly, with the same certificate; the rest goes on
// upstream.
func (d *Daemon) namesZone(state *log.State, view policy.View, fresh log.Freshness, accepted bool, now int64,
	serves func(types.Identity) bool) (*names.Zone, []heldOverride, int64) {
	z := &names.Zone{Members: map[string][]netip.Addr{}, Overrides: map[string]names.Override{}, Public: state.Domain()}
	if network := names.Label(state.Network()); network != "" {
		z.Domain = network + "." + types.NamesTLD
	}
	shared := map[string]bool{}
	var held []heldOverride
	for _, n := range state.Nodes() {
		// A member the policy keeps apart from this device is none of its
		// names: it could not be reached by them.
		if !view.Lists(d.self, n.Identity) {
			continue
		}
		for _, name := range n.Names {
			held = append(held, heldOverride{name: name, target: n.Identity, device: n.Name})
		}
		for _, p := range n.Published {
			// A name for members alone the policy does not name for this
			// device is resolved as by the internet, which reaches nothing.
			mine := !p.Members || n.Identity != d.self && (!view.Restricted ||
				slices.Contains(view.Out[n.Identity].Names, p.Label))
			if reachedDirectly(p) && state.Domain() != "" && serves(n.Identity) && mine {
				held = append(held, heldOverride{name: p.Under(state.Domain()), target: n.Identity, device: n.Name,
					published: true, members: p.Members})
			}
		}
		if name, err := shareName(state, n.Identity); err == nil && d.sharing(n.Identity, time.Unix(now, 0)) {
			held = append(held, heldOverride{name: name, target: n.Identity, device: n.Name, published: true})
		}
		l := names.Label(n.Name)
		if l == "" || z.Domain == "" {
			continue
		}
		if _, dup := z.Members[l]; dup {
			shared[l] = true
		}
		z.Members[l] = memberAddrs(state, n)
	}
	for l := range shared {
		delete(z.Members, l)
	}
	slices.SortFunc(held, func(a, b heldOverride) int { return strings.Compare(a.name, b.name) })
	until := int64(math.MaxInt64)
	if fresh.Enforced() {
		until = fresh.Until
	}
	if !fresh.Fresh(now) {
		return z, held, until
	}
	targets := map[string]heldOverride{}
	for _, h := range held {
		if !accepted && !h.published {
			continue
		}
		n, _ := state.Node(h.target)
		z.Overrides[h.name] = names.Override{Addrs: memberAddrs(state, n), Target: h.target.String()}
		targets[h.target.String()] = h
	}
	z.Up = func(target string) bool {
		h, ok := targets[target]
		return ok && d.overrideNot(h, until) == ""
	}
	return z, held, until
}

// overrideNot is why h is not answered now, the view being fresh until
// then, "" where it is.
func (d *Daemon) overrideNot(h heldOverride, until int64) string {
	switch {
	case d.now().Unix() >= until:
		return "this device's view of the network is stale"
	case h.target == d.self:
		return ""
	}
	if r := d.reachable.Load(); r != nil && (*r)[h.target] {
		return ""
	}
	return cmp.Or(h.device, h.target.ShortString()) + " is not reachable"
}

// memberAddrs are n's overlay addresses, IPv4 first.
func memberAddrs(state *log.State, n types.NodeRecord) []netip.Addr {
	var out []netip.Addr
	if n.V4 != nil {
		out = append(out, *n.V4)
	}
	return append(out, state.Addr6(n.Identity))
}

// UplinkResolvConf is where resolved lists the host's resolvers of every
// link, which its stub would route a query of juist's domains back from.
var UplinkResolvConf = "/run/systemd/resolve/resolv.conf"

// uplinkResolvers are the host's own resolvers, but on the loopback, which
// is resolved's stub or juist's own: what is not answered from the names
// asks them, not the stub, which would route it back.
func uplinkResolvers() []netip.AddrPort {
	b, err := os.ReadFile(UplinkResolvConf)
	if err != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil && !a.Unmap().IsLoopback() {
				out = append(out, netip.AddrPortFrom(a.Unmap(), 53))
			}
		}
	}
	return out
}

// routedDomains are the domains z has a word on, its own first, then the
// network's public domain, each once.
func routedDomains(z *names.Zone) []string {
	if z == nil {
		return nil
	}
	var out []string
	if z.Domain != "" {
		out = append(out, z.Domain)
	}
	if z.Public != "" {
		out = append(out, z.Public)
	}
	var others []string
	for n := range z.Overrides {
		if z.Public != "" && (n == z.Public || strings.HasSuffix(n, "."+z.Public)) {
			continue
		}
		others = append(others, n)
	}
	slices.Sort(others)
	return append(out, others...)
}

// reachedDirectly reports whether members reach p at its member, on the port
// the internet reaches it on: by TLS on 443, or by TCP on its own port. A
// service behind --proxy may want the ingress's header.
func reachedDirectly(p types.PublishedName) bool {
	if p.Public != 0 {
		return p.Public == p.Port && !p.Proxy
	}
	return p.Port == 443 && !p.Proxy
}
