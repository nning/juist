package daemon

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/dnsfwd"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/resolved"
	"github.com/nning/juist/ipc"
)

// DefaultDNSPort is where an exit node's forwarder answers its members' DNS,
// on its overlay addresses alone: UDP and TCP. Members ask it on
// dnsAskedPort, which the data plane redirects there, as a resolver that
// takes no port, FreeBSD's, needs.
const (
	DefaultDNSPort = 41646
	dnsAskedPort   = 53
)

// dnsRenewal is how often a host's DNS routing is given again, which a
// restarted resolved forgets.
const dnsRenewal = 5 * time.Minute

// A DNSRouting is what the host's DNS asks by this node's device: Servers,
// for Domains, with Search tried for single names too, and for every name
// the host does not route elsewhere by a longer domain where Everything.
type DNSRouting struct {
	Servers    []netip.AddrPort
	Domains    []string
	Search     []string
	Everything bool
}

func (r DNSRouting) empty() bool { return len(r.Servers) == 0 }

func (r DNSRouting) equal(o DNSRouting) bool {
	return slices.Equal(r.Servers, o.Servers) && slices.Equal(r.Domains, o.Domains) &&
		slices.Equal(r.Search, o.Search) && r.Everything == o.Everything
}

// dnsOffWhy is why juistd leaves the host's DNS alone, as its owner said.
const dnsOffWhy = "DNS is off on this device"

// errNoDomains is a host resolver that routes no domains, only every name.
var errNoDomains = errors.New("this host's resolver routes no domains")

// A HostDNS routes the host's DNS through this node's device as a routing
// says, or gives it back.
type HostDNS interface {
	Route(r DNSRouting) error
	Revert() error
}

// A DNSServer answers members' DNS on addrs, from sources allowed admits,
// until closed.
type DNSServer func(addrs []netip.Addr, allowed func(netip.Addr) bool) (io.Closer, error)

// resolvedDNS is systemd-resolved's routing for the device named dev.
type resolvedDNS struct{ dev string }

func (r resolvedDNS) link() (int, *resolved.Client, error) {
	ifc, err := net.InterfaceByName(r.dev)
	if err != nil {
		return 0, nil, err
	}
	c, err := resolved.Dial()
	return ifc.Index, c, err
}

func (r resolvedDNS) Route(rt DNSRouting) error {
	i, c, err := r.link()
	if err != nil {
		return err
	}
	defer c.Close()
	var domains []resolved.Domain
	for _, s := range rt.Search {
		domains = append(domains, resolved.Domain{Name: s, Search: true})
	}
	for _, d := range rt.Domains {
		if !slices.Contains(rt.Search, d) {
			domains = append(domains, resolved.Domain{Name: d})
		}
	}
	return c.Configure(i, rt.Servers, domains, rt.Everything)
}

// routesDomains says resolved routes domains to a link, as juist's names need.
func (resolvedDNS) routesDomains() bool { return true }

// routing is how resolved routes names to every link but this one.
func (r resolvedDNS) routing() (resolved.Routing, error) {
	i, c, err := r.link()
	if err != nil {
		return resolved.Routing{}, err
	}
	defer c.Close()
	return c.Routing(i)
}

func (r resolvedDNS) Revert() error {
	i, c, err := r.link()
	if errors.Is(err, resolved.ErrNotRunning) {
		return nil
	}
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Revert(i)
}

// plumbedDNS is the host's DNS through resolvconf(8), by the helper that
// plumbs the device named dev, as on FreeBSD, whose resolver takes no port.
type plumbedDNS struct {
	p   conn.Plumber
	dev string
}

func (r plumbedDNS) Route(rt DNSRouting) error {
	if !rt.Everything {
		return errNoDomains
	}
	var addrs []netip.Addr
	for _, s := range rt.Servers {
		if s.Port() != 53 {
			return fmt.Errorf("the exit node answers DNS on port %d, which this host's resolver cannot ask", s.Port())
		}
		addrs = append(addrs, s.Addr())
	}
	return r.p.SetDNS(r.dev, addrs, rt.Search)
}

func (r plumbedDNS) Revert() error { return r.p.SetDNS(r.dev, nil, nil) }

// VPNDNS is the host's DNS through a VPN device's own servers, as Android's
// VpnService sets them, which every program's lookups then go to.
func VPNDNS(p conn.Plumber, dev string) HostDNS { return vpnDNS{plumbedDNS{p: p, dev: dev}} }

type vpnDNS struct{ plumbedDNS }

func (vpnDNS) through(string, []netip.AddrPort) (bool, string) { return true, "" }

// through reports whether the host's programs ask servers, whose resolver
// resolvconf wrote.
func (r plumbedDNS) through(path string, servers []netip.AddrPort) (bool, string) {
	return asksOnly(path, servers, "the exit node")
}

// defaultDNSServer answers on the device named dev. A name this device's own
// zone overrides it asks the host's resolvers of, not its stub, which would
// answer the override to members that did not agree to it.
func (d *Daemon) defaultDNSServer(dev string) DNSServer {
	return func(addrs []netip.Addr, allowed func(netip.Addr) bool) (io.Closer, error) {
		return dnsfwd.Start(dnsfwd.Options{Addrs: addrs, Port: DefaultDNSPort, Device: dev, Allowed: allowed,
			UpstreamFor: d.membersUpstreamFor})
	}
}

// membersUpstreamFor is who a member's query q is asked of: the host's
// resolvers resolved would ask where this device's zone overrides its name
// and the host's resolver asks juist's, and [Daemon.uplinkFor] otherwise,
// which know no override.
func (d *Daemon) membersUpstreamFor(q []byte) []netip.AddrPort {
	if z := d.zone.Load(); z != nil && d.namesRouted.Load() && z.Overridden(q) {
		return d.hostUpstreamFor(q)
	}
	return d.uplinkFor(q)
}

// tailscaledResolvers answer from the host's tailnet, whose addresses a
// member reaching the internet through this exit node cannot reach.
var tailscaledResolvers = []netip.Addr{netip.MustParseAddr("100.100.100.100"), netip.MustParseAddr("fd7a:115c:a1e0::53")}

// PreTailscaleResolvConf is the host's resolv.conf as tailscaled found it
// before writing its own.
var PreTailscaleResolvConf = "/etc/resolv.pre-tailscale-backup.conf"

// uplinkFor is who a member's query q is asked of where no override is
// answered: those the host asks, by resolved's routing where resolv.conf
// names its stub alone, its own where it asks juistd alone, but never
// tailscaled's resolvers; nil, the forwarder's own, where they are all there
// is.
func (d *Daemon) uplinkFor(q []byte) []netip.AddrPort {
	if s, ok := d.hostDNS.(soleResolver); ok {
		// Never resolv.conf, which names juistd's own resolver.
		return d.soleUpstream(s)
	}
	ups := dnsfwd.HostResolvers()
	stubOnly := len(ups) > 0 && !slices.ContainsFunc(ups, func(a netip.AddrPort) bool { return !a.Addr().IsLoopback() })
	if r := d.hostRouting.Load(); r != nil && stubOnly {
		if name, ok := names.Question(q); ok {
			ups = withoutTailscaled(r.Servers(name))
			if len(ups) == 0 {
				for _, s := range r.Scopes {
					if s.DefaultRoute {
						ups = append(ups, withoutTailscaled(s.Servers)...)
					}
				}
			}
		}
	} else if ups = withoutTailscaled(ups); len(ups) == 0 {
		ups = withoutTailscaled(dnsfwd.ResolversIn(PreTailscaleResolvConf))
	}
	if len(ups) == 0 {
		return nil
	}
	return ups
}

func withoutTailscaled(ups []netip.AddrPort) []netip.AddrPort {
	return slices.DeleteFunc(slices.Clone(ups), func(a netip.AddrPort) bool { return slices.Contains(tailscaledResolvers, a.Addr()) })
}

// namesUpstreamFor is who juistd's resolver asks q of, what it does not
// answer itself: the exit node in use, else the host's resolvers.
func (d *Daemon) namesUpstreamFor(q []byte) []netip.AddrPort {
	if up := d.namesExit.Load(); up != nil && len(*up) > 0 {
		return *up
	}
	return d.hostUpstreamFor(q)
}

// hostUpstreamFor is the host's resolvers resolved asks q's name of, but on
// juist's device, never none-nil; the host's resolvers in turn where its
// routing could not be read, or where the host asks juistd alone.
func (d *Daemon) hostUpstreamFor(q []byte) []netip.AddrPort {
	if s, ok := d.hostDNS.(soleResolver); ok {
		return append([]netip.AddrPort{}, d.soleUpstream(s)...)
	}
	if r := d.hostRouting.Load(); r != nil {
		if name, ok := names.Question(q); ok {
			return r.Servers(name)
		}
	}
	return append([]netip.AddrPort{}, uplinkResolvers()...)
}

// hostRoutingEvery is how often the host's routing is read again, which a
// link coming or going, as a VPN's, changes.
const hostRoutingEvery = 30 * time.Second

// readHostRoutingLocked reads the host resolver's routing, where it has one
// to read and has not been read for hostRoutingEvery; failing, it is
// forgotten.
func (d *Daemon) readHostRoutingLocked() {
	rr, ok := d.hostDNS.(interface {
		routing() (resolved.Routing, error)
	})
	if !ok || !d.hostRoutingAt.IsZero() && d.now().Sub(d.hostRoutingAt) < hostRoutingEvery {
		return
	}
	d.hostRoutingAt = d.now()
	r, err := rr.routing()
	if err != nil {
		d.logOnce("daemon: reading the host's DNS routing: " + err.Error())
		d.hostRouting.Store(nil)
		return
	}
	d.hostRouting.Store(&r)
}

// serveDNS answers members' DNS on addrs, from overlay, while on, and stops
// otherwise; it reports the port it answers on, zero for none.
func (d *Daemon) serveDNS(on bool, addrs []netip.Addr, overlay []netip.Prefix) uint16 {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	return d.serveDNSLocked(on, addrs, overlay)
}

func (d *Daemon) serveDNSLocked(on bool, addrs []netip.Addr, overlay []netip.Prefix) uint16 {
	on = on && !d.dnsClosed
	if on && d.dnsServer != nil && slices.Equal(addrs, d.dnsAddrs) && slices.Equal(overlay, d.dnsOverlay) {
		return DefaultDNSPort
	}
	if d.dnsServer != nil {
		d.dnsServer.Close()
		d.dnsServer, d.dnsAddrs, d.dnsOverlay = nil, nil, nil
	}
	if !on || d.startDNS == nil || len(addrs) == 0 {
		return 0
	}
	overlay = slices.Clone(overlay)
	allowed := func(a netip.Addr) bool {
		return slices.ContainsFunc(overlay, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	s, err := d.startDNS(addrs, allowed)
	if err != nil {
		d.logOnce("daemon: answering members' DNS: " + err.Error())
		return 0
	}
	d.dnsServer, d.dnsAddrs, d.dnsOverlay = s, slices.Clone(addrs), overlay
	return DefaultDNSPort
}

// dnsRetry is how long a failed routing of the host's DNS waits before it is
// tried again, which each reconcile would otherwise do.
const dnsRetry = 30 * time.Second

// routeDNS routes the host's DNS to servers, or gives it back where there are
// none; keep keeps what is routed, renewing it. It reports whether DNS goes
// through the tunnel, and why not, where it was meant to.
func (d *Daemon) routeDNS(servers []netip.AddrPort, keep bool) (bool, string) {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	if d.dnsClosed {
		return false, ""
	}
	return d.routeDNSLocked(servers, keep)
}

func (d *Daemon) routeDNSLocked(exit []netip.AddrPort, keep bool) (bool, string) {
	if keep {
		exit = d.dnsExit
	}
	d.dnsExit = slices.Clone(exit)
	up := slices.Clone(exit)
	d.namesExit.Store(&up)
	want := d.wantRoutingLocked(exit)
	if d.names != nil && len(exit) == 0 || d.dnsServer != nil {
		d.readHostRoutingLocked()
	}
	d.namesStatus = nil
	d.namesRouted.Store(false)
	if want.empty() {
		if !d.dnsRouting.empty() && d.hostDNS != nil {
			if err := d.hostDNS.Revert(); err != nil {
				d.logOnce("daemon: giving the host's DNS back: " + err.Error())
			}
		}
		d.dnsRouting, d.dnsWhy = DNSRouting{}, ""
		off := d.dnsOff.Load()
		if off && d.names != nil {
			d.names.Close()
			d.names = nil
		}
		d.namesStatus = d.namesNotLocked()
		if off && len(exit) > 0 {
			return false, dnsOffWhy
		}
		return false, ""
	}
	if d.hostDNS == nil {
		d.namesStatus = d.namesNotLocked()
		return false, "juistd runs without a device of its own"
	}
	same := want.equal(d.dnsRouting)
	switch {
	case same && d.dnsWhy == "" && d.now().Sub(d.dnsRoutedAt) < dnsRenewal:
		return d.routedLocked(exit)
	case same && d.dnsWhy != "" && d.now().Sub(d.dnsRoutedAt) < dnsRetry:
		return d.routedLocked(exit)
	}
	// Taken for routed even where it failed half-way, so that going off
	// gives the link back whatever of it resolved took.
	d.dnsRouting, d.dnsRoutedAt, d.dnsWhy = want, d.now(), ""
	if err := d.hostDNS.Route(want); err != nil {
		d.logOnce("daemon: routing the host's DNS: " + err.Error())
		switch {
		case errors.Is(err, resolved.ErrNotRunning) && tailscaledWrote(cmp.Or(d.resolvConf, "/etc/resolv.conf")):
			d.dnsWhy = "tailscaled writes " + cmp.Or(d.resolvConf, "/etc/resolv.conf")
		case errors.Is(err, resolved.ErrNotRunning):
			d.dnsWhy = "systemd-resolved does not run on this host"
		case errors.Is(err, resolved.ErrNoPolkit):
			d.dnsWhy = "systemd-resolved refused juistd: polkit is not installed"
		case errors.Is(err, resolved.ErrNotAuthorized):
			d.dnsWhy = "systemd-resolved refused juistd"
		default:
			d.dnsWhy = err.Error()
		}
	}
	return d.routedLocked(exit)
}

// routedLocked is what the routing last given makes of the exit node's DNS,
// as [Daemon.routeDNS] reports it, and of the network's names.
func (d *Daemon) routedLocked(exit []netip.AddrPort) (bool, string) {
	named := d.names != nil && d.dnsRouting.Servers[0] == d.namesAt
	d.namesRouted.Store(named && d.dnsWhy == "")
	if !named {
		d.namesStatus = d.namesNotLocked()
	}
	if d.dnsWhy != "" {
		if named {
			z := d.zone.Load()
			d.namesStatus = &ipc.Names{Domain: z.Domain, Public: z.Public, Not: d.dnsWhy}
		}
		return false, d.dnsWhy
	}
	through, why := d.throughStub()
	if named {
		z := d.zone.Load()
		d.namesStatus = &ipc.Names{Domain: z.Domain, Public: z.Public, Resolved: through, Not: why}
	}
	if len(exit) == 0 {
		return false, ""
	}
	return through, why
}

// namesNotLocked is why the host resolves none of the network's names, nil
// where there are none to resolve.
func (d *Daemon) namesNotLocked() *ipc.Names {
	z := d.zone.Load()
	switch {
	case d.dnsClosed || z == nil || z == noZone:
		return nil
	case z.Domain == "" && z.Public == "":
		return &ipc.Names{Not: "the network's name is no DNS label", Cannot: true}
	case d.dnsOff.Load():
		return &ipc.Names{Domain: z.Domain, Public: z.Public, Not: dnsOffWhy, Cannot: true, Off: true}
	case d.hostDNS == nil || d.startNames == nil:
		return &ipc.Names{Domain: z.Domain, Public: z.Public, Not: "juistd runs without a device of its own", Cannot: true}
	case !routesDomains(d.hostDNS):
		return &ipc.Names{Domain: z.Domain, Public: z.Public, Not: errNoDomains.Error(), Cannot: true}
	}
	return &ipc.Names{Domain: z.Domain, Public: z.Public, Not: cmp.Or(d.namesWhy, "juistd does not answer them")}
}

// setZone has the host resolve what p plans of the network's names.
func (d *Daemon) setZone(p exitPlan) {
	if p.zone == nil {
		return
	}
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	d.zone.Store(p.zone)
	d.overrides, d.namesUntil, d.namesAccepted = p.overrides, p.namesUntil, p.accepted
}

// namesNow is what the last reconcile made of the network's names, with
// whether each public name is answered as of now.
func (d *Daemon) namesNow() *ipc.Names {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	if d.namesStatus == nil {
		return nil
	}
	n := *d.namesStatus
	n.Accepted = d.namesAccepted
	for _, h := range d.overrides {
		if h.members {
			n.ForMembers = append(n.ForMembers, h.name)
		}
		if h.published {
			continue // the network's own domain's, which the publish lines say
		}
		o := ipc.NameOverride{Name: h.name, Device: h.device}
		if n.Accepted {
			o.Not = d.overrideNot(h, d.namesUntil)
		}
		n.Overrides = append(n.Overrides, o)
	}
	return &n
}

// SetDNSOff records whether this device's owner had juistd leave the host's
// DNS alone: the network's names and an exit node's DNS alike.
func (d *Daemon) SetDNSOff(off bool) {
	d.dnsOff.Store(off)
	d.MarkDirty()
}

// SetAcceptNames records whether this device's owner agreed that it
// resolves the public names the network points at members to them.
func (d *Daemon) SetAcceptNames(on bool) {
	d.mu.Lock()
	d.acceptNames = on
	d.mu.Unlock()
	d.MarkDirty()
}

func routesDomains(h HostDNS) bool {
	rd, ok := h.(interface{ routesDomains() bool })
	return ok && rd.routesDomains()
}

// wantRoutingLocked is the host's DNS routing with exit, the exit node's
// resolvers or none: juist's resolver for the names it answers, and for
// every name with an exit node; else the exit node's resolvers, or none.
func (d *Daemon) wantRoutingLocked(exit []netip.AddrPort) DNSRouting {
	if d.dnsClosed || d.dnsOff.Load() {
		return DNSRouting{}
	}
	z := d.zone.Load()
	if domains := routedDomains(z); len(domains) > 0 && d.namesServingLocked() {
		_, sole := d.hostDNS.(soleResolver)
		r := DNSRouting{Servers: []netip.AddrPort{d.namesAt}, Domains: domains, Everything: len(exit) > 0 || sole}
		if z.Domain != "" {
			r.Search = []string{z.Domain}
		}
		return r
	}
	if len(exit) > 0 {
		return DNSRouting{Servers: slices.Clone(exit), Everything: true}
	}
	return DNSRouting{}
}

// namesServingLocked has juist's resolver answer the host, where the host's
// resolver routes domains to it, and reports whether it does.
func (d *Daemon) namesServingLocked() bool {
	if d.names != nil {
		return true
	}
	if !routesDomains(d.hostDNS) || d.startNames == nil || d.dnsClosed {
		return false
	}
	if !d.namesFailedAt.IsZero() && d.now().Sub(d.namesFailedAt) < dnsRetry {
		return false
	}
	answer := func(q []byte) []byte {
		if z := d.zone.Load(); z != nil {
			return z.Answer(q)
		}
		return nil
	}
	at, err := d.namesAddrNow()
	var s io.Closer
	if err == nil {
		s, err = d.startNames(at, answer, d.namesUpstreamFor)
	}
	if err != nil {
		d.namesFailedAt, d.namesWhy = d.now(), err.Error()
		d.logOnce("daemon: answering the host's names: " + err.Error())
		return false
	}
	d.names, d.namesAt, d.namesFailedAt, d.namesWhy = s, at, time.Time{}, ""
	d.soleAnswersAt(at.Addr())
	return true
}

// throughStub reports whether the host's programs ask resolved, whose routing
// is then theirs, and why not; or, where the host's DNS says itself, whether
// they ask the servers routed.
func (d *Daemon) throughStub() (bool, string) {
	path := cmp.Or(d.resolvConf, "/etc/resolv.conf")
	if t, ok := d.hostDNS.(interface {
		through(string, []netip.AddrPort) (bool, string)
	}); ok {
		return t.through(path, d.dnsRouting.Servers)
	}
	servers, why := nameservers(path)
	if why != "" {
		return false, why
	}
	if b, _ := os.ReadFile(path); bytes.HasPrefix(b, []byte(uplinkHeader)) {
		// Programs ask each server in turn, the exit node's among them.
		return false, path + " lists every link's servers, systemd-resolved's uplink mode, not its stub"
	}
	for _, s := range servers {
		if s != "127.0.0.53" && s != "127.0.0.54" {
			return false, path + " asks " + s + ", not systemd-resolved"
		}
	}
	return true, ""
}

// uplinkHeader opens the resolv.conf systemd-resolved writes with every
// link's servers.
const uplinkHeader = "# This is /run/systemd/resolve/resolv.conf managed by"

// nameservers are the resolvers path names, and why none where it names none.
func nameservers(path string) ([]string, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, path + " cannot be read"
	}
	var servers []string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
	}
	if len(servers) == 0 {
		return nil, path + " names no resolver"
	}
	return servers, ""
}

// closeDNS stops answering members' DNS and gives the host's back, for good:
// a reconcile racing Close starts neither again.
func (d *Daemon) closeDNS() {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	d.dnsClosed = true
	d.serveDNSLocked(false, nil, nil)
	d.routeDNSLocked(nil, false)
	if d.names != nil {
		d.names.Close()
		d.names = nil
		d.namesRouted.Store(false)
	}
}

// exitDNS is where the host's DNS goes while the exit node at addrs, which
// announced e, is in use: those of its addresses it answers on. A refused
// exit node's still, so that lookups go nowhere rather than to the LAN.
func exitDNS(addrs []netip.Prefix, e gossip.Endpoint) []netip.AddrPort {
	port := cmp.Or(e.DNS, DefaultDNSPort)
	var out []netip.AddrPort
	for _, a := range addrs {
		if !(e.NoV4 && a.Addr().Is4()) {
			out = append(out, netip.AddrPortFrom(a.Addr(), port))
		}
	}
	return out
}
