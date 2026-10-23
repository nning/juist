package daemon

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// The host's DNS routing is given again every dnsRenewal, which a restarted
// resolved forgets, and every dnsRenewalWatched where resolved's restarts
// are watched.
const (
	dnsRenewal        = 5 * time.Minute
	dnsRenewalWatched = time.Hour
)

// A watchedDNS calls restarted each time the host's resolver starts again,
// and watching with whether it watches, until ctx ends.
type watchedDNS interface {
	watch(ctx context.Context, watching func(bool), restarted func())
}

func (resolvedDNS) watch(ctx context.Context, watching func(bool), restarted func()) {
	resolved.WatchRestarts(ctx, watching, restarted)
}

// watchHostDNS has the host's DNS routed again each time its resolver starts
// again, where it can be watched.
func (d *Daemon) watchHostDNS(ctx context.Context) {
	w, ok := d.hostDNS.(watchedDNS)
	if !ok || !d.waits.track() {
		return
	}
	go func() {
		defer d.waits.done()
		w.watch(ctx, d.dns.watched.Store, func() {
			d.dns.mu.Lock()
			d.dns.routedAt = time.Time{}
			d.dns.mu.Unlock()
			d.reconcileSoon()
		})
	}()
}

// interfacesChanged reconciles soon, as a link coming or going, as a VPN's,
// may change where the host's DNS goes.
func (d *Daemon) interfacesChanged() { d.reconcileSoon() }

// dnsRenewalNow is how long the routing given stands.
func (d *Daemon) dnsRenewalNow() time.Duration {
	if d.dns.watched.Load() {
		return dnsRenewalWatched
	}
	return dnsRenewal
}

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

// dnsState is the DNS this device answers members as an exit node, and the
// host's: routing is what the host was last told, and names answers it from
// the zone. mu is held across the host's resolver and the servers' Close.
type dnsState struct {
	mu       sync.Mutex
	server   io.Closer
	addrs    []netip.Addr
	overlay  []netip.Prefix
	routing  DNSRouting       // what the host was last told
	exit     []netip.AddrPort // the exit node's resolvers it is meant to ask
	routedAt time.Time
	why      string // why the routing last failed, "" where it did not
	closed   bool
	watched  atomic.Bool // the resolver's restarts are watched

	// serveFailedAt is when answering members' DNS last failed to start,
	// and serveWhy why; zero and "" while it answers or is not asked to.
	serveFailedAt time.Time
	serveWhy      string

	names         io.Closer
	namesAt       netip.AddrPort // where names answers, while it does
	namesFailedAt time.Time
	namesWhy      string // why names did not start
	namesStatus   *ipc.Names
	overrides     []heldOverride // the network's public names, answered or not
	namesAccepted bool
	namesUntil    int64 // until when overrides are answered, the view's freshness
}

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

// routingWithin bounds a read of resolved's routing, connecting included.
const routingWithin = 5 * time.Second

// routing is how resolved routes names to every link but this one.
func (r resolvedDNS) routing() (resolved.Routing, error) {
	ifc, err := net.InterfaceByName(r.dev)
	if err != nil {
		return resolved.Routing{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), routingWithin)
	defer cancel()
	c, err := resolved.DialContext(ctx)
	if err != nil {
		return resolved.Routing{}, err
	}
	defer c.Close()
	links := func() []int {
		var out []int
		if ifcs, err := net.Interfaces(); err == nil {
			for _, i := range ifcs {
				out = append(out, i.Index)
			}
		}
		return out
	}
	rt, err := c.Routing(ifc.Index, links)
	for k, sc := range rt.Scopes {
		rt.Scopes[k].Subnets = linkSubnets(sc.Ifindex)
	}
	return rt, err
}

// linkSubnets are the addresses of the link at ifindex, with their prefixes.
func linkSubnets(ifindex int) []netip.Prefix {
	if ifindex == 0 {
		return nil
	}
	ifc, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return nil
	}
	addrs, _ := ifc.Addrs()
	var out []netip.Prefix
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ip, _ := netip.AddrFromSlice(n.IP)
			ones, _ := n.Mask.Size()
			out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
		}
	}
	return out
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
func (d *Daemon) membersUpstreamFor(q []byte) ([]netip.AddrPort, error) {
	if z := d.zone.Load(); z != nil && d.namesRouted.Load() && z.Overridden(q) {
		return d.hostUpstreamFor(q, true)
	}
	return d.uplinkFor(q)
}

// tailscaledResolvers answer from the host's tailnet, whose addresses a
// member reaching the internet through this exit node cannot reach.
var tailscaledResolvers = []netip.Addr{netip.MustParseAddr("100.100.100.100"), netip.MustParseAddr("fd7a:115c:a1e0::53")}

// PreTailscaleResolvConf is the host's resolv.conf as tailscaled found it
// before writing its own.
var PreTailscaleResolvConf = "/etc/resolv.pre-tailscale-backup.conf"

// resolvedStubs are where systemd-resolved's stub answers.
var resolvedStubs = []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("127.0.0.54")}

// errStubDown refuses a name the host would ask resolved's stub of, which
// does not run.
var errStubDown = errors.New("resolv.conf names systemd-resolved alone, which is not running")

// errTailnetOnly refuses a member's name the host routes to tailscaled alone.
var errTailnetOnly = errors.New("the host asks tailscaled alone, whose answers members cannot reach")

// stubAlone reports whether ups are resolved's stub alone.
func stubAlone(ups []netip.AddrPort) bool {
	return len(ups) > 0 && !slices.ContainsFunc(ups, func(a netip.AddrPort) bool { return !slices.Contains(resolvedStubs, a.Addr()) })
}

func withoutStub(ups []netip.AddrPort) []netip.AddrPort {
	return slices.DeleteFunc(slices.Clone(ups), func(a netip.AddrPort) bool { return slices.Contains(resolvedStubs, a.Addr()) })
}

// stubLinked reports whether resolv.conf is a link to one of resolved's,
// which a dangling one is too.
func stubLinked() bool {
	to, err := os.Readlink(dnsfwd.ResolvConf)
	return err == nil && strings.Contains(to, "systemd/resolve/")
}

// uplinkFor is who a member's query q is asked of where no override is
// answered: those resolved would ask, where it runs, but never tailscaled's
// resolvers; its own where the host asks juistd alone; else those
// resolv.conf names, or tailscaled's predecessor's; nil, the forwarder's
// own, where they are all there is. An error refuses q.
func (d *Daemon) uplinkFor(q []byte) ([]netip.AddrPort, error) {
	if s, ok := d.hostDNS.(soleResolver); ok {
		// Never resolv.conf, which names juistd's own resolver.
		return d.soleUpstream(s), nil
	}
	r, err := d.hostRoutingNow()
	ups := dnsfwd.HostResolvers()
	switch {
	case errors.Is(err, resolved.ErrNotRunning):
		if stubAlone(ups) || len(ups) == 0 && stubLinked() {
			return nil, errStubDown
		}
		ups = withoutStub(ups)
	case err != nil:
		return nil, err
	case r != nil:
		return d.routed(r, q, true)
	}
	if ups = withoutTailscaled(ups); len(ups) == 0 {
		ups = withoutTailscaled(dnsfwd.ResolversIn(PreTailscaleResolvConf))
	}
	if len(ups) == 0 {
		return nil, nil
	}
	return ups, nil
}

func withoutTailscaled(ups []netip.AddrPort) []netip.AddrPort {
	return slices.DeleteFunc(slices.Clone(ups), func(a netip.AddrPort) bool { return slices.Contains(tailscaledResolvers, a.Addr()) })
}

// namesUpstreamFor is who juistd's resolver asks q of, what it does not
// answer itself: the exit node in use, else the host's resolvers.
func (d *Daemon) namesUpstreamFor(q []byte) ([]netip.AddrPort, error) {
	if up := d.namesExit.Load(); up != nil && len(*up) > 0 {
		return *up, nil
	}
	return d.hostUpstreamFor(q, false)
}

// hostUpstreamFor is the host's resolvers resolved asks q's name of, but on
// juist's device; where resolved is not running, those resolv.conf names
// but its stub; the host's resolvers in turn where the host asks juistd
// alone or has no routing to read. For members, never tailscaled's. An
// error refuses q.
func (d *Daemon) hostUpstreamFor(q []byte, members bool) ([]netip.AddrPort, error) {
	if s, ok := d.hostDNS.(soleResolver); ok {
		return append([]netip.AddrPort{}, d.soleUpstream(s)...), nil
	}
	r, err := d.hostRoutingNow()
	var ups []netip.AddrPort
	switch {
	case errors.Is(err, resolved.ErrNotRunning):
		if ups = withoutStub(dnsfwd.HostResolvers()); len(ups) == 0 {
			return nil, errStubDown
		}
	case err != nil:
		return nil, err
	case r != nil:
		return d.routed(r, q, members)
	default:
		ups = append([]netip.AddrPort{}, uplinkResolvers()...)
	}
	if members {
		theirs := withoutTailscaled(ups)
		if len(theirs) == 0 && len(ups) > 0 {
			d.forwardRefused(errTailnetOnly)
			return nil, errTailnetOnly
		}
		ups = theirs
	}
	return ups, nil
}

// routed is who resolved asks q of by r, refusing as resolved's stub would
// answer it what the stub refuses, what resolved answers itself or asks no
// DNS server of; and for the host, what it asks over TLS, which would leave
// in plain text by the local network; for members, whose queries leave at
// this site, never tailscaled's resolvers, and q refused where they are all
// there is.
func (d *Daemon) routed(r *resolved.Routing, q []byte, members bool) ([]netip.AddrPort, error) {
	name, qtype, qclass, ok := names.QuestionOf(q)
	if !ok {
		return nil, &dnsfwd.Refusal{RCode: dnsfwd.RCodeFormErr, Err: errors.New("no question")}
	}
	if stubRefuses(q, qtype, qclass) || ownHostname(name) || inEtcHosts(name) {
		return nil, &dnsfwd.Refusal{RCode: dnsfwd.RCodeRefused, Err: resolved.ErrNotUnicast}
	}
	ups, overTLS, err := r.Route(name, qtype)
	switch {
	case errors.Is(err, resolved.ErrNeverResolved):
		return nil, &dnsfwd.Refusal{RCode: dnsfwd.RCodeNXDomain, Err: err}
	case errors.Is(err, resolved.ErrOwn):
		return nil, err
	case errors.Is(err, resolved.ErrNoServers):
		d.forwardRefused(err)
		return nil, &dnsfwd.Refusal{RCode: dnsfwd.RCodeRefused, Err: err}
	case err != nil:
		return nil, &dnsfwd.Refusal{RCode: dnsfwd.RCodeRefused, Err: err}
	case overTLS && !members:
		d.forwardRefused(resolved.ErrOverTLS)
		return nil, resolved.ErrOverTLS
	}
	if members {
		if ups = withoutTailscaled(ups); len(ups) == 0 {
			d.forwardRefused(errTailnetOnly)
			return nil, errTailnetOnly
		}
	}
	return ups, nil
}

// stubRefuses reports whether resolved's stub refuses q, of type qtype and
// class qclass: more than one question, no recursion desired, a zone
// transfer, a type obsolete or no question's, or a class but IN and ANY.
func stubRefuses(q []byte, qtype, qclass uint16) bool {
	return binary.BigEndian.Uint16(q[4:]) != 1 || q[2]&0x01 == 0 || slices.Contains(stubRefusedTypes, qtype) ||
		qclass != 1 && qclass != 255
}

// stubRefusedTypes are zone transfers, obsolete types and those no question
// asks for, as resolved's stub has them.
var stubRefusedTypes = []uint16{0, 3, 4, 7, 8, 9, 10, 11, 14, 30, 38, 41, 46, 249, 250, 251, 252, 253, 254}

// ownHostname reports whether name is the host's own, which resolved
// answers itself.
func ownHostname(name string) bool {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return false
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	short, _, _ := strings.Cut(h, ".")
	return name == h || name == short
}

// forwardRefused has juist health say err refused a name the host routes,
// and logs it at most every hostRoutingLogEvery.
func (d *Daemon) forwardRefused(err error) {
	now, why := d.now(), err.Error()
	d.hostRouting.mu.Lock()
	at, logged := d.hostRouting.refusedLogged[why]
	log := !logged || now.Sub(at) >= hostRoutingLogEvery
	if log {
		if d.hostRouting.refusedLogged == nil {
			d.hostRouting.refusedLogged = map[string]time.Time{}
		}
		d.hostRouting.refusedLogged[why] = now
	}
	if now.Unix() != d.hostRouting.refusedAt || why != d.hostRouting.refusedWhy {
		d.hostRouting.refusedAt, d.hostRouting.refusedWhy = now.Unix(), why
		d.setStatus(func(s *ipc.Status) { s.DNSRefused, s.DNSRefusedAt = why, now.Unix() })
	}
	d.hostRouting.mu.Unlock()
	if log {
		d.logf("daemon: refusing names the host routes: %s", why)
	}
}

// A query goes by a read of the host's DNS routing begun at most
// hostRoutingFresh before it, as resolved signals no change to a link's
// domains, and waits at most hostRoutingWait for one.
const (
	hostRoutingFresh = time.Second
	hostRoutingWait  = 3 * time.Second
)

// errHostRoutingSlow is a read of the host's DNS routing that outlasted
// hostRoutingWait.
var errHostRoutingSlow = fmt.Errorf("no answer within %v", hostRoutingWait)

// A routingReader reads how the host's resolver routes names to every link
// but juist's.
type routingReader interface {
	routing() (resolved.Routing, error)
}

// A domainRouter says whether the host's resolver routes domains to a link,
// as juist's names need.
type domainRouter interface{ routesDomains() bool }

// A throughReporter reports whether the host's programs ask the servers
// routed, and why not, as [Daemon.throughStub].
type throughReporter interface {
	through(path string, servers []netip.AddrPort) (bool, string)
}

// A namesPorter names the port juistd's resolver must answer the host on, in
// place of [NamesPort].
type namesPorter interface{ namesPort() uint16 }

// What each host resolver can, held at compile time: the daemon finds each
// capability by a type assertion, which a renamed method would fail silently.
var (
	_ watchedDNS      = resolvedDNS{}
	_ routingReader   = resolvedDNS{}
	_ domainRouter    = resolvedDNS{}
	_ throughReporter = plumbedDNS{}
	_ soleResolver    = fileDNS{}
	_ domainRouter    = fileDNS{}
	_ throughReporter = fileDNS{}
	_ soleResolver    = resolvconfDNS{}
	_ domainRouter    = resolvconfDNS{}
	_ namesPorter     = resolvconfDNS{}
	_ throughReporter = resolvconfDNS{}
)

// A capability lost to a renamed method fails to build here, not silently.
var (
	_ watchedDNS      = resolvedDNS{}
	_ routingReader   = resolvedDNS{}
	_ domainRouter    = resolvedDNS{}
	_ domainRouter    = fileDNS{}
	_ domainRouter    = resolvconfDNS{}
	_ soleResolver    = fileDNS{}
	_ soleResolver    = resolvconfDNS{}
	_ throughReporter = plumbedDNS{}
	_ throughReporter = vpnDNS{}
	_ throughReporter = fileDNS{}
	_ throughReporter = resolvconfDNS{}
	_ namesPorter     = resolvconfDNS{}
)

// hostRoutingState is what the host's DNS routing was last read as, and the
// refusals logged by it. Its lock is never held across D-Bus.
type hostRoutingState struct {
	mu       sync.Mutex
	read     *routingRead // the last read, done or under way
	why      string       // why the last read failed, "" where it did not
	logged   bool         // whether this run of failures was logged
	loggedAt time.Time

	refusedLogged map[string]time.Time // when each reason a name was refused was logged
	refusedAt     int64                // the second refusedWhy was last said in
	refusedWhy    string
}

// A routingRead is one read of the host's DNS routing, begun at at; r and
// err are set once done is closed.
type routingRead struct {
	at   time.Time
	done chan struct{}
	r    *resolved.Routing
	err  error
}

func (rd *routingRead) finished() bool {
	select {
	case <-rd.done:
		return true
	default:
		return false
	}
}

// hostRoutingNow is the host's DNS routing, read anew unless a read begun
// within hostRoutingFresh is done or under way, which callers share; nil
// where there is none to read, and [resolved.ErrNotRunning] where resolved
// is not running. Another error is a read that failed or outlasted
// hostRoutingWait, never an older routing.
func (d *Daemon) hostRoutingNow() (*resolved.Routing, error) {
	rr, ok := d.hostDNS.(routingReader)
	if !ok {
		return nil, nil
	}
	asked := d.now()
	fresh := func(rd *routingRead) bool { return asked.Sub(rd.at) < hostRoutingFresh }
	wait := time.NewTimer(hostRoutingWait)
	defer wait.Stop()
	for {
		d.hostRouting.mu.Lock()
		rd := d.hostRouting.read
		if rd == nil || rd.finished() && !fresh(rd) {
			rd = d.readHostRoutingLocked(rr)
		}
		d.hostRouting.mu.Unlock()
		select {
		case <-rd.done:
			// One under way since before asked is no answer to it.
			if fresh(rd) {
				return rd.r, rd.err
			}
			continue
		case <-wait.C:
		}
		d.hostRouting.mu.Lock()
		if rd.finished() && fresh(rd) {
			d.hostRouting.mu.Unlock()
			return rd.r, rd.err
		}
		log := func() {}
		if !rd.finished() {
			log = d.hostRoutingReadLocked(errHostRoutingSlow)
		}
		d.hostRouting.mu.Unlock()
		log()
		return nil, errHostRoutingSlow
	}
}

// readHostRoutingLocked begins a read of the host's DNS routing. The caller
// holds hostRouting.mu.
func (d *Daemon) readHostRoutingLocked(rr routingReader) *routingRead {
	rd := &routingRead{at: d.now(), done: make(chan struct{})}
	d.hostRouting.read = rd
	go d.readHostRouting(rr, rd)
	return rd
}

// readHostRouting reads the host's DNS routing into rd.
func (d *Daemon) readHostRouting(rr routingReader, rd *routingRead) {
	r, err := rr.routing()
	rd.err = err
	switch {
	case errors.Is(err, resolved.ErrNotRunning):
		d.logOnce("daemon: reading the host's DNS routing: " + err.Error())
		err = nil
	case err == nil:
		rd.r = &r
	}
	d.hostRouting.mu.Lock()
	defer d.hostRouting.mu.Unlock()
	// Logged before the waiters go on, so a query refused has its cause said.
	d.hostRoutingReadLocked(err)()
	close(rd.done)
}

// hostRoutingLogEvery is how often a failure to read the host's DNS
// routing is logged at most, as reads may fail and succeed in turn.
const hostRoutingLogEvery = time.Minute

// hostRoutingReadLocked records whether the host's DNS routing could be
// read, err nil where it could, for the status, and is what to log: a
// failure not yet logged, at most every hostRoutingLogEvery, and the end of
// a run logged. The caller holds hostRouting.mu.
func (d *Daemon) hostRoutingReadLocked(err error) (log func()) {
	why := ""
	if err != nil {
		why = err.Error()
	}
	was := d.hostRouting.why
	d.hostRouting.why = why
	if why != was {
		d.setStatus(func(s *ipc.Status) { s.DNSRoutingUnread = why })
	}
	switch {
	case why != "" && !d.hostRouting.logged:
		now := d.now()
		if d.hostRouting.loggedAt.IsZero() || now.Sub(d.hostRouting.loggedAt) >= hostRoutingLogEvery {
			d.hostRouting.logged, d.hostRouting.loggedAt = true, now
			return func() { d.logf("daemon: refusing names the host routes, as its DNS routing cannot be read: %s", why) }
		}
	case why == "" && d.hostRouting.logged:
		d.hostRouting.logged = false
		return func() { d.logf("daemon: the host's DNS routing is read again") }
	}
	return func() {}
}

// hostRoutingReconciled has a failure to read the host's DNS routing said
// no longer once nothing forwards by it, and read again where something
// does, as reads are otherwise a query's, but never once DNS is closed. The
// caller holds dns.mu.
func (d *Daemon) hostRoutingReconciled(forwards bool) {
	rr, ok := d.hostDNS.(routingReader)
	d.hostRouting.mu.Lock()
	defer d.hostRouting.mu.Unlock()
	switch {
	case d.hostRouting.why == "":
	case !ok || !forwards || d.dns.closed:
		d.hostRouting.why, d.hostRouting.logged = "", false
		d.setStatus(func(s *ipc.Status) { s.DNSRoutingUnread = "" })
	case d.hostRouting.read == nil || d.hostRouting.read.finished() && d.now().Sub(d.hostRouting.read.at) >= hostRoutingFresh:
		d.readHostRoutingLocked(rr)
	}
}

// serveDNS answers members' DNS on addrs, from overlay, while on, and stops
// otherwise; it reports the port it answers on, zero for none, and why it
// answers none where it was to.
func (d *Daemon) serveDNS(on bool, addrs []netip.Addr, overlay []netip.Prefix) (uint16, string) {
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	return d.serveDNSLocked(on, addrs, overlay), d.dns.serveWhy
}

func (d *Daemon) serveDNSLocked(on bool, addrs []netip.Addr, overlay []netip.Prefix) uint16 {
	on = on && !d.dns.closed
	if on && d.dns.server != nil && slices.Equal(addrs, d.dns.addrs) && slices.Equal(overlay, d.dns.overlay) {
		return DefaultDNSPort
	}
	if d.dns.server != nil {
		d.dns.server.Close()
		d.dns.server, d.dns.addrs, d.dns.overlay = nil, nil, nil
	}
	if !on || d.startDNS == nil || len(addrs) == 0 {
		d.dns.serveFailedAt, d.dns.serveWhy = time.Time{}, ""
		return 0
	}
	overlay = slices.Clone(overlay)
	allowed := func(a netip.Addr) bool {
		return slices.ContainsFunc(overlay, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	s, err := d.startDNS(addrs, allowed)
	if err != nil {
		// Tried again at a reconcile dnsRetry on, not the next one by chance.
		d.dns.serveFailedAt, d.dns.serveWhy = d.now(), err.Error()
		d.logOnce("daemon: answering members' DNS: " + err.Error())
		return 0
	}
	d.dns.server, d.dns.addrs, d.dns.overlay = s, slices.Clone(addrs), overlay
	d.dns.serveFailedAt, d.dns.serveWhy = time.Time{}, ""
	return DefaultDNSPort
}

// dnsRetry is how long a failed routing of the host's DNS waits before it is
// tried again, which each reconcile would otherwise do.
const dnsRetry = 30 * time.Second

// dnsDue is when the routing of the host's DNS is next given again, renewed
// or retried, or juist's resolver started again after it failed; zero for
// none.
func (d *Daemon) dnsDue() time.Time {
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	var next soonest
	if !d.dns.namesFailedAt.IsZero() {
		next.add(d.dns.namesFailedAt.Add(dnsRetry))
	}
	if !d.dns.serveFailedAt.IsZero() {
		next.add(d.dns.serveFailedAt.Add(dnsRetry))
	}
	_, keeps := d.hostDNS.(vpnDNS)
	switch {
	case d.dns.closed || d.hostDNS == nil || d.dns.routing.empty():
	case d.dns.why != "":
		next.add(d.dns.routedAt.Add(dnsRetry))
	case !keeps:
		next.add(d.dns.routedAt.Add(d.dnsRenewalNow()))
	}
	return next.at
}

// routeDNS routes the host's DNS to servers, or gives it back where there are
// none; keep keeps what is routed, renewing it. It reports whether DNS goes
// through the tunnel, and why not, where it was meant to.
func (d *Daemon) routeDNS(servers []netip.AddrPort, keep bool) (bool, string) {
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	if d.dns.closed {
		return false, ""
	}
	return d.routeDNSLocked(servers, keep)
}

func (d *Daemon) routeDNSLocked(exit []netip.AddrPort, keep bool) (bool, string) {
	if keep {
		exit = d.dns.exit
	}
	d.dns.exit = slices.Clone(exit)
	up := slices.Clone(exit)
	d.namesExit.Store(&up)
	defer func() { d.hostRoutingReconciled(d.dns.names != nil && len(d.dns.exit) == 0 || d.dns.server != nil) }()
	want := d.wantRoutingLocked(exit)
	d.dns.namesStatus = nil
	d.namesRouted.Store(false)
	if want.empty() {
		if !d.dns.routing.empty() && d.hostDNS != nil {
			if err := d.hostDNS.Revert(); err != nil {
				d.logOnce("daemon: giving the host's DNS back: " + err.Error())
			}
		}
		d.dns.routing, d.dns.why = DNSRouting{}, ""
		off := d.dnsOff.Load()
		if off && d.dns.names != nil {
			d.dns.names.Close()
			d.dns.names = nil
		}
		d.dns.namesStatus = d.namesNotLocked()
		if off && len(exit) > 0 {
			return false, dnsOffWhy
		}
		return false, ""
	}
	if d.hostDNS == nil {
		d.dns.namesStatus = d.namesNotLocked()
		return false, "juistd runs without a device of its own"
	}
	same := want.equal(d.dns.routing)
	switch {
	case same && d.dns.why == "" && d.now().Sub(d.dns.routedAt) < d.dnsRenewalNow():
		return d.routedLocked(exit)
	case same && d.dns.why != "" && d.now().Sub(d.dns.routedAt) < dnsRetry:
		return d.routedLocked(exit)
	}
	// Taken for routed even where it failed half-way, so that going off
	// gives the link back whatever of it resolved took.
	d.dns.routing, d.dns.routedAt, d.dns.why = want, d.now(), ""
	if err := d.hostDNS.Route(want); err != nil {
		d.logOnce("daemon: routing the host's DNS: " + err.Error())
		switch {
		case errors.Is(err, resolved.ErrNotRunning) && tailscaledWrote(cmp.Or(d.resolvConf, "/etc/resolv.conf")):
			d.dns.why = "tailscaled writes " + cmp.Or(d.resolvConf, "/etc/resolv.conf")
		case errors.Is(err, resolved.ErrNotRunning):
			d.dns.why = "systemd-resolved does not run on this host"
		case errors.Is(err, resolved.ErrNoPolkit):
			d.dns.why = "systemd-resolved refused juistd: polkit is not installed"
		case errors.Is(err, resolved.ErrNotAuthorized):
			d.dns.why = "systemd-resolved refused juistd"
		default:
			d.dns.why = err.Error()
		}
	}
	return d.routedLocked(exit)
}

// routedLocked is what the routing last given makes of the exit node's DNS,
// as [Daemon.routeDNS] reports it, and of the network's names.
func (d *Daemon) routedLocked(exit []netip.AddrPort) (bool, string) {
	named := d.dns.names != nil && d.dns.routing.Servers[0] == d.dns.namesAt
	d.namesRouted.Store(named && d.dns.why == "")
	if !named {
		d.dns.namesStatus = d.namesNotLocked()
	}
	if d.dns.why != "" {
		if named {
			z := d.zone.Load()
			d.dns.namesStatus = &ipc.Names{Domain: z.Domain, Public: z.Public, Not: d.dns.why}
		}
		return false, d.dns.why
	}
	through, why := d.throughStub()
	if named {
		z := d.zone.Load()
		d.dns.namesStatus = &ipc.Names{Domain: z.Domain, Public: z.Public, Resolved: through, Not: why}
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
	case d.dns.closed || z == nil || z == noZone:
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
	return &ipc.Names{Domain: z.Domain, Public: z.Public, Not: cmp.Or(d.dns.namesWhy, "juistd does not answer them")}
}

// setZone has the host resolve what p plans of the network's names.
func (d *Daemon) setZone(p exitPlan) {
	if p.zone == nil {
		return
	}
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	d.zone.Store(p.zone)
	d.dns.overrides, d.dns.namesUntil, d.dns.namesAccepted = p.overrides, p.namesUntil, p.accepted
}

// namesNow is what the last reconcile made of the network's names, with
// whether each public name is answered as of now.
func (d *Daemon) namesNow() *ipc.Names {
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	if d.dns.namesStatus == nil {
		return nil
	}
	n := *d.dns.namesStatus
	n.Accepted = d.dns.namesAccepted
	for _, h := range d.dns.overrides {
		if h.members {
			n.ForMembers = append(n.ForMembers, h.name)
		}
		if h.published {
			continue // the network's own domain's, which the publish lines say
		}
		o := ipc.NameOverride{Name: h.name, Device: h.device}
		if n.Accepted {
			o.Not = d.overrideNot(h, d.dns.namesUntil)
		}
		n.Overrides = append(n.Overrides, o)
	}
	return &n
}

func routesDomains(h HostDNS) bool {
	rd, ok := h.(domainRouter)
	return ok && rd.routesDomains()
}

// wantRoutingLocked is the host's DNS routing with exit, the exit node's
// resolvers or none: juist's resolver for the names it answers, and for
// every name with an exit node; else the exit node's resolvers, or none.
func (d *Daemon) wantRoutingLocked(exit []netip.AddrPort) DNSRouting {
	if d.dns.closed || d.dnsOff.Load() {
		return DNSRouting{}
	}
	z := d.zone.Load()
	if domains := routedDomains(z); len(domains) > 0 && d.namesServingLocked() {
		_, sole := d.hostDNS.(soleResolver)
		r := DNSRouting{Servers: []netip.AddrPort{d.dns.namesAt}, Domains: domains, Everything: len(exit) > 0 || sole}
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
	if d.dns.names != nil {
		return true
	}
	if !routesDomains(d.hostDNS) || d.startNames == nil || d.dns.closed {
		return false
	}
	if !d.dns.namesFailedAt.IsZero() && d.now().Sub(d.dns.namesFailedAt) < dnsRetry {
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
		d.dns.namesFailedAt, d.dns.namesWhy = d.now(), err.Error()
		d.logOnce("daemon: answering the host's names: " + err.Error())
		return false
	}
	d.dns.names, d.dns.namesAt, d.dns.namesFailedAt, d.dns.namesWhy = s, at, time.Time{}, ""
	d.soleAnswersAt(at.Addr())
	return true
}

// throughStub reports whether the host's programs ask resolved, whose routing
// is then theirs, and why not; or, where the host's DNS says itself, whether
// they ask the servers routed.
func (d *Daemon) throughStub() (bool, string) {
	path := cmp.Or(d.resolvConf, "/etc/resolv.conf")
	if t, ok := d.hostDNS.(throughReporter); ok {
		return t.through(path, d.dns.routing.Servers)
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
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	d.dns.closed = true
	d.serveDNSLocked(false, nil, nil)
	d.routeDNSLocked(nil, false)
	if d.dns.names != nil {
		d.dns.names.Close()
		d.dns.names = nil
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
