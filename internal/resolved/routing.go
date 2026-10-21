package resolved

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

// A Routing is where resolved asks each name, by its links' servers and
// domains as they were read, but for one link's.
type Routing struct {
	Scopes []Scope
}

// A Scope is one link's servers, a delegate's (systemd 258's
// dns-delegate.d) where Delegate names it, or the global ones at Ifindex 0,
// with its Domains, escaped as resolved writes them, without a final dot,
// "" for "."; Search says one of them is a search domain, not for routing
// alone, DefaultRoute that it takes every name no other's domain claims,
// OverTLS that resolved asks it over TLS, opportunistically or not, and Own
// that it is juistd's own device. Subnets are the link's own addresses with
// their prefixes, which [Routing] does not read.
type Scope struct {
	Ifindex      int
	Delegate     string
	Servers      []netip.AddrPort
	Domains      []string
	Search       bool
	DefaultRoute bool
	OverTLS      bool
	Own          bool
	Subnets      []netip.Prefix
}

var (
	// ErrNotUnicast is a name resolved asks no DNS server of: the local
	// host's, mDNS's and LLMNR's, and those no scope is routed for.
	ErrNotUnicast = errors.New("systemd-resolved asks no DNS server of it")

	// ErrNeverResolved is a name resolved answers NXDOMAIN itself, as RFC
	// 6303, 6761 and 9476 reserve it.
	ErrNeverResolved = errors.New("systemd-resolved never resolves it")

	// ErrOwn is a name resolved would ask juistd's own device of.
	ErrOwn = errors.New("systemd-resolved asks juistd's own device")

	// ErrNoServers is a name refused as resolved knows no DNS server.
	ErrNoServers = errors.New("systemd-resolved knows no DNS server")

	// ErrOverTLS is a name resolved would ask over TLS, for a caller that
	// refuses it rather than ask in plain text.
	ErrOverTLS = errors.New("systemd-resolved asks over DNS over TLS, which juistd does not speak")
)

type busServer struct {
	Ifindex int32
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// addrPort is s as it is asked: an IPv6 link-local address with its link.
func (s busServer) addrPort() (netip.AddrPort, bool) {
	a, ok := netip.AddrFromSlice(s.Address)
	if !ok {
		return netip.AddrPort{}, false
	}
	if a = a.Unmap(); a.Is6() && a.IsLinkLocalUnicast() && s.Ifindex > 0 {
		a = a.WithZone(strconv.Itoa(int(s.Ifindex)))
	}
	return netip.AddrPortFrom(a, cmpPort(s.Port)), true
}

// absent reports whether err is a method or property resolved does not
// have, as an older one.
func absent(err error) bool {
	var e dbus.Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Name {
	case "org.freedesktop.DBus.Error.UnknownMethod", "org.freedesktop.DBus.Error.UnknownProperty",
		"org.freedesktop.DBus.Error.UnknownInterface", "org.freedesktop.DBus.Properties.Error.PropertyNotFound":
		return true
	}
	return false
}

// linkServer is a server of a link's own DNSEx, which names no link.
type linkServer struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// sameServer reports whether a link's server l is the manager's m, which
// names its link, or the loopback for a loopback address (systemd 255).
func sameServer(m busServer, l linkServer, ifindex int) bool {
	return (int(m.Ifindex) == ifindex || m.Ifindex == loopbackIfindex) && m.Family == l.Family &&
		slices.Equal(m.Address, l.Address) && m.Port == l.Port && m.Name == l.Name
}

const (
	loopbackIfindex = 1
	scopeDNS        = 1 // ScopesMask's SD_RESOLVED_DNS
)

// errChanging is resolved's servers changing while they were read.
var errChanging = errors.New("systemd-resolved's servers changed while read")

// Routing reads how resolved routes names to its links, own among them,
// juistd's, which no name is asked of, to its delegates and to its global
// servers, its fallback ones where it would ask them. Links are those the
// manager's servers and domains name, and where it files a server under the
// loopback, as systemd 255 does every loopback server, those links gives,
// which may name a link whose servers are on the loopback alone.
func (c *Client) Routing(own int, links func() []int) (Routing, error) {
	r, err := c.routing(own, links)
	if errors.Is(err, errChanging) {
		r, err = c.routing(own, links)
	}
	return r, err
}

func (c *Client) routing(own int, links func() []int) (Routing, error) {
	var servers []busServer
	if err := c.property(c.obj, manager, "DNSEx", &servers); err != nil {
		return Routing{}, err
	}
	var domains []struct {
		Ifindex   int32
		Domain    string
		RouteOnly bool
	}
	if err := c.property(c.obj, manager, "Domains", &domains); err != nil {
		return Routing{}, err
	}
	var globalTLS string
	if err := c.property(c.obj, manager, "DNSOverTLS", &globalTLS); err != nil {
		return Routing{}, err
	}
	var order []int
	for _, s := range servers {
		order = append(order, int(s.Ifindex))
	}
	for _, d := range domains {
		order = append(order, int(d.Ifindex))
	}
	if slices.ContainsFunc(servers, func(s busServer) bool { return s.Ifindex == loopbackIfindex }) && links != nil {
		order = append(order, links()...)
	}
	seen := map[int]bool{0: true, loopbackIfindex: true}
	order = slices.DeleteFunc(order, func(i int) bool {
		if seen[i] {
			return true
		}
		seen[i] = true
		return false
	})
	// The manager lists every link's servers after the global ones; what no
	// link claims is global: at ifindex 0, on the loopback, or bound to a
	// link resolved has, never one of a link it no longer has.
	unclaimed := slices.Clone(servers)
	known := map[int]bool{0: true, loopbackIfindex: true}
	var r Routing
	for _, i := range order {
		sc, has, ok, err := c.link(i)
		if err != nil {
			return Routing{}, err
		}
		known[i] = has && i != own
		for _, l := range sc.own {
			if k := slices.IndexFunc(unclaimed, func(m busServer) bool { return sameServer(m, l, i) }); k >= 0 {
				unclaimed = slices.Delete(unclaimed, k, k+1)
			}
		}
		if ok {
			sc.Own = i == own
			r.Scopes = append(r.Scopes, sc.Scope)
		}
	}
	global := Scope{DefaultRoute: true, OverTLS: globalTLS != "no"}
	for _, s := range unclaimed {
		if a, ok := s.addrPort(); ok && known[int(s.Ifindex)] {
			global.Servers = append(global.Servers, a)
		}
	}
	for _, d := range domains {
		if d.Ifindex == 0 {
			global.addDomain(d.Domain, d.RouteOnly)
		}
	}
	if len(global.Servers) > 0 {
		r.Scopes = append([]Scope{global}, r.Scopes...)
	}
	delegates, err := c.delegates(globalTLS != "no")
	if err != nil {
		return Routing{}, err
	}
	r.Scopes = append(r.Scopes, delegates...)
	if len(global.Servers) == 0 && !slices.ContainsFunc(r.Scopes, func(sc Scope) bool { return sc.DefaultRoute && len(sc.Servers) > 0 }) {
		var fallback []busServer
		if err := c.property(c.obj, manager, "FallbackDNSEx", &fallback); err != nil && !absent(err) {
			return Routing{}, err
		}
		global.Domains, global.Search = nil, false
		for _, s := range fallback {
			if a, ok := s.addrPort(); ok {
				global.Servers = append(global.Servers, a)
			}
		}
		if len(global.Servers) > 0 {
			r.Scopes = append(r.Scopes, global)
		}
	}
	var again []busServer
	if err := c.property(c.obj, manager, "DNSEx", &again); err != nil {
		return Routing{}, err
	}
	if !slices.EqualFunc(servers, again, func(a, b busServer) bool {
		return a.Ifindex == b.Ifindex && a.Family == b.Family && slices.Equal(a.Address, b.Address) && a.Port == b.Port && a.Name == b.Name
	}) {
		return Routing{}, errChanging
	}
	return r, nil
}

// A readLink is a link's scope as resolved has it, and the servers its
// DNSEx lists.
type readLink struct {
	Scope
	own []linkServer
}

// link reads the link at ifindex: has, where resolved has it, its servers
// whether or not it has a DNS scope, and ok where it has one.
func (c *Client) link(ifindex int) (_ readLink, has, ok bool, _ error) {
	path, err := c.linkPath(ifindex)
	var e dbus.Error
	if errors.As(err, &e) && e.Name == busName+".NoSuchLink" {
		return readLink{}, false, false, nil
	}
	if err != nil {
		return readLink{}, false, false, err
	}
	props, err := c.all(c.conn.Object(busName, path), busName+".Link")
	if err != nil {
		return readLink{}, false, false, err
	}
	rl := readLink{Scope: Scope{Ifindex: ifindex}}
	var mask uint64
	var domains []struct {
		Domain    string
		RouteOnly bool
	}
	var tls string
	if err := cmp.Or(stored(props, "DNSEx", &rl.own), stored(props, "ScopesMask", &mask), stored(props, "Domains", &domains),
		stored(props, "DefaultRoute", &rl.DefaultRoute), stored(props, "DNSOverTLS", &tls)); err != nil {
		return readLink{}, false, false, err
	}
	if mask&scopeDNS == 0 {
		return rl, true, false, nil
	}
	for _, l := range rl.own {
		if a, ok := (busServer{Ifindex: int32(ifindex), Family: l.Family, Address: l.Address, Port: l.Port}).addrPort(); ok {
			rl.Servers = append(rl.Servers, a)
		}
	}
	for _, d := range domains {
		rl.addDomain(d.Domain, d.RouteOnly)
	}
	rl.OverTLS = tls != "no"
	return rl, true, true, nil
}

// all is every property of obj's iface, in one call.
func (c *Client) all(obj dbus.BusObject, iface string) (map[string]dbus.Variant, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var m map[string]dbus.Variant
	err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, iface).Store(&m)
	return m, err
}

// stored stores props' name in out.
func stored(props map[string]dbus.Variant, name string, out any) error {
	v, ok := props[name]
	if !ok {
		return fmt.Errorf("systemd-resolved has no %s", name)
	}
	return v.Store(out)
}

func (sc *Scope) addDomain(domain string, routeOnly bool) {
	name := strings.Trim(domain, ".")
	sc.Domains = append(sc.Domains, name)
	sc.Search = sc.Search || !routeOnly && name != ""
}

// delegates are resolved's delegates' scopes, none where it has none to
// list; overTLS is resolved's own setting, which theirs is.
func (c *Client) delegates(overTLS bool) ([]Scope, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var listed []struct {
		ID   string
		Path dbus.ObjectPath
	}
	if err := c.obj.CallWithContext(ctx, manager+".ListDelegates", 0).Store(&listed); err != nil {
		if absent(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Scope
	for _, l := range listed {
		obj, iface := c.conn.Object(busName, l.Path), busName+".DnsDelegate"
		sc := Scope{Delegate: l.ID, OverTLS: overTLS}
		var servers []busServer
		if err := c.property(obj, iface, "DNS", &servers); err != nil {
			return nil, err
		}
		for _, s := range servers {
			if a, ok := s.addrPort(); ok {
				sc.Servers = append(sc.Servers, a)
			}
		}
		var domains []struct {
			Domain    string
			RouteOnly bool
		}
		if err := c.property(obj, iface, "Domains", &domains); err != nil {
			return nil, err
		}
		for _, d := range domains {
			sc.addDomain(d.Domain, d.RouteOnly)
		}
		if err := c.property(obj, iface, "DefaultRoute", &sc.DefaultRoute); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

func cmpPort(p uint16) uint16 {
	if p == 0 {
		return 53
	}
	return p
}

func (c *Client) linkPath(ifindex int) (dbus.ObjectPath, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var path dbus.ObjectPath
	err := c.obj.CallWithContext(ctx, manager+".GetLink", 0, int32(ifindex)).Store(&path)
	return path, err
}

func (c *Client) property(obj dbus.BusObject, iface, name string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v); err != nil {
		return err
	}
	return v.Store(out)
}

const (
	typeA    = 1
	typeAAAA = 28
	typeSVCB = 64
)

// Route is how resolved routes a query of name and type qtype to DNS
// servers, as dns_scope_good_domain does: the servers of the scopes asked,
// in the order read, and whether one of them is asked over TLS. It is
// [ErrNeverResolved], [ErrNotUnicast] or [ErrNoServers] where resolved would
// ask no DNS server, [ErrOwn] where it would ask juistd's alone. The local
// host's own name, /etc/hosts and what the stub refuses are the caller's to
// refuse.
func (r Routing) Route(name string, qtype uint16) (_ []netip.AddrPort, overTLS bool, _ error) {
	b := []byte(strings.Trim(name, "."))
	for k := range b {
		b[k] = lower(b[k])
	}
	name = string(b)
	if neverResolved(name) {
		return nil, false, ErrNeverResolved
	}
	single := name != "" && !strings.Contains(name, ".")
	// A query with DO set, whose single labels resolved's stub relaxes, is
	// held to the same rules: refused where it differs.
	if local(name, qtype) || (single || name == "") && (qtype == typeA || qtype == typeAAAA) {
		return nil, false, ErrNotUnicast
	}
	addr, isAddr := reverseAddr(name)
	const no, maybe = -2, -1
	best := no
	got := make([]int, len(r.Scopes))
	for k, sc := range r.Scopes {
		m := no
		n := -1
		for _, d := range sc.Domains {
			// juistd's own domains route what it forwards elsewhere; its
			// "~." takes every name all the same.
			if !sc.Own || d == "" {
				n = max(n, matches(name, d))
			}
		}
		switch {
		case len(sc.Servers) == 0:
		case sc.Search && single && !sc.Own:
			m = 1
		case n >= 0:
			m = n
		case linkLocalReverse(name) || matches(name, "local") >= 0:
		case isAddr && slices.ContainsFunc(sc.Subnets, func(p netip.Prefix) bool { return p.Contains(addr) }):
			m = 0
		case sc.DefaultRoute:
			m = maybe
		}
		got[k], best = m, max(best, m)
	}
	// LLMNR takes a single label by one label too, before any DNS scope
	// but one that takes it as much; it is asked no DNSSEC, SOA or NS.
	if best == no && !slices.ContainsFunc(r.Scopes, func(sc Scope) bool { return len(sc.Servers) > 0 && !sc.Own }) {
		return nil, false, ErrNoServers
	}
	if best == no || single && best < 1 && !slices.Contains(notLLMNR, qtype) {
		return nil, false, ErrNotUnicast
	}
	var out []netip.AddrPort
	for k, sc := range r.Scopes {
		if got[k] == best && !sc.Own {
			out = append(out, sc.Servers...)
			overTLS = overTLS || sc.OverTLS
		}
	}
	if len(out) == 0 {
		return nil, false, ErrOwn
	}
	return out, overTLS, nil
}

// notLLMNR are the types resolved asks no LLMNR of: SOA, NS and DNSSEC's.
var notLLMNR = []uint16{6, 2, 43, 48, 46, 47, 50, 51}

// neverResolved reports whether resolved answers name NXDOMAIN itself.
func neverResolved(name string) bool {
	return matches(name, "0.in-addr.arpa") >= 0 || name == "255.255.255.255.in-addr.arpa" ||
		name == strings.Repeat("0.", 32)+"ip6.arpa" || matches(name, "invalid") >= 0 || matches(name, "alt") >= 0
}

// local reports whether resolved answers name of type qtype from the local
// host alone.
func local(name string, qtype uint16) bool {
	switch name {
	case "localhost", "localhost.localdomain", "_gateway", "_outbound", "_localdnsstub", "_localdnsproxy",
		"1." + strings.Repeat("0.", 31) + "ip6.arpa":
		return true
	case "_dns.resolver.arpa":
		return qtype != typeSVCB
	}
	return strings.HasSuffix(name, ".localhost") || strings.HasSuffix(name, ".localhost.localdomain") ||
		matches(name, "127.in-addr.arpa") >= 0 || matches(name, "resolver.arpa") >= 0
}

// linkLocalReverse reports whether name is under a link-local address's
// reverse zone, which resolved asks LLMNR and mDNS of.
func linkLocalReverse(name string) bool {
	for _, z := range []string{"254.169.in-addr.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa"} {
		if matches(name, z) >= 0 {
			return true
		}
	}
	return false
}

// reverseAddr is the address whose whole reverse name name is.
func reverseAddr(name string) (netip.Addr, bool) {
	if v4, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		l := strings.Split(v4, ".")
		if len(l) != 4 {
			return netip.Addr{}, false
		}
		slices.Reverse(l)
		a, err := netip.ParseAddr(strings.Join(l, "."))
		return a, err == nil && a.Is4()
	}
	if v6, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		l := strings.Split(v6, ".")
		if len(l) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for k, nib := range l {
			v, err := strconv.ParseUint(nib, 16, 4)
			if err != nil || len(nib) != 1 {
				return netip.Addr{}, false
			}
			i := 31 - k
			b[i/2] |= byte(v) << (4 * (1 - i%2))
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// matches is how many labels of domain, "" for the root, name is under, -1
// where it is under none of it. domain is escaped as resolved writes it, a
// dot within a label as \.; name, as a query's, has no dot in a label.
func matches(name, domain string) int {
	d := labels(domain)
	var n []string
	if name != "" {
		n = strings.Split(name, ".")
	}
	if len(d) > len(n) {
		return -1
	}
	for k, l := range d {
		if n[len(n)-len(d)+k] != l {
			return -1
		}
	}
	return len(d)
}

// labels are domain's labels, unescaped and lowercase.
func labels(domain string) []string {
	var out []string
	var l []byte
	for k := 0; k < len(domain); k++ {
		switch c := domain[k]; {
		case c == '.':
			out, l = append(out, string(l)), nil
		case c == '\\' && k+3 < len(domain) && isDigit(domain[k+1]) && isDigit(domain[k+2]) && isDigit(domain[k+3]):
			v, _ := strconv.Atoi(domain[k+1 : k+4])
			l, k = append(l, lower(byte(v))), k+3
		case c == '\\' && k+1 < len(domain):
			l, k = append(l, lower(domain[k+1])), k+1
		default:
			l = append(l, lower(c))
		}
	}
	if len(l) > 0 {
		out = append(out, string(l))
	}
	return out
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
