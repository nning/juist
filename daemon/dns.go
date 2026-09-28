package daemon

import (
	"cmp"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/dnsfwd"
	"github.com/nning/juist/internal/resolved"
)

// DefaultDNSPort is where an exit node answers its members' DNS, on its
// overlay addresses alone: UDP and TCP.
const DefaultDNSPort = 41646

// dnsRenewal is how often a host's DNS routing is given again, which a
// restarted resolved forgets.
const dnsRenewal = 5 * time.Minute

// A HostDNS routes the host's DNS through this node's device, to servers,
// for every name the host does not route elsewhere by a longer domain, or
// gives it back.
type HostDNS interface {
	Route(servers []netip.AddrPort) error
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

func (r resolvedDNS) Route(servers []netip.AddrPort) error {
	i, c, err := r.link()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Route(i, servers)
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

// defaultDNSServer answers on the device named dev.
func defaultDNSServer(dev string) DNSServer {
	return func(addrs []netip.Addr, allowed func(netip.Addr) bool) (io.Closer, error) {
		return dnsfwd.Start(dnsfwd.Options{Addrs: addrs, Port: DefaultDNSPort, Device: dev, Allowed: allowed})
	}
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

func (d *Daemon) routeDNSLocked(servers []netip.AddrPort, keep bool) (bool, string) {
	if keep {
		if len(d.dnsRouted) == 0 {
			return false, ""
		}
		servers = d.dnsRouted
	}
	if len(servers) == 0 {
		if len(d.dnsRouted) > 0 && d.hostDNS != nil {
			if err := d.hostDNS.Revert(); err != nil {
				d.logOnce("daemon: giving the host's DNS back: " + err.Error())
			}
		}
		d.dnsRouted, d.dnsWhy = nil, ""
		return false, ""
	}
	if d.hostDNS == nil {
		return false, "juistd runs without a device of its own"
	}
	same := slices.Equal(servers, d.dnsRouted)
	switch {
	case same && d.dnsWhy == "" && d.now().Sub(d.dnsRoutedAt) < dnsRenewal:
		return d.throughStub()
	case same && d.dnsWhy != "" && d.now().Sub(d.dnsRoutedAt) < dnsRetry:
		return false, d.dnsWhy
	}
	// Taken for routed even where it failed half-way, so that going off
	// gives the link back whatever of it resolved took.
	d.dnsRouted, d.dnsRoutedAt, d.dnsWhy = slices.Clone(servers), d.now(), ""
	if err := d.hostDNS.Route(servers); err != nil {
		d.logOnce("daemon: routing the host's DNS through the exit node: " + err.Error())
		switch {
		case errors.Is(err, resolved.ErrNotRunning):
			d.dnsWhy = "systemd-resolved does not run on this host"
		case errors.Is(err, resolved.ErrNotAuthorized):
			d.dnsWhy = "systemd-resolved refused juistd"
		default:
			d.dnsWhy = err.Error()
		}
		return false, d.dnsWhy
	}
	return d.throughStub()
}

// throughStub reports whether the host's programs ask resolved, whose routing
// is then theirs, and why not.
func (d *Daemon) throughStub() (bool, string) {
	path := cmp.Or(d.resolvConf, "/etc/resolv.conf")
	b, err := os.ReadFile(path)
	if err != nil {
		return false, path + " cannot be read"
	}
	var servers []string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
	}
	for _, s := range servers {
		if s != "127.0.0.53" && s != "127.0.0.54" {
			return false, path + " asks " + s + ", not systemd-resolved"
		}
	}
	if len(servers) == 0 {
		return false, path + " names no resolver"
	}
	return true, ""
}

// closeDNS stops answering members' DNS and gives the host's back, for good:
// a reconcile racing Close starts neither again.
func (d *Daemon) closeDNS() {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	d.dnsClosed = true
	d.serveDNSLocked(false, nil, nil)
	d.routeDNSLocked(nil, false)
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
