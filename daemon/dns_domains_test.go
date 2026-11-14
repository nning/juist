package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

type domainsCall struct {
	servers         []netip.Addr
	port            uint16
	domains, search []string
}

type recordingDomains struct {
	calls []domainsCall
	dns   [][]netip.Addr // each SetDNS's servers
}

func (r *recordingDomains) SetDNS(_ string, servers []netip.Addr, _ []string) error {
	r.dns = append(r.dns, servers)
	return nil
}

func (r *recordingDomains) SetDomains(_ string, servers []netip.Addr, port uint16, domains, search []string) error {
	r.calls = append(r.calls, domainsCall{servers, port, domains, search})
	return nil
}

// macOS's host DNS hands the helper juist's domains on the resolver's port,
// every name to the default resolver with an exit node, on 53 alone, and
// reverts to none.
func TestDomainsDNSRoutesDomainsAlone(t *testing.T) {
	rec := &recordingDomains{}
	h := domainsDNS{p: rec, dev: "utun100"}
	if !routesDomains(h) {
		t.Fatal("domainsDNS says it routes no domains")
	}
	at := netip.MustParseAddrPort("100.64.0.1:41647")
	err := h.Route(DNSRouting{Servers: []netip.AddrPort{at}, Domains: []string{"home.juist", "64.100.in-addr.arpa"}, Search: []string{"home.juist"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Route(DNSRouting{Servers: []netip.AddrPort{at}, Domains: []string{"home.juist"}, Everything: true}); err == nil {
		t.Error("every name was routed to a port the default resolver cannot ask")
	}
	exit := netip.MustParseAddrPort("100.64.0.1:53")
	if err := h.Route(DNSRouting{Servers: []netip.AddrPort{exit}, Everything: true}); err != nil {
		t.Fatal(err)
	}
	if err := h.Revert(); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 3 {
		t.Fatalf("%d calls, want 3: %+v", len(rec.calls), rec.calls)
	}
	if want := [][]netip.Addr{nil, {exit.Addr()}, nil}; !slices.EqualFunc(rec.dns, want, slices.Equal) {
		t.Errorf("default resolvers: %v, want %v", rec.dns, want)
	}
	c := rec.calls[0]
	if !slices.Equal(c.servers, []netip.Addr{at.Addr()}) || c.port != at.Port() ||
		!slices.Equal(c.domains, []string{"home.juist", "64.100.in-addr.arpa"}) || !slices.Equal(c.search, []string{"home.juist"}) {
		t.Errorf("routed %+v", c)
	}
	for _, c := range rec.calls[1:] {
		if len(c.domains) != 0 || len(c.servers) != 0 {
			t.Errorf("with the exit node alone, then reverted: %+v", c)
		}
	}
}

// A Mac's names count as resolved once routed through /etc/resolver, whatever
// /etc/resolv.conf lists: macOS's resolver reads the files itself.
func TestMacNamesResolveThroughResolverFiles(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(conf, []byte("nameserver 192.168.178.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, served := &recordingDomains{}, &fakeNames{}
	f := exitFixture(t, 1, -1, func(o *Options) {
		o.HostDNS, o.ServeNames, o.ResolvConf = domainsDNS{p: rec, dev: "utun100"}, served.start, conf
	})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) == 0 || len(rec.calls[len(rec.calls)-1].domains) == 0 {
		t.Fatalf("no domains routed: %+v", rec.calls)
	}
	if n := f.d.Status().Names; n == nil || !n.Resolved {
		t.Errorf("names: %+v", n)
	}
}

// Neither the Android app nor a Mac carries multicast, which on a Mac would
// give the device a link-local address its helper refuses.
func TestMulticastIsNotCarriedOnAndroidOrMacOS(t *testing.T) {
	for goos, want := range map[string]bool{"linux": true, "freebsd": true, "android": false, "darwin": false} {
		if got := multicastOn(goos); got != want {
			t.Errorf("multicast on %s: %v, want %v", goos, got, want)
		}
	}
}

// Turning multicast on is refused on a Mac, which would say "multicast on"
// and carry none.
func TestAMacRefusesMulticast(t *testing.T) {
	mac := Options{TunName: "utun100"}
	if err := multicastRefused(mac, "darwin"); err == nil || err.Error() != "a Mac carries no multicast" {
		t.Errorf("on a Mac: %v", err)
	}
	if err := multicastRefused(Options{TunName: "juist0"}, "linux"); err != nil {
		t.Errorf("on Linux: %v", err)
	}
	if err := multicastRefused(Options{TunName: "juist0"}, "android"); err == nil {
		t.Error("the Android app took multicast")
	}
}
