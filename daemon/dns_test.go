package daemon

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/resolved"
	"github.com/nning/juist/types"
)

// stubResolvConf is a resolv.conf asking resolved's stub.
func stubResolvConf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.53\noptions edns0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeHostDNS records where the host's DNS was routed; err is what routing
// returns.
type fakeHostDNS struct {
	mu      sync.Mutex
	routed  []netip.AddrPort
	routing DNSRouting
	calls   []string
	err     error
}

func (h *fakeHostDNS) Route(r DNSRouting) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "route")
	if h.err != nil {
		return h.err
	}
	h.routed, h.routing = slices.Clone(r.Servers), r
	return nil
}

func (h *fakeHostDNS) Revert() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "revert")
	h.routed, h.routing = nil, DNSRouting{}
	return nil
}

func (h *fakeHostDNS) now() ([]netip.AddrPort, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.routed), slices.Clone(h.calls)
}

// fakeDNSServer records where it answers, and whether it was closed.
type fakeDNSServer struct {
	mu     sync.Mutex
	addrs  []netip.Addr
	closed bool
}

func (s *fakeDNSServer) start(addrs []netip.Addr, allowed func(netip.Addr) bool) (io.Closer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addrs, s.closed = slices.Clone(addrs), false
	if allowed(netip.MustParseAddr("8.8.8.8")) {
		panic("the resolver would answer the internet")
	}
	return s, nil
}

func (s *fakeDNSServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (f *reconcileFixture) learnExitDNS(t *testing.T, dev *device, port uint16, serving bool, dns uint16) {
	t.Helper()
	e, err := endpointFor(dev, port)
	if err != nil {
		t.Fatal(err)
	}
	e.Exit, e.DNS, e.Seq = serving, dns, e.Seq+1
	if err := e.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
}

// While an exit node is in use, the host's DNS goes to its resolver on its
// overlay addresses, refused or not; off, it is given back.
func TestTheHostsDNSGoesThroughTheExitNode(t *testing.T) {
	host := &fakeHostDNS{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS = host })
	exit := f.nw.devices[1]
	f.learnExitDNS(t, exit, 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	state := f.auth.State()
	want := []netip.AddrPort{netip.AddrPortFrom(*exit.record.V4, DefaultDNSPort),
		netip.AddrPortFrom(state.Addr6(exit.record.Identity), DefaultDNSPort)}
	if got, _ := host.now(); len(got) != len(want) || !slices.Contains(got, want[0]) || !slices.Contains(got, want[1]) {
		t.Fatalf("the host's DNS goes to %v, want %v", got, want)
	}
	if st := f.d.Status().Exit; st == nil || !st.DNS || st.DNSNot != "" {
		t.Errorf("the status says %+v", st)
	}
	// Refused, lookups go nowhere rather than to the LAN.
	f.learnExitDNS(t, exit, 7001, false, 0)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, _ := host.now(); len(got) == 0 {
		t.Error("refused, the host's DNS was given back")
	}
	f.d.SetExitChoice(ExitChoice{Chosen: true})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, calls := host.now(); len(got) > 0 || calls[len(calls)-1] != "revert" {
		t.Errorf("off, the host's DNS goes to %v after %v", got, calls)
	}
}

// Where the host's DNS cannot go through the exit node, the status says why.
func TestDNSOutsideTheTunnelIsSaid(t *testing.T) {
	for _, tc := range []struct {
		name string
		dns  uint16
		err  error
		want string
	}{
		{"no resolver", 0, nil, "n1 answers no DNS"},
		{"polkit", DefaultDNSPort, resolved.ErrNotAuthorized, "systemd-resolved refused juistd"},
		{"no resolved", DefaultDNSPort, resolved.ErrNotRunning, "systemd-resolved does not run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHostDNS{err: tc.err}
			f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS = host })
			exit := f.nw.devices[1]
			f.learnExitDNS(t, exit, 7001, true, tc.dns)
			f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
			if err := f.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if st := f.d.Status().Exit; st == nil || st.DNS || !strings.Contains(st.DNSNot, tc.want) || st.Refused != "" {
				t.Errorf("the status says %+v, want %q", st, tc.want)
			}
		})
	}
}

// An exit node answers members' DNS on its overlay addresses while it serves,
// on port 53, which it has the data plane redirect to its forwarder, and says
// so in its announcement; stopping, it answers none.
func TestAnExitNodeAnswersItsMembersDNS(t *testing.T) {
	server := &fakeDNSServer{}
	f := exitFixture(t, 0, -1, func(o *Options) { o.ServeExit, o.ServeDNS = true, server.start })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	addrs := slices.Clone(server.addrs)
	server.mu.Unlock()
	state := f.auth.State()
	if !slices.Contains(addrs, *f.self.record.V4) || !slices.Contains(addrs, state.Addr6(f.self.record.Identity)) {
		t.Fatalf("it answers on %v", addrs)
	}
	if a, _ := f.d.Announcement(); a.DNS != dnsAskedPort {
		t.Errorf("its announcement names port %d", a.DNS)
	}
	if _, s := f.mgr.exitState(); s.DNS != DefaultDNSPort {
		t.Errorf("the data plane redirects DNS to port %d", s.DNS)
	}
	f.d.SetServeConsent(false)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()
	if a, _ := f.d.Announcement(); !closed || a.DNS != 0 {
		t.Errorf("stopped, the resolver is closed %v, announced on %d", closed, a.DNS)
	}
}

// routedFixture is a daemon routing the host's DNS through exit node 1.
func routedFixture(t *testing.T, host *fakeHostDNS, mutate func(*Options)) *reconcileFixture {
	t.Helper()
	f := exitFixture(t, 1, -1, func(o *Options) {
		o.HostDNS = host
		if mutate != nil {
			mutate(o)
		}
	})
	f.learnExitDNS(t, f.nw.devices[1], 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, _ := host.now(); len(got) == 0 {
		t.Fatal("the host's DNS was not routed to begin with")
	}
	return f
}

// Off, the host's DNS comes back even while the data plane is down; an exit
// node that left the network keeps it where it is, as its traffic stays
// refused.
func TestDNSFollowsTheChoiceWhateverTheNetwork(t *testing.T) {
	host := &fakeHostDNS{}
	f := routedFixture(t, host, nil)
	f.mgr.mu.Lock()
	f.mgr.err = errors.New("no peers today")
	f.mgr.mu.Unlock()
	f.d.SetExitChoice(ExitChoice{Chosen: true})
	_ = f.d.Reconcile()
	if got, _ := host.now(); len(got) > 0 {
		t.Errorf("off with the data plane down, the host's DNS goes to %v", got)
	}

	host = &fakeHostDNS{}
	f = routedFixture(t, host, nil)
	rec, err := f.auth.Builder().RemoveNode(f.nw.devices[1].record.Identity, f.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if got, calls := host.now(); len(got) == 0 {
		t.Errorf("the exit node gone, the host's DNS was given back: %v", calls)
	}
	if e, _ := f.mgr.exitState(); e != conn.EgressRefused {
		t.Errorf("egress %v", e)
	}
}

// Where the host's programs do not ask resolved, its routing is none of
// theirs, and the status says so.
func TestDNSAroundResolvedIsSaid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := &fakeHostDNS{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ResolvConf = host, path })
	f.learnExitDNS(t, f.nw.devices[1], 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Exit; st == nil || st.DNS || !strings.Contains(st.DNSNot, "asks 192.168.1.1, not systemd-resolved") {
		t.Errorf("the status says %+v", st)
	}
}

// resolved's list of every link's servers, as Debian's cloud images take for
// resolv.conf, is said for what it is, not by the exit node's address.
func TestResolvedsUplinkModeIsSaid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).\n"+
		"# Do not edit.\n\nnameserver 198.18.0.1\nnameserver 10.0.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := &fakeHostDNS{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ResolvConf = host, path })
	f.learnExitDNS(t, f.nw.devices[1], 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Exit; st == nil || st.DNS || !strings.Contains(st.DNSNot, "every link's servers") {
		t.Errorf("the status says %+v", st)
	}
}

// A failed routing is not tried again on every reconcile.
func TestAFailedDNSRoutingWaits(t *testing.T) {
	host := &fakeHostDNS{err: resolved.ErrNotAuthorized}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS = host })
	f.learnExitDNS(t, f.nw.devices[1], 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
	for range 3 {
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if _, calls := host.now(); len(calls) != 1 {
		t.Errorf("tried %v", calls)
	}
}

// Closed, the daemon neither answers DNS nor routes it again.
func TestAClosedDaemonLeavesDNSAlone(t *testing.T) {
	server := &fakeDNSServer{}
	host := &fakeHostDNS{}
	f := exitFixture(t, 0, -1, func(o *Options) { o.HostDNS, o.ServeDNS = host, server.start })
	f.d.closeDNS()
	if port := f.d.serveDNS(true, []netip.Addr{netip.MustParseAddr("100.64.0.1")}, nil); port != 0 {
		t.Error("a closed daemon answers DNS again")
	}
	if through, _ := f.d.routeDNS([]netip.AddrPort{netip.MustParseAddrPort("100.64.0.2:41646")}, false); through {
		t.Error("a closed daemon routes the host's DNS again")
	}
	if _, calls := host.now(); len(calls) != 0 {
		t.Errorf("the host's DNS was touched: %v", calls)
	}
}

// An exit node without overlay IPv4 is sent the internet's IPv6 alone and
// asked for DNS on IPv6 alone, and the status says IPv4 is refused; it says
// so too of a family the grant leaves out, or this device has none of.
func TestAnExitNodeOfOneFamilyIsSaid(t *testing.T) {
	host := &fakeHostDNS{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS = host })
	exit := f.nw.devices[1]
	e, err := endpointFor(exit, 7001)
	if err != nil {
		t.Fatal(err)
	}
	e.Exit, e.DNS, e.NoV4, e.Seq = true, DefaultDNSPort, true, e.Seq+1
	if err := e.Sign(exit.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if r := f.peerRoutes(t, exit); len(r) == 0 || slices.ContainsFunc(r, func(p netip.Prefix) bool { return p.Addr().Is4() }) {
		t.Errorf("the exit node carries %v", r)
	}
	if got, _ := host.now(); len(got) != 1 || !got[0].Addr().Is6() {
		t.Errorf("the host's DNS goes to %v", got)
	}
	if st := f.d.Status().Exit; st == nil || st.Refused != "" || st.Partly != "IPv4 refused: n1 has no IPv4 in the network" {
		t.Errorf("the status says %+v", st)
	}

	for _, tc := range []struct {
		routes []netip.Prefix
		noV4   bool
		want   string
	}{
		{defaultRoutes[:1], false, "IPv6 refused: n1 carries IPv4 alone"},
		{defaultRoutes[1:], false, "IPv4 refused: n1 carries IPv6 alone"},
		{defaultRoutes, true, "IPv4 refused: this device has no IPv4 in the network"},
	} {
		f = exitFixtureWith(t, func(nw *network) {
			nw.devices[1].record.Roles = []types.Role{types.RoleExit}
			nw.devices[1].record.Routes = tc.routes
		}, func(o *Options) { o.NoV4 = tc.noV4 })
		exit = f.nw.devices[1]
		f.learnExitDNS(t, exit, 7001, true, DefaultDNSPort)
		f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if st := f.d.Status().Exit; st == nil || st.Refused != "" || st.Partly != tc.want {
			t.Errorf("granted %v, without IPv4 %v, the status says %+v", tc.routes, tc.noV4, st)
		}
	}
}

// dnsPlumber records the resolvers a helper is asked for.
type dnsPlumber struct {
	conn.Plumber
	set [][]netip.Addr
}

func (p *dnsPlumber) SetDNS(_ string, servers []netip.Addr) error {
	p.set = append(p.set, servers)
	return nil
}

// Where a helper plumbs the host, as on FreeBSD, its DNS goes to the exit node
// on port 53 alone, which a resolver without ports can ask, and is through
// where resolv.conf asks nothing else.
func TestAHelpersDNSTakesPort53Alone(t *testing.T) {
	p := &dnsPlumber{}
	h := plumbedDNS{p: p, dev: "juist0"}
	at := func(port uint16) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("198.19.44.2"), port)}
	}
	every := func(port uint16) DNSRouting { return DNSRouting{Servers: at(port), Everything: true} }
	if err := h.Route(every(DefaultDNSPort)); err == nil || !strings.Contains(err.Error(), "port 41646") {
		t.Errorf("an exit node on 41646 alone: %v", err)
	}
	if err := h.Route(DNSRouting{Servers: at(53), Domains: []string{"home.juist"}}); !errors.Is(err, errNoDomains) {
		t.Errorf("domains alone: %v", err)
	}
	if err := h.Route(every(53)); err != nil || len(p.set) != 1 || p.set[0][0] != at(53)[0].Addr() {
		t.Errorf("on 53: %v, the helper was asked %v", err, p.set)
	}
	if err := h.Revert(); err != nil || len(p.set) != 2 || len(p.set[1]) != 0 {
		t.Errorf("giving it back: %v, %v", err, p.set)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	os.WriteFile(conf, []byte("# Generated by resolvconf\nnameserver 198.19.44.2\n"), 0o644)
	if ok, why := h.through(conf, at(53)); !ok {
		t.Errorf("through: %s", why)
	}
	os.WriteFile(conf, []byte("nameserver 10.0.2.3\n"), 0o644)
	if ok, why := h.through(conf, at(53)); ok || !strings.Contains(why, "asks 10.0.2.3") {
		t.Errorf("another resolver: %v %s", ok, why)
	}
}
