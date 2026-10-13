package daemon

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/dnsfwd"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/internal/resolved"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
	"golang.org/x/net/dns/dnsmessage"
)

// domainsHostDNS is a host resolver that routes domains, as resolved does.
type domainsHostDNS struct{ fakeHostDNS }

func (*domainsHostDNS) routesDomains() bool { return true }

// fakeNames is a names server that records how it was started, and fails
// where err is set.
type fakeNames struct {
	mu       sync.Mutex
	at       netip.AddrPort
	answer   func([]byte) []byte
	upstream func([]byte) []netip.AddrPort
	closed   bool
	err      error
}

func (f *fakeNames) start(at netip.AddrPort, answer func([]byte) []byte, upstream func([]byte) []netip.AddrPort) (io.Closer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.at, f.answer, f.upstream = at, answer, upstream
	return f, nil
}

func (f *fakeNames) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func nameQuery(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// Where the host routes domains, juist's resolver answers it the network's
// names: the host routes the network's domain and searches it, and every
// name besides while an exit node is used, which the resolver then asks;
// else the host's own resolvers, not the stub. Closed, it all goes back.
func TestTheHostResolvesTheNetworksNames(t *testing.T) {
	uplink := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(uplink, []byte("nameserver 127.0.0.53\nnameserver 10.0.2.3\n"), 0o644)
	was := UplinkResolvConf
	UplinkResolvConf = uplink
	t.Cleanup(func() { UplinkResolvConf = was })
	host, served := &domainsHostDNS{}, &fakeNames{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ServeNames = host, served.start })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	r := host.routing
	host.mu.Unlock()
	at := netip.AddrPortFrom(f.auth.State().Addr6(f.self.record.Identity), NamesPort)
	want := DNSRouting{Servers: []netip.AddrPort{at}, Domains: []string{"m2-testnet.juist"},
		Search: []string{"m2-testnet.juist"}}
	if !r.equal(want) {
		t.Fatalf("routed %+v, want %+v", r, want)
	}
	if served.at != at {
		t.Errorf("answers at %v", served.at)
	}
	if n := f.d.Status().Names; n == nil || !reflect.DeepEqual(*n, ipc.Names{Domain: "m2-testnet.juist", Resolved: true}) {
		t.Errorf("the status says %+v", n)
	}
	if got := served.upstream(nameQuery(t, "mx.example.net.")); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("10.0.2.3:53")}) {
		t.Errorf("asks %v upstream, want the host's own resolver alone", got)
	}
	resp := served.answer(nameQuery(t, "n1.m2-testnet.juist."))
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil || len(m.Answers) != 1 {
		t.Fatalf("n1 is answered %+v, %v", m, err)
	}
	if got := netip.AddrFrom16(m.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA); got != f.auth.State().Addr6(f.nw.devices[1].record.Identity) {
		t.Errorf("n1 is %v", got)
	}

	exit := f.nw.devices[1]
	f.learnExitDNS(t, exit, 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	r = host.routing
	host.mu.Unlock()
	if !r.Everything || !slices.Equal(r.Servers, want.Servers) {
		t.Errorf("with an exit node, routed %+v", r)
	}
	exitDNS := []netip.AddrPort{netip.AddrPortFrom(*exit.record.V4, DefaultDNSPort),
		netip.AddrPortFrom(f.auth.State().Addr6(exit.record.Identity), DefaultDNSPort)}
	if up := served.upstream(nameQuery(t, "mx.example.net.")); len(up) != 2 || !slices.Contains(up, exitDNS[0]) || !slices.Contains(up, exitDNS[1]) {
		t.Errorf("with an exit node, asks %v upstream, want %v", up, exitDNS)
	}

	f.d.closeDNS()
	host.mu.Lock()
	calls := host.calls
	host.mu.Unlock()
	if calls[len(calls)-1] != "revert" || !served.closed {
		t.Errorf("closed, the host was told %q and the resolver closed %v", calls, served.closed)
	}
}

// A resolver that will not start leaves the host's DNS to the exit node
// alone, as without names.
func TestNamesThatWillNotStartLeaveTheExitNode(t *testing.T) {
	host, served := &domainsHostDNS{}, &fakeNames{err: errors.New("address in use")}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ServeNames = host, served.start })
	exit := f.nw.devices[1]
	f.learnExitDNS(t, exit, 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	r := host.routing
	host.mu.Unlock()
	if !r.Everything || len(r.Domains) != 0 || slices.Contains(r.Servers, f.d.namesAt) {
		t.Errorf("routed %+v", r)
	}
	if n := f.d.Status().Names; n == nil || n.Resolved || n.Cannot || n.Not != "address in use" {
		t.Errorf("the status says %+v", n)
	}
}

// Where the network's names cannot resolve, the status says why.
func TestNamesNotResolvedAreSaid(t *testing.T) {
	for _, tc := range []struct {
		name   string
		host   HostDNS
		uplink bool
		want   ipc.Names
	}{
		{"no domains", &fakeHostDNS{}, false, ipc.Names{Domain: "m2-testnet.juist", Not: errNoDomains.Error(), Cannot: true}},
		{"refused", &domainsHostDNS{fakeHostDNS{err: resolved.ErrNotAuthorized}}, false,
			ipc.Names{Domain: "m2-testnet.juist", Not: "systemd-resolved refused juistd"}},
		{"uplink mode", &domainsHostDNS{}, true, ipc.Names{Domain: "m2-testnet.juist"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served := &fakeNames{}
			f := exitFixture(t, 1, -1, func(o *Options) {
				o.HostDNS, o.ServeNames = tc.host, served.start
				if tc.uplink {
					o.ResolvConf = filepath.Join(t.TempDir(), "resolv.conf")
					os.WriteFile(o.ResolvConf, []byte(uplinkHeader+" man:systemd-resolved(8)\nnameserver 10.0.2.3\n"), 0o644)
				}
			})
			if err := f.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
			n := f.d.Status().Names
			if n == nil {
				t.Fatal("the status says nothing of names")
			}
			if tc.uplink {
				if n.Resolved || !strings.Contains(n.Not, "uplink mode") {
					t.Errorf("the status says %+v", n)
				}
				return
			}
			if !reflect.DeepEqual(*n, tc.want) {
				t.Errorf("the status says %+v, want %+v", n, tc.want)
			}
		})
	}
}

// namesFixture is a network of three whose n1 the log points mx.example.net
// at, on a host that routes domains, n0 accepting names where accept.
func namesFixture(t *testing.T, accept bool) (*reconcileFixture, *domainsHostDNS, *fakeNames) {
	t.Helper()
	host, served := &domainsHostDNS{}, &fakeNames{}
	f := exitFixtureWith(t, func(nw *network) { nw.devices[1].record.Names = []string{"mx.example.net"} },
		func(o *Options) { o.HostDNS, o.ServeNames, o.AcceptNames = host, served.start, accept })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	return f, host, served
}

// answeredA is the IPv4 address served answers name with, nil where it
// passes the query upstream, and invalid where it answers none.
func answeredA(t *testing.T, served *fakeNames, name string) *netip.Addr {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	resp := served.answer(q)
	if resp == nil {
		return nil
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	var a netip.Addr
	if len(m.Answers) > 0 {
		a = netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A)
	}
	return &a
}

func routedNow(h *domainsHostDNS) DNSRouting {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.routing
}

// A public name is resolved to its member only once the owner agreed, and
// while the member is reachable: until then, and when it is not, the host
// resolves it as without juist, and the status says why.
func TestAPublicNameNeedsTheOwnersWord(t *testing.T) {
	f, host, served := namesFixture(t, false)
	if r := routedNow(host); slices.Contains(r.Domains, "mx.example.net") {
		t.Errorf("not agreed, the host routes %v", r.Domains)
	}
	if a := answeredA(t, served, "mx.example.net."); a != nil {
		t.Errorf("not agreed, mx.example.net is %v", a)
	}
	n := f.d.Status().Names
	if n == nil || n.Accepted || len(n.Overrides) != 1 || n.Overrides[0] != (ipc.NameOverride{Name: "mx.example.net", Device: "n1"}) {
		t.Fatalf("not agreed, the status says %+v", n)
	}

	f.d.SetAcceptNames(true)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if r := routedNow(host); !slices.Equal(r.Domains, []string{"m2-testnet.juist", "mx.example.net"}) || r.Everything {
		t.Errorf("agreed, the host routes %+v", r)
	}
	if a := answeredA(t, served, "mx.example.net."); a != nil {
		t.Errorf("before n1 was reached, mx.example.net is %v", a)
	}
	if n := f.d.Status().Names; !n.Accepted || n.Overrides[0].Not != "n1 is not reachable" {
		t.Errorf("before n1 was reached, the status says %+v", n)
	}

	n1 := f.nw.devices[1].record.Identity
	f.d.reachable.Store(&map[types.Identity]bool{n1: true})
	if a := answeredA(t, served, "MX.example.net."); a == nil || *a != *f.nw.devices[1].record.V4 {
		t.Errorf("n1 reached, mx.example.net is %v", a)
	}
	if n := f.d.Status().Names; n.Overrides[0].Not != "" {
		t.Errorf("n1 reached, the status says %+v", n)
	}
	f.d.reachable.Store(&map[types.Identity]bool{n1: false})
	if a := answeredA(t, served, "mx.example.net."); a != nil {
		t.Errorf("n1 lost, mx.example.net is %v", a)
	}
}

// A stale view answers no public name, whether it went stale before the
// zone was made or after.
func TestAStaleViewAnswersNoPublicName(t *testing.T) {
	f, _, _ := namesFixture(t, true)
	state := f.auth.State()
	n1 := f.nw.devices[1].record.Identity
	f.d.reachable.Store(&map[types.Identity]bool{n1: true})
	now := time.Now().Unix()
	for _, tc := range []struct {
		name  string
		fresh log.Freshness
		want  bool
	}{
		{"not enforced", log.Freshness{}, true},
		{"fresh", log.Freshness{Signers: 1, Until: now + 60}, true},
		{"stale", log.Freshness{Signers: 1, Until: now - 1}, false},
	} {
		z, held, until := f.d.namesZone(state, policy.View{}, tc.fresh, true, now, func(types.Identity) bool { return false })
		if _, ok := z.Overrides["mx.example.net"]; ok != tc.want || len(held) != 1 {
			t.Errorf("%s: the zone overrides %v, holding %v", tc.name, z.Overrides, held)
		}
		if got := f.d.overrideNot(held[0], until) == ""; got != tc.want {
			t.Errorf("%s: answered %v", tc.name, got)
		}
	}
	z, held, until := f.d.namesZone(state, policy.View{}, log.Freshness{Signers: 1, Until: now + 1}, true, now, func(types.Identity) bool { return false })
	if !z.Up(n1.String()) {
		t.Fatal("fresh, the override is not up")
	}
	if why := f.d.overrideNot(held[0], until-2); why != "this device's view of the network is stale" {
		t.Errorf("gone stale, the override is %q", why)
	}
}

// A device that cannot tell who is a member resolves none of their names.
func TestNoMemberNoNames(t *testing.T) {
	f, host, served := namesFixture(t, true)
	f.d.reachable.Store(&map[types.Identity]bool{f.nw.devices[1].record.Identity: true})
	f.d.teardown(ipc.Derived{NotMember: true}, "for the test")
	if r := routedNow(host); !r.empty() {
		t.Errorf("torn down, the host routes %+v", r)
	}
	if a := answeredA(t, served, "mx.example.net."); a != nil {
		t.Errorf("torn down, mx.example.net is %v", a)
	}
	if a := answeredA(t, served, "n1.m2-testnet.juist."); a != nil {
		t.Errorf("torn down, n1 is %v", a)
	}
	if n := f.d.Status().Names; n != nil {
		t.Errorf("torn down, the status says %+v", n)
	}
}

// The owner's word on public names is kept, and a reset forgets it with the
// network.
func TestTheNamesWordIsKept(t *testing.T) {
	nw := newNetwork(t, 2)
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	on, off := true, false
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdNames, AcceptNames: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.NamesFile)); err != nil {
		t.Errorf("the word is not kept: %v", err)
	}
	f.s.mu.Lock()
	accepted := f.s.acceptNames
	f.s.mu.Unlock()
	if !accepted {
		t.Error("the service does not hold the word")
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdNames, AcceptNames: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.NamesFile)); !os.IsNotExist(err) {
		t.Errorf("taken back, the word is kept: %v", err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdNames, AcceptNames: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdReset, Force: true}); err != nil {
		t.Fatal(err)
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.acceptNames {
		t.Error("the service holds on to the word after a reset")
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.NamesFile)); !os.IsNotExist(err) {
		t.Errorf("a reset left the word: %v", err)
	}
}

// An exit node asks the host's resolvers, not its stub, for a member's query
// of a name its own zone overrides, so that no member is answered an
// override it did not agree to.
func TestAnExitNodeHandsNoOverrideOn(t *testing.T) {
	uplink := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(uplink, []byte("nameserver 127.0.0.53\nnameserver 10.0.2.3\n"), 0o644)
	was := UplinkResolvConf
	UplinkResolvConf = uplink
	t.Cleanup(func() { UplinkResolvConf = was })
	host := hostResolvConf(t, "nameserver 10.0.2.9\n")
	f, _, _ := namesFixture(t, true)
	up := netip.MustParseAddrPort("10.0.2.3:53")
	for name, want := range map[string][]netip.AddrPort{
		"mx.example.net.": {up}, "MX.Example.net.": {up}, "a.mx.example.net.": {up},
		"example.net.": host, "www.example.net.": host, "n1.m2-testnet.juist.": host,
	} {
		if got := f.d.membersUpstreamFor(nameQuery(t, name)); !slices.Equal(got, want) || (want != nil) != (got != nil) {
			t.Errorf("%s is asked of %v, want %v", name, got, want)
		}
	}
	os.Remove(uplink)
	if got := f.d.membersUpstreamFor(nameQuery(t, "mx.example.net.")); got == nil || len(got) != 0 {
		t.Errorf("without the host's resolvers, an overridden name is asked of %v, want none", got)
	}
}

// hostResolvConf has the host's resolv.conf say text, for the test, and is
// the resolvers it names.
func hostResolvConf(t *testing.T, text string) []netip.AddrPort {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(path, []byte(text), 0o644)
	was := dnsfwd.ResolvConf
	dnsfwd.ResolvConf = path
	t.Cleanup(func() { dnsfwd.ResolvConf = was })
	return dnsfwd.HostResolvers()
}

// Where the host's resolver does not ask juist's, as without resolved, an
// exit node asks a member's overridden name of the host's resolvers, which
// know no override, rather than of none: whether juist's resolver did not
// start, or started and resolved could not be told of it.
func TestAnExitNodeWithoutNamesAsksTheHostsResolvers(t *testing.T) {
	was := UplinkResolvConf
	UplinkResolvConf = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { UplinkResolvConf = was })
	want := hostResolvConf(t, "nameserver 10.0.2.9\n")
	for name, tc := range map[string]struct {
		names error
		host  error
	}{
		"no resolver of juist's": {names: errors.New("no address")},
		"no resolved":            {host: resolved.ErrNotRunning},
	} {
		t.Run(name, func(t *testing.T) {
			served := &fakeNames{err: tc.names}
			host := &domainsHostDNS{fakeHostDNS{err: tc.host}}
			f := exitFixtureWith(t, func(nw *network) { nw.devices[1].record.Names = []string{"mx.example.net"} },
				func(o *Options) { o.HostDNS, o.ServeNames, o.AcceptNames = host, served.start, true })
			if err := f.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if z := f.d.zone.Load(); z == nil || !z.Overridden(nameQuery(t, "mx.example.net.")) {
				t.Fatal("the zone overrides no mx.example.net")
			}
			if got := f.d.membersUpstreamFor(nameQuery(t, "mx.example.net.")); !slices.Equal(got, want) {
				t.Errorf("an overridden name is asked of %v, want the host's %v", got, want)
			}
		})
	}
}

// An exit node asks nothing of tailscaled for a member, whose answer would
// come from the host's tailnet, out of the member's reach: where tailscaled
// wrote resolv.conf, the resolvers it replaced are asked; where resolved
// routes the tailnet's domain to tailscaled, its other links are.
func TestAnExitNodeAsksNothingOfTailscaled(t *testing.T) {
	ap := netip.MustParseAddrPort
	q := nameQuery(t, "devvm.example-tail.ts.net.")

	pre := filepath.Join(t.TempDir(), "resolv.pre-tailscale-backup.conf")
	os.WriteFile(pre, []byte("nameserver 185.12.64.1\nnameserver 185.12.64.2\n"), 0o644)
	was := PreTailscaleResolvConf
	PreTailscaleResolvConf = pre
	t.Cleanup(func() { PreTailscaleResolvConf = was })
	hostResolvConf(t, "nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\nsearch example-tail.ts.net\n")
	f := exitFixtureWith(t, func(*network) {}, func(o *Options) { o.HostDNS = &fakeHostDNS{err: resolved.ErrNotRunning} })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, want := f.d.membersUpstreamFor(q), []netip.AddrPort{ap("185.12.64.1:53"), ap("185.12.64.2:53")}; !slices.Equal(got, want) {
		t.Errorf("without resolved, a member's tailnet name is asked of %v, want %v", got, want)
	}

	hostResolvConf(t, "nameserver 127.0.0.53\n")
	f.d.hostRouting.Store(&resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true},
		{Ifindex: 7, Servers: []netip.AddrPort{ap("100.100.100.100:53")}, Domains: []string{"example-tail.ts.net"}, DefaultRoute: true},
	}})
	if got, want := f.d.membersUpstreamFor(q), []netip.AddrPort{ap("10.0.2.3:53")}; !slices.Equal(got, want) {
		t.Errorf("through resolved, a member's tailnet name is asked of %v, want %v", got, want)
	}
}

// routingHostDNS routes domains and has its routing read, failing with err.
type routingHostDNS struct {
	domainsHostDNS
	r   resolved.Routing
	err error
}

func (h *routingHostDNS) routing() (resolved.Routing, error) { return h.r, h.err }

// What juistd's resolver does not answer, without an exit node, it asks the
// resolvers resolved would, by the host's routing: a public name's own link
// where one claims it, as a VPN's; and the host's resolvers in turn where
// the routing cannot be read.
func TestWhatIsNotAnsweredGoesWhereTheHostRoutesIt(t *testing.T) {
	uplink := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(uplink, []byte("nameserver 10.0.2.3\n"), 0o644)
	was := UplinkResolvConf
	UplinkResolvConf = uplink
	t.Cleanup(func() { UplinkResolvConf = was })
	ap := netip.MustParseAddrPort
	host := &routingHostDNS{r: resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true},
		{Ifindex: 5, Servers: []netip.AddrPort{ap("10.99.2.2:53")}, Domains: []string{"example.net"}},
	}}}
	served := &fakeNames{}
	f := exitFixtureWith(t, func(nw *network) { nw.devices[1].record.Names = []string{"mx.example.net"} },
		func(o *Options) { o.HostDNS, o.ServeNames, o.AcceptNames = host, served.start, true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]netip.AddrPort{"mx.example.net.": ap("10.99.2.2:53"), "example.org.": ap("10.0.2.3:53")} {
		if got := served.upstream(nameQuery(t, name)); !slices.Equal(got, []netip.AddrPort{want}) {
			t.Errorf("%s is asked of %v, want %v", name, got, want)
		}
	}
	if got := f.d.membersUpstreamFor(nameQuery(t, "mx.example.net.")); !slices.Equal(got, []netip.AddrPort{ap("10.99.2.2:53")}) {
		t.Errorf("a member's mx.example.net is asked of %v", got)
	}

	host.err = errors.New("no bus")
	f.d.dnsMu.Lock()
	f.d.hostRoutingAt = time.Time{}
	f.d.readHostRoutingLocked()
	f.d.dnsMu.Unlock()
	if got := served.upstream(nameQuery(t, "mx.example.net.")); !slices.Equal(got, []netip.AddrPort{ap("10.0.2.3:53")}) {
		t.Errorf("the routing unread, mx.example.net is asked of %v", got)
	}
}

// juistd's resolver answers on an address the device holds: IPv6, else, on a
// host without it, the current IPv4 address; on none, it does not start.
func TestTheNamesAddressIsOneTheDeviceHolds(t *testing.T) {
	p := netip.MustParsePrefix
	addrs := []netip.Prefix{p("fd12::5/128"), p("198.18.0.9/32"), p("198.18.0.5/32")}
	for _, tc := range []struct {
		held []string
		want string
	}{
		{[]string{"fd12::5", "198.18.0.5", "198.18.0.9"}, "[fd12::5]:41647"},
		{[]string{"198.18.0.5", "198.18.0.9"}, "198.18.0.5:41647"},
		{[]string{"198.18.0.9"}, "198.18.0.9:41647"},
		{nil, ""},
	} {
		held := func(a netip.Addr) bool { return slices.Contains(tc.held, a.String()) }
		at, ok := namesAddrOf(addrs, held)
		if got := map[bool]string{true: at.String(), false: ""}[ok]; got != tc.want {
			t.Errorf("holding %v, answers at %q, want %q", tc.held, got, tc.want)
		}
	}
	d := &Daemon{tunName: "lo"}
	d.held.Store(&addrs)
	if at, err := d.namesAddrNow(); err == nil {
		t.Errorf("answers at %v, which the device does not hold", at)
	}
}

// A renamed device is answered by its new name once the record is applied,
// and its old name by none.
func TestARenamedDeviceIsAnsweredByItsNewName(t *testing.T) {
	f, _, served := namesFixture(t, false)
	n1 := f.nw.devices[1].record
	if a := answeredA(t, served, "n1.m2-testnet.juist."); a == nil || *a != *n1.V4 {
		t.Fatalf("n1 is %v, want %v", a, *n1.V4)
	}
	rec, err := f.auth.Builder().RenameNode(n1.Identity, "storage")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(f.nw.admin, f.auth.State().Schema()); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if a := answeredA(t, served, "storage.m2-testnet.juist."); a == nil || *a != *n1.V4 {
		t.Errorf("renamed, storage is %v, want %v", a, *n1.V4)
	}
	if a := answeredA(t, served, "n1.m2-testnet.juist."); a == nil || a.IsValid() {
		t.Errorf("renamed, n1 is %v, want no address", a)
	}
}

// The status names the network's public domain beside its own, which the
// host resolves through juistd alike.
func TestTheStatusNamesThePublicDomain(t *testing.T) {
	served := &fakeNames{}
	f := exitFixtureWith(t, func(nw *network) { nw.domain = "pub.example.org" },
		func(o *Options) { o.HostDNS, o.ServeNames = &fakeHostDNS{}, served.start })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	want := ipc.Names{Domain: "m2-testnet.juist", Public: "pub.example.org", Not: errNoDomains.Error(), Cannot: true}
	if n := f.d.Status().Names; n == nil || !reflect.DeepEqual(*n, want) {
		t.Errorf("the status says %+v, want %+v", n, want)
	}
}

// juistd's resolver passes on a public name it does not answer with a TTL
// no longer than its own answers', so that the name, once published, is
// answered by it soon.
func TestTheNamesServerPassesOnShortTTLs(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, _ := p.Start(buf[:n])
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AAAAResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 38400},
				dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()})
			m, _ := b.Finish()
			pc.WriteTo(m, src)
		}
	}()
	up := netip.MustParseAddrPort(pc.LocalAddr().String())
	s, err := defaultNamesServer("")(netip.MustParseAddrPort("127.0.0.1:0"),
		func([]byte) []byte { return nil }, func([]byte) []netip.AddrPort { return []netip.AddrPort{up} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.(*dnsfwd.Forwarder).Port()).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(nameQuery(t, "status.example.org."))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil || len(m.Answers) != 1 {
		t.Fatalf("answer %+v, %v", m, err)
	}
	if ttl := m.Answers[0].Header.TTL; ttl != names.TTL {
		t.Errorf("passed on with TTL %d, want %d", ttl, names.TTL)
	}
}
