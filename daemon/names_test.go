package daemon

import (
	"errors"
	"fmt"
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
	upstream func([]byte) ([]netip.AddrPort, error)
	closed   bool
	err      error
}

func (f *fakeNames) start(at netip.AddrPort, answer func([]byte) []byte, upstream func([]byte) ([]netip.AddrPort, error)) (io.Closer, error) {
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

// upsOf is who upstream asks q of, failing the test where it refuses q.
func upsOf(t *testing.T, upstream func([]byte) ([]netip.AddrPort, error), q []byte) []netip.AddrPort {
	t.Helper()
	ups, err := upstream(q)
	if err != nil {
		t.Errorf("refused: %v", err)
	}
	return ups
}

func nameQuery(t *testing.T, name string) []byte {
	t.Helper()
	return typedQuery(t, name, dnsmessage.TypeAAAA)
}

func typedQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET})
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
	if got := upsOf(t, served.upstream, nameQuery(t, "mx.example.net.")); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("10.0.2.3:53")}) {
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
	if up := upsOf(t, served.upstream, nameQuery(t, "mx.example.net.")); len(up) != 2 || !slices.Contains(up, exitDNS[0]) || !slices.Contains(up, exitDNS[1]) {
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
	if !r.Everything || len(r.Domains) != 0 || slices.Contains(r.Servers, f.d.dns.namesAt) {
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

	f.d.changePrefs(func(p *Prefs) { p.AcceptNames = true })
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
	accepted := f.s.prefs.AcceptNames
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
	if f.s.prefs.AcceptNames {
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
		if got := upsOf(t, f.d.membersUpstreamFor, nameQuery(t, name)); !slices.Equal(got, want) || (want != nil) != (got != nil) {
			t.Errorf("%s is asked of %v, want %v", name, got, want)
		}
	}
	os.Remove(uplink)
	if got := upsOf(t, f.d.membersUpstreamFor, nameQuery(t, "mx.example.net.")); got == nil || len(got) != 0 {
		t.Errorf("without the host's resolvers, an overridden name is asked of %v, want none", got)
	}
	os.WriteFile(uplink, []byte("nameserver 100.100.100.100\n"), 0o644)
	if ups, err := f.d.membersUpstreamFor(nameQuery(t, "mx.example.net.")); err == nil {
		t.Errorf("the host's resolvers tailscaled's alone, a member's overridden name is asked of %v", ups)
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
			if got := upsOf(t, f.d.membersUpstreamFor, nameQuery(t, "mx.example.net.")); !slices.Equal(got, want) {
				t.Errorf("an overridden name is asked of %v, want the host's %v", got, want)
			}
		})
	}
}

// An exit node asks nothing of tailscaled for a member, whose answer would
// come from the host's tailnet, out of the member's reach: where tailscaled
// wrote resolv.conf, the resolvers it replaced are asked; where resolved
// routes the tailnet's domain to tailscaled, its names are refused.
func TestAnExitNodeAsksNothingOfTailscaled(t *testing.T) {
	ap := netip.MustParseAddrPort
	q := nameQuery(t, "devvm.example-tail.ts.net.")

	pre := filepath.Join(t.TempDir(), "resolv.pre-tailscale-backup.conf")
	os.WriteFile(pre, []byte("nameserver 185.12.64.1\nnameserver 185.12.64.2\n"), 0o644)
	was := PreTailscaleResolvConf
	PreTailscaleResolvConf = pre
	t.Cleanup(func() { PreTailscaleResolvConf = was })
	hostResolvConf(t, "nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\nsearch example-tail.ts.net\n")
	host := &readHostDNS{plainHostDNS: plainHostDNS{fakeHostDNS{err: resolved.ErrNotRunning}}, routingSource: routingSource{err: resolved.ErrNotRunning}}
	f := exitFixtureWith(t, func(*network) {}, func(o *Options) { o.HostDNS = host })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, want := upsOf(t, f.d.membersUpstreamFor, q), []netip.AddrPort{ap("185.12.64.1:53"), ap("185.12.64.2:53")}; !slices.Equal(got, want) {
		t.Errorf("without resolved, a member's tailnet name is asked of %v, want %v", got, want)
	}

	hostResolvConf(t, "nameserver 127.0.0.53\n")
	host.set(resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true},
		{Ifindex: 7, Servers: []netip.AddrPort{ap("100.100.100.100:53")}, Domains: []string{"example-tail.ts.net"}, DefaultRoute: true},
	}}, nil)
	if ups, err := f.d.membersUpstreamFor(q); err == nil {
		t.Errorf("through resolved, a member's tailnet name is asked of %v", ups)
	}
}

// A routingSource is a host resolver's routing, read as set, and where gate
// is set, once it is closed.
type routingSource struct {
	rmu   sync.Mutex
	r     resolved.Routing
	err   error
	reads int
	gate  chan struct{}
}

func (h *routingSource) routing() (resolved.Routing, error) {
	h.rmu.Lock()
	h.reads++
	gate := h.gate
	h.rmu.Unlock()
	if gate != nil {
		<-gate
	}
	h.rmu.Lock()
	defer h.rmu.Unlock()
	return h.r, h.err
}

func (h *routingSource) set(r resolved.Routing, err error) {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	h.r, h.err = r, err
}

func (h *routingSource) fail(err error) {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	h.err = err
}

func (h *routingSource) readCount() int {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	return h.reads
}

// readHostDNS has its routing read, but routes no domains.
type readHostDNS struct {
	plainHostDNS
	routingSource
}

// plainHostDNS keeps fakeHostDNS's routing field from hiding routingSource's.
type plainHostDNS struct{ fakeHostDNS }

// routingHostDNS routes domains and has its routing read.
type routingHostDNS struct {
	domainsHostDNS
	routingSource
}

// routingFixture is an exit node whose host's resolv.conf names resolved's
// stub alone, whose resolved routes lab.example to a link, and whose clock
// moves as advance says.
func routingFixture(t *testing.T, mutate func(*Options)) (*reconcileFixture, *routingHostDNS, *fakeNames, func(time.Duration)) {
	t.Helper()
	ap := netip.MustParseAddrPort
	uplink := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(uplink, []byte("nameserver 10.0.2.3\n"), 0o644)
	was := UplinkResolvConf
	UplinkResolvConf = uplink
	t.Cleanup(func() { UplinkResolvConf = was })
	hostResolvConf(t, "nameserver 127.0.0.53\n")
	hosts := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(hosts, []byte("127.0.0.1 localhost\n10.0.2.50 printer.lab.example\n"), 0o644)
	wasHosts := EtcHosts
	EtcHosts = hosts
	t.Cleanup(func() { EtcHosts = wasHosts })
	host := &routingHostDNS{routingSource: routingSource{r: resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true},
		{Ifindex: 5, Servers: []netip.AddrPort{ap("10.99.2.2:53")}, Domains: []string{"lab.example"}},
	}}}}
	served := &fakeNames{}
	f := exitFixtureWith(t, func(nw *network) { nw.devices[1].record.Names = []string{"mx.example.net"} }, func(o *Options) {
		o.HostDNS, o.ServeNames, o.AcceptNames = host, served.start, true
		if mutate != nil {
			mutate(o)
		}
	})
	now := time.Now()
	var mu sync.Mutex
	f.d.clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if served.upstream == nil {
		t.Fatal("juistd's resolver did not start")
	}
	advance := func(by time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(by) }
	return f, host, served, advance
}

// What juistd's resolver does not answer, without an exit node, it asks the
// resolvers resolved would, by the host's routing: a public name's own link
// where one claims it, as a VPN's; and the host's resolvers in turn where
// resolved is not running.
func TestWhatIsNotAnsweredGoesWhereTheHostRoutesIt(t *testing.T) {
	ap := netip.MustParseAddrPort
	f, host, served, _ := routingFixture(t, nil)
	host.set(resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true},
		{Ifindex: 5, Servers: []netip.AddrPort{ap("10.99.2.2:53")}, Domains: []string{"example.net"}},
	}}, nil)
	for name, want := range map[string]netip.AddrPort{"mx.example.net.": ap("10.99.2.2:53"), "example.org.": ap("10.0.2.3:53")} {
		if got := upsOf(t, served.upstream, nameQuery(t, name)); !slices.Equal(got, []netip.AddrPort{want}) {
			t.Errorf("%s is asked of %v, want %v", name, got, want)
		}
	}
	if got := upsOf(t, f.d.membersUpstreamFor, nameQuery(t, "mx.example.net.")); !slices.Equal(got, []netip.AddrPort{ap("10.99.2.2:53")}) {
		t.Errorf("a member's mx.example.net is asked of %v", got)
	}
}

// A domain the host routes to a link from now on is asked of that link by
// the next query a second later, by juistd's resolver and for members
// alike, though resolved signals no such change.
func TestADomainMovedIsAskedOfItsNewLinkAtOnce(t *testing.T) {
	ap := netip.MustParseAddrPort
	f, host, served, advance := routingFixture(t, nil)
	q := nameQuery(t, "other.pub.example.org.")
	if got := upsOf(t, served.upstream, q); !slices.Equal(got, []netip.AddrPort{ap("10.0.2.3:53")}) {
		t.Fatalf("before example.org is routed, it is asked of %v", got)
	}
	host.set(resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true},
		{Ifindex: 5, Servers: []netip.AddrPort{ap("10.99.2.2:53")}, Domains: []string{"lab.example", "example.org"}},
	}}, nil)
	advance(time.Second)
	if got := upsOf(t, served.upstream, q); !slices.Equal(got, []netip.AddrPort{ap("10.99.2.2:53")}) {
		t.Errorf("by juistd's resolver, example.org is asked of %v once the host routes it to a link", got)
	}
	if got := upsOf(t, f.d.membersUpstreamFor, q); !slices.Equal(got, []netip.AddrPort{ap("10.99.2.2:53")}) {
		t.Errorf("for a member, example.org is asked of %v once the host routes it to a link", got)
	}
}

// Where the host's routing cannot be read, a name it routes is refused,
// SERVFAIL: never asked of the link the last read routed it to, nor of the
// host's resolvers, for juistd's resolver and members alike. The failure is
// logged once and juist health says it until a read succeeds.
func TestAnUnreadRoutingRefusesTheName(t *testing.T) {
	var logs struct {
		sync.Mutex
		lines []string
	}
	logf := safeLogf(t, "")
	f, host, served, advance := routingFixture(t, func(o *Options) {
		o.Logf = func(format string, args ...any) {
			logs.Lock()
			logs.lines = append(logs.lines, fmt.Sprintf(format, args...))
			logs.Unlock()
			logf(format, args...)
		}
	})
	q := nameQuery(t, "a.lab.example.")
	upsOf(t, served.upstream, q)
	host.fail(errors.New("dbus: call timed out"))
	for range 2 {
		advance(hostRoutingFresh)
		if ups, err := served.upstream(q); err == nil {
			t.Errorf("the routing unread, juistd's resolver asks %v", ups)
		}
		if ups, err := f.d.membersUpstreamFor(q); err == nil {
			t.Errorf("the routing unread, a member's name is asked of %v", ups)
		}
	}
	if why := f.d.Status().DNSRoutingUnread; why != "dbus: call timed out" {
		t.Errorf("the status says %q", why)
	}
	logs.Lock()
	refusals := 0
	for _, l := range logs.lines {
		if strings.Contains(l, "cannot be read") {
			refusals++
		}
	}
	logs.Unlock()
	if refusals != 1 {
		t.Errorf("the failure was logged %d times", refusals)
	}

	at, err := defaultNamesServer("", nil)(netip.MustParseAddrPort("127.0.0.1:0"), func([]byte) []byte { return nil }, f.d.namesUpstreamFor)
	if err != nil {
		t.Fatal(err)
	}
	defer at.Close()
	c, err := net.Dial("udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), at.(*dnsfwd.Forwarder).Port()).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(q)
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	var p dnsmessage.Parser
	if h, perr := p.Start(buf[:n]); err != nil || perr != nil || h.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("juistd's resolver answers %x, %v", buf[:n], err)
	}

	host.fail(nil)
	advance(hostRoutingFresh)
	upsOf(t, served.upstream, q)
	if why := f.d.Status().DNSRoutingUnread; why != "" {
		t.Errorf("read again, the status says %q", why)
	}

	host.fail(resolved.ErrNotRunning)
	advance(hostRoutingFresh)
	if ups, err := served.upstream(q); err == nil {
		t.Errorf("resolved's stub alone in resolv.conf, not running, juistd's resolver asks %v", ups)
	}
	if ups, err := f.d.membersUpstreamFor(q); err == nil {
		t.Errorf("resolved's stub alone in resolv.conf, not running, a member's name is asked of %v", ups)
	}
	if why := f.d.Status().DNSRoutingUnread; why != "" {
		t.Errorf("resolved not running, the status says %q", why)
	}
	own := hostResolvConf(t, "nameserver 127.0.0.53\nnameserver 10.0.2.9\n")[1:]
	if got := upsOf(t, served.upstream, q); !slices.Equal(got, own) {
		t.Errorf("resolved not running, juistd's resolver asks a.lab.example of %v, want resolv.conf's %v", got, own)
	}
	own = hostResolvConf(t, "nameserver 10.0.2.9\n")
	if got := upsOf(t, f.d.membersUpstreamFor, q); !slices.Equal(got, own) {
		t.Errorf("resolved not running, a member's a.lab.example is asked of %v, want resolv.conf's %v", got, own)
	}
}

// An exit node asks a member's name of no resolver where the host routes
// it to tailscaled alone, whose answer the member cannot reach, nor of the
// default route, which would put a tailnet's name to the public, nor where
// a tailnet takes every name ("~."), which resolved sends to it; juist
// health says so, and the log once.
func TestAnExitNodeRefusesANameOnlyTailscaledAnswers(t *testing.T) {
	ap := netip.MustParseAddrPort
	var logs struct {
		sync.Mutex
		lines []string
	}
	logf := safeLogf(t, "")
	f, host, _, advance := routingFixture(t, func(o *Options) {
		o.Logf = func(format string, args ...any) {
			logs.Lock()
			logs.lines = append(logs.lines, fmt.Sprintf(format, args...))
			logs.Unlock()
			logf(format, args...)
		}
	})
	host.set(resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("9.9.9.9:53")}, DefaultRoute: true},
		{Ifindex: 7, Servers: []netip.AddrPort{ap("100.100.100.100:53")}, Domains: []string{"corp.example"}},
	}}, nil)
	advance(hostRoutingFresh)
	if got := upsOf(t, f.d.membersUpstreamFor, nameQuery(t, "example.org.")); !slices.Equal(got, []netip.AddrPort{ap("9.9.9.9:53")}) {
		t.Errorf("example.org is asked of %v", got)
	}
	if f.d.Status().DNSRefused != "" {
		t.Error("nothing refused, the status says a refusal")
	}
	for range 2 {
		if ups, err := f.d.membersUpstreamFor(nameQuery(t, "secret.corp.example.")); err == nil {
			t.Errorf("a name the host routes to tailscaled alone is asked of %v", ups)
		}
	}
	if st := f.d.Status(); st.DNSRefused != errTailnetOnly.Error() || st.DNSRefusedAt == 0 {
		t.Errorf("the status says %q at %d", st.DNSRefused, st.DNSRefusedAt)
	}
	host.set(resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("9.9.9.9:53")}, DefaultRoute: true},
		{Ifindex: 7, Servers: []netip.AddrPort{ap("100.100.100.100:53")}, Domains: []string{"", "corp.example"}, DefaultRoute: true},
	}}, nil)
	advance(hostRoutingFresh)
	if ups, err := f.d.membersUpstreamFor(nameQuery(t, "example.org.")); err == nil {
		t.Errorf("tailscaled taking every name, example.org is asked of %v", ups)
	}
	logs.Lock()
	defer logs.Unlock()
	n := 0
	for _, l := range logs.lines {
		if strings.Contains(l, "tailscaled alone") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("three refusals logged %d times", n)
	}
}

// Where resolved runs, a member's name goes where it routes it, whatever
// resolv.conf names besides its stub: never a link's resolver it did not
// route the name to, nor a public one that would answer what resolved
// refused.
func TestAMembersNameGoesWhereResolvedRoutesIt(t *testing.T) {
	ap := netip.MustParseAddrPort
	f, _, served, _ := routingFixture(t, nil)
	q := nameQuery(t, "a.lab.example.")
	for _, conf := range []string{"nameserver 10.0.2.3\nnameserver 10.99.2.2\n", "nameserver 127.0.0.53\nnameserver 1.1.1.1\n"} {
		hostResolvConf(t, conf)
		for name, upstream := range map[string]func([]byte) ([]netip.AddrPort, error){
			"juistd's resolver": served.upstream, "a member": f.d.membersUpstreamFor} {
			if got := upsOf(t, upstream, q); !slices.Equal(got, []netip.AddrPort{ap("10.99.2.2:53")}) {
				t.Errorf("resolv.conf %q, %s asks a.lab.example of %v", conf, name, got)
			}
		}
	}
}

// What resolved asks no DNS server of is refused as resolved answers it:
// what it never resolves NXDOMAIN, what it answers itself, from the hosts
// file too, or asks mDNS or LLMNR of REFUSED, as what its stub refuses;
// what it asks over TLS juistd's resolver refuses SERVFAIL, which juist
// health says, as the host's query would leave in plain text by its local
// network, but a member's, which leaves at this site, is asked.
func TestWhatResolvedAsksNoServerOfIsRefused(t *testing.T) {
	ap := netip.MustParseAddrPort
	f, host, served, advance := routingFixture(t, nil)
	own, _ := os.Hostname()
	for name, rcode := range map[string]uint8{"x.invalid.": dnsfwd.RCodeNXDomain, "printer.local.": dnsfwd.RCodeRefused,
		"localhost.": dnsfwd.RCodeRefused, "nas.": dnsfwd.RCodeRefused, own + ".": dnsfwd.RCodeRefused,
		"printer.lab.example.": dnsfwd.RCodeRefused, "50.2.0.10.in-addr.arpa.": dnsfwd.RCodeRefused} {
		for who, upstream := range map[string]func([]byte) ([]netip.AddrPort, error){
			"juistd's resolver": served.upstream, "a member": f.d.membersUpstreamFor} {
			var r *dnsfwd.Refusal
			if ups, err := upstream(typedQuery(t, name, dnsmessage.TypeTXT)); !errors.As(err, &r) || r.RCode != rcode {
				t.Errorf("%s: %s TXT is asked of %v, %v; want RCODE %d", who, name, ups, err, rcode)
			}
			if ups, err := upstream(nameQuery(t, name)); !errors.As(err, &r) || r.RCode != rcode {
				t.Errorf("%s: %s is asked of %v, %v; want RCODE %d", who, name, ups, err, rcode)
			}
		}
	}
	raw := func(edit func([]byte) []byte) []byte { return edit(slices.Clone(nameQuery(t, "example.org."))) }
	for what, q := range map[string][]byte{
		"no recursion desired": raw(func(q []byte) []byte { q[2] &^= 0x01; return q }),
		"two questions":        raw(func(q []byte) []byte { q[5] = 2; return append(q, q[12:]...) }),
		"a zone transfer":      raw(func(q []byte) []byte { q[len(q)-3] = 252; return q }),
		"class CH":             raw(func(q []byte) []byte { q[len(q)-1] = 3; return q }),
	} {
		var r *dnsfwd.Refusal
		if ups, err := f.d.membersUpstreamFor(q); !errors.As(err, &r) || r.RCode != dnsfwd.RCodeRefused {
			t.Errorf("%s: asked of %v, %v", what, ups, err)
		}
	}
	host.set(resolved.Routing{Scopes: []resolved.Scope{{Ifindex: 2, Domains: []string{"lan"}}}}, nil)
	advance(hostRoutingFresh)
	if ups, err := f.d.membersUpstreamFor(nameQuery(t, "example.org.")); err == nil {
		t.Errorf("resolved knowing no server, example.org is asked of %v", ups)
	}
	if why := f.d.Status().DNSRefused; why != resolved.ErrNoServers.Error() {
		t.Errorf("resolved knowing no server, the status says %q", why)
	}
	host.set(resolved.Routing{Scopes: []resolved.Scope{
		{Ifindex: 2, Servers: []netip.AddrPort{ap("10.0.2.3:53")}, DefaultRoute: true, OverTLS: true},
	}}, nil)
	advance(hostRoutingFresh)
	if got := upsOf(t, f.d.membersUpstreamFor, nameQuery(t, "example.org.")); !slices.Equal(got, []netip.AddrPort{ap("10.0.2.3:53")}) {
		t.Errorf("over TLS, a member's example.org, which leaves at this site, is asked of %v", got)
	}
	if why := f.d.Status().DNSRefused; why == resolved.ErrOverTLS.Error() {
		t.Errorf("for a member, the status says %q", why)
	}
	var r *dnsfwd.Refusal
	if ups, err := served.upstream(nameQuery(t, "example.org.")); err == nil || errors.As(err, &r) {
		t.Errorf("over TLS, juistd's resolver asks example.org of %v, %v", ups, err)
	}
	if why := f.d.Status().DNSRefused; why != resolved.ErrOverTLS.Error() {
		t.Errorf("the status says %q", why)
	}
}

// A failure that persists is logged once hostRoutingLogEvery has passed
// since the last, though one before it ended within that time.
func TestAPersistingFailureIsLogged(t *testing.T) {
	var logs struct {
		sync.Mutex
		lines []string
	}
	logf := safeLogf(t, "")
	_, host, served, advance := routingFixture(t, func(o *Options) {
		o.Logf = func(format string, args ...any) {
			logs.Lock()
			logs.lines = append(logs.lines, fmt.Sprintf(format, args...))
			logs.Unlock()
			logf(format, args...)
		}
	})
	q := nameQuery(t, "a.lab.example.")
	step := func(err error, by time.Duration) {
		host.fail(err)
		advance(by)
		served.upstream(q)
	}
	failing := errors.New("dbus: call timed out")
	step(failing, hostRoutingFresh)
	step(nil, hostRoutingFresh)
	step(failing, hostRoutingFresh)
	step(failing, hostRoutingLogEvery)
	logs.Lock()
	defer logs.Unlock()
	n := 0
	for _, l := range logs.lines {
		if strings.Contains(l, "cannot be read") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("a failure persisting past a minute logged %d times, want 2: %q", n, logs.lines)
	}
}

// Where resolved is not running and resolv.conf is a link to one of its own
// that is gone, a member's name is refused, not asked of the resolvers
// tailscaled replaced.
func TestADanglingStubLinkRefusesTheName(t *testing.T) {
	pre := filepath.Join(t.TempDir(), "resolv.pre-tailscale-backup.conf")
	os.WriteFile(pre, []byte("nameserver 185.12.64.1\n"), 0o644)
	was := PreTailscaleResolvConf
	PreTailscaleResolvConf = pre
	t.Cleanup(func() { PreTailscaleResolvConf = was })
	f, host, _, advance := routingFixture(t, nil)
	link := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.Symlink(filepath.Join(t.TempDir(), "run/systemd/resolve/stub-resolv.conf"), link); err != nil {
		t.Fatal(err)
	}
	wasConf := dnsfwd.ResolvConf
	dnsfwd.ResolvConf = link
	t.Cleanup(func() { dnsfwd.ResolvConf = wasConf })
	host.fail(resolved.ErrNotRunning)
	advance(hostRoutingFresh)
	if ups, err := f.d.membersUpstreamFor(nameQuery(t, "example.org.")); err == nil {
		t.Errorf("a dangling stub link, example.org is asked of %v", ups)
	}
}

// A failure to read the host's routing is said no longer once a reconcile
// finds it read again, though no query came, or nothing forwarding by it.
func TestAReconcileEndsAFailureToRead(t *testing.T) {
	f, host, served, advance := routingFixture(t, nil)
	host.fail(errors.New("dbus: call timed out"))
	advance(hostRoutingFresh)
	served.upstream(nameQuery(t, "a.lab.example."))
	if f.d.Status().DNSRoutingUnread == "" {
		t.Fatal("the failure is not said")
	}
	host.fail(nil)
	advance(hostRoutingFresh)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the failure to be said no longer", func() bool { return f.d.Status().DNSRoutingUnread == "" })

	host.fail(errors.New("dbus: call timed out"))
	advance(hostRoutingFresh)
	served.upstream(nameQuery(t, "a.lab.example."))
	if f.d.Status().DNSRoutingUnread == "" {
		t.Fatal("the failure is not said again")
	}
	f.d.changePrefs(func(p *Prefs) { p.DNSOff = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if why := f.d.Status().DNSRoutingUnread; why != "" {
		t.Errorf("with DNS off, the status says %q", why)
	}
}

// Closing DNS begins no read of the host's routing, which nothing would
// wait for, though a failure was said.
func TestClosingDNSReadsNoRouting(t *testing.T) {
	f, host, served, advance := routingFixture(t, nil)
	host.fail(errors.New("dbus: call timed out"))
	advance(hostRoutingFresh)
	served.upstream(nameQuery(t, "a.lab.example."))
	advance(hostRoutingFresh)
	before := host.readCount()
	f.d.closeDNS()
	time.Sleep(100 * time.Millisecond)
	if n := host.readCount() - before; n != 0 {
		t.Errorf("closing DNS read the routing %d times", n)
	}
	if why := f.d.Status().DNSRoutingUnread; why != "" {
		t.Errorf("closed, the status says %q", why)
	}
}

// Reads that fail and succeed in turn log the failure once a minute at most.
func TestAFlappingReadIsLoggedRarely(t *testing.T) {
	var logs struct {
		sync.Mutex
		lines []string
	}
	logf := safeLogf(t, "")
	_, host, served, advance := routingFixture(t, func(o *Options) {
		o.Logf = func(format string, args ...any) {
			logs.Lock()
			logs.lines = append(logs.lines, fmt.Sprintf(format, args...))
			logs.Unlock()
			logf(format, args...)
		}
	})
	q := nameQuery(t, "a.lab.example.")
	for i := range 10 {
		if i%2 == 0 {
			host.fail(errors.New("dbus: call timed out"))
		} else {
			host.fail(nil)
		}
		advance(hostRoutingFresh)
		served.upstream(q)
	}
	logs.Lock()
	defer logs.Unlock()
	n := 0
	for _, l := range logs.lines {
		if strings.Contains(l, "DNS routing") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("five failures in ten seconds logged %d lines, want 2: %q", n, logs.lines)
	}
}

// Queries at once share one read of the host's routing, and a read is not
// begun again within hostRoutingFresh of the last.
func TestQueriesShareOneRead(t *testing.T) {
	ap := netip.MustParseAddrPort
	f, host, served, advance := routingFixture(t, nil)
	advance(hostRoutingFresh)
	before := host.readCount()
	gate := make(chan struct{})
	host.rmu.Lock()
	host.gate = gate
	host.rmu.Unlock()
	q := nameQuery(t, "a.lab.example.")
	var wg sync.WaitGroup
	got := make([][]netip.AddrPort, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				got[i], _ = served.upstream(q)
			} else {
				got[i], _ = f.d.membersUpstreamFor(q)
			}
		}()
	}
	for host.readCount() == before {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	for i, ups := range got {
		if !slices.Equal(ups, []netip.AddrPort{ap("10.99.2.2:53")}) {
			t.Errorf("query %d is asked of %v", i, ups)
		}
	}
	if n := host.readCount() - before; n != 1 {
		t.Errorf("%d queries at once read the routing %d times", len(got), n)
	}
	advance(hostRoutingFresh - time.Millisecond)
	upsOf(t, served.upstream, q)
	if n := host.readCount() - before; n != 1 {
		t.Errorf("within hostRoutingFresh, the routing was read %d times", n)
	}
	advance(time.Millisecond)
	upsOf(t, served.upstream, q)
	if n := host.readCount() - before; n != 2 {
		t.Errorf("after hostRoutingFresh, the routing was read %d times", n)
	}
}

// A read of the host's routing that hangs refuses the query after
// hostRoutingWait, and holds no later one longer.
func TestAHangingReadRefusesTheName(t *testing.T) {
	_, host, served, advance := routingFixture(t, nil)
	advance(hostRoutingFresh)
	gate := make(chan struct{})
	host.rmu.Lock()
	host.gate = gate
	host.rmu.Unlock()
	t.Cleanup(func() { close(gate) })
	q := nameQuery(t, "a.lab.example.")
	type result struct {
		ups []netip.AddrPort
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		ups, err := served.upstream(q)
		done <- result{ups, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			t.Errorf("the read hanging, a.lab.example is asked of %v", r.ups)
		}
		if took := time.Since(start); took < hostRoutingWait-100*time.Millisecond {
			t.Errorf("refused after %v, before hostRoutingWait", took)
		}
	case <-time.After(hostRoutingWait + 2*time.Second):
		t.Fatal("the query waits on a hanging read")
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
		at, ok := namesAddrOf(addrs, held, NamesPort)
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
	if err := rec.Sign(f.nw.admin); err != nil {
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
	s, err := defaultNamesServer("", nil)(netip.MustParseAddrPort("127.0.0.1:0"),
		func([]byte) []byte { return nil }, func([]byte) ([]netip.AddrPort, error) { return []netip.AddrPort{up}, nil })
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
