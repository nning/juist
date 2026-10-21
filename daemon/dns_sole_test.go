package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/resolved"
	"github.com/nning/juist/ipc"
)

// Where no systemd-resolved runs and resolv.sh pointed resolv.conf at
// juistd's, juistd writes it to ask its resolver alone, with the host's own
// search domains and options after its own, and asks the host's own
// resolvers, never resolv.conf, of every name it does not answer, for the
// host and for members alike; the host's own queries on 53 are taken to its
// port. Closed, the file is the host's own again.
func TestAHostWithoutResolvedAsksJuistdAlone(t *testing.T) {
	dir := t.TempDir()
	saved, own, conf := filepath.Join(dir, "saved"), filepath.Join(dir, "own"), filepath.Join(dir, "resolv.conf")
	os.WriteFile(saved, []byte("nameserver 10.0.2.3\nsearch lan\noptions edns0\n"), 0o644)
	os.Symlink(saved, own)
	os.Symlink(own, conf)
	var mu sync.Mutex
	var redirected [][]netip.AddrPort
	host := fileDNS{own: own, saved: saved, redirect: func(to []netip.AddrPort) error {
		mu.Lock()
		defer mu.Unlock()
		redirected = append(redirected, slices.Clone(to))
		return nil
	}}
	served := &fakeNames{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ServeNames, o.ResolvConf = host, served.start, conf })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	at := netip.AddrPortFrom(f.auth.State().Addr6(f.self.record.Identity), NamesPort)
	if served.at != at {
		t.Errorf("answers at %v, want %v", served.at, at)
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := fileHeader + saved + "\nnameserver " + at.Addr().String() + "\nsearch m2-testnet.juist lan\noptions edns0\n"
	if string(b) != want {
		t.Errorf("resolv.conf is\n%s\nwant\n%s", b, want)
	}
	if fi, err := os.Lstat(own); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("juistd's resolv.conf: %v, %v", fi.Mode(), err)
	}
	mu.Lock()
	if len(redirected) == 0 || !slices.Equal(redirected[len(redirected)-1], []netip.AddrPort{at}) {
		t.Errorf("53 taken to %v, want %v", redirected, at)
	}
	mu.Unlock()
	if n := f.d.Status().Names; n == nil || !reflect.DeepEqual(*n, ipc.Names{Domain: "m2-testnet.juist", Resolved: true}) {
		t.Errorf("the status says %+v", n)
	}
	hostOwn := []netip.AddrPort{netip.MustParseAddrPort("10.0.2.3:53")}
	if got := upsOf(t, served.upstream, nameQuery(t, "mx.example.net.")); !slices.Equal(got, hostOwn) {
		t.Errorf("asks %v upstream, want the host's own %v", got, hostOwn)
	}
	if got := upsOf(t, f.d.uplinkFor, nameQuery(t, "mx.example.net.")); !slices.Equal(got, hostOwn) {
		t.Errorf("asks %v for members, want the host's own %v", got, hostOwn)
	}

	f.d.closeDNS()
	if l, err := os.Readlink(own); err != nil || l != saved {
		t.Errorf("closed, juistd's resolv.conf links to %q, %v", l, err)
	}
	mu.Lock()
	if last := redirected[len(redirected)-1]; len(last) != 0 {
		t.Errorf("closed, 53 is still taken to %v", last)
	}
	mu.Unlock()
}

// Once something else wrote resolv.conf in its place, as a DHCP client may,
// the names are not resolved, and the status says why.
func TestAResolvConfTakenBackIsNotThrough(t *testing.T) {
	dir := t.TempDir()
	own, conf := filepath.Join(dir, "own"), filepath.Join(dir, "resolv.conf")
	os.WriteFile(conf, []byte("nameserver 10.0.2.3\n"), 0o644)
	ok, why := fileDNS{own: own}.through(conf, nil)
	if ok || !strings.Contains(why, "no longer juistd's") {
		t.Errorf("through %v: %s", ok, why)
	}
}

// On FreeBSD resolvconf takes juistd's resolver for its device alone, on 53,
// searching the network's domain before the host's, and juistd asks the
// other interfaces' resolvers, never its own nor tailscaled's, which asks
// every interface's but its own.
func TestFreeBSDsResolvconfAsksJuistdOn53(t *testing.T) {
	dir := t.TempDir()
	lists := filepath.Join(dir, "resolvconf")
	os.WriteFile(lists, []byte(`#!/bin/sh
[ "$1" = -l ] || exit 2
cat <<'EOF'
# resolv.conf from tailscale
nameserver 100.100.100.100
search example.ts.net

# resolv.conf from vtnet0
nameserver 10.0.2.3
search lan

# resolv.conf from juist0
nameserver fd00::1
search m2-testnet.juist
EOF
`), 0o755)
	was := Resolvconf
	Resolvconf = lists
	t.Cleanup(func() { Resolvconf = was })
	conf := filepath.Join(dir, "resolv.conf")
	p := &dnsPlumber{conf: conf}
	served := &fakeNames{}
	f := exitFixture(t, 1, -1, func(o *Options) {
		o.HostDNS, o.ServeNames, o.ResolvConf = resolvconfDNS{plumbedDNS{p: p, dev: "juist0"}}, served.start, conf
	})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	at := netip.AddrPortFrom(f.auth.State().Addr6(f.self.record.Identity), 53)
	if served.at != at {
		t.Errorf("answers at %v, want %v", served.at, at)
	}
	p.mu.Lock()
	if len(p.set) == 0 || !slices.Equal(p.set[len(p.set)-1], []netip.Addr{at.Addr()}) ||
		!slices.Equal(p.search[len(p.search)-1], []string{"m2-testnet.juist", "example.ts.net", "lan"}) {
		t.Errorf("resolvconf was given %v searching %v", p.set, p.search)
	}
	p.mu.Unlock()
	if n := f.d.Status().Names; n == nil || !n.Resolved {
		t.Errorf("the status says %+v", n)
	}
	if got := upsOf(t, served.upstream, nameQuery(t, "mx.example.net.")); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("10.0.2.3:53")}) {
		t.Errorf("asks %v upstream, want vtnet0's alone", got)
	}
}

// Where tailscaled wrote resolv.conf before resolv.sh pointed it at juistd's,
// tailscaled takes it back and keeps juistd's as the host's own, asking
// juistd's resolver in turn: juistd asks the resolvers tailscaled found, never
// tailscaled's nor its own, lest a query go round between them.
func TestJuistdAsksNotTailscaledWhichAsksJuistd(t *testing.T) {
	dir := t.TempDir()
	saved, own, conf := filepath.Join(dir, "saved"), filepath.Join(dir, "own"), filepath.Join(dir, "resolv.conf")
	tailscaleds := filepath.Join(dir, "pre-tailscale")
	os.WriteFile(saved, []byte("# resolv.conf(5) file generated by tailscale\nnameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\nsearch example.ts.net lan\n"), 0o644)
	os.WriteFile(tailscaleds, []byte("domain lan\nsearch lan\nnameserver 10.11.1.1\n"), 0o644)
	os.Symlink(saved, own)
	os.Symlink(own, conf)
	was := PreTailscaleResolvConf
	PreTailscaleResolvConf = tailscaleds
	t.Cleanup(func() { PreTailscaleResolvConf = was })
	host := fileDNS{own: own, saved: saved, redirect: func([]netip.AddrPort) error { return nil }}
	served := &fakeNames{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ServeNames, o.ResolvConf = host, served.start, conf })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("10.11.1.1:53")}
	asks := func(when string) {
		t.Helper()
		if got := upsOf(t, served.upstream, nameQuery(t, "mx.example.net.")); !slices.Equal(got, want) {
			t.Errorf("%s, asks %v upstream, want %v", when, got, want)
		}
		if got := upsOf(t, f.d.uplinkFor, nameQuery(t, "mx.example.net.")); !slices.Equal(got, want) {
			t.Errorf("%s, asks %v for members, want %v", when, got, want)
		}
	}
	asks("tailscaled's in resolv.conf")

	os.Remove(tailscaleds)
	os.Symlink(own, tailscaleds)
	f.d.sole.mu.Lock()
	f.d.sole.readAt = time.Time{}
	f.d.sole.mu.Unlock()
	asks("tailscaled's own linked to juistd's")
}

// Where tailscaled wrote resolv.conf, which resolv.sh leaves it, or took it
// back, the status says so.
func TestTheStatusSaysTailscaledWritesResolvConf(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(conf, []byte("# resolv.conf(5) file generated by tailscale\nnameserver 100.100.100.100\n"), 0o644)
	served := &fakeNames{}
	host := &domainsHostDNS{fakeHostDNS{err: resolved.ErrNotRunning}}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ServeNames, o.ResolvConf = host, served.start, conf })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	want := "tailscaled writes " + conf
	if n := f.d.Status().Names; n == nil || n.Resolved || n.Not != want {
		t.Errorf("without resolved, the status says %+v, want %q", n, want)
	}
	if ok, why := (fileDNS{own: filepath.Join(t.TempDir(), "own")}).through(conf, nil); ok || why != want {
		t.Errorf("taken back, through %v: %s", ok, why)
	}
}

// With DNS off, juistd gives the host's DNS back and stops answering it, for
// the network's names and an exit node's DNS alike, and says so; on again, it
// takes it again, without a restart.
func TestDNSOffLeavesTheHostsDNSAlone(t *testing.T) {
	host, served := &domainsHostDNS{}, &fakeNames{}
	f := exitFixture(t, 1, -1, func(o *Options) { o.HostDNS, o.ServeNames = host, served.start })
	exit := f.nw.devices[1]
	f.learnExitDNS(t, exit, 7001, true, DefaultDNSPort)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if routed, _ := host.now(); len(routed) == 0 {
		t.Fatal("DNS on, the host's DNS was not routed")
	}

	f.d.changePrefs(func(p *Prefs) { p.DNSOff = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if routed, calls := host.now(); len(routed) != 0 || calls[len(calls)-1] != "revert" {
		t.Errorf("DNS off, the host's DNS goes to %v after %v", routed, calls)
	}
	served.mu.Lock()
	closed := served.closed
	served.mu.Unlock()
	if !closed {
		t.Error("DNS off, juistd's resolver still answers the host")
	}
	st := f.d.Status()
	if n := st.Names; n == nil || n.Resolved || !n.Cannot || !n.Off || n.Not != dnsOffWhy {
		t.Errorf("DNS off, the names say %+v", n)
	}
	if ex := st.Exit; ex == nil || ex.DNS || ex.DNSNot != dnsOffWhy {
		t.Errorf("DNS off, the exit node says %+v", ex)
	}

	f.d.changePrefs(func(p *Prefs) { p.DNSOff = false })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if routed, _ := host.now(); len(routed) == 0 {
		t.Error("DNS on again, the host's DNS was not routed")
	}
	if ex := f.d.Status().Exit; ex == nil || ex.DNSNot == dnsOffWhy {
		t.Errorf("DNS on again, the exit node says %+v", ex)
	}
}
