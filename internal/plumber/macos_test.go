package plumber

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The helper writes a file per domain and one to search, replaces and
// removes only its device's own, and leaves another's file of a domain it
// wants in place, saying so.
func TestResolverFilesAreTheDevicesAlone(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("corp.example", "nameserver 10.0.0.53\n")
	write("other.juist", resolverHeader("utun101")+"nameserver 100.64.0.9\n")
	write("old.juist", resolverHeader("utun100")+"nameserver 100.64.0.1\n")
	srv := []netip.Addr{netip.MustParseAddr("100.64.0.1")}

	err := writeResolvers(dir, "utun100", srv, 41647, []string{"home.juist", "corp.example"}, []string{"home.juist"})
	if err == nil {
		t.Error("another's file of a domain wanted was not said")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "home.juist"))
	if want := resolverHeader("utun100") + "nameserver 100.64.0.1\nport 41647\n"; string(got) != want {
		t.Errorf("home.juist:\n%s\nwant\n%s", got, want)
	}
	got, _ = os.ReadFile(filepath.Join(dir, searchFile("utun100")))
	if want := resolverHeader("utun100") + "search home.juist\n"; string(got) != want {
		t.Errorf("%s:\n%s\nwant\n%s", searchFile("utun100"), got, want)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "corp.example")); string(got) != "nameserver 10.0.0.53\n" {
		t.Errorf("another's file was changed: %q", got)
	}
	names := func() []string {
		es, _ := os.ReadDir(dir)
		var out []string
		for _, e := range es {
			out = append(out, e.Name())
		}
		return out
	}
	if n := names(); slices.Contains(n, "old.juist") || !slices.Contains(n, "other.juist") {
		t.Errorf("after setting: %v, want old.juist gone and other.juist kept", n)
	}

	if err := writeResolvers(dir, "utun100", nil, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := names(); !slices.Equal(n, []string{"corp.example", "other.juist"}) {
		t.Errorf("after clearing: %v", n)
	}
}

// A symlink of a domain's name is not followed out of the directory.
func TestResolverFilesFollowNoLink(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "passwd")
	if err := os.WriteFile(target, []byte("root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "home.juist")); err != nil {
		t.Fatal(err)
	}
	srv := []netip.Addr{netip.MustParseAddr("100.64.0.1")}
	if err := writeResolvers(dir, "utun100", srv, 41647, []string{"home.juist"}, nil); err == nil {
		t.Error("a link in a domain's place was not said")
	}
	if got, _ := os.ReadFile(target); string(got) != "root\n" {
		t.Errorf("the link's target was written: %q", got)
	}
}

// A network with many public names routes every one of them, each a domain
// of its own, and the network's own domain with them.
func TestDomainsTakeAllOfALargeNetworksNames(t *testing.T) {
	h := &fakeHost{}
	d := &device{addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}
	domains := []string{"home.juist", "64.100.in-addr.arpa"}
	for i := range 40 {
		domains = append(domains, "app"+strconv.Itoa(i)+".example.org")
	}
	if err := setDomains(h, "utun100", d, []netip.Addr{netip.MustParseAddr("100.64.0.1")}, 41647, domains, []string{"home.juist"}); err != nil {
		t.Fatal(err)
	}
	if err := setDomains(h, "utun100", d, []netip.Addr{netip.MustParseAddr("100.64.0.9")}, 41647, domains, nil); err == nil {
		t.Error("a resolver that is not the device's own was taken")
	}
	if err := setDomains(h, "utun100", d, []netip.Addr{netip.MustParseAddr("100.64.0.1")}, 41647, []string{"bad domain"}, nil); err == nil {
		t.Error("a domain with a space was taken")
	}
}

// The host's resolver files go with the device: hung up on, the helper
// clears the domains it set, a set that failed halfway too.
func TestDomainsGoWithTheDevice(t *testing.T) {
	for _, fail := range []bool{false, true} {
		h := &fakeHost{domainsFail: fail}
		c, done := pair(t, h)
		f, err := c.OpenTUN("juist0", 1280)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if err := c.SetAddrs("juist0", []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}); err != nil {
			t.Fatal(err)
		}
		err = c.SetDomains("juist0", []netip.Addr{netip.MustParseAddr("100.64.0.1")}, 41647, []string{"home.juist"}, nil)
		if (err != nil) != fail {
			t.Fatalf("failing %v: %v", fail, err)
		}
		h.took()
		c.Close()
		<-done
		if got := h.took(); !slices.Contains(got, "domains juist0 []:0 [] search []") {
			t.Errorf("failing %v, hung up on, the helper did: %q", fail, got)
		}
	}
}

// The script that sets DNS through an exit node on a Mac names the servers
// and search domains under the device's own key, and removes that key.
func TestScutilScriptSetsAndRemovesTheDevicesKey(t *testing.T) {
	got := scutilDNS("utun100", []netip.Addr{netip.MustParseAddr("100.64.0.7")}, []string{"home.juist"})
	want := "d.init\nd.add SearchOrder # 100000\nd.add ServerAddresses * 100.64.0.7\n" +
		"d.add SupplementalMatchDomains * \"\"\nd.add SearchDomains * home.juist\n" +
		"set State:/Network/Service/juist-utun100/DNS\nquit\n"
	if got != want {
		t.Errorf("set:\n%s\nwant\n%s", got, want)
	}
	if got := scutilDNS("utun100", nil, nil); got != "remove State:/Network/Service/juist-utun100/DNS\nquit\n" {
		t.Errorf("remove: %q", got)
	}
}

// The token pfctl -E prints among its other lines is what release gives
// back; output without one is no token.
func TestPFTokenIsReadFromEnablesOutput(t *testing.T) {
	out := "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 7584592434324738\n"
	if got := pfToken(out); got != "7584592434324738" {
		t.Errorf("token %q", got)
	}
	if got := pfToken("pfctl: pf already enabled\n"); got != "" {
		t.Errorf("token %q from no token", got)
	}
}

// fakePF is pfctl as a Mac's pf answers it: running or not, with Apple's
// ruleset or the host's, giving a fresh token on each -E and forgetting all
// on -d.
type fakePF struct {
	running   bool
	rules     string
	nat       string
	tokens    map[string]bool
	next      int
	calls     []string
	reloadsTo string // the rules pfctl -f /etc/pf.conf loads
}

const appleRules = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
const appleNAT = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"

func (f *fakePF) run(args ...string) (string, string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch strings.Join(args, " ") {
	case "-s info":
		if f.running {
			return "Status: Enabled for 0 days\n", "", nil
		}
		return "Status: Disabled\n", "", nil
	case "-s rules":
		return f.rules, "No ALTQ support in kernel\n", nil
	case "-s nat":
		return f.nat, "", nil
	case "-f /etc/pf.conf":
		f.rules, f.nat = f.reloadsTo, appleNAT
		return "", "", nil
	case "-E":
		f.next++
		t := strconv.Itoa(1000 + f.next)
		f.tokens[t], f.running = true, true
		return "", "No ALTQ support in kernel\npf enabled\nToken : " + t + "\n", nil
	case "-d":
		f.running, f.tokens = false, map[string]bool{}
		return "", "", nil
	}
	if len(args) == 2 && args[0] == "-X" {
		if !f.tokens[args[1]] {
			return "", "pfctl: DIOCSTOPREF: No such file or directory\n", errors.New("exit status 1")
		}
		delete(f.tokens, args[1])
		f.running = len(f.tokens) > 0
		return "", "", nil
	}
	return "", "", fmt.Errorf("pfctl %v: not faked", args)
}

func newFakePF(t *testing.T) (*fakePF, macPF) {
	f := &fakePF{rules: appleRules, nat: appleNAT, tokens: map[string]bool{}, reloadsTo: appleRules}
	return f, macPF{pfctl: f.run, state: filepath.Join(t.TempDir(), "juistd.pf")}
}

// Two anchors hold pf by one token, given back when both let go.
func TestMacPFIsHeldByOneToken(t *testing.T) {
	f, p := newFakePF(t)
	for _, u := range []string{"utun100_in", "utun100_egress"} {
		if err := p.hold(u); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.tokens) != 1 || !f.running {
		t.Fatalf("tokens %v, running %v", f.tokens, f.running)
	}
	if err := p.release("utun100_in"); err != nil || !f.running {
		t.Fatalf("one released: %v, running %v", err, f.running)
	}
	if err := p.release("utun100_egress"); err != nil || f.running {
		t.Fatalf("both released: %v, running %v", err, f.running)
	}
	if _, err := os.Stat(p.state); !os.IsNotExist(err) {
		t.Errorf("state left: %v", err)
	}
}

// pf turned off behind juist's back is turned on again at the next hold,
// by a new token; the dead one is forgotten, and neither release nor the
// next device's opening fails on it.
func TestMacPFComesBackAfterPfctlD(t *testing.T) {
	f, p := newFakePF(t)
	if err := p.hold("utun100_in"); err != nil {
		t.Fatal(err)
	}
	f.run("-d")
	if err := p.hold("utun100_in"); err != nil {
		t.Fatal(err)
	}
	if !f.running {
		t.Fatal("pf left off after pfctl -d")
	}
	f.run("-d")
	if err := p.release("utun100_in"); err != nil {
		t.Fatalf("release of a dead token: %v", err)
	}
	if _, err := os.Stat(p.state); !os.IsNotExist(err) {
		t.Errorf("a dead token kept: %v", err)
	}
}

// The host's ruleset must call the com.apple anchors, filter included and
// before any quick pass; an empty one is given /etc/pf.conf.
func TestMacPFTakesAppleRulesAlone(t *testing.T) {
	for _, c := range []struct {
		name, rules string
		ok          bool
	}{
		{"Apple's", appleRules, true},
		{"empty, reloaded", "", true},
		{"scrub anchor alone", "scrub-anchor \"com.apple/*\" all fragment reassemble\n", false},
		{"quick pass first", "pass in quick on en0 all\n" + appleRules, false},
	} {
		f, p := newFakePF(t)
		f.rules = c.rules
		if c.rules == "" {
			f.nat = ""
		}
		err := p.hold("utun100_in")
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && f.running {
			t.Errorf("%s: pf turned on over rules that skip juist's anchors", c.name)
		}
	}
}

// On a Mac the guard keeps the overlay to the device, and an exit node's
// anchor passes no answers over the host's rules.
func TestMacAnchorsKeepToTheDevice(t *testing.T) {
	g := GuardSpec{Own: []netip.Addr{netip.MustParseAddr("100.64.0.1")}, Overlay: []netip.Addr{netip.MustParseAddr("100.64.0.2")}}
	if got := macGuardRules("utun100", g); !strings.Contains(got, "block drop in quick on ! utun100 from <juist_overlay>\n") {
		t.Errorf("guard:\n%s", got)
	}
	e := EgressSpec{Mode: EgressTunnel, V4: true, Local: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}
	gw := gateway{dev: "en0", hop: netip.MustParseAddr("192.168.1.1"), addr: netip.MustParseAddr("192.168.1.20")}
	if got := macEgressRules("utun100", e, 301, gw, gateway{}); strings.Contains(got, "pass in") {
		t.Errorf("egress passes answers:\n%s", got)
	}
}

// One network's exit node on a Mac blocks neither another network's daemon
// nor its own, in tunnel and refused alike: pf runs com.apple's anchors in
// the order of their names, and the first quick rule a packet matches wins.
func TestMacExitNodeLeavesTheOtherNetworksDaemon(t *testing.T) {
	gw := gateway{dev: "en0", hop: netip.MustParseAddr("192.168.1.1"), addr: netip.MustParseAddr("192.168.1.20")}
	for _, mode := range []string{EgressTunnel, EgressRefused} {
		e := EgressSpec{Mode: mode, V4: true, V6: true, Local: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}
		anchors := map[string]string{
			daemonAnchor("utun100"): macDaemonRules("utun100", 300),
			daemonAnchor("utun101"): macDaemonRules("utun101", 301),
			"utun100_egress":        macEgressRules("utun100", e, 300, gw, gateway{}),
			"utun101_in":            "",
		}
		names := slices.Sorted(maps.Keys(anchors))
		for _, uid := range []int{300, 301} {
			first := ""
			for _, name := range names {
				for line := range strings.Lines(anchors[name]) {
					if outQuickMatches(line, "en0", uid) {
						first = cmp.Or(first, strings.TrimSpace(line))
					}
				}
			}
			if !strings.HasPrefix(first, "pass") {
				t.Errorf("%s: a daemon of uid %d sending to the internet on en0 meets %q first", mode, uid, first)
			}
		}
		// What the exit node's routes take into the device, its daemon's
		// own route-to sends out by the host's gateway.
		first := ""
		for _, name := range names {
			for line := range strings.Lines(anchors[name]) {
				if outQuickMatches(line, "utun100", 300) {
					first = cmp.Or(first, strings.TrimSpace(line))
				}
			}
		}
		if !strings.Contains(first, "route-to") {
			t.Errorf("%s: the daemon's own packet routed into utun100 meets %q first", mode, first)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// outQuickMatches is whether line, a quick out rule, matches a UDP packet
// on dev from uid to an address outside every table, from a port no rule
// names.
func outQuickMatches(line, dev string, uid int) bool {
	f := strings.Fields(line)
	if len(f) < 3 || f[1] != "out" && !(len(f) > 2 && f[2] == "out") || !slices.Contains(f, "quick") ||
		slices.Contains(f, "inet6") || slices.Contains(f, "port") || slices.Contains(f, "icmp6") || strings.Contains(line, "<juist_local>") && !strings.Contains(line, "! <juist_local>") {
		return false
	}
	if i := slices.Index(f, "on"); i >= 0 && (f[i+1] == "!") == (f[i+1+btoi(f[i+1] == "!")] == dev) {
		return false
	}
	if i := slices.Index(f, "user"); i >= 0 && f[i+1] != strconv.Itoa(uid) {
		return false
	}
	return true
}

// Two networks on one Mac each get their own search file, and a reverse zone
// both route stays the first's, neither an error.
func TestTwoInstancesShareTheResolverDirectory(t *testing.T) {
	dir := t.TempDir()
	rev := []string{"18.198.in-addr.arpa", "19.198.in-addr.arpa"}
	if err := writeResolvers(dir, "utun100", []netip.Addr{netip.MustParseAddr("198.18.0.1")}, 53,
		append([]string{"a.juist"}, rev...), []string{"a.juist"}); err != nil {
		t.Fatal(err)
	}
	if err := writeResolvers(dir, "utun101", []netip.Addr{netip.MustParseAddr("198.19.0.7")}, 53,
		append([]string{"b.juist"}, rev...), []string{"b.juist"}); err != nil {
		t.Errorf("the second instance's domains were refused: %v", err)
	}
	for name, dev := range map[string]string{"a.juist": "utun100", "b.juist": "utun101", "18.198.in-addr.arpa": "utun100",
		searchFile("utun100"): "utun100", searchFile("utun101"): "utun101"} {
		if b, _ := os.ReadFile(filepath.Join(dir, name)); !strings.HasPrefix(string(b), resolverHeader(dev)) {
			t.Errorf("%s: %q, want %s's", name, b, dev)
		}
	}
	if err := writeResolvers(dir, "utun101", nil, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "18.198.in-addr.arpa")); err != nil {
		t.Errorf("the second instance removed the first's reverse zone: %v", err)
	}
}
