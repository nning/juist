package plumber

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		if os.Getenv("JUIST_REQUIRE_OS_PLUMBING") != "" {
			t.Fatal("needs root, and JUIST_REQUIRE_OS_PLUMBING is set")
		}
		t.Skip("needs root")
	}
}

// A device is one helper's: another asking for it is told at once, not left
// waiting on a device someone holds; a leftover nobody holds is replaced.
func TestADeviceIsOneHelpers(t *testing.T) {
	requireRoot(t)
	f, destroy, err := FreeBSD{}.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start := time.Now()
	if _, _, err := (FreeBSD{}).OpenTUN("juist7", 1280); !errors.Is(err, syscall.EBUSY) {
		t.Errorf("a second helper's open: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the second helper waited %v", d)
	}
	f.Close()
	if err := destroy(); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("/sbin/ifconfig", "tun", "create", "name", "juist7").CombinedOutput(); err != nil {
		t.Fatalf("a leftover: %v: %s", err, out)
	}
	f, destroy, err = FreeBSD{}.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatalf("over a leftover: %v", err)
	}
	f.Close()
	if err := destroy(); err != nil {
		t.Fatal(err)
	}
}

// A large network's routes go in and out within seconds, as route(8) run
// once a route would not.
func TestManyRoutesGoInFast(t *testing.T) {
	requireRoot(t)
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer destroy()
	defer f.Close()
	var routes []netip.Prefix
	for i := range 2000 {
		routes = append(routes, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 240 + byte(i>>8), byte(i)}), 32))
	}
	routes = append(routes, netip.MustParsePrefix("198.18.250.0/24"), netip.MustParsePrefix("fd00:77::/64"))
	start := time.Now()
	for _, p := range routes {
		if err := h.AddRoute("juist7", p, netip.Addr{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range routes {
		if err := h.DelRoute("juist7", p, netip.Addr{}); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("%d routes took %v", len(routes), d)
	}
	if err := h.DelRoute("juist7", routes[0], netip.Addr{}); err != nil {
		t.Errorf("deleting a route gone: %v", err)
	}
}

// Deleting its route leaves the host's own to the same prefix, whether
// multipath routing let juist's stand beside it or not.
func TestARouteDeletedLeavesTheHosts(t *testing.T) {
	requireRoot(t)
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer destroy()
	defer f.Close()
	p := netip.MustParsePrefix("198.18.251.0/24")
	if out, err := exec.Command("/sbin/route", "-q", "add", "-net", p.String(), "127.0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("the host's route: %v: %s", err, out)
	}
	defer exec.Command("/sbin/route", "-q", "delete", "-net", p.String()).Run()
	src := netip.MustParseAddr("198.19.0.7")
	if err := h.AddAddr("juist7", netip.PrefixFrom(src, 32)); err != nil {
		t.Fatal(err)
	}
	h.AddRoute("juist7", p, src)
	if err := h.DelRoute("juist7", p, src); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command("/usr/bin/netstat", "-rn", "-f", "inet").Output()
	var left []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "198.18.251.0/24") {
			left = append(left, l)
		}
	}
	if len(left) != 1 || !strings.Contains(left[0], "lo0") {
		t.Errorf("after deleting juist's, the routes to %v are %q", p, left)
	}
}

// A link-local address given is the device's only one: the one the kernel
// gives it goes, and gives it no other later.
func TestALinkLocalAddressGivenIsTheDevicesOnly(t *testing.T) {
	requireRoot(t)
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer destroy()
	defer f.Close()
	ula, ll := netip.MustParsePrefix("fd90::1:2:3:4/128"), netip.MustParsePrefix("fe80::1:2:3:4/128")
	for _, p := range []netip.Prefix{ula, ll} {
		if err := h.AddAddr("juist7", p); err != nil {
			t.Fatal(err)
		}
	}
	linkLocals := func() []string {
		ifc, err := net.InterfaceByName("juist7")
		if err != nil {
			t.Fatal(err)
		}
		addrs, _ := ifc.Addrs()
		var out []string
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.IsLinkLocalUnicast() {
				out = append(out, ipn.String())
			}
		}
		return out
	}
	if got := linkLocals(); len(got) != 1 || got[0] != "fe80::1:2:3:4/64" {
		t.Errorf("the device holds the link-locals %q", got)
	}
	exec.Command("/sbin/ifconfig", "juist7", "down").Run()
	exec.Command("/sbin/ifconfig", "juist7", "up").Run()
	if got := linkLocals(); len(got) != 1 {
		t.Errorf("up again, the device holds the link-locals %q", got)
	}
	if err := h.DelAddr("juist7", ll); err != nil {
		t.Fatal(err)
	}
	if got := linkLocals(); len(got) != 0 {
		t.Errorf("deleted, the device holds the link-locals %q", got)
	}
}

// Serving loads pf with juist's anchor, forwards, and puts pf and
// forwarding back as it found them once it stops, or the device goes.
func TestServingSetsTheHostUpAndBack(t *testing.T) {
	requireRoot(t)
	was, err := sysctls(strings.Fields(forwardingKeys))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := pfOutput("-s", "info")
	pfWasOn := strings.Contains(info, "Status: Enabled")
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	addr := netip.MustParseAddr("198.18.244.1")
	if out, err := exec.Command("/sbin/ifconfig", "juist7", "inet", "198.18.244.1/32", "198.18.244.1", "alias").CombinedOutput(); err != nil {
		t.Fatalf("an address: %v: %s", err, out)
	}
	s := ServeSpec{Sources: prefixes("198.18.244.0/24"), Addrs: []netip.Addr{addr}, DNSPort: 41646,
		Local: prefixes("10.0.0.0/8", "198.18.0.0/15")}
	if err := h.SetServe("juist7", s); err != nil {
		t.Fatal(err)
	}
	nat, _ := pfOutput("-a", "juist/juist7", "-s", "nat")
	if !strings.Contains(nat, "198.18.244.0/24") || !strings.Contains(nat, "port = domain") {
		t.Errorf("the anchor's translations:\n%s", nat)
	}
	now, _ := sysctls(strings.Fields(forwardingKeys))
	for k, v := range now {
		if v != "1" {
			t.Errorf("serving, %s is %s", k, v)
		}
	}
	if err := h.SetServe("juist7", ServeSpec{}); err != nil {
		t.Fatal(err)
	}
	if nat, _ := pfOutput("-a", "juist/juist7", "-s", "nat"); strings.TrimSpace(nat) != "" {
		t.Errorf("stopped, the anchor holds:\n%s", nat)
	}
	after, _ := sysctls(strings.Fields(forwardingKeys))
	for k, v := range was {
		if after[k] != v {
			t.Errorf("stopped, %s is %s, was %s", k, after[k], v)
		}
	}
	info, _ = pfOutput("-s", "info")
	if on := strings.Contains(info, "Status: Enabled"); on != pfWasOn {
		t.Errorf("stopped, pf is on: %v, was %v", on, pfWasOn)
	}
	// The device's end ends serving too.
	if err := h.SetServe("juist7", s); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := destroy(); err != nil {
		t.Fatal(err)
	}
	after, _ = sysctls(strings.Fields(forwardingKeys))
	for k, v := range was {
		if after[k] != v {
			t.Errorf("destroyed, %s is %s, was %s", k, after[k], v)
		}
	}
}

// Using an exit node routes the internet into the device behind a guard,
// which outlasts the device where it refuses; going direct takes both away
// and puts pf back as found.
// A device's guard has pf run with its anchor, its device in juist's group,
// and pf back as it was once it ends, by the device's end too.
func TestAGuardSetsTheHostUpAndBack(t *testing.T) {
	requireRoot(t)
	info, _ := pfOutput("-s", "info")
	pfWasOn := strings.Contains(info, "Status: Enabled")
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist6", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if out, _ := exec.Command("/sbin/ifconfig", "juist6").CombinedOutput(); !strings.Contains(string(out), "groups: tun "+DeviceGroup) {
		t.Errorf("the device is in no group of juist's:\n%s", out)
	}
	g := GuardSpec{Own: []netip.Addr{netip.MustParseAddr("198.18.240.1")}, Overlay: []netip.Addr{netip.MustParseAddr("198.18.240.2")}}
	if err := h.SetGuard("juist6", g); err != nil {
		t.Fatal(err)
	}
	rules, _ := pfOutput("-a", "juist/juist6_in", "-s", "rules")
	for _, want := range []string{"block drop in quick on ! juist6 from any to <juist_own>",
		"block drop in quick on ! juist from <juist_overlay> to any", "pass in quick on lo0"} {
		if !strings.Contains(rules, want) {
			t.Errorf("the anchor lacks %q:\n%s", want, rules)
		}
	}
	if info, _ := pfOutput("-s", "info"); !strings.Contains(info, "Status: Enabled") {
		t.Error("guarding, pf is off")
	}
	// The host reaches its own address by TCP, both ends of which come in
	// by the loopback, as its resolver's fallback does.
	if out, err := exec.Command("/sbin/ifconfig", "juist6", "inet", "198.18.240.1/32", "198.18.240.1", "alias").CombinedOutput(); err != nil {
		t.Fatalf("an address: %v: %s", err, out)
	}
	ln, err := net.Listen("tcp", "198.18.240.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second); err != nil {
		t.Errorf("guarded, the host does not reach its own address by TCP: %v", err)
	} else {
		c.Close()
	}
	if err := h.SetGuard("juist6", GuardSpec{}); err != nil {
		t.Fatal(err)
	}
	if rules, _ := pfOutput("-a", "juist/juist6_in", "-s", "rules"); strings.TrimSpace(rules) != "" {
		t.Errorf("unguarded, the anchor holds:\n%s", rules)
	}
	info, _ = pfOutput("-s", "info")
	if on := strings.Contains(info, "Status: Enabled"); on != pfWasOn {
		t.Errorf("unguarded, pf is on: %v, was %v", on, pfWasOn)
	}
	if err := h.SetGuard("juist6", g); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := destroy(); err != nil {
		t.Fatal(err)
	}
	if rules, _ := pfOutput("-a", "juist/juist6_in", "-s", "rules"); strings.TrimSpace(rules) != "" {
		t.Errorf("destroyed, the anchor holds:\n%s", rules)
	}
	info, _ = pfOutput("-s", "info")
	if on := strings.Contains(info, "Status: Enabled"); on != pfWasOn {
		t.Errorf("destroyed, pf is on: %v, was %v", on, pfWasOn)
	}
}

func TestEgressSetsTheHostUpAndBack(t *testing.T) {
	requireRoot(t)
	info, _ := pfOutput("-s", "info")
	pfWasOn := strings.Contains(info, "Status: Enabled")
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e := EgressSpec{Mode: EgressTunnel, V4: true, Local: prefixes("10.0.0.0/8"), Capture: prefixes("1.0.0.0/8", "8.0.0.0/7")}
	if err := h.SetEgress("juist7", e, 870); err != nil {
		t.Fatal(err)
	}
	rules, _ := pfOutput("-a", "juist/juist7_egress", "-s", "rules")
	if !strings.Contains(rules, "user = 870") || !strings.Contains(rules, "block drop out quick all") {
		t.Errorf("the guard:\n%s", rules)
	}
	out, _ := exec.Command("/sbin/route", "-n", "get", "8.8.8.8").CombinedOutput()
	if !strings.Contains(string(out), "juist7") {
		t.Errorf("8.8.8.8 is not routed into the device:\n%s", out)
	}
	// Refused with the device gone, nothing but local space leaves.
	if err := h.SetEgress("juist7", EgressSpec{Mode: EgressRefused, Local: e.Local, Capture: e.Capture}, 870); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := destroy(); err != nil {
		t.Fatal(err)
	}
	if rules, _ := pfOutput("-a", "juist/juist7_egress", "-s", "rules"); !strings.Contains(rules, "block drop out quick all") {
		t.Errorf("the device gone, the guard went:\n%s", rules)
	}
	if !h.Free("juist7") {
		t.Fatal("the device's lock is held")
	}
	if err := h.SetEgress("juist7", EgressSpec{Mode: EgressDirect}, 870); err != nil {
		t.Fatal(err)
	}
	if rules, _ := pfOutput("-a", "juist/juist7_egress", "-s", "rules"); strings.TrimSpace(rules) != "" {
		t.Errorf("direct, the guard holds:\n%s", rules)
	}
	info, _ = pfOutput("-s", "info")
	if on := strings.Contains(info, "Status: Enabled"); on != pfWasOn {
		t.Errorf("direct, pf is on: %v, was %v", on, pfWasOn)
	}
}

// The host's DNS goes to the servers alone by the device, and back.
func TestDNSGoesByResolvconf(t *testing.T) {
	requireRoot(t)
	was, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	h := FreeBSD{}
	if err := h.SetDNS("juist7", []netip.Addr{netip.MustParseAddr("198.18.244.1")}, nil); err != nil {
		t.Fatal(err)
	}
	now, _ := os.ReadFile("/etc/resolv.conf")
	if !strings.Contains(string(now), "nameserver 198.18.244.1") || strings.Count(string(now), "nameserver") != 1 {
		t.Errorf("routed, resolv.conf reads:\n%s", now)
	}
	if err := h.SetDNS("juist7", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.SetDNS("juist7", nil, nil); err != nil {
		t.Errorf("giving back what is back: %v", err)
	}
	if after, _ := os.ReadFile("/etc/resolv.conf"); string(after) != string(was) {
		t.Errorf("given back, resolv.conf reads:\n%s\nwas:\n%s", after, was)
	}
}

// What someone takes of juist's pf state is put back as egress is given
// again, and a ruleset the host loaded since is left be when juist lets go.
func TestPFIsKeptAndLeftBe(t *testing.T) {
	requireRoot(t)
	t.Cleanup(func() { pfctl("", "-F", "all"); pfctl("", "-d") })
	h := FreeBSD{}
	f, destroy, err := h.OpenTUN("juist7", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer destroy()
	defer f.Close()
	e := EgressSpec{Mode: EgressRefused, Local: prefixes("10.0.0.0/8"), Capture: prefixes("1.0.0.0/8")}
	if err := h.SetEgress("juist7", e, 870); err != nil {
		t.Fatal(err)
	}
	if err := pfctl("", "-a", "juist/juist7_egress", "-F", "rules"); err != nil {
		t.Fatal(err)
	}
	if err := pfctl("", "-d"); err != nil {
		t.Fatal(err)
	}
	if err := h.SetEgress("juist7", e, 870); err != nil {
		t.Fatal(err)
	}
	info, _ := pfOutput("-s", "info")
	rules, _ := pfOutput("-a", "juist/juist7_egress", "-s", "rules")
	if !strings.Contains(info, "Status: Enabled") || !strings.Contains(rules, "block drop out quick all") {
		t.Errorf("given again, pf is %q and the guard reads:\n%s", strings.SplitN(info, "\n", 2)[0], rules)
	}
	if !strings.Contains(rules, "pass in") || h.Answers() != "" {
		t.Errorf("with juist's ruleset, answers do not leave the way they came (%q):\n%s", h.Answers(), rules)
	}
	// The host's own ruleset now, calling juist's anchors, which the answer
	// rules, passing what comes in, would open to everything.
	own := "nat-anchor \"juist/*\"\nrdr-anchor \"juist/*\"\nblock in all\nanchor \"juist/*\"\n" +
		"block drop in quick proto tcp from any to any port 9 # the host's\n"
	if err := pfctl(own, "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := h.SetEgress("juist7", e, 870); err != nil {
		t.Fatal(err)
	}
	if rules, _ := pfOutput("-a", "juist/juist7_egress", "-s", "rules"); strings.Contains(rules, "pass in") {
		t.Errorf("beside the host's own ruleset, juist passes what comes in:\n%s", rules)
	}
	if h.Answers() == "" {
		t.Error("beside the host's own ruleset, answers are said to leave the way they came")
	}
	if err := h.SetEgress("juist7", EgressSpec{Mode: EgressDirect}, 870); err != nil {
		t.Fatal(err)
	}
	info, _ = pfOutput("-s", "info")
	rules, _ = pfOutput("-s", "rules")
	if !strings.Contains(info, "Status: Enabled") || !strings.Contains(rules, "port = discard") {
		t.Errorf("let go, the host's ruleset went: %q\n%s", strings.SplitN(info, "\n", 2)[0], rules)
	}
	pfctl("", "-F", "all")
	pfctl("", "-d")
}

// A pf juist turned on, which the host has since set to start with it,
// stays on once juist lets go: it is the host's now.
func TestAPfTheHostStartsIsLeftOn(t *testing.T) {
	requireRoot(t)
	info, _ := pfOutput("-s", "info")
	rules, _ := pfOutput("-s", "rules")
	if !strings.Contains(info, "Status: Disabled") || strings.TrimSpace(rules) != "" {
		t.Skip("pf runs, or holds rules, already")
	}
	was, _ := exec.Command("/usr/sbin/sysrc", "-n", "pf_enable").Output()
	t.Cleanup(func() {
		exec.Command("/usr/sbin/sysrc", "pf_enable="+strings.TrimSpace(string(was))).Run()
		pfctl("", "-F", "all")
		pfctl("", "-d")
	})
	h := FreeBSD{}
	e := EgressSpec{Mode: EgressRefused, Local: prefixes("10.0.0.0/8")}
	if err := h.SetEgress("juist7", e, 870); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/sbin/sysrc", "pf_enable=YES").CombinedOutput(); err != nil {
		t.Fatalf("sysrc: %v: %s", err, out)
	}
	if err := h.SetEgress("juist7", EgressSpec{Mode: EgressDirect}, 870); err != nil {
		t.Fatal(err)
	}
	if info, _ := pfOutput("-s", "info"); !strings.Contains(info, "Status: Enabled") {
		t.Error("juist turned off a pf the host starts itself")
	}
}

// The helper binds 443 for the relay where root granted it alone, and never
// where another program answers on the wildcard: root's socket at the address
// would take that server's clients.
func TestTheRelaysPortIsTakenFromNoServer(t *testing.T) {
	requireRoot(t)
	was := RelayGrant
	RelayGrant = filepath.Join(t.TempDir(), "relay-443")
	defer func() { RelayGrant = was }()
	probe, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Skip("no route off this host")
	}
	host := probe.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	probe.Close()
	if _, err := (FreeBSD{}).ListenHTTPS(host); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("without root's grant: %v", err)
	}
	if err := os.WriteFile(RelayGrant, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	server, err := net.Listen("tcp4", "0.0.0.0:443")
	if err != nil {
		t.Skipf("443 is held here: %v", err)
	}
	if f, err := (FreeBSD{}).ListenHTTPS(host); err == nil {
		f.Close()
		t.Error("443 was taken at the host's address from a server on the wildcard")
	}
	server.Close()
	f, err := FreeBSD{}.ListenHTTPS(host)
	if err != nil {
		t.Fatalf("granted, with no server: %v", err)
	}
	f.Close()
}
