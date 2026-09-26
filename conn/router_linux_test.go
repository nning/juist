//go:build linux && !android

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tstun"
	"tailscale.com/tsconst"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

// tailscalePrefBase and tailscaleTable are what tailscaled's Linux router
// uses (wgengine/router/osrouter/router_linux.go in the pinned module).
const (
	tailscalePrefBase = 5200
	tailscaleTable    = 52
)

func TestJuistRulesStayClearOfTailscale(t *testing.T) {
	if juistRouteTable == tailscaleTable || (juistRouteTable >= 253 && juistRouteTable <= 255) || juistRouteTable == 0 {
		t.Fatalf("juistRouteTable %d collides with Tailscale's or a kernel table", juistRouteTable)
	}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules := juistRules(fam)
		want := []struct {
			pref, table int
			mark        bool
			unreachable bool
		}{
			{5110, unix.RT_TABLE_MAIN, true, false},
			{5130, unix.RT_TABLE_DEFAULT, true, false},
			{5150, 0, true, true},
			{5170, juistRouteTable, false, false},
		}
		if len(rules) != len(want) {
			t.Fatalf("family %d: %d rules, want %d", fam, len(rules), len(want))
		}
		for i, w := range want {
			ru := rules[i]
			if ru.Family != fam || ru.Priority != w.pref || ru.Table != w.table ||
				(ru.Type == unix.RTN_UNREACHABLE) != w.unreachable {
				t.Errorf("rule %d = %+v, want %+v", i, ru, w)
			}
			if w.mark && (ru.Mark != tsconst.LinuxBypassMarkNum || ru.Mask != tsconst.LinuxFwmarkMaskNum) {
				t.Errorf("rule %d: mark %#x/%#x, want the bypass mark", i, ru.Mark, ru.Mask)
			}
			if !w.mark && (ru.Mark != -1 || ru.Mask != -1) {
				t.Errorf("rule %d matches a mark (%#x/%#x); it must match every packet", i, ru.Mark, ru.Mask)
			}
			// Below Tailscale's first rule, so ours are consulted first, and
			// inside the range the restore filter watches.
			if ru.Priority >= tailscalePrefBase+10 || !isJuistRulePref(uint32(ru.Priority)) {
				t.Errorf("rule %d: priority %d is not ours or not ahead of Tailscale's", i, ru.Priority)
			}
			if ru.Goto != -1 || ru.Flow != -1 || ru.SuppressIfgroup != -1 || ru.SuppressPrefixlen != -1 {
				t.Errorf("rule %d sets an attribute it does not mean: %+v", i, ru)
			}
		}
	}
	for _, pref := range []uint32{5099, 5200, 5210, 5270, 1310} {
		if isJuistRulePref(pref) {
			t.Errorf("isJuistRulePref(%d) = true; a Tailscale rule's deletion would trigger our restore", pref)
		}
	}
}

func TestReconcile(t *testing.T) {
	p := netip.MustParsePrefix
	a, b, c := p("198.18.0.2/32"), p("198.18.0.3/32"), p("fd7a:115c:a1e0::2/128")
	var added, deleted []netip.Prefix
	failAdd, failDel := map[netip.Prefix]bool{}, map[netip.Prefix]bool{}
	add := func(x netip.Prefix) error {
		if failAdd[x] {
			return fmt.Errorf("add %v", x)
		}
		added = append(added, x)
		return nil
	}
	del := func(x netip.Prefix) error {
		if failDel[x] {
			return fmt.Errorf("del %v", x)
		}
		deleted = append(deleted, x)
		return nil
	}
	step := func(have map[netip.Prefix]bool, want ...netip.Prefix) (map[netip.Prefix]bool, error) {
		added, deleted = nil, nil
		var errs []error
		next := reconcile(have, want, add, del, &errs)
		return next, errors.Join(errs...)
	}
	keys := func(m map[netip.Prefix]bool) []netip.Prefix {
		var out []netip.Prefix
		for k := range m {
			out = append(out, k)
		}
		slices.SortFunc(out, func(x, y netip.Prefix) int { return x.Addr().Compare(y.Addr()) })
		return out
	}

	have, err := step(nil, a, b)
	if err != nil || len(added) != 2 || len(deleted) != 0 || len(have) != 2 {
		t.Fatalf("from empty: have %v added %v deleted %v err %v", keys(have), added, deleted, err)
	}
	have, err = step(have, a, b)
	if err != nil || len(added)+len(deleted) != 0 {
		t.Fatalf("an identical config touched the OS: added %v deleted %v err %v", added, deleted, err)
	}

	// One failed add must not stop the rest, and stays absent so it is retried.
	failAdd[c] = true
	failDel[a] = true
	have, err = step(have, b, c)
	if err == nil {
		t.Fatal("failures were not reported")
	}
	if got := keys(have); !slices.Equal(got, []netip.Prefix{a, b}) {
		t.Fatalf("after a failed add of %v and a failed delete of %v: have %v", c, a, got)
	}
	delete(failAdd, c)
	delete(failDel, a)
	have, err = step(have, b, c)
	if err != nil || !slices.Equal(added, []netip.Prefix{c}) || !slices.Equal(deleted, []netip.Prefix{a}) {
		t.Fatalf("retry: added %v deleted %v err %v", added, deleted, err)
	}

	have, err = step(have)
	if err != nil || len(have) != 0 || len(deleted) != 2 {
		t.Fatalf("empty config: have %v deleted %v err %v", keys(have), deleted, err)
	}
}

func TestUsableDropsIPv6WithoutIt(t *testing.T) {
	p := netip.MustParsePrefix
	in := []netip.Prefix{p("198.18.0.2/32"), p("fd7a:115c:a1e0::2/128"), p("10.1.2.3/24")}
	if got := usable(in, false, true); !slices.Equal(got, []netip.Prefix{p("198.18.0.2/32"), p("10.1.2.0/24")}) {
		t.Errorf("without IPv6, routes: %v", got)
	}
	if got := usable(in, true, false); !slices.Equal(got, in) {
		t.Errorf("with IPv6, addresses: %v", got)
	}
}

func TestLinkV6Usable(t *testing.T) {
	dir := t.TempDir()
	for name, v := range map[string]string{"on": "0\n", "off": "1\n", "odd": "?\n"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "disable_ipv6"), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]bool{"on": true, "off": false, "odd": true, "absent": false} {
		if got := linkV6Usable(dir, name); got != want {
			t.Errorf("linkV6Usable(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestNetnsRouterLeavesTailscaleAlone runs juist's router in a namespace that
// already holds tailscaled's rules and an exit node's default route: ours must
// win for peer addresses, restore themselves, and go on Close without taking
// Tailscale's along — nor lose ours when Tailscale removes its own.
func TestNetnsRouterLeavesTailscaleAlone(t *testing.T) {
	lab := newNetnsLab(t)
	n := lab.newDetachedNode("r", 1)
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating this test binary: %v", err)
	}
	cmd := lab.exec(n, self, "-test.run", "^TestHelperNetnsRouter$", "-test.v", "-test.timeout", "2m")
	cmd.Env = append(os.Environ(), netnsHelperEnv+"=router", envTun+"="+n.tun)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("router helper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), protoPrefix+"ROUTER OK") {
		t.Fatalf("router helper did not run to the end:\n%s", out)
	}
}

// TestHelperNetnsRouter is the namespace half of
// TestNetnsRouterLeavesTailscaleAlone.
func TestHelperNetnsRouter(t *testing.T) {
	if os.Getenv(netnsHelperEnv) != "router" {
		t.Skip("not a netns router helper invocation")
	}
	p := netip.MustParsePrefix
	selfV4, selfV6 := p("198.18.0.1/32"), p("fd7a:115c:a1e0::1/128")
	peerV4, peerV6 := p("198.18.0.2/32"), p("fd7a:115c:a1e0::2/128")
	fams := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}

	// tailscaled with an exit node: its first and last rule, and a default
	// route in table 52 that would swallow our peers' addresses.
	for _, fam := range fams {
		for _, ru := range tailscaleRules(fam) {
			if err := netlink.RuleAdd(&ru); err != nil {
				t.Fatalf("seeding %v: %v", ru, err)
			}
		}
	}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: netipx.PrefixIPNet(p("0.0.0.0/0")), Table: tailscaleTable, Type: unix.RTN_BLACKHOLE,
	}); err != nil {
		t.Fatalf("seeding table 52: %v", err)
	}

	name := os.Getenv(envTun)
	dev, err := tun.CreateTUN(name, int(tstun.DefaultTUNMTU()))
	if err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	defer dev.Close()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	mon.Start()
	newRouter := func() router.Router {
		r, err := newOSRouter(t.Logf, dev, mon, nil, bus)
		if err != nil {
			t.Fatalf("newOSRouter: %v", err)
		}
		return r
	}

	r := newRouter()
	if err := r.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	cfg := &router.Config{LocalAddrs: []netip.Prefix{selfV4, selfV6}, Routes: []netip.Prefix{peerV4, peerV6}}
	for i := range 2 {
		if err := r.Set(cfg); err != nil {
			t.Fatalf("Set #%d: %v", i+1, err)
		}
	}
	requireRules(t, fams, true)
	requireTailscaleIntact(t, fams)
	peers := []netip.Prefix{peerV4}
	if linkV6Usable("/proc/sys/net/ipv6/conf", name) {
		peers = append(peers, peerV6)
	} else {
		t.Logf("no IPv6 on %s; asserting the v4 half only", name)
	}
	for _, pfx := range peers {
		if !routedVia(pfx.Addr(), link) {
			t.Errorf("%v is not routed into %s past table 52's default route", pfx.Addr(), name)
		}
	}
	if routedVia(netip.MustParseAddr("198.18.0.9"), link) {
		t.Errorf("an address of no peer is routed into %s", name)
	}

	// With two IPv4 addresses, as while a renumbering is under way, a peer is
	// sent to from the first; dropping it moves the routes to the other.
	retiring := p("198.18.0.3/32")
	if err := r.Set(&router.Config{LocalAddrs: []netip.Prefix{selfV6, retiring, selfV4}, Routes: cfg.Routes}); err != nil {
		t.Fatalf("Set with a retiring address: %v", err)
	}
	if got := routeSrc(peerV4.Addr()); got != retiring.Addr() {
		t.Errorf("with a retiring address the peer is sent to from %v, want %v", got, retiring.Addr())
	}
	if err := r.Set(cfg); err != nil {
		t.Fatalf("Set without the retiring address: %v", err)
	}
	if got := routeSrc(peerV4.Addr()); got != selfV4.Addr() || !routedVia(peerV4.Addr(), link) {
		t.Errorf("after the retiring address went the peer is sent to from %v (routed into %s: %v), want %v",
			got, name, routedVia(peerV4.Addr(), link), selfV4.Addr())
	}

	// systemd-networkd's move: delete one of ours and expect it back.
	gone := juistRules(netlink.FAMILY_V4)[3]
	if err := netlink.RuleDel(&gone); err != nil {
		t.Fatalf("deleting %v: %v", gone, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !haveRule(t, gone) {
		if time.Now().After(deadline) {
			t.Fatalf("%v was not restored", gone)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	requireRules(t, fams, false)
	requireTailscaleIntact(t, fams)
	if rs, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: juistRouteTable}, netlink.RT_FILTER_TABLE); err != nil || len(rs) != 0 {
		t.Errorf("table %d after Close: %v (err %v)", juistRouteTable, rs, err)
	}

	// tailscaled shutting down deletes its rules the way its delIPRules does:
	// by priority and table, any mark. Ours must survive that.
	r = newRouter()
	if err := r.Up(); err != nil {
		t.Fatalf("second Up: %v", err)
	}
	for _, fam := range fams {
		for _, ru := range tailscaleRules(fam) {
			ru.Mark, ru.Mask = -1, -1
			if err := netlink.RuleDel(&ru); err != nil {
				t.Fatalf("deleting Tailscale's %v: %v", ru, err)
			}
		}
	}
	requireRules(t, fams, true)
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// The engine may close a router it never brought up.
	if err := newRouter().Close(); err != nil {
		t.Fatalf("Close without Up: %v", err)
	}
	fmt.Println(protoPrefix + "ROUTER OK")
}

func tailscaleRules(fam int) []netlink.Rule {
	main, all := *netlink.NewRule(), *netlink.NewRule()
	main.Family, main.Priority, main.Table = fam, tailscalePrefBase+10, unix.RT_TABLE_MAIN
	main.Mark, main.Mask = tsconst.LinuxBypassMarkNum, tsconst.LinuxFwmarkMaskNum
	all.Family, all.Priority, all.Table = fam, tailscalePrefBase+70, tailscaleTable
	return []netlink.Rule{main, all}
}

func haveRule(t *testing.T, want netlink.Rule) bool {
	t.Helper()
	rules, err := netlink.RuleList(want.Family)
	if err != nil {
		t.Fatalf("listing rules: %v", err)
	}
	return slices.ContainsFunc(rules, func(ru netlink.Rule) bool {
		return ru.Priority == want.Priority && ru.Table == want.Table && ru.Mark == want.Mark &&
			ru.Mask == want.Mask && (ru.Type == unix.RTN_UNREACHABLE) == (want.Type == unix.RTN_UNREACHABLE)
	})
}

func requireRules(t *testing.T, fams []int, present bool) {
	t.Helper()
	for _, fam := range fams {
		for _, ru := range juistRules(fam) {
			if haveRule(t, ru) != present {
				t.Errorf("%v (family %d): present = %v, want %v", ru, fam, !present, present)
			}
		}
	}
}

func requireTailscaleIntact(t *testing.T, fams []int) {
	t.Helper()
	for _, fam := range fams {
		for _, ru := range tailscaleRules(fam) {
			if !haveRule(t, ru) {
				t.Errorf("Tailscale's %v (family %d) is gone", ru, fam)
			}
		}
	}
	rs, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: tailscaleTable}, netlink.RT_FILTER_TABLE)
	if err != nil || len(rs) == 0 {
		t.Errorf("table 52's default route is gone (err %v)", err)
	}
}

// routeSrc is the source address the kernel chooses for dst.
func routeSrc(dst netip.Addr) netip.Addr {
	rs, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	if err != nil || len(rs) == 0 {
		return netip.Addr{}
	}
	a, _ := netip.AddrFromSlice(rs[0].Src)
	return a.Unmap()
}

func routedVia(dst netip.Addr, link netlink.Link) bool {
	rs, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	return err == nil && len(rs) > 0 && rs[0].LinkIndex == link.Attrs().Index
}
