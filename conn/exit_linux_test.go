//go:build linux && !android

package conn

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	mnl "github.com/mdlayher/netlink"
	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
	"tailscale.com/types/key"
)

// routeFor is what the exit table does with ip: the longest of its routes
// holding it, and of those the lowest metric.
func routeFor(routes []exitRoute, ip netip.Addr) (exitRoute, bool) {
	var best exitRoute
	found := false
	for _, r := range routes {
		if !r.dst.Contains(ip) {
			continue
		}
		if !found || r.dst.Bits() > best.dst.Bits() || r.dst.Bits() == best.dst.Bits() && r.metric < best.metric {
			best, found = r, true
		}
	}
	return best, found
}

// The exit table sends the internet into the tunnel, refused or not, so that
// a loose reverse-path check finds a route, and hands back to the host's
// routes what no exit node carries, and nothing in public space.
func TestTheExitTable(t *testing.T) {
	routes := exitRoutes(true)
	for ip, want := range map[string]int{
		"8.8.8.8": unix.RTN_UNICAST, "2606:4700::1111": unix.RTN_UNICAST, "203.0.114.9": unix.RTN_UNICAST,
		"2a02:810d::10": unix.RTN_UNICAST,
		"169.254.1.1":   unix.RTN_THROW, "224.0.0.251": unix.RTN_THROW, "255.255.255.255": unix.RTN_THROW,
		"fe80::1": unix.RTN_THROW, "ff02::fb": unix.RTN_THROW,
		"10.1.2.3": unix.RTN_THROW, "192.168.1.1": unix.RTN_THROW, "100.100.100.100": unix.RTN_THROW,
		"198.18.4.1": unix.RTN_THROW, "fd7a:115c:a1e0::1": unix.RTN_THROW,
	} {
		r, ok := routeFor(routes, netip.MustParseAddr(ip))
		if !ok || r.typ != want {
			t.Errorf("%s goes by %+v, want type %d", ip, r, want)
		}
	}
	if r, ok := routeFor(exitRoutes(false), netip.MustParseAddr("2606:4700::1111")); !ok ||
		r.typ != unix.RTN_UNREACHABLE {
		t.Errorf("IPv6 a tunnel without it cannot carry goes by %+v, want refused", r)
	}
	// Where the route into the tunnel goes with its device, the refusal
	// behind it stands.
	var left []exitRoute
	for _, r := range exitRoutes(true) {
		if r.typ != unix.RTN_UNICAST {
			left = append(left, r)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700::1111"} {
		if r, ok := routeFor(left, netip.MustParseAddr(ip)); !ok || r.typ != unix.RTN_UNREACHABLE {
			t.Errorf("without the device, %s goes by %+v, want refused", ip, r)
		}
	}
}

// Serving asks the host to forward each family it carries, and IPv6 only
// where the kernel has it.
func TestServingNeedsForwarding(t *testing.T) {
	v4, v6 := Internet(true, false, nil), Internet(true, true, nil)
	for _, tc := range []struct {
		name   string
		sysctl map[string]string
		routes []netip.Prefix
		ok     bool
	}{
		{"both on", map[string]string{"ipv4": "1\n", "ipv6": "1\n"}, v6, true},
		{"v4 off", map[string]string{"ipv4": "0\n", "ipv6": "1\n"}, v6, false},
		{"v6 off", map[string]string{"ipv4": "1\n", "ipv6": "0\n"}, v6, false},
		{"v6 off, v4 alone", map[string]string{"ipv4": "1\n", "ipv6": "0\n"}, v4, true},
		{"no v6 kernel", map[string]string{"ipv4": "1\n"}, v6, true},
		{"unreadable", map[string]string{}, v4, false},
	} {
		read := func(path string) ([]byte, error) {
			for fam, v := range tc.sysctl {
				if strings.Contains(path, "/"+fam+"/") {
					return []byte(v), nil
				}
			}
			if strings.Contains(path, "ipv6") {
				return nil, os.ErrNotExist
			}
			return nil, os.ErrPermission
		}
		if err := forwardingOff(read, tc.routes); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// An instance finds a lower one's exit table among the rules, which comes
// first, and not its own, a higher one's or an overlay's rules.
func TestOtherEgress(t *testing.T) {
	rule := func(pref, table int) netlink.Rule {
		r := *netlink.NewRule()
		r.Priority, r.Table = pref, table
		return r
	}
	own := rule(juistRulePrefBase+exitRuleExit+1, exitTable(1))
	peers := rule(juistRulePrefBase+70+2, juistRouteTable+2)
	if j := otherEgress([]netlink.Rule{own, peers}, 1, true); j != -1 {
		t.Errorf("found %d among its own and an overlay's rules", j)
	}
	other := rule(juistRulePrefBase+exitRuleExit+3, exitTable(3))
	if j := otherEgress([]netlink.Rule{peers, other}, 5, true); j != 3 {
		t.Errorf("found %d, want 3", j)
	}
	if j := otherEgress([]netlink.Rule{own, peers, other}, 1, true); j != -1 {
		t.Errorf("found %d, a higher instance, whose table comes after its own", j)
	}
	if j := otherEgress([]netlink.Rule{own, peers, other}, 1, false); j != 3 {
		t.Errorf("serving, found %d, want the higher instance 3, whose table would take its peers' traffic", j)
	}
	if j := otherEgress([]netlink.Rule{rule(juistRulePrefBase+exitRuleExit+3, 254)}, 5, true); j != -1 {
		t.Errorf("a stranger's rule at that preference was taken for juist's: %d", j)
	}
}

// The package's exit-node.sh clears these rules and tables by number.
func TestTheExitScriptKnowsTheRules(t *testing.T) {
	b, err := os.ReadFile("../packaging/exit-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pref $((" + strconv.Itoa(juistRulePrefBase+exitRuleOwn) + " + i)) table main",
		"pref $((" + strconv.Itoa(juistRulePrefBase+exitRuleExit) + " + i)) table $((" + strconv.Itoa(exitTable(0)) + " + i))",
		"flush table $((" + strconv.Itoa(exitTable(0)) + " + i))",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("exit-node.sh lacks %s", want)
		}
	}
	if !strings.Contains(string(b), "for t in juist$i juist${i}guard juist${i}in") || natTable(0, 7).Name != "juist7" ||
		guardTable(0, 7).Name != "juist7guard" || inTable(0, 7).Name != "juist7in" {
		t.Error("exit-node.sh does not name the nftables tables as conn does")
	}
}

// addrIn reads the address a prefix is about where IPv4 and IPv6 keep it.
func TestAddrInReadsTheRightAddress(t *testing.T) {
	for _, tc := range []struct {
		p        string
		src      bool
		off, len uint32
	}{{"10.0.0.0/8", true, 12, 4}, {"10.0.0.0/8", false, 16, 4}, {"fd00::/8", true, 8, 16}, {"fd00::/8", false, 24, 16}} {
		e := addrIn(netip.MustParsePrefix(tc.p), tc.src)
		pl := e[0].(*expr.Payload)
		mask := e[1].(*expr.Bitwise).Mask
		if pl.Offset != tc.off || pl.Len != tc.len || len(mask) != int(tc.len) || mask[0] != 0xff || mask[1] != 0 {
			t.Errorf("%s src %v: offset %d len %d mask %x", tc.p, tc.src, pl.Offset, pl.Len, mask)
		}
	}
}

// The guard lets out what goes into the tunnel, to loopback, bypass-marked,
// juistd's own on output, DHCP, and what goes to what no exit node carries,
// of its family, and drops the rest; refusing, it rejects what goes into the
// tunnel for anywhere else.
func TestTheGuardDropsWhatElseWouldLeave(t *testing.T) {
	both := tunnelled{v4: true, v6: true}
	allowed := offTunnel()
	v4, v6 := 0, 0
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	for _, tc := range []struct {
		fam            nftables.TableFamily
		output, refuse bool
		want           int
	}{
		{nftables.TableFamilyIPv4, true, false, 6 + v4 + 1}, {nftables.TableFamilyIPv4, false, false, 4 + v4 + 1},
		{nftables.TableFamilyIPv6, true, false, 7 + v6 + 1}, {nftables.TableFamilyIPv4, true, true, v4 + 1 + 5 + v4 + 1},
	} {
		rules := guardRules(tc.fam, tc.output, "juist0", both, tc.refuse, 900)
		if len(rules) != tc.want {
			t.Errorf("%v output %v refuse %v: %d rules, want %d", tc.fam, tc.output, tc.refuse, len(rules), tc.want)
			continue
		}
		last := rules[len(rules)-1]
		if v, ok := last[len(last)-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop || len(last) != 2 {
			t.Errorf("%v: the last rule is %v, not a drop of everything", tc.fam, last)
		}
		rejects := 0
		for _, r := range rules[:len(rules)-1] {
			switch v := r[len(r)-1].(type) {
			case *expr.Reject:
				rejects++
			case *expr.Verdict:
				if v.Kind != expr.VerdictAccept {
					t.Errorf("%v: a rule before the last does not accept: %v", tc.fam, r)
				}
			}
		}
		if want := map[bool]int{true: 1, false: 0}[tc.refuse]; rejects != want {
			t.Errorf("%v refuse %v: %d rejects", tc.fam, tc.refuse, rejects)
		}
	}
	if n := len(guardRules(nftables.TableFamilyIPv4, true, "", both, true, 0)); n != 4+v4+1 {
		t.Errorf("with no device and root: %d rules", n)
	}
	for _, a := range []string{"203.0.114.9", "8.8.8.8", "2a02:810d::10"} {
		if slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) }) {
			t.Errorf("%s may leave outside the tunnel", a)
		}
	}
}

// The kernel lists a default route without a destination, and IPv6 with the
// metric 1024 where 0 was asked for: read back, they are the routes juist
// installs, and no sweep takes them away.
func TestExitRoutesReadBack(t *testing.T) {
	for _, tc := range []struct {
		fam  int
		nr   netlink.Route
		want exitRoute
	}{
		{netlink.FAMILY_V4, netlink.Route{Type: unix.RTN_UNICAST}, exitRoute{netip.MustParsePrefix("0.0.0.0/0"), unix.RTN_UNICAST, 0}},
		{netlink.FAMILY_V6, netlink.Route{Type: unix.RTN_UNREACHABLE, Priority: refusedMetric},
			exitRoute{netip.MustParsePrefix("::/0"), unix.RTN_UNREACHABLE, refusedMetric}},
		{netlink.FAMILY_V6, netlink.Route{Type: unix.RTN_THROW, Priority: 1024,
			Dst: netipx.PrefixIPNet(netip.MustParsePrefix("fe80::/10"))},
			exitRoute{netip.MustParsePrefix("fe80::/10"), unix.RTN_THROW, 0}},
	} {
		if got, ok := exitRouteOf(tc.fam, tc.nr); !ok || got != tc.want {
			t.Errorf("%+v read back as %+v, %v; want %+v", tc.nr, got, ok, tc.want)
		}
	}
	want := map[exitRoute]bool{}
	for _, rt := range exitRoutes(true) {
		want[rt] = true
	}
	if !want[exitRoute{netip.MustParsePrefix("fe80::/10"), unix.RTN_THROW, 0}] {
		t.Error("the table has no fe80::/10 throw to compare with")
	}
}

// Every juist device of the host may bring overlay sources in; others not.
func TestServingLetsEveryJuistDeviceIn(t *testing.T) {
	rules := serveRules(nftables.TableFamilyIPv4, ifname("juist0"), []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")})
	if cmp := rules[0][1].(*expr.Cmp); string(cmp.Data) != "juist" || cmp.Op != expr.CmpOpNeq {
		t.Errorf("the first rule compares the input device with %q", cmp.Data)
	}
}

// Serving drops forwarded packets from elsewhere with an overlay source, and
// new ones into the overlay from public space.
func TestServingDropsWhatIsNoPeers(t *testing.T) {
	srcs := []netip.Prefix{netip.MustParsePrefix("198.18.4.0/22"), netip.MustParsePrefix("fd12:3456:789a::/48")}
	rules := serveRules(nftables.TableFamilyIPv4, ifname("juist0"), srcs)
	if v := rules[0][len(rules[0])-1].(*expr.Verdict); v.Kind != expr.VerdictDrop {
		t.Errorf("the first rule does not drop an overlay source from elsewhere: %v", rules[0])
	}
	last := rules[len(rules)-1]
	if v := last[len(last)-1].(*expr.Verdict); v.Kind != expr.VerdictDrop {
		t.Errorf("the last rule does not drop what is new into the overlay: %v", last)
	}
	v4special := 0
	for _, p := range localSpace {
		if p.Addr().Is4() {
			v4special++
		}
	}
	if len(rules) != 1+v4special+1 {
		t.Errorf("%d rules, want %d", len(rules), 2+v4special)
	}
}

// The guard lets out the host's own DHCP from its client port alone, and its
// neighbour discovery at hop limit 255; it forwards neither.
func TestTheGuardLetsTheHostsOwnLinkTrafficOut(t *testing.T) {
	both := tunnelled{v4: true, v6: true}
	for _, tc := range []struct {
		fam  nftables.TableFamily
		want []byte
	}{{nftables.TableFamilyIPv4, []byte{0, 68, 0, 67}}, {nftables.TableFamilyIPv6, []byte{2, 34, 2, 35}}} {
		has := func(rules [][]expr.Any, match func(expr.Any) bool) bool {
			return slices.ContainsFunc(rules, func(r []expr.Any) bool { return slices.ContainsFunc(r, match) })
		}
		dhcp := func(e expr.Any) bool { c, ok := e.(*expr.Cmp); return ok && slices.Equal(c.Data, tc.want) }
		nd := func(e expr.Any) bool { rg, ok := e.(*expr.Range); return ok && rg.FromData[0] == 133 }
		out, fwd := guardRules(tc.fam, true, "juist0", both, false, 900), guardRules(tc.fam, false, "juist0", both, false, 0)
		if !has(out, dhcp) || has(fwd, dhcp) {
			t.Errorf("%v: DHCP out %v, forwarded %v", tc.fam, has(out, dhcp), has(fwd, dhcp))
		}
		if tc.fam == nftables.TableFamilyIPv6 && (!has(out, nd) || has(fwd, nd)) {
			t.Errorf("neighbour discovery out %v, forwarded %v", has(out, nd), has(fwd, nd))
		}
	}
}

// The host's own routes are every table's but this instance's and the
// default, other overlays' tables among them; what a network pushed into
// main by DHCP or router advertisement is not the host's to keep.
func TestTheHostsOwnRoutes(t *testing.T) {
	route := func(dst string, table, proto, typ, link int) netlink.Route {
		return netlink.Route{Dst: netipx.PrefixIPNet(netip.MustParsePrefix(dst)), Table: table,
			Protocol: netlink.RouteProtocol(proto), Type: typ, LinkIndex: link}
	}
	const own, inst = 7, 0
	if _, keep := hostRoute(route("fd11:2233:4455::7/128", juistRouteTable, unix.RTPROT_BOOT, unix.RTN_UNICAST, 6), own, 1); !keep {
		t.Error("a lower instance's route is not the host's to the higher")
	}
	for _, tc := range []struct {
		nr   netlink.Route
		keep bool
	}{
		{route("10.8.0.0/24", unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RTN_UNICAST, 3), true},           // a VPN
		{route("172.17.0.0/16", unix.RT_TABLE_MAIN, unix.RTPROT_KERNEL, unix.RTN_UNICAST, 4), true},       // docker
		{route("100.101.2.3/32", 52, unix.RTPROT_BOOT, unix.RTN_UNICAST, 5), true},                        // tailscaled's
		{route("fd11:2233:4455::7/128", juistRouteTable+1, unix.RTPROT_BOOT, unix.RTN_UNICAST, 6), false}, // a higher instance's
		{route("100.70.0.0/16", 1000, unix.RTPROT_BOOT, unix.RTN_UNICAST, 6), false},                      // a VRF's, or marked traffic's
		{route("10.9.0.0/16", 52, unix.RTPROT_DHCP, unix.RTN_UNICAST, 2), false},
		{route("10.0.0.0/8", unix.RT_TABLE_MAIN, unix.RTPROT_DHCP, unix.RTN_UNICAST, 2), false}, // option 121
		{route("2001:db8:1::/48", unix.RT_TABLE_MAIN, unix.RTPROT_RA, unix.RTN_UNICAST, 2), false},
		{route("192.168.50.0/24", routeTable(inst), unix.RTPROT_BOOT, unix.RTN_UNICAST, own), false}, // its own
		{route("0.0.0.0/0", unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RTN_UNICAST, 2), false},
		{route("192.0.2.0/24", unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RTN_UNREACHABLE, 0), false},
	} {
		if _, keep := hostRoute(tc.nr, own, inst); keep != tc.keep {
			t.Errorf("%v in table %d, protocol %d: kept %v", tc.nr.Dst, tc.nr.Table, tc.nr.Protocol, keep)
		}
	}
}

// The exit rule leaves bypass-marked packets to later rules, so that
// tailscaled's own traffic is never refused, a router of this instance's or
// not.
func TestTheExitRuleLeavesBypassMarkedPackets(t *testing.T) {
	ru := exitRule(netlink.FAMILY_V4, 2)
	if !ru.Invert || ru.Mark != tsconst.LinuxBypassMarkNum || ru.Mask != tsconst.LinuxFwmarkMaskNum ||
		ru.Table != exitTable(2) || ru.Priority != juistRulePrefBase+exitRuleExit+2 {
		t.Errorf("the exit rule is %+v", ru)
	}
}

// A family no exit node carries is refused into the tunnel, at once rather
// than dropped unsaid by WireGuard, but for the subnets routers carry.
func TestTheGuardRefusesWhatNoPeerCarries(t *testing.T) {
	peers := map[key.NodePublic]Peer{
		key.NewNode().Public(): {Routes: Internet(true, false, nil)},
		key.NewNode().Public(): {Subnets: []netip.Prefix{netip.MustParsePrefix("2a01:4f8:1::/48"), netip.MustParsePrefix("192.168.50.0/24")}},
	}
	through := tunnelledBy(peers)
	if !through.carries(nftables.TableFamilyIPv4) || through.carries(nftables.TableFamilyIPv6) || len(through.subnets) != 2 {
		t.Fatalf("the peers carry %+v", through)
	}
	subnet := netip.MustParsePrefix("2a01:4f8:1::/48").Addr().AsSlice()
	rules := guardRules(nftables.TableFamilyIPv6, true, "juist0", through, false, 900)
	reject, passes := -1, -1
	for i, r := range rules {
		if _, ok := r[len(r)-1].(*expr.Reject); ok && reject < 0 {
			reject = i
		}
		for _, e := range r {
			if c, ok := e.(*expr.Cmp); ok && slices.Equal(c.Data, subnet) && passes < 0 {
				passes = i
			}
		}
	}
	if reject < 0 || passes < 0 || passes > reject {
		t.Errorf("the subnet passes at rule %d, the rest is rejected at %d", passes, reject)
	}
	if !tunnelledBy(peers).equal(through) || through.equal(tunnelled{v4: true}) {
		t.Error("equal is wrong")
	}
}

// An exit rule without the bypass mark, as earlier builds left, is told apart
// from the marked one, which alone stays.
func TestAnUnmarkedExitRuleIsFound(t *testing.T) {
	want := exitRule(netlink.FAMILY_V4, 1)
	unmarked := *netlink.NewRule()
	unmarked.Priority, unmarked.Table = want.Priority, want.Table
	other := unmarked
	other.Table = exitTable(2)
	if !unmarkedExitRule(unmarked, want) || unmarkedExitRule(want, want) || unmarkedExitRule(other, want) {
		t.Error("the unmarked exit rule is not told apart")
	}
}

// A kernel without IPv6 policy routing takes no IPv6 egress rule, the guard
// keeping IPv6 in, and has none to delete; one without IPv4's cannot keep
// egress in, so adding there fails.
func TestEgressRulesWithoutPolicyRouting(t *testing.T) {
	v4, v6 := netlink.FAMILY_V4, netlink.FAMILY_V6
	wrapped := func(e syscall.Errno) error { return fmt.Errorf("adding a rule: %w", e) }
	for _, tc := range []struct {
		add  bool
		fam  int
		err  error
		done bool
	}{
		{true, v4, nil, true},
		{true, v4, wrapped(syscall.EEXIST), true},
		{true, v6, wrapped(syscall.EAFNOSUPPORT), true},
		{true, v4, wrapped(syscall.EAFNOSUPPORT), false},
		{true, v6, wrapped(syscall.ENOENT), false},
		{true, v4, wrapped(syscall.EPERM), false},
		{false, v4, wrapped(syscall.ENOENT), true},
		{false, v4, wrapped(syscall.EAFNOSUPPORT), true},
		{false, v6, wrapped(syscall.EAFNOSUPPORT), true},
		{false, v6, wrapped(syscall.EEXIST), false},
		{false, v4, wrapped(syscall.EPERM), false},
	} {
		if got := ruleDone(tc.add, tc.fam, tc.err); got != tc.done {
			t.Errorf("add %v, family %d, %v: done %v, want %v", tc.add, tc.fam, tc.err, got, tc.done)
		}
	}
}

// firewalld's strict IPv6 reverse-path rule looks the source up by the
// incoming device, its loose one does not, as the kernel lists them.
func TestAStrictReversePathRuleIsToldApart(t *testing.T) {
	rule := func(exprs ...expr.Any) []byte {
		var list []mnl.Attribute
		for _, e := range exprs {
			b, err := expr.Marshal(byte(nftables.TableFamilyINet), e)
			if err != nil {
				t.Fatal(err)
			}
			list = append(list, mnl.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: b})
		}
		exprs2, err := mnl.MarshalAttributes(list)
		if err != nil {
			t.Fatal(err)
		}
		b, err := mnl.MarshalAttributes([]mnl.Attribute{
			{Type: unix.NFTA_RULE_TABLE, Data: []byte("firewalld\x00")},
			{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: exprs2},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nfproto := &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}
	strict := rule(nfproto, &expr.Fib{Register: 1, FlagSADDR: true, FlagMARK: true, FlagIIF: true, ResultOIF: true})
	loose := rule(nfproto, &expr.Fib{Register: 1, FlagSADDR: true, FlagMARK: true, ResultOIF: true})
	if !strictRPRule(strict) || strictRPRule(loose) || strictRPRule(rule(nfproto)) || strictRPRule(nil) {
		t.Error("the strict rule is not told apart from the loose one")
	}
}

// Peers' DNS is redirected to the forwarder where it asks this node's own
// address on port 53, and no other server's.
func TestDNSIsRedirectedToTheForwarder(t *testing.T) {
	addr := netip.MustParseAddr("10.11.11.13")
	rule := dnsRedirect(ifname("juist0"), addr, unix.IPPROTO_UDP, 41646)
	var sawAddr, saw53, sawPort, redir bool
	for _, e := range rule {
		switch v := e.(type) {
		case *expr.Cmp:
			sawAddr = sawAddr || slices.Equal(v.Data, addr.AsSlice())
			saw53 = saw53 || slices.Equal(v.Data, []byte{0, 53})
		case *expr.Immediate:
			sawPort = slices.Equal(v.Data, []byte{0xa2, 0xae})
		case *expr.Redir:
			redir = v.RegisterProtoMin == 1
		}
	}
	if !sawAddr || !saw53 || !sawPort || !redir {
		t.Errorf("the rule %v: address %v, port 53 %v, forwarder %v, redirect %v", rule, sawAddr, saw53, sawPort, redir)
	}
}

// Answers to what came in by another device pass the guard, in both chains,
// unless the host is isolated; a connection is marked for it only where it
// comes in by a device of neither juist's nor the loopback.
func TestTheGuardPassesAnswersButIsolated(t *testing.T) {
	answering := func(rules [][]expr.Any) bool {
		return slices.ContainsFunc(rules, func(r []expr.Any) bool {
			ct, ok := r[0].(*expr.Ct)
			return ok && ct.Key == expr.CtKeyDIRECTION
		})
	}
	for _, output := range []bool{true, false} {
		if !answering(guardRules(nftables.TableFamilyIPv4, output, "juist0", tunnelled{v4: true}, false, 900)) {
			t.Errorf("output %v: answers do not pass", output)
		}
		if answering(guardRules(nftables.TableFamilyIPv4, output, "juist0", tunnelled{v4: true, answers: true}, true, 900)) {
			t.Errorf("output %v: isolated, answers pass", output)
		}
	}
	var names [][]byte
	var fibs []*expr.Fib
	for _, e := range markIncoming("vpn0") {
		if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpNeq && len(c.Data) != 4 {
			names = append(names, c.Data)
		}
		if f, ok := e.(*expr.Fib); ok {
			fibs = append(fibs, f)
		}
		if ct, ok := e.(*expr.Ct); ok && ct.Key == expr.CtKeySTATE {
			t.Error("only new connections are marked, not those older than the guard")
		}
	}
	if len(names) != 3 || string(names[0]) != "juist" || string(names[1]) != "lo\x00" || string(names[2]) != "vpn0\x00" {
		t.Errorf("a connection is marked coming in by any device but %q", names)
	}
	// Sent to the device's own address, from where the host's routes, with
	// the answer's mark, lead back by that device.
	if len(fibs) != 2 || !fibs[0].FlagDADDR || !fibs[0].FlagIIF || !fibs[0].ResultADDRTYPE ||
		!fibs[1].FlagSADDR || !fibs[1].FlagMARK || !fibs[1].FlagIIF || !fibs[1].ResultOIF {
		t.Errorf("a connection is marked without both lookups: %+v", fibs)
	}
	if !isExitRulePref(uint32(juistRulePrefBase+exitRuleAnswers+3), 3) {
		t.Error("the answer rule, deleted, is not put back")
	}
	if r := answerRule(unix.AF_INET, 3); r.Priority != juistRulePrefBase+exitRuleAnswers+3 || r.Table != unix.RT_TABLE_MAIN ||
		r.Mark != answerMark || r.Mask != answerMark || answerMark&tsconst.LinuxFwmarkMaskNum != 0 {
		t.Errorf("the answer rule is %+v", r)
	}
}

// The in table drops what is for this node's addresses by any device but its
// own and loopback, and what is from an overlay address by any but a juist
// device too.
func TestTheInTableKeepsTheOverlayToItsDevice(t *testing.T) {
	own, overlay := &nftables.Set{Name: "own", ID: 1}, &nftables.Set{Name: "overlay", ID: 2}
	for _, fam := range families {
		rules := inRules(fam, "jt0", own, overlay)
		if len(rules) != 2 {
			t.Fatalf("%v: %d rules, want 2", fam, len(rules))
		}
		off := map[nftables.TableFamily][2]uint32{nftables.TableFamilyIPv4: {16, 12}, nftables.TableFamilyIPv6: {24, 8}}[fam]
		for i, want := range []struct {
			set  string
			from []string
		}{{"own", []string{"jt0\x00", "lo\x00"}}, {"overlay", []string{"juist", "jt0\x00", "lo\x00"}}} {
			r := rules[i]
			var from []string
			for _, e := range r {
				if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpNeq {
					from = append(from, string(c.Data))
				}
			}
			if !slices.Equal(from, want.from) {
				t.Errorf("%v rule %d: not from %q, want %q", fam, i, from, want.from)
			}
			pl := r[len(r)-4].(*expr.Payload)
			lk := r[len(r)-3].(*expr.Lookup)
			if pl.Offset != off[i] || lk.SetName != want.set {
				t.Errorf("%v rule %d: looks up offset %d in %s", fam, i, pl.Offset, lk.SetName)
			}
			if v := r[len(r)-1].(*expr.Verdict); v.Kind != expr.VerdictDrop {
				t.Errorf("%v rule %d does not drop", fam, i)
			}
		}
	}
	if rules := inRules(nftables.TableFamilyIPv4, "jt0", nil, overlay); len(rules) != 1 {
		t.Errorf("without own addresses: %d rules", len(rules))
	}
}
