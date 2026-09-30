//go:build linux && !android

package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tailscale/netlink"
	"github.com/tailscale/netlink/nl"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

// exitTable is instance inst's table for traffic bound outside the overlay,
// apart from its peers' and Tailscale's.
func exitTable(inst int) int { return juistRouteTable + 0x100 + inst }

// Egress rules, inst above their base like [juistRules]: juistd's own
// traffic, by its user, goes by the host's routes so that it can always reach
// its exit node and the rest; then the exit table, which throws back to the
// host's routes what no exit node carries and the networks the host is on.
// Both sit after the overlay's table and below Tailscale's 5210; the exit
// table comes before the host's routes, so that routes a network pushes, as
// DHCP option 121 does, cannot take the internet out of the tunnel.
const (
	exitRuleAnswers  = 60
	exitRuleOwn      = 80
	exitRuleExit     = 100
	exitRuleMaxShift = 9
)

// answerMark marks, in conntrack, a connection that came in by another
// device than juist's, and each packet answering it, which the rule at
// exitRuleAnswers sends by the host's routes, the way it came. Apart from
// Tailscale's bits.
const answerMark = 0x20000000

// answerRule is instance inst's rule sending answers by the host's routes.
func answerRule(family, inst int) netlink.Rule {
	ru := *netlink.NewRule()
	ru.Family, ru.Priority, ru.Table = family, juistRulePrefBase+exitRuleAnswers+inst, unix.RT_TABLE_MAIN
	ru.Mark, ru.Mask = answerMark, answerMark
	return ru
}

// exitRule leaves bypass-marked packets, tailscaled's and magicsock's, to
// later rules: without a router of this instance's, as while no mesh runs,
// no bypass rule of its own comes before it.
func exitRule(family, inst int) netlink.Rule {
	exit := *netlink.NewRule()
	exit.Family, exit.Priority, exit.Table = family, juistRulePrefBase+exitRuleExit+inst, exitTable(inst)
	exit.Mark, exit.Mask, exit.Invert = tsconst.LinuxBypassMarkNum, tsconst.LinuxFwmarkMaskNum, true
	return exit
}

// dropUnmarkedExitRules deletes instance inst's exit rules of earlier builds,
// without the mark, which the marked one does not replace. The kernel matches
// a deletion without a mark to any mark, so the marked rule may go too: the
// caller adds it again, and the guard holds meanwhile.
func dropUnmarkedExitRules(fam, inst int) error {
	want := exitRule(fam, inst)
	for range 4 {
		rules, err := netlink.RuleListFiltered(fam, &netlink.Rule{Priority: want.Priority}, netlink.RT_FILTER_PRIORITY)
		if err != nil {
			if errors.Is(err, syscall.EAFNOSUPPORT) {
				return nil
			}
			return err
		}
		if !slices.ContainsFunc(rules, func(ru netlink.Rule) bool { return unmarkedExitRule(ru, want) }) {
			return nil
		}
		del := *netlink.NewRule()
		del.Family, del.Priority, del.Table = fam, want.Priority, want.Table
		if err := netlink.RuleDel(&del); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("deleting an unmarked exit rule: %w", err)
		}
	}
	return errors.New("conn: an unmarked exit rule stays")
}

// unmarkedExitRule reports whether listed rule ru is want's place and table
// without its mark.
func unmarkedExitRule(ru, want netlink.Rule) bool {
	return ru.Priority == want.Priority && ru.Table == want.Table && !ru.Invert && ru.Mark <= 0
}

// isExitRulePref reports whether pref is one of instance inst's egress rules.
func isExitRulePref(pref uint32, inst int) bool {
	return pref == uint32(juistRulePrefBase+exitRuleOwn+inst) || pref == uint32(juistRulePrefBase+exitRuleExit+inst) ||
		pref == uint32(juistRulePrefBase+exitRuleAnswers+inst)
}

// An exitRoute is one route of the exit table.
type exitRoute struct {
	dst    netip.Prefix
	typ    int // unix.RTN_*
	metric int
}

// refusedMetric puts the refusal of the default routes behind the route into
// the tunnel, so that it stands where that goes with the device.
const refusedMetric = 0xffff

// exitRoutes is the exit table: the internet into the tunnel, and what no
// exit node carries thrown back to the host's routes. Refused, it goes into
// the tunnel still, where the guard rejects it: an unreachable route would
// fail a loose reverse-path check (rp_filter, firewalld's IPv6_rpfilter) for
// every packet from public space, juistd's own answers among them. Behind
// both, the unreachable routes stand where the device goes, or has no IPv6.
func exitRoutes(v6 bool) []exitRoute {
	v4, v6all := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	out := []exitRoute{{v4, unix.RTN_UNREACHABLE, refusedMetric}, {v6all, unix.RTN_UNREACHABLE, refusedMetric},
		{v4, unix.RTN_UNICAST, 0}}
	if v6 {
		out = append(out, exitRoute{v6all, unix.RTN_UNICAST, 0})
	}
	for _, p := range offTunnel() {
		out = append(out, exitRoute{p, unix.RTN_THROW, 0})
	}
	return out
}

func (r *linuxRouter) setEgress(e Egress, t tunnelled) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("conn: router is closed")
	}
	r.want, r.tunnelled = e, t
	return r.setEgressLocked(e)
}

// setEgressLocked installs e whole, whatever it finds, and is repeated on
// every reconcile, a change of the host's networks and a deleted rule:
// someone may have flushed any of it, unannounced. The guard comes first, so
// that nothing leaves outside the tunnel meanwhile, then the exit table, then
// the rules that consult it, so that none points at a table without it.
func (r *linuxRouter) setEgressLocked(e Egress) error {
	if e == EgressDirect {
		var errs []error
		errs = append(errs, r.delExitRulesLocked())
		for rt := range r.exit {
			if err := r.delExitRoute(rt); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(r.exit, rt)
		}
		errs = append(errs, setGuard(r.inst, false, "", tunnelled{}, false, 0))
		r.egress = e
		return errors.Join(errs...)
	}
	// Where a lower network's routing takes this one's traffic, this one
	// routes nothing of its own, whose guard would drop what the other sends
	// into its tunnel; it installs again once that one's rule goes. Beside
	// one that serves, it installs all the same, and the other stops
	// serving: failing closed comes first.
	if other, err := r.otherEgressLocked(true); err != nil {
		return err
	} else if other >= 0 {
		return errors.Join(ErrEgressTaken, r.setEgressLocked(EgressDirect))
	}
	if err := setGuard(r.inst, true, r.link.Attrs().Name, r.tunnelled, e == EgressRefused, uint32(os.Getuid())); err != nil {
		return err
	}
	var errs []error
	want := map[exitRoute]bool{}
	for _, rt := range exitRoutes(linkV6Usable("/proc/sys/net/ipv6/conf", r.link.Attrs().Name)) {
		// Without IPv6 policy routing an IPv6 table is main itself; the
		// guard alone keeps IPv6 in there.
		if rt.dst.Addr().Is6() && (!r.v6Present || !r.v6Rules) {
			continue
		}
		want[rt] = true
		// Replaced whether or not it is thought there: a route someone
		// flushed is not announced.
		if err := r.addExitRoute(rt); err != nil {
			errs = append(errs, err)
			continue
		}
		r.exit[rt] = true
	}
	if !r.exitListed {
		// What an earlier juistd of this instance left, which this one
		// would not know to take away.
		for _, fam := range r.ruleFamilies() {
			routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: exitTable(r.inst)}, netlink.RT_FILTER_TABLE)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, nr := range routes {
				if rt, ok := exitRouteOf(fam, nr); ok && !want[rt] {
					r.exit[rt] = true
				}
			}
		}
		r.exitListed = true
	}
	for rt := range r.exit {
		if !want[rt] {
			if err := r.delExitRoute(rt); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(r.exit, rt)
		}
	}
	errs = append(errs, r.addExitRulesLocked())
	r.egress = e
	return errors.Join(errs...)
}

// exitRouteOf is the exit route nr, of family fam, is, where it is one juist
// makes: a default route lists without a destination, and IPv6 gives the
// metric 0 juist asks for as 1024.
func exitRouteOf(fam int, nr netlink.Route) (exitRoute, bool) {
	p, ok := netip.MustParsePrefix("0.0.0.0/0"), true
	if fam == netlink.FAMILY_V6 {
		p = netip.MustParsePrefix("::/0")
	}
	if nr.Dst != nil {
		p, ok = netipx.FromStdIPNet(nr.Dst)
	}
	switch nr.Type {
	case unix.RTN_UNICAST, unix.RTN_UNREACHABLE, unix.RTN_THROW:
	default:
		ok = false
	}
	metric := nr.Priority
	if fam == netlink.FAMILY_V6 && metric == 1024 {
		metric = 0
	}
	return exitRoute{dst: p, typ: nr.Type, metric: metric}, ok
}

// otherEgressLocked is another instance whose exit table the host's rules
// consult, or -1; lower, a lower one alone: the first of them takes every
// address it is asked about, and a higher one's, shadowed, finds this one
// when it next installs.
func (r *linuxRouter) otherEgressLocked(lower bool) (int, error) {
	for _, fam := range r.ruleFamilies() {
		rules, err := netlink.RuleList(fam)
		if err != nil {
			return -1, fmt.Errorf("listing rules: %w", err)
		}
		if j := otherEgress(rules, r.inst, lower); j >= 0 {
			return j, nil
		}
	}
	return -1, nil
}

func otherEgress(rules []netlink.Rule, inst int, lower bool) int {
	for _, ru := range rules {
		j := ru.Priority - juistRulePrefBase - exitRuleExit
		if j >= 0 && j <= exitRuleMaxShift && j != inst && (j < inst || !lower) && ru.Table == exitTable(j) {
			return j
		}
	}
	return -1
}

func (r *linuxRouter) exitNLRoute(rt exitRoute) *netlink.Route {
	nr := exitNLRouteIn(r.inst, rt)
	if rt.typ == unix.RTN_UNICAST {
		nr.LinkIndex = r.link.Attrs().Index
		if rt.dst.Addr().Is4() && r.src4.IsValid() {
			nr.Src = r.src4.AsSlice()
		}
	}
	return nr
}

func exitNLRouteIn(inst int, rt exitRoute) *netlink.Route {
	return &netlink.Route{Dst: netipx.PrefixIPNet(rt.dst), Table: exitTable(inst), Type: rt.typ, Priority: rt.metric}
}

func (r *linuxRouter) addExitRoute(rt exitRoute) error {
	if err := netlink.RouteReplace(r.exitNLRoute(rt)); err != nil {
		return fmt.Errorf("adding exit route %v: %w", rt.dst, err)
	}
	return nil
}

func (r *linuxRouter) delExitRoute(rt exitRoute) error {
	err := netlink.RouteDel(r.exitNLRoute(rt))
	if err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.ENODEV) {
		return fmt.Errorf("deleting exit route %v: %w", rt.dst, err)
	}
	return nil
}

// addExitRulesLocked adds the egress rules. Without IPv6 policy routing the
// guard alone keeps IPv6 in, refusing what it would route outside.
func (r *linuxRouter) addExitRulesLocked() error {
	var errs []error
	uid := os.Getuid()
	for _, fam := range r.ruleFamilies() {
		// Root's traffic is the host's; only a juistd of its own user can be
		// told apart from what the exit node is for.
		if uid != 0 {
			if err := uidRule(unix.RTM_NEWRULE, fam, juistRulePrefBase+exitRuleOwn+r.inst, uint32(uid)); err != nil &&
				!errors.Is(err, syscall.EEXIST) {
				errs = append(errs, fmt.Errorf("adding the rule for juistd's own traffic: %w", err))
			}
		}
		errs = append(errs, dropUnmarkedExitRules(fam, r.inst))
		errs = append(errs, setAnswerRule(fam, r.inst, !r.tunnelled.answers))
		ru := exitRule(fam, r.inst)
		if err := netlink.RuleAdd(&ru); err != nil && !errors.Is(err, syscall.EEXIST) {
			errs = append(errs, fmt.Errorf("adding %v: %w", ru, err))
		}
	}
	return errors.Join(errs...)
}

// setAnswerRule adds instance inst's answer rule in fam, or deletes it.
func setAnswerRule(fam, inst int, on bool) error {
	ru := answerRule(fam, inst)
	if on {
		if err := netlink.RuleAdd(&ru); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("adding %v: %w", ru, err)
		}
		return nil
	}
	if err := netlink.RuleDel(&ru); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return fmt.Errorf("deleting %v: %w", ru, err)
	}
	return nil
}

func (r *linuxRouter) delExitRulesLocked() error {
	var errs []error
	uid := os.Getuid()
	for _, fam := range r.ruleFamilies() {
		if uid != 0 {
			if err := uidRule(unix.RTM_DELRULE, fam, juistRulePrefBase+exitRuleOwn+r.inst, uint32(uid)); err != nil &&
				!errors.Is(err, syscall.ENOENT) {
				errs = append(errs, fmt.Errorf("deleting the rule for juistd's own traffic: %w", err))
			}
		}
		ru := exitRule(fam, r.inst)
		if err := netlink.RuleDel(&ru); err != nil && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, fmt.Errorf("deleting %v: %w", ru, err))
		}
		errs = append(errs, setAnswerRule(fam, r.inst, false))
	}
	return errors.Join(errs...)
}

// lans is what [attached] finds, and the routes in main that need no gateway,
// as the /64 a router advertises beside a /128 address from DHCPv6.
func (r *linuxRouter) answersThrough() string { return "" }

func (r *linuxRouter) lans() ([]netip.Prefix, []netip.Addr) {
	nets, hosts := attached(r.link.Attrs().Name)
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, nr := range routes {
			if nr.Dst == nil || nr.Gw != nil || len(nr.MultiPath) > 0 || nr.Type != unix.RTN_UNICAST ||
				nr.LinkIndex == r.link.Attrs().Index {
				continue
			}
			if p, ok := netipx.FromStdIPNet(nr.Dst); ok && p.Bits() > 0 && !p.IsSingleIP() {
				nets = append(nets, p.Masked())
			}
		}
	}
	return nets, hosts
}

// hostRoutes is what [attached] finds, and the routes of main, tailscaled's
// table 52 and lower juist instances' tables but default ones: what ordinary
// traffic of the host reaches by them, other VPNs' and container bridges'
// among them. Routes a network pushed, by DHCP or router advertisement, are
// none of the host's own: a hostile LAN could push one over any subnet to
// take it out of the tunnel.
func (r *linuxRouter) hostRoutes() []netip.Prefix {
	nets, _ := attached(r.link.Attrs().Name)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return nets
	}
	for _, nr := range routes {
		if p, ok := hostRoute(nr, r.link.Attrs().Index, r.inst); ok {
			nets = append(nets, p)
		}
	}
	return nets
}

// watchHostRoutes calls changed, from a goroutine of its own, whenever a route
// [linuxRouter.hostRoutes] counts comes or goes, until the router closes: the
// network monitor says nothing of a route alone.
func (r *linuxRouter) watchHostRoutes(changed func()) {
	ch := make(chan netlink.RouteUpdate, 64)
	err := netlink.RouteSubscribeWithOptions(ch, r.done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) { r.logf("watching the host's routes: %v", err) },
	})
	if err != nil {
		r.logf("watching the host's routes: %v", err)
		return
	}
	go func() {
		for u := range ch {
			if _, ok := hostRoute(u.Route, r.link.Attrs().Index, r.inst); ok {
				changed()
			}
		}
	}()
}

// hostRoute is the prefix nr gives the host, where it is one of its own; own
// is this instance's device. A lower instance's routes are the host's, which
// the higher leaves to it, so that two granting one prefix do not flap.
func hostRoute(nr netlink.Route, own, inst int) (netip.Prefix, bool) {
	lower := nr.Table >= routeTable(0) && nr.Table < routeTable(inst)
	switch {
	case nr.Dst == nil, nr.LinkIndex == own, nr.Type != unix.RTN_UNICAST,
		nr.Table != unix.RT_TABLE_MAIN && nr.Table != 52 && !lower,
		nr.Protocol == unix.RTPROT_DHCP || nr.Protocol == unix.RTPROT_RA:
		return netip.Prefix{}, false
	}
	p, ok := netipx.FromStdIPNet(nr.Dst)
	if !ok || p.Bits() == 0 || p.Addr().IsLinkLocalUnicast() || p.Addr().IsMulticast() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// onLinksChanged installs the egress again for the host's networks as they
// are now.
func (r *linuxRouter) onLinksChanged() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.want == EgressDirect {
		return
	}
	if err := r.setEgressLocked(r.want); err != nil && !errors.Is(err, ErrEgressTaken) {
		r.logf("egress after a change of the host's networks: %v", err)
	}
}

// uidRule adds or deletes "from all uidrange uid-uid lookup main" at pref,
// which the netlink package cannot say.
func uidRule(op uint16, family, pref int, uid uint32) error {
	flags := unix.NLM_F_ACK
	if op == unix.RTM_NEWRULE {
		flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	req := nl.NewNetlinkRequest(int(op), flags)
	msg := nl.NewRtMsg()
	msg.Family = uint8(family)
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_MAIN
	msg.Type = unix.RTN_UNICAST
	req.AddData(msg)
	b := make([]byte, 4)
	nl.NativeEndian().PutUint32(b, uint32(pref))
	req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, b))
	r := make([]byte, 8)
	nl.NativeEndian().PutUint32(r[0:], uid)
	nl.NativeEndian().PutUint32(r[4:], uid)
	req.AddData(nl.NewRtAttr(unix.FRA_UID_RANGE, r))
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// natTable is instance inst's nftables table for serving as an exit node,
// and guardTable its table keeping a client's traffic in the tunnel, in each
// family.
func natTable(family nftables.TableFamily, inst int) *nftables.Table {
	return &nftables.Table{Family: family, Name: "juist" + strconv.Itoa(inst)}
}

func guardTable(family nftables.TableFamily, inst int) *nftables.Table {
	return &nftables.Table{Family: family, Name: "juist" + strconv.Itoa(inst) + "guard"}
}

var families = []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6}

// setGuard, on, drops what would leave outside the tunnel dev: every packet
// sent or forwarded out of another device, but for bypass-marked ones
// (magicsock's and tailscaled's), juistd's own by uid, DHCP, and those to
// what no exit node carries. Routing sends nothing there; the guard holds
// where routing does not, as for a socket bound to a device, or routes
// someone deleted. What goes into dev for the internet it rejects in a family
// through does not carry, and with refuse in both; through's subnets pass.
// dev may be "" where there is no tunnel; off removes the guard.
// Tables are replaced whole, in one transaction.
func setGuard(inst int, on bool, dev string, through tunnelled, refuse bool, uid uint32) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("conn: nftables: %w", err)
	}
	defer c.CloseLasting()
	for _, fam := range families {
		t := guardTable(fam, inst)
		c.AddTable(t) // so that the delete below cannot fail for a missing table
		c.DelTable(t)
	}
	if on {
		for _, fam := range families {
			t := c.AddTable(guardTable(fam, inst))
			if !through.answers {
				// Marked where a connection comes in, before routing, and
				// on its answers, forwarded ones there and the host's own
				// in a route chain, which routes them again.
				accept := nftables.ChainPolicyAccept
				pre := c.AddChain(&nftables.Chain{Table: t, Name: "answers-in", Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle, Policy: &accept})
				c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: markIncoming(dev)})
				c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: clearAnswerMark()})
				c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: markAnswer()})
				out := c.AddChain(&nftables.Chain{Table: t, Name: "answers-out", Type: nftables.ChainTypeRoute,
					Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle, Policy: &accept})
				c.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: markAnswer()})
			}
			for _, hook := range []*nftables.ChainHook{nftables.ChainHookOutput, nftables.ChainHookForward} {
				accept := nftables.ChainPolicyAccept
				ch := c.AddChain(&nftables.Chain{Table: t, Name: map[bool]string{true: "output", false: "forward"}[hook == nftables.ChainHookOutput],
					Type: nftables.ChainTypeFilter, Hooknum: hook, Priority: nftables.ChainPriorityFilter, Policy: &accept})
				for _, rule := range guardRules(fam, hook == nftables.ChainHookOutput, dev, through, refuse, uid) {
					c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: rule})
				}
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: guarding the tunnel: %w", err)
	}
	return nil
}

// guardRules are one guard chain's rules, in order, the last dropping.
func guardRules(fam nftables.TableFamily, output bool, dev string, through tunnelled, refuse bool, uid uint32) [][]expr.Any {
	refuse = refuse || !through.carries(fam)
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	otherFam := func(p netip.Prefix) bool { return p.Addr().Is4() != (fam == nftables.TableFamilyIPv4) }
	allowed := slices.DeleteFunc(offTunnel(), otherFam)
	oif := func(d string) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(d)}}
	}
	var rules [][]expr.Any
	if dev != "" && refuse {
		for _, p := range slices.Concat(allowed, slices.DeleteFunc(slices.Clone(through.subnets), otherFam)) {
			rules = append(rules, slices.Concat(oif(dev), addrIn(p, false), []expr.Any{accept}))
		}
		rules = append(rules, append(oif(dev), &expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 0}))
	} else if dev != "" {
		rules = append(rules, append(oif(dev), accept))
	}
	if !through.answers {
		rules = append(rules, append(isAnswer(), accept))
	}
	rules = append(rules, append(oif("lo"), accept))
	rules = append(rules, [][]expr.Any{
		{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(tsconst.LinuxFwmarkMaskNum), Xor: u32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(tsconst.LinuxBypassMarkNum)}, accept},
	}...)
	if output && uid != 0 {
		rules = append(rules, []expr.Any{&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(uid)}, accept})
	}
	// The host's own DHCP, to a server that may be off the link and in
	// public space, from the client's port, which only root may bind; and
	// its neighbour discovery, which answers from global addresses too, and
	// never leaves the link (hop limit 255). Neither is forwarded.
	if output {
		rules = append(rules, dhcpRule(fam, accept))
		if fam == nftables.TableFamilyIPv6 {
			rules = append(rules, []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{255}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
				&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{133}, ToData: []byte{137}}, accept})
		}
	}
	for _, p := range allowed {
		rules = append(rules, append(addrIn(p, false), accept))
	}
	return append(rules, []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}})
}

// markIncoming marks a connection coming in by another device, from its
// first packet or, for one older than the guard, its next: "ct direction
// original ct mark & answerMark == 0 iifname != { juist*, dev, lo } fib
// daddr . iif type local meta mark set meta mark | answerMark fib saddr .
// mark . iif oif != 0 ct mark set ct mark | answerMark". It must be sent to
// an address of that device, and the host's routes, as answers take them,
// must lead back by it: what a LAN sends to the overlay's addresses, or what
// comes in by a device whose routes are not the host's, as another VPN's, is
// no connection to answer that way.
func markIncoming(dev string) []expr.Any {
	e := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}}, // IP_CT_DIR_ORIGINAL
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(answerMark), Xor: u32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(0)},
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("juist")}, // a prefix: every instance's
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname("lo")},
	}
	if dev != "" {
		e = append(e, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(dev)})
	}
	return append(e,
		&expr.Fib{Register: 1, FlagDADDR: true, FlagIIF: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(unix.RTN_LOCAL)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(answerMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		&expr.Fib{Register: 1, FlagSADDR: true, FlagMARK: true, FlagIIF: true, ResultOIF: true},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: u32(0)},
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(answerMark)},
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK, SourceRegister: true},
	)
}

// clearAnswerMark takes the mark [markIncoming] looked the way back up with
// off the packet that came in: "ct direction original meta mark set meta
// mark & ~answerMark".
func clearAnswerMark() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(0)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}

// isAnswer is "ct direction reply ct mark & answerMark != 0".
func isAnswer() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // IP_CT_DIR_REPLY
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(answerMark), Xor: u32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: u32(0)},
	}
}

// markAnswer is [isAnswer] "meta mark set meta mark | answerMark".
func markAnswer() []expr.Any {
	return append(isAnswer(),
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(answerMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1})
}

// dhcpRule is "udp sport client dport server", of DHCP in fam.
func dhcpRule(fam nftables.TableFamily, verdict expr.Any) []expr.Any {
	client, server := uint16(68), uint16(67)
	if fam == nftables.TableFamilyIPv6 {
		client, server = 546, 547
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1,
			Data: []byte{byte(client >> 8), byte(client), byte(server >> 8), byte(server)}}, verdict}
}

// ifname is dev as an interface name compares in nftables.
func ifname(dev string) []byte { return []byte(dev + "\x00") }

func u32(v uint32) []byte {
	b := make([]byte, 4)
	nl.NativeEndian().PutUint32(b, v)
	return b
}

// addrIn is "saddr in p", or "daddr in p" where dst.
func addrIn(p netip.Prefix, src bool) []expr.Any {
	off, n := uint32(16), uint32(4)
	if p.Addr().Is6() {
		off, n = 24, 16
	}
	if src {
		off -= n
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: netipx.PrefixIPNet(p).Mask, Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Masked().Addr().AsSlice()},
	}
}

func (r *linuxRouter) setServe(s Serve) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed && s.serving() {
		return errors.New("conn: router is closed")
	}
	return r.setServeLocked(s)
}

// setServeLocked serves s from a table of this instance's own, which it
// replaces whole; with no routes it removes the table. It masquerades what
// peers send from s.Sources out of any device but this node's, and drops
// what arrives from elsewhere with an overlay source, or comes new into the
// overlay from a public one: forwarding is on for the whole host, and neither
// is a peer's.
func (r *linuxRouter) setServeLocked(s Serve) error {
	if s.serving() {
		// Any other instance's egress, higher ones' too: its table would take
		// what this one's peers send out. Refused, nothing is served.
		refuse := forwardingOff(os.ReadFile, slices.Concat(s.Routes, s.Subnets))
		if refuse == nil {
			if other, err := r.otherEgressLocked(false); err != nil {
				refuse = err
			} else if other >= 0 {
				refuse = ErrEgressTaken
			}
		}
		if refuse != nil {
			return errors.Join(refuse, r.setServeLocked(Serve{}))
		}
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("conn: nftables: %w", err)
	}
	defer c.CloseLasting()
	for _, fam := range families {
		t := natTable(fam, r.inst)
		c.AddTable(t) // so that the delete below cannot fail for a missing table
		c.DelTable(t)
	}
	if s.serving() {
		dev := ifname(r.link.Attrs().Name)
		for _, fam := range families {
			t := c.AddTable(natTable(fam, r.inst))
			accept := nftables.ChainPolicyAccept
			nat := c.AddChain(&nftables.Chain{Table: t, Name: "postrouting", Type: nftables.ChainTypeNAT,
				Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})
			fwd := c.AddChain(&nftables.Chain{Table: t, Name: "forward", Type: nftables.ChainTypeFilter,
				Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
			for _, rule := range serveRules(fam, dev, s.Sources) {
				c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: rule})
			}
			for _, src := range s.Sources {
				if src.Addr().Is4() == (fam == nftables.TableFamilyIPv4) {
					c.AddRule(&nftables.Rule{Table: t, Chain: nat, Exprs: masquerade(src, dev)})
				}
			}
			if s.DNS == 0 {
				continue
			}
			dnat := c.AddChain(&nftables.Chain{Table: t, Name: "prerouting", Type: nftables.ChainTypeNAT,
				Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
			for a := range r.addrs {
				if a.Addr().Is4() != (fam == nftables.TableFamilyIPv4) {
					continue
				}
				for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
					c.AddRule(&nftables.Rule{Table: t, Chain: dnat, Exprs: dnsRedirect(dev, a.Addr(), proto, s.DNS)})
				}
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: setting up masquerade: %w", err)
	}
	r.serving = s.serving()
	return nil
}

// serveRules are the serving table's forward chain: "iifname != juist*
// saddr in sources drop", then for what goes out of dev from elsewhere, new,
// "saddr in local space accept" and "drop". Every juist device of the host
// is let through the first, since networks on one host may share overlay
// space.
func serveRules(fam nftables.TableFamily, dev []byte, sources []netip.Prefix) [][]expr.Any {
	family := []byte(strings.TrimRight(strings.TrimSuffix(string(dev), "\x00"), "0123456789"))
	notFromDev := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: dev}}
	notFromJuist := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: family}}
	intoDevNew := slices.Concat(notFromDev, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dev},
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(expr.CtStateBitNEW), Xor: u32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: u32(0)},
	})
	drop := &expr.Verdict{Kind: expr.VerdictDrop}
	var rules [][]expr.Any
	for _, src := range sources {
		if src.Addr().Is4() == (fam == nftables.TableFamilyIPv4) {
			rules = append(rules, slices.Concat(notFromJuist, addrIn(src, true), []expr.Any{drop}))
		}
	}
	for _, p := range localSpace {
		if p.Addr().Is4() == (fam == nftables.TableFamilyIPv4) {
			rules = append(rules, slices.Concat(intoDevNew, addrIn(p, true), []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}))
		}
	}
	return append(rules, slices.Concat(intoDevNew, []expr.Any{drop}))
}

// forwardingOff checks the host forwards every family routes hold, reading
// sysctls through read.
func forwardingOff(read func(string) ([]byte, error), routes []netip.Prefix) error {
	for _, fam := range []struct {
		v6   bool
		path string
	}{{false, "/proc/sys/net/ipv4/conf/all/forwarding"}, {true, "/proc/sys/net/ipv6/conf/all/forwarding"}} {
		if !slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Addr().Is6() == fam.v6 }) {
			continue
		}
		b, err := read(fam.path)
		if fam.v6 && errors.Is(err, os.ErrNotExist) {
			continue // no IPv6 here; peers' IPv6 is dropped, as it would be refused
		}
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			return ErrForwardingOff
		}
	}
	return nil
}

// dnsRedirect is "iifname dev daddr addr l4proto proto th dport 53 redirect
// to :port": peers' DNS to this node's address, and to no other server.
func dnsRedirect(dev []byte, addr netip.Addr, proto byte, port uint16) []expr.Any {
	return slices.Concat(
		[]expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dev}},
		addrIn(netip.PrefixFrom(addr, addr.BitLen()), false),
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
			&expr.Immediate{Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Redir{RegisterProtoMin: 1},
		})
}

// masquerade is "saddr src oifname != dev masquerade".
func masquerade(src netip.Prefix, dev []byte) []expr.Any {
	return slices.Concat(addrIn(src, true), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: dev},
		&expr.Masq{},
	})
}

// RefuseEgress refuses instance inst's internet traffic where it has no
// router, as while its juistd runs no mesh: the refusing routes, the rules
// and the guard, which need no device of the instance's. A router of the
// instance's takes them over. Where a lower instance routes the internet
// already, it is that one's, and ErrEgressTaken says so.
func RefuseEgress(inst int, isolate bool) error {
	var errs []error
	uid := os.Getuid()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("conn: listing rules: %w", err)
	}
	if otherEgress(rules, inst, true) >= 0 {
		return errors.Join(ErrEgressTaken, ClearEgress(inst))
	}
	if err := setGuard(inst, true, "", tunnelled{answers: isolate}, true, uint32(uid)); err != nil {
		errs = append(errs, err)
	}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		v6 := fam == netlink.FAMILY_V6
		if _, err := netlink.RuleList(fam); v6 && err != nil {
			continue // no IPv6, or none by policy: the guard alone keeps it in
		}
		for _, rt := range exitRoutes(false) {
			if rt.dst.Addr().Is6() != v6 || rt.typ == unix.RTN_UNICAST {
				continue
			}
			if err := netlink.RouteReplace(exitNLRouteIn(inst, rt)); err != nil {
				errs = append(errs, fmt.Errorf("adding exit route %v: %w", rt.dst, err))
			}
		}
		if uid != 0 {
			if err := uidRule(unix.RTM_NEWRULE, fam, juistRulePrefBase+exitRuleOwn+inst, uint32(uid)); err != nil &&
				!errors.Is(err, syscall.EEXIST) {
				errs = append(errs, err)
			}
		}
		errs = append(errs, dropUnmarkedExitRules(fam, inst))
		if err := setAnswerRule(fam, inst, !isolate); err != nil && !(v6 && errors.Is(err, syscall.EAFNOSUPPORT)) {
			errs = append(errs, err)
		}
		ru := exitRule(fam, inst)
		if err := netlink.RuleAdd(&ru); err != nil && !errors.Is(err, syscall.EEXIST) && !(v6 && errors.Is(err, syscall.EAFNOSUPPORT)) {
			errs = append(errs, fmt.Errorf("adding %v: %w", ru, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("conn: refusing egress: %w", err)
	}
	return nil
}

// ClearEgress removes instance inst's egress rules, exit table and guard,
// which a stopping node leaves refusing on purpose: traffic stays in rather
// than leaving directly while juistd restarts, or after it failed.
func ClearEgress(inst int) error {
	var errs []error
	uid := os.Getuid()
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if uid != 0 {
			if err := uidRule(unix.RTM_DELRULE, fam, juistRulePrefBase+exitRuleOwn+inst, uint32(uid)); err != nil &&
				!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
				errs = append(errs, err)
			}
		}
		ru := exitRule(fam, inst)
		// And those of M6a's first layouts: the exit rule without its mark,
		// and the host rule before it, which let the host's routes win.
		unmarked := *netlink.NewRule()
		unmarked.Family, unmarked.Priority, unmarked.Table = fam, ru.Priority, ru.Table
		legacy := *netlink.NewRule()
		legacy.Family, legacy.Priority = fam, juistRulePrefBase+90+inst
		legacy.Table, legacy.SuppressPrefixlen = unix.RT_TABLE_MAIN, 0
		answers := answerRule(fam, inst)
		for _, ru := range []*netlink.Rule{&ru, &unmarked, &legacy, &answers} {
			if err := netlink.RuleDel(ru); err != nil && !errors.Is(err, syscall.ENOENT) &&
				!errors.Is(err, syscall.EAFNOSUPPORT) {
				errs = append(errs, err)
			}
		}
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: exitTable(inst)}, netlink.RT_FILTER_TABLE)
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			errs = append(errs, err)
			continue
		}
		for i := range routes {
			if routes[i].Dst == nil {
				// A default route, which the kernel lists without one and
				// the netlink package deletes with one only.
				rt, _ := exitRouteOf(fam, routes[i])
				routes[i].Dst = netipx.PrefixIPNet(rt.dst)
			}
			if err := netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
				errs = append(errs, err)
			}
		}
	}
	if err := setGuard(inst, false, "", tunnelled{}, false, 0); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("conn: clearing egress: %w", err)
	}
	return nil
}

// carries reports whether an exit node's routes carry fam.
func (t tunnelled) carries(fam nftables.TableFamily) bool {
	if fam == nftables.TableFamilyIPv6 {
		return t.v6
	}
	return t.v4
}
