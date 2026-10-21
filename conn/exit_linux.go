//go:build linux && !android

package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"syscall"

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
		if err := netlink.RuleDel(&del); !ruleDone(false, fam, err) {
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
	for _, fam := range r.ruleFamilies() {
		errs = append(errs, addExitRules(fam, r.inst, !r.tunnelled.answers))
	}
	return errors.Join(errs...)
}

// addExitRules adds instance inst's egress rules in fam, its answer rule
// where answers and not otherwise.
func addExitRules(fam, inst int, answers bool) error {
	var errs []error
	// Root's traffic is the host's; only a juistd of its own user can be
	// told apart from what the exit node is for.
	if uid := os.Getuid(); uid != 0 {
		if err := uidRule(unix.RTM_NEWRULE, fam, juistRulePrefBase+exitRuleOwn+inst, uint32(uid)); !ruleDone(true, fam, err) {
			errs = append(errs, fmt.Errorf("adding the rule for juistd's own traffic: %w", err))
		}
	}
	errs = append(errs, dropUnmarkedExitRules(fam, inst), setAnswerRule(fam, inst, answers))
	ru := exitRule(fam, inst)
	if err := netlink.RuleAdd(&ru); !ruleDone(true, fam, err) {
		errs = append(errs, fmt.Errorf("adding %v: %w", ru, err))
	}
	return errors.Join(errs...)
}

// ruleDone reports whether adding a rule in fam, or else deleting it, that
// returned err leaves nothing to do. A kernel without IPv6 policy routing
// takes no IPv6 rule, which the guard covers; without IPv4's, adding fails.
func ruleDone(add bool, fam int, err error) bool {
	switch {
	case err == nil:
		return true
	case add:
		return errors.Is(err, syscall.EEXIST) || fam == netlink.FAMILY_V6 && errors.Is(err, syscall.EAFNOSUPPORT)
	}
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EAFNOSUPPORT)
}

// setAnswerRule adds instance inst's answer rule in fam, or deletes it.
func setAnswerRule(fam, inst int, on bool) error {
	ru := answerRule(fam, inst)
	if on {
		if err := netlink.RuleAdd(&ru); !ruleDone(true, fam, err) {
			return fmt.Errorf("adding %v: %w", ru, err)
		}
		return nil
	}
	if err := netlink.RuleDel(&ru); !ruleDone(false, fam, err) {
		return fmt.Errorf("deleting %v: %w", ru, err)
	}
	return nil
}

func (r *linuxRouter) delExitRulesLocked() error {
	var errs []error
	for _, fam := range r.ruleFamilies() {
		errs = append(errs, delExitRules(fam, r.inst))
	}
	return errors.Join(errs...)
}

// delExitRules deletes instance inst's egress rules in fam, with those of
// M6a's first layouts: the exit rule without its mark, and the host rule
// before it, which let the host's routes win.
func delExitRules(fam, inst int) error {
	var errs []error
	if uid := os.Getuid(); uid != 0 {
		if err := uidRule(unix.RTM_DELRULE, fam, juistRulePrefBase+exitRuleOwn+inst, uint32(uid)); !ruleDone(false, fam, err) {
			errs = append(errs, fmt.Errorf("deleting the rule for juistd's own traffic: %w", err))
		}
	}
	ru := exitRule(fam, inst)
	unmarked := *netlink.NewRule()
	unmarked.Family, unmarked.Priority, unmarked.Table = fam, ru.Priority, ru.Table
	legacy := *netlink.NewRule()
	legacy.Family, legacy.Priority = fam, juistRulePrefBase+90+inst
	legacy.Table, legacy.SuppressPrefixlen = unix.RT_TABLE_MAIN, 0
	answers := answerRule(fam, inst)
	for _, ru := range []*netlink.Rule{&ru, &unmarked, &legacy, &answers} {
		if err := netlink.RuleDel(ru); !ruleDone(false, fam, err) {
			errs = append(errs, fmt.Errorf("deleting %v: %w", ru, err))
		}
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
		errs = append(errs, addExitRules(fam, inst, !isolate))
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
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		errs = append(errs, delExitRules(fam, inst))
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
