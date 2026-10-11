//go:build linux && !android

package conn

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/tsconst"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

const (
	// juistRouteTable holds only the default instance's peer routes: 0x6a75
	// is "ju", apart from Tailscale's 52 and the kernel's 253–255. Instance n
	// has table juistRouteTable+n.
	juistRouteTable = 0x6a75

	// juistRulePrefBase is below Tailscale's 5200, so an overlay route wins
	// over an exit node's default route in table 52.
	juistRulePrefBase = 5100
)

// routeTable is instance inst's routing table.
func routeTable(inst int) int { return juistRouteTable + inst }

// juistRules are Tailscale's policy rules with instance inst's table and
// priorities: bypass-marked packets (magicsock's own) skip the overlay,
// everything else consults the table and falls through to later rules on a
// miss. Instance n's rules sit n above the default's, so every instance's
// bypass comes before any instance's table, each deletes only its own, and
// where two tables claim one address the lower instance's wins.
func juistRules(family, inst int) []netlink.Rule {
	specs := []struct {
		pref, table int
		mark        bool
		typ         uint8
	}{
		{10, unix.RT_TABLE_MAIN, true, 0},
		{30, unix.RT_TABLE_DEFAULT, true, 0},
		{50, 0, true, unix.RTN_UNREACHABLE},
		{70, routeTable(inst), false, 0},
	}
	rules := make([]netlink.Rule, 0, len(specs))
	for _, s := range specs {
		ru := *netlink.NewRule()
		ru.Family = family
		ru.Priority = juistRulePrefBase + s.pref + inst
		ru.Table = s.table
		ru.Type = s.typ
		if s.mark {
			ru.Mark = tsconst.LinuxBypassMarkNum
			ru.Mask = tsconst.LinuxFwmarkMaskNum
		}
		rules = append(rules, ru)
	}
	return rules
}

// isJuistRulePref reports whether pref is one of instance inst's rules.
func isJuistRulePref(pref uint32, inst int) bool {
	for _, ru := range juistRules(netlink.FAMILY_V4, inst) {
		if pref == uint32(ru.Priority) {
			return true
		}
	}
	return false
}

// linuxRouter programs juist's addresses, routes and policy rules. Of the
// router config it serves only LocalAddrs and Routes; its netfilter state is
// tables of its own.
type linuxRouter struct {
	logf      logger.Logf
	link      netlink.Link
	inst      int  // the host's juist instance this is, which owns table and rules
	v6Present bool // the kernel has IPv6 at all
	v6Rules   bool // and routes it by policy
	ec        *eventbus.Client

	restorePending atomic.Bool
	restoreLimit   *rate.Limiter

	// done ends the watch of the host's routes when the router closes.
	done     chan struct{}
	doneOnce sync.Once

	mu       sync.Mutex
	closed   bool
	addrs    map[netip.Prefix]bool
	routes   map[netip.Prefix]bool
	src4     netip.Addr // the IPv4 source the routes were installed with
	v6Logged bool
	egress   Egress // installed
	want     Egress // asked for, which a lower instance's egress may keep out
	// tunnelled is what the peers carry, the rest refused into the tunnel.
	tunnelled tunnelled
	exit      map[exitRoute]bool // the exit table's routes installed
	// exitListed says the exit table was read for what an earlier juistd
	// of this instance left there.
	exitListed bool
	serving    bool // the serving table is installed
	// groFor is the uplink serving last looked at, and groWas its features
	// as they were where it changed them.
	groFor string
	groWas map[string]bool
	mon    *netmon.Monitor
	// inOwn and inPeers are what the in table guards, where inInstalled.
	inOwn, inPeers []netip.Addr
	inInstalled    bool
}

func newOSRouter(logf logger.Logf, dev tun.Device, mon *netmon.Monitor, _ *health.Tracker, bus *eventbus.Bus,
	inst int) (router.Router, error) {
	name, err := dev.Name()
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("looking up link %q: %w", name, err)
	}
	_, err = os.Stat("/proc/sys/net/ipv6")
	r := &linuxRouter{
		logf:         logger.WithPrefix(logf, "router: "),
		link:         link,
		inst:         inst,
		v6Present:    err == nil,
		v6Rules:      err == nil,
		restoreLimit: rate.NewLimiter(rate.Every(5*time.Second), 10),
		exit:         map[exitRoute]bool{},
		done:         make(chan struct{}),
		mon:          mon,
	}
	r.ec = bus.Client("juist-router")
	eventbus.SubscribeFunc(r.ec, func(d netmon.RuleDeleted) { r.onRuleDeleted(d.Priority) })
	eventbus.SubscribeFunc(r.ec, func(d netmon.ChangeDelta) {
		if d.InterfaceIPsChanged || d.IsInitialState {
			r.onLinksChanged()
		}
	})
	return r, nil
}

func closeUnstartedRouter(r router.Router) { r.Close() }

func (r *linuxRouter) Up() error {
	if err := netlink.LinkSetUp(r.link); err != nil {
		return fmt.Errorf("bringing %s up: %w", r.link.Attrs().Name, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addRulesLocked()
}

func (r *linuxRouter) Set(cfg *router.Config) error {
	if cfg == nil {
		cfg = &router.Config{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v6 := linkV6Usable("/proc/sys/net/ipv6/conf", r.link.Attrs().Name)
	if !v6 && !r.v6Logged {
		r.v6Logged = true
		r.logf("no IPv6 on %s; skipping its IPv6 addresses and routes", r.link.Attrs().Name)
	}
	var errs []error
	// New addresses, then the routes naming a new source, then the old
	// addresses: deleting an address deletes the routes naming it, and a
	// packet routed meanwhile leaves by the host's default route.
	addrs := usable(cfg.LocalAddrs, v6, false)
	r.addrs = reconcile(r.addrs, slices.Concat(addrs, slices.Collect(maps.Keys(r.addrs))), r.addAddr, r.delAddr, &errs)
	if src := preferredSrc4(cfg.LocalAddrs); src != r.src4 {
		r.src4 = src
		for p := range r.routes {
			r.routes[p] = false
		}
		if r.egress != EgressDirect {
			errs = append(errs, r.setEgressLocked(r.egress))
		}
	}
	r.routes = reconcile(r.routes, usable(cfg.Routes, v6, true), r.addRoute, r.delRoute, &errs)
	r.addrs = reconcile(r.addrs, addrs, r.addAddr, r.delAddr, &errs)
	return errors.Join(errs...)
}

// Close must not assume Up ran: the engine closes routers it never brought up.
func (r *linuxRouter) Close() error {
	r.doneOnce.Do(func() { close(r.done) })
	r.mu.Lock()
	r.closed = true
	var errs []error
	// A chosen exit node's traffic stays refused, not let out, until the
	// next node takes over or [ClearEgress] ends it.
	if r.egress != EgressDirect {
		errs = append(errs, r.setEgressLocked(EgressRefused))
	}
	if r.serving {
		errs = append(errs, r.setServeLocked(Serve{}))
	}
	if r.inInstalled {
		errs = append(errs, setInGuard(r.inst, r.link.Attrs().Name, nil, nil))
	}
	r.routes = reconcile(r.routes, nil, r.addRoute, r.delRoute, &errs)
	errs = append(errs, r.delRulesLocked())
	r.mu.Unlock()
	r.ec.Close()
	return errors.Join(errs...)
}

// reconcile applies want over have and returns what is now installed. It keeps
// going past failures, appending each to errs: a failed add stays absent and a
// failed delete stays present, so the next call retries both.
func reconcile(have map[netip.Prefix]bool, want []netip.Prefix, add, del func(netip.Prefix) error, errs *[]error) map[netip.Prefix]bool {
	next := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		if have[p] {
			next[p] = true
			continue
		}
		if err := add(p); err != nil {
			*errs = append(*errs, err)
			continue
		}
		next[p] = true
	}
	for p := range have {
		if next[p] {
			continue
		}
		if err := del(p); err != nil {
			*errs = append(*errs, err)
			next[p] = true
		}
	}
	return next
}

// usable drops IPv6 prefixes when v6 is false, masking them first for routes.
func usable(ps []netip.Prefix, v6, mask bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.Addr().Is6() && !v6 {
			continue
		}
		if mask {
			p = p.Masked()
		}
		out = append(out, p)
	}
	return out
}

// linkV6Usable reports whether the kernel runs IPv6 on the link: its conf
// directory exists only while it does, and disable_ipv6 may turn it off.
func linkV6Usable(confDir, name string) bool {
	b, err := os.ReadFile(filepath.Join(confDir, name, "disable_ipv6"))
	if err != nil {
		// Only absence is a verdict; an unreadable knob is no reason to skip.
		return !errors.Is(err, os.ErrNotExist)
	}
	off, err := strconv.ParseBool(strings.TrimSpace(string(b)))
	return err != nil || !off
}

func (r *linuxRouter) addAddr(p netip.Prefix) error {
	if err := netlink.AddrReplace(r.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(p)}); err != nil {
		return fmt.Errorf("adding address %v: %w", p, err)
	}
	return nil
}

func (r *linuxRouter) delAddr(p netip.Prefix) error {
	err := netlink.AddrDel(r.link, &netlink.Addr{IPNet: netipx.PrefixIPNet(p)})
	if err != nil && !errors.Is(err, syscall.EADDRNOTAVAIL) {
		return fmt.Errorf("deleting address %v: %w", p, err)
	}
	return nil
}

func (r *linuxRouter) route(p netip.Prefix) *netlink.Route {
	return &netlink.Route{LinkIndex: r.link.Attrs().Index, Dst: netipx.PrefixIPNet(p), Table: routeTable(r.inst)}
}

func (r *linuxRouter) addRoute(p netip.Prefix) error {
	rt := r.route(p)
	if p.Addr().Is4() && r.src4.IsValid() {
		rt.Src = r.src4.AsSlice()
	}
	if err := netlink.RouteReplace(rt); err != nil {
		return fmt.Errorf("adding route %v: %w", p, err)
	}
	return nil
}

func (r *linuxRouter) delRoute(p netip.Prefix) error {
	err := netlink.RouteDel(r.route(p))
	if err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.ENODEV) {
		return fmt.Errorf("deleting route %v: %w", p, err)
	}
	return nil
}

func (r *linuxRouter) ruleFamilies() []int {
	if r.v6Rules {
		return []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	}
	return []int{netlink.FAMILY_V4}
}

func (r *linuxRouter) addRulesLocked() error {
	var errs []error
	for _, fam := range r.ruleFamilies() {
		for _, ru := range juistRules(fam, r.inst) {
			err := netlink.RuleAdd(&ru)
			if fam == netlink.FAMILY_V6 && errors.Is(err, syscall.EAFNOSUPPORT) {
				r.logf("the kernel has no IPv6 policy routing; skipping IPv6 rules")
				r.v6Rules = false
				break
			}
			if err != nil && !errors.Is(err, syscall.EEXIST) {
				errs = append(errs, fmt.Errorf("adding %v: %w", ru, err))
			}
		}
	}
	return errors.Join(errs...)
}

// delRulesLocked matches on priority as well as table and action, so it never
// removes a rule Tailscale installed.
func (r *linuxRouter) delRulesLocked() error {
	var errs []error
	for _, fam := range r.ruleFamilies() {
		for _, ru := range juistRules(fam, r.inst) {
			if err := netlink.RuleDel(&ru); err != nil && !errors.Is(err, syscall.ENOENT) {
				errs = append(errs, fmt.Errorf("deleting %v: %w", ru, err))
			}
		}
	}
	return errors.Join(errs...)
}

// onRuleDeleted restores our rules after someone else (systemd-networkd, say)
// deletes them, once per burst and at a bounded rate.
func (r *linuxRouter) onRuleDeleted(pref uint32) {
	// Another instance's exit rule going may let this one's egress in.
	other := pref >= juistRulePrefBase+exitRuleExit && pref <= juistRulePrefBase+exitRuleExit+exitRuleMaxShift
	if !isJuistRulePref(pref, r.inst) && !isExitRulePref(pref, r.inst) && !other || r.restorePending.Swap(true) {
		return
	}
	res := r.restoreLimit.Reserve()
	if !res.OK() {
		r.restorePending.Store(false)
		return
	}
	time.AfterFunc(res.Delay()+250*time.Millisecond, func() {
		r.restorePending.Store(false)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed {
			return
		}
		if err := r.addRulesLocked(); err != nil {
			r.logf("restoring ip rules: %v", err)
		}
		if r.want != EgressDirect {
			if err := r.setEgressLocked(r.want); err != nil && !errors.Is(err, ErrEgressTaken) {
				r.logf("restoring egress: %v", err)
			}
		}
	})
}
