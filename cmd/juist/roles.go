package main

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

const rolesAbout = `Roles:

  exit     carries other devices' internet traffic, once its operator
           agrees: juist exit serve
  relay    relays for devices that cannot reach each other; best on two or
           more devices with public addresses
  voucher  vouches hourly that the network state is current, so cut-off
           devices notice; keep one online. Not an admin key.`

const subnetsAbout = `

A PREFIX, such as 192.168.1.0/24, is a subnet the device routes for every
member, once its operator agrees: juist subnet serve.`

func cmdGrant(a *app, args []string) error {
	s := spec{name: "juist grant", args: "DEVICE ROLE|PREFIX...", min: 2, max: -1, about: `
Give a device roles, or subnets to route. ` + rolesAbout + subnetsAbout}
	return changeRoles(a, s, args, true)
}

func cmdRevoke(a *app, args []string) error {
	s := spec{name: "juist revoke", args: "DEVICE ROLE|PREFIX...", min: 2, max: -1, about: `
Take roles or subnets from a device. ` + rolesAbout + subnetsAbout}
	return changeRoles(a, s, args, false)
}

func changeRoles(a *app, s spec, args []string, grant bool) error {
	fs := newFlags(s.name)
	yes := new(bool)
	if !grant {
		fs.BoolVar(yes, "yes", false, "do not ask")
	}
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	target, err := resolveDevice(state, pos[0])
	if err != nil {
		return err
	}
	name := displayMember(target)
	roles := map[types.Role]bool{}
	for _, r := range target.Roles {
		roles[r] = true
	}
	subnets := slices.Clone(target.SubnetRoutes())
	for _, arg := range pos[1:] {
		if pfx, ok, err := parseSubnet(arg, name); ok || err != nil {
			if err != nil {
				return err
			}
			if subnets, err = a.changeSubnet(state, target, subnets, pfx, grant); err != nil {
				return err
			}
			continue
		}
		r, err := parseRole(arg)
		if err != nil {
			return err
		}
		roles[r] = grant
	}
	var next []types.Role
	for r, on := range roles {
		if on {
			next = append(next, r)
		}
	}
	next = sortRoles(next)
	routes := exitRoutes(subnets, slices.Contains(next, types.RoleExit))
	if slices.Equal(next, target.Roles) && sameRoutes(routes, target.Routes) {
		a.ok("%s: unchanged", name)
		return nil
	}
	aum, err := auth.Builder().SetNodeRoutes(target.Identity, next, routes)
	if err != nil {
		return err
	}
	if !slices.Contains(next, types.RoleAdmin) {
		if err := a.checkAdminDeviceLoss(auth.State(), target, *yes); err != nil {
			return err
		}
	}
	var parts []string
	if len(next) > 0 {
		parts = append(parts, "roles "+describeRoles(next))
	}
	if len(subnets) > 0 {
		parts = append(parts, "routes "+listPrefixes(sortedPrefixes(subnets)))
	}
	done := name + ": " + cmp.Or(strings.Join(parts, ", "), "no roles, no subnets")
	_, err = a.submit(auth, &change{aum: aum, file: "roles-" + fileSafe(name) + ".rec", done: done})
	return err
}

// parseSubnet reads arg as a subnet for device name to route, where it is a
// prefix at all: ok says it is meant as one.
func parseSubnet(arg, name string) (pfx netip.Prefix, ok bool, err error) {
	if !strings.Contains(arg, "/") {
		return netip.Prefix{}, false, nil
	}
	pfx, err = netip.ParsePrefix(arg)
	switch {
	case err != nil:
		return pfx, true, fmt.Errorf("%q is no prefix, such as 192.168.1.0/24", arg)
	case pfx.Bits() == 0:
		return pfx, true, fmt.Errorf("%v is the internet\nhint: juist grant %s exit", pfx, name)
	case pfx.Masked() != pfx:
		return pfx, true, fmt.Errorf("%v has host bits set\nhint: %v", pfx, pfx.Masked())
	}
	return pfx.Masked(), true, nil
}

// changeSubnet is subnets with pfx granted or taken, checked as the log will
// check it, with the words a person needs; granting public space warns.
func (a *app) changeSubnet(state *log.State, target types.NodeRecord, subnets []netip.Prefix, pfx netip.Prefix,
	grant bool) ([]netip.Prefix, error) {
	name := displayMember(target)
	if !grant {
		if !slices.Contains(subnets, pfx) {
			return nil, fmt.Errorf("%s does not route %v\nhint: juist subnet", name, pfx)
		}
		return slices.DeleteFunc(subnets, func(p netip.Prefix) bool { return p == pfx }), nil
	}
	if slices.Contains(subnets, pfx) {
		return subnets, nil
	}
	for _, p := range subnets {
		if p.Overlaps(pfx) {
			return nil, fmt.Errorf("%v overlaps %v, which %s routes already", pfx, p, name)
		}
	}
	for _, n := range state.Nodes() {
		for _, p := range n.SubnetRoutes() {
			if n.Identity != target.Identity && p.Overlaps(pfx) {
				return nil, fmt.Errorf("%v overlaps %v, which %s routes", pfx, p, displayMember(n))
			}
		}
	}
	for _, r := range []struct {
		p    netip.Prefix
		what string
	}{
		{netip.MustParsePrefix("127.0.0.0/8"), "is every host's own"}, {netip.MustParsePrefix("::1/128"), "is every host's own"},
		{netip.MustParsePrefix("169.254.0.0/16"), "never leaves a link"}, {netip.MustParsePrefix("fe80::/10"), "never leaves a link"},
		{netip.MustParsePrefix("224.0.0.0/4"), "is multicast"}, {netip.MustParsePrefix("ff00::/8"), "is multicast"},
		{netip.MustParsePrefix("240.0.0.0/4"), "is reserved"},
	} {
		if r.p.Overlaps(pfx) {
			return nil, fmt.Errorf("%v %s, which no device routes: %v", pfx, r.what, r.p)
		}
	}
	for _, own := range append(slices.Clone(state.V4Ranges()), state.ULA()) {
		if own.Overlaps(pfx) {
			return nil, fmt.Errorf("%v overlaps the network's own addresses, %v", pfx, own)
		}
	}
	if slices.ContainsFunc(conn.Internet(true, true, nil), pfx.Overlaps) {
		a.warn("%v is public space: every member reaches it through %s", pfx, name)
	}
	return append(subnets, pfx), nil
}

func sortedPrefixes(ps []netip.Prefix) []netip.Prefix {
	out := slices.Clone(ps)
	slices.SortFunc(out, func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return x.Bits() - y.Bits()
	})
	return out
}

// listPrefixes is ps, comma-separated.
func listPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

// checkAdminDeviceLoss is asked before target stops being a voucher.
// It refuses to leave fewer vouchers than must vouch, which would leave
// every device stale until a lower threshold lands, and before the last one
// goes, which ends freshness checks, it warns and, unless yes, asks.
func (a *app) checkAdminDeviceLoss(state *log.State, target types.NodeRecord, yes bool) error {
	if !slices.Contains(target.Roles, types.RoleAdmin) {
		return nil
	}
	name := displayMember(target)
	switch left := len(state.NodesWithRole(types.RoleAdmin)) - 1; {
	case left == 0:
		a.warn("%s is the last voucher; without one, freshness goes unchecked", name)
		return a.proceed(yes, "continue?")
	case uint32(left) < state.Vouchers():
		return fmt.Errorf("%s is one of the %d vouchers needed; without it every device goes stale\n"+
			"hint: juist admins vouchers %d", name, state.Vouchers(), left)
	}
	return nil
}

// exitRoutes is routes with the default routes an exit node holds, or without.
func exitRoutes(routes []netip.Prefix, exit bool) []netip.Prefix {
	out := slices.DeleteFunc(slices.Clone(routes), func(p netip.Prefix) bool { return p.Bits() == 0 })
	if exit {
		out = append(out, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	}
	return out
}

func sameRoutes(a, b []netip.Prefix) bool {
	key := func(ps []netip.Prefix) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.String()
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}

// Role names as operators type them, and the log's names for them.
var roleNames = []struct {
	user string
	role types.Role
}{
	// "voucher", not the log's "admin": an admin key votes on changes, and
	// this role vouches for the network's state. "admin" is still accepted.
	{"voucher", types.RoleAdmin},
	{"relay", types.RoleRelayCapable},
	{"exit", types.RoleExit},
}

// describeGrant is roles, and the subnets routed beside them.
func describeGrant(roles []types.Role, subnets []netip.Prefix) string {
	switch {
	case len(subnets) == 0:
		return describeRoles(roles)
	case len(roles) == 0 && len(subnets) <= 2:
		return "routes " + listPrefixes(subnets)
	case len(roles) == 0:
		return fmt.Sprintf("routes %d subnets", len(subnets))
	case len(subnets) <= 2:
		return describeRoles(roles) + ", routes " + listPrefixes(subnets)
	}
	return fmt.Sprintf("%s, routes %d subnets", describeRoles(roles), len(subnets))
}

func describeRoles(roles []types.Role) string {
	var out []string
	for _, r := range roles {
		name := string(r)
		for _, rn := range roleNames {
			if rn.role == r {
				name = rn.user
			}
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ", ")
}

func parseRole(s string) (types.Role, error) {
	for _, rn := range roleNames {
		if strings.EqualFold(s, rn.user) || strings.EqualFold(s, string(rn.role)) {
			return rn.role, nil
		}
	}
	names := make([]string, len(roleNames))
	for i, rn := range roleNames {
		names[i] = rn.user
	}
	return "", fmt.Errorf("%q is not a role%s; the roles are %s and %s", s, didYouMean(strings.ToLower(s), names...),
		strings.Join(names[:len(names)-1], ", "), names[len(names)-1])
}
