package main

import (
	"cmp"
	"flag"
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
  ingress  takes connections from the internet for the names devices
           publish; on a device with a public address, and nothing else
  service  a service member: juistd --serve beside a service, which every
           device keeps from opening any connection to it
  publish  shares under its own name at once, without a vote each time:
           juist share FILE, juist publish PORT
  relay    relays for devices that cannot reach each other; best on two or
           more devices with public addresses
  voucher  vouches hourly that the network state is current, so cut-off
           devices notice; where too few vouch for 48 hours, devices reach
           only vouchers: give it to devices that are always on. Not an
           admin key.`

func cmdGrant(a *app, args []string) error {
	s := spec{name: "juist grant", args: "DEVICE ROLE...", min: 2, max: -1, about: `
Give a device roles. ` + rolesAbout}
	return changeRoles(a, s, args, true)
}

func cmdRevoke(a *app, args []string) error {
	s := spec{name: "juist revoke", args: "DEVICE ROLE...", min: 2, max: -1, about: `
Take roles from a device. ` + rolesAbout}
	return changeRoles(a, s, args, false)
}

func changeRoles(a *app, s spec, args []string, grant bool) error {
	fs := newFlags(s.name)
	yes := new(bool)
	if !grant {
		fs.BoolVar(yes, "yes", false, "do not ask")
	}
	auth, target, pos, err := a.deviceChange(s, fs, args)
	if err != nil {
		return err
	}
	roles := map[types.Role]bool{}
	for _, r := range target.Roles {
		roles[r] = true
	}
	for _, arg := range pos {
		if err := notARole(arg, displayMember(target), grant); err != nil {
			return err
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
	if grant {
		if err := roleConflict(target, sortRoles(next)); err != nil {
			return err
		}
	}
	applied, err := a.submitRoutes(auth, target, sortRoles(next), target.SubnetRoutes(), *yes)
	if err != nil || !applied {
		return err
	}
	name := displayMember(target)
	vouches, relays := roles[types.RoleAdmin], roles[types.RoleRelayCapable]
	if vouches != target.HasRole(types.RoleAdmin) || vouches && relays != target.HasRole(types.RoleRelayCapable) {
		st := auth.State()
		a.warnVouchers(vouchersWith(st.Nodes(), target, sortRoles(next)), int(st.Vouchers()))
	}
	for _, r := range []types.Role{types.RoleIngress, types.RoleService} {
		if target.HasRole(r) && !roles[r] {
			// The role confined the device; a member like any other is not.
			a.warn("%s is confined no more, now a member like any other", name)
			a.hint("one that may be compromised goes by juist remove %s", name)
		}
	}
	if target.HasRole(types.RoleIngress) && !roles[types.RoleIngress] {
		a.hint("on %s, juist ingress serve --stop", name)
	}
	if roles[types.RolePublish] && !target.HasRole(types.RolePublish) {
		a.hint("on %s, juist share FILE or juist publish PORT", name)
	}
	if !roles[types.RoleIngress] || target.HasRole(types.RoleIngress) {
		return nil
	}
	return a.serveIngressNext(target)
}

// roleConflict says which of target's roles keeps it from next, as the log
// refuses: an ingress beside a voucher, an exit node or publish, and a
// service member beside anything.
func roleConflict(target types.NodeRecord, next []types.Role) error {
	apart := func(a, b types.Role) bool {
		switch {
		case a == types.RoleService || b == types.RoleService:
			return true
		case a == types.RoleIngress || b == types.RoleIngress:
			return slices.Contains([]types.Role{types.RoleAdmin, types.RoleExit, types.RolePublish}, a) ||
				slices.Contains([]types.Role{types.RoleAdmin, types.RoleExit, types.RolePublish}, b)
		}
		return false
	}
	name := displayMember(target)
	for _, r := range next {
		for _, other := range next {
			if r == other || !apart(r, other) || target.HasRole(r) || !target.HasRole(other) {
				continue
			}
			had, wants := describeRoles([]types.Role{other}), describeRoles([]types.Role{r})
			return fmt.Errorf("%s holds the role %s, which the role %s excludes\nhint: juist revoke %s %s",
				name, had, wants, name, had)
		}
	}
	return nil
}

// notARole names the command that takes arg, where it is a subnet or a
// public name for device.
func notARole(arg, device string, grant bool) error {
	verb := map[bool]string{true: "add", false: "remove"}[grant]
	switch {
	case strings.Contains(arg, "/"):
		return fmt.Errorf("%s is a subnet, not a role\nhint: juist subnet %s %s %s", arg, verb, device, arg)
	case strings.Contains(arg, "."):
		return fmt.Errorf("%s is a public name, not a role\nhint: juist names %s %s %s", arg, verb, device, arg)
	}
	return nil
}

// deviceChange parses args for s, its flags fs, and opens the log and the
// device the first argument names; the rest are what to change.
func (a *app) deviceChange(s spec, fs *flag.FlagSet, args []string) (*log.Authority, types.NodeRecord, []string, error) {
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return nil, types.NodeRecord{}, nil, err
	}
	auth, err := a.networkLog()
	if err != nil {
		return nil, types.NodeRecord{}, nil, err
	}
	target, err := resolveDevice(auth.State(), pos[0])
	return auth, target, pos[1:], err
}

// submitRoutes proposes target's roles and subnets as next and subnets, and
// reports whether the change applied.
func (a *app) submitRoutes(auth *log.Authority, target types.NodeRecord, next []types.Role, subnets []netip.Prefix,
	yes bool) (bool, error) {
	name := displayMember(target)
	routes := exitRoutes(subnets, slices.Contains(next, types.RoleExit))
	if slices.Equal(next, target.Roles) && sameRoutes(routes, target.Routes) {
		a.ok("%s: unchanged", name)
		return false, nil
	}
	aum, err := auth.Builder().SetNodeRoutes(target.Identity, next, routes)
	if err != nil {
		return false, err
	}
	if !slices.Contains(next, types.RoleAdmin) {
		if err := a.checkAdminDeviceLoss(auth.State(), target, yes); err != nil {
			return false, err
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
	return a.submit(auth, &change{aum: aum, file: "roles-" + fileSafe(name) + ".rec", done: done})
}

// parseSubnet reads arg as a subnet for device name to route.
func parseSubnet(arg, name string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(arg)
	switch {
	case err != nil:
		return pfx, fmt.Errorf("%q is no prefix, such as 192.168.1.0/24", arg)
	case pfx.Bits() == 0:
		return pfx, fmt.Errorf("%v is the internet\nhint: juist grant %s exit", pfx, name)
	case pfx.Masked() != pfx:
		return pfx, fmt.Errorf("%v has host bits set\nhint: %v", pfx, pfx.Masked())
	}
	return pfx, nil
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
	{"ingress", types.RoleIngress},
	{"service", types.RoleService},
	{"publish", types.RolePublish},
}

// describeGrant is roles, the subnets routed beside them, and whether the
// device answers names or publishes any.
func describeGrant(roles []types.Role, subnets []netip.Prefix, names, publishes bool) string {
	var parts []string
	if len(roles) > 0 {
		parts = append(parts, describeRoles(roles))
	}
	switch {
	case len(subnets) > 2:
		parts = append(parts, fmt.Sprintf("routes %d subnets", len(subnets)))
	case len(subnets) > 0:
		parts = append(parts, "routes "+listPrefixes(subnets))
	}
	if names {
		parts = append(parts, "names")
	}
	if publishes {
		parts = append(parts, "publishes")
	}
	if len(parts) == 0 {
		return describeRoles(nil)
	}
	return strings.Join(parts, ", ")
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
