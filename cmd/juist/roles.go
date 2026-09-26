package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

const rolesAbout = `Roles:

  relay    relays for devices that cannot reach each other; best on two or
           more devices with public addresses
  voucher  vouches hourly that the network state is current, so cut-off
           devices notice; keep one online. Not an admin key.`

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
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	target, err := resolveDevice(auth.State(), pos[0])
	if err != nil {
		return err
	}
	roles := map[types.Role]bool{}
	for _, r := range target.Roles {
		roles[r] = true
	}
	for _, arg := range pos[1:] {
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
	name := displayMember(target)
	if slices.Equal(next, target.Roles) {
		a.ok("%s: unchanged", name)
		return nil
	}
	aum, err := auth.Builder().SetNodeRoutes(target.Identity, next, target.Routes)
	if err != nil {
		return err
	}
	if !slices.Contains(next, types.RoleAdmin) {
		if err := a.checkAdminDeviceLoss(auth.State(), target, *yes); err != nil {
			return err
		}
	}
	done := fmt.Sprintf("%s: roles %s", name, describeRoles(next))
	if len(next) == 0 {
		done = name + ": no roles"
	}
	_, err = a.submit(auth, &change{aum: aum, file: "roles-" + fileSafe(name) + ".rec", done: done})
	return err
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

// Role names as operators type them, and the log's names for them.
var roleNames = []struct {
	user string
	role types.Role
}{
	// "voucher", not the log's "admin": an admin key votes on changes, and
	// this role vouches for the network's state. "admin" is still accepted.
	{"voucher", types.RoleAdmin},
	{"relay", types.RoleRelayCapable},
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
	return "", fmt.Errorf("%q is not a role%s; the roles are %s", s, didYouMean(strings.ToLower(s), names...),
		strings.Join(names, " and "))
}
