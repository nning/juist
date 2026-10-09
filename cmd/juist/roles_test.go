package main

import (
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/types"
)

func TestRemoveAsksFirst(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	enrollDevice(t, admin, "phone")
	if _, err := admin.answer("n", "remove", "phone"); err == nil {
		t.Fatal("remove went ahead when told no")
	}
	if _, err := admin.run("remove", "phone"); err == nil {
		t.Fatal("remove went ahead with nobody to ask")
	}
	mustContain(t, admin.mustRun("devices"), "phone")
	if out, err := admin.answer("y", "remove", "phone"); err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	if strings.Contains(admin.mustRun("devices"), "phone") {
		t.Fatal("the device is still listed after removing it")
	}
}

func TestGrant(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	enrollDevice(t, admin, "phone")
	mustContain(t, admin.mustRun("grant", "phone", "relay"), "phone: roles relay")
	mustContain(t, admin.mustRun("grant", "phone", "relay"), "unchanged")
	mustContain(t, admin.mustRun("revoke", "phone", "relay"), "phone: no roles")
	if _, err := admin.run("grant", "phone", "wizard"); err == nil {
		t.Fatal("granted a role that does not exist")
	}
}

// Taking away admin devices is held to the vouching threshold: fewer than
// must vouch is refused, since every device would go stale, and the last
// one goes only when confirmed, since freshness then ends.
func TestAdminDevicesAreNotLostByAccident(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--voucher")
	enrollDevice(t, c, "phone")
	c.mustRun("grant", "phone", "voucher")
	c.mustRun("admins", "vouchers", "2")
	for _, args := range [][]string{{"remove", "phone", "--yes"}, {"revoke", "phone", "admin", "--yes"}} {
		if _, err := c.run(args...); err == nil || !strings.Contains(err.Error(), "juist admins vouchers 1") {
			t.Fatalf("juist %q below the threshold: %v", args, err)
		}
	}
	c.mustRun("admins", "vouchers", "1")
	c.mustRun("revoke", "phone", "admin")
	if _, err := c.run("revoke", "laptop", "admin"); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("the last admin device went unasked: %v", err)
	}
	mustContain(t, c.mustRun("revoke", "laptop", "admin", "--yes"), "last voucher")
}

// A role that excludes one the device holds is refused in words, naming
// what to take away.
func TestARoleThatExcludesAnotherIsSaid(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "vps")
	admin.mustRun("grant", "vps", "voucher")
	for _, tc := range []struct{ role, want string }{
		{"ingress", "vps holds the role voucher, which the role ingress excludes\nhint: juist revoke vps voucher"},
		{"service", "vps holds the role voucher, which the role service excludes\nhint: juist revoke vps voucher"},
	} {
		if _, err := admin.run("grant", "vps", tc.role); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("grant %s: %v", tc.role, err)
		}
	}
	admin.mustRun("grant", "vps", "relay")
}

// A voucher set without a spare, or with a relay as the one voucher needed,
// is said when it is made, not when every device has gone limited.
func TestVoucherSetsWithoutASpareAreSaid(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--voucher")
	enrollDevice(t, c, "vps")
	enrollDevice(t, c, "nas")
	mustLack(t, c.mustRun("grant", "laptop", "publish"), "warning")
	mustContain(t, c.mustRun("grant", "laptop", "relay"), "no spare voucher", "laptop relays too")
	out := c.mustRun("grant", "vps", "voucher")
	mustContain(t, out, "laptop relays too")
	mustLack(t, out, "no spare voucher")
	out = c.mustRun("admins", "vouchers", "2")
	mustContain(t, out, "no spare voucher")
	mustLack(t, out, "relays too")
	mustLack(t, c.mustRun("grant", "nas", "voucher"), "warning")
}

func mustLack(t *testing.T, out, s string) {
	t.Helper()
	if strings.Contains(out, s) {
		t.Fatalf("output has %q:\n%s", s, out)
	}
}

// A voucher whose membership has expired is no spare.
func TestAnExpiredVoucherIsNoSpare(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	var out syncBuffer
	a := newCLI(t).app(&out, "")
	a.now = func() time.Time { return now }
	voucher := types.NodeRecord{Name: "nas", Roles: []types.Role{types.RoleAdmin}}
	expired := types.NodeRecord{Name: "laptop", Roles: []types.Role{types.RoleAdmin}, Expiry: uint64(now.Unix())}
	a.warnVouchers([]types.NodeRecord{voucher, expired}, 1)
	mustContain(t, out.String(), "no spare voucher")
}
