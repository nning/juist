package main

import (
	"strings"
	"testing"
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
	c.mustRun("create", "home", "--device", "laptop")
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
