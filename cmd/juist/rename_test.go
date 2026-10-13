package main

import (
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// A renamed device keeps everything but its name, is found by the new one
// and no longer by the old, and the approval says what others reach it by.
func TestRenameADevice(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`juist admins add second (nid:\S+)`).
		FindStringSubmatch(second.mustRun("admins", "new", "second"))
	if key == nil {
		t.Fatal("admins new printed no key")
	}
	first.mustRun("create", "home", "--device", "laptop", "--quorum", "2", "--admin", "second="+key[1])
	genesis := filepath.Join(first.home, genesisFileFor("home"))
	second.mustRun("approve", "--yes", genesis)
	first.mustRun("apply", genesis)
	before, _ := resolveDevice(openLog(t, first).State(), "laptop")

	for _, bad := range []struct{ name, want string }{
		{"_desk", "device name"},
		{"my desk", "device name"},
		{"büro", "device name"},
	} {
		if _, err := first.run("rename", "laptop", bad.name); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("renamed to %q: %v", bad.name, err)
		}
	}
	mustContain(t, first.mustRun("rename", "LAPTOP", "laptop"), `unchanged: named "laptop"`)
	mustContain(t, first.mustRun("rename", "laptop", "desk"), "needs 1 more vote", "juist approve rename-laptop.rec")
	pending := filepath.Join(dir, "rename-laptop.rec")
	mustContain(t, second.mustRun("approve", "--yes", pending), `renames nid:`, `to "desk"`)
	mustContain(t, first.mustRun("log", "verify", pending), "renames laptop (", `) to "desk"`,
		"desk.home.juist resolves to it, and laptop.home.juist no longer does")
	mustContain(t, first.mustRun("apply", pending), "applied")

	state := openLog(t, first).State()
	after, err := resolveDevice(state, "desk")
	if err != nil {
		t.Fatal(err)
	}
	want := before.Clone()
	want.Name = "desk"
	if !reflect.DeepEqual(&after, want) {
		t.Fatalf("renamed, the device is %+v, want %+v", after, *want)
	}
	if _, err := resolveDevice(state, "laptop"); err == nil {
		t.Error("the old name still finds the device")
	}
	mustContain(t, first.mustRun("devices"), "desk (this device)")
	mustContain(t, first.mustRun("log"), `renaming of a device: laptop to "desk"`)
}

// Where two devices held a label from before, the rename says that it then
// resolves to the other.
func TestARenameGivesASharedLabelToTheOther(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	auth := openLog(t, admin)
	keys, err := admin.home2().adminKeys()
	if err != nil {
		t.Fatal(err)
	}
	twin := testNode(t, "NAS")
	add, err := auth.Builder().AddNode(twin, sealer())
	if err == nil {
		err = add.SignUnder(keys[0], auth.State().Schema())
	}
	if err == nil {
		err = auth.Inform(add)
	}
	if err != nil {
		t.Fatal(err)
	}
	aum, err := auth.Builder().RenameNode(twin.Identity, "storage")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"),
		"storage.home.juist resolves to it, and nas.home.juist to nas (")
}

// A name another device's folds like is refused, as is one the device's
// share name cannot follow; a name that gives no DNS label is warned of.
func TestARenameKeepsNamesApart(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	if _, err := admin.run("rename", "nas", "Laptop"); err == nil || !strings.Contains(err.Error(), `another device is named "laptop" already`) {
		t.Errorf("renamed to another device's name: %v", err)
	}
	admin.mustRun("network", "domain", "pub.example.org")
	admin.mustRun("grant", "laptop", "publish")
	admin.mustRun("publish", "add", "nas", "web")
	for _, bad := range []struct{ name, want string }{
		{"my.laptop", `"my.laptop" gives no DNS label for laptop to share under`},
		{"web", "web.pub.example.org is published on nas already"},
	} {
		if _, err := admin.run("rename", "laptop", bad.name); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("renamed to %q: %v", bad.name, err)
		}
	}
	admin.mustRun("publish", "add", "laptop", "blog")
	admin.mustRun("names", "add", "laptop", "mx.pub.example.org")
	for _, bad := range []struct{ name, want string }{
		{"blog", "laptop publishes blog.pub.example.org already, the name it would share under"},
		{"mx", "laptop points mx.pub.example.org at itself already"},
	} {
		if _, err := admin.run("rename", "laptop", bad.name); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("renamed to %q: %v", bad.name, err)
		}
	}
	long := strings.Repeat("b", 62) + "." + strings.Repeat("c", 62) + "." + strings.Repeat("d", 62) + ".org"
	admin.mustRun("network", "domain", long)
	if _, err := admin.run("rename", "laptop", strings.Repeat("a", 63)); err == nil ||
		!strings.Contains(err.Error(), "laptop cannot be named") || strings.Contains(err.Error(), "log:") {
		t.Errorf("renamed to a share name too long: %v", err)
	}
	admin.mustRun("network", "domain", "pub.example.org")
	mustContain(t, admin.mustRun("rename", "laptop", "desk"), "renamed laptop to desk")
	auth := openLog(t, admin)
	desk, _ := resolveDevice(auth.State(), "desk")
	aum, err := auth.Builder().RenameNode(desk.Identity, "study")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"),
		"shares under study.pub.example.org, not desk.pub.example.org")
	aum, err = auth.Builder().RenameNode(desk.Identity, "Desk")
	if err != nil {
		t.Fatal(err)
	}
	if got := effect(&aum, auth.State(), 0); len(got) != 1 {
		t.Errorf("a change of case is said as %q", got)
	}
	out := admin.mustRun("rename", "nas", "nas_1")
	mustContain(t, out, `warning: "nas_1" is no DNS label: nas gets no name under home.juist`, "renamed nas to nas_1")
}
