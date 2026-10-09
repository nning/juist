package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// TestMultiAdminChangeFromStartToFinish: a change started by one admin,
// approved by another on a machine with no network, and applied back.
func TestMultiAdminChangeFromStartToFinish(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	mustContain(t, first.mustRun("admins"), "second", "2 of 2 votes")

	epoch := openLog(t, first).State().Epoch()
	mustContain(t, first.mustRun("rotate", "group-secret"), "1 more vote")
	pending := filepath.Join(dir, "rotate-group-secret.rec")
	if _, err := first.run("apply", pending); err == nil {
		t.Fatal("one admin of two applied a change alone")
	}
	mustContain(t, second.mustRun("approve", "--yes", pending), "apply on a device in the network")
	first.mustRun("apply", pending)
	if openLog(t, first).State().Epoch() != epoch+1 {
		t.Fatal("the approved change did not apply")
	}
}

// TestPendingChangesAreNeverOverwritten: a pending record collects approvals
// in place, so a second change of the same kind gets its own file.
func TestPendingChangesAreNeverOverwritten(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--quorum", "1", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("rotate", "group-secret")
	one, err := os.ReadFile(filepath.Join(dir, "rotate-group-secret.rec"))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, first.mustRun("rotate", "group-secret"), "rotate-group-secret-2.rec")
	if again, _ := os.ReadFile(filepath.Join(dir, "rotate-group-secret.rec")); !bytes.Equal(one, again) {
		t.Fatal("the second change wrote over the first")
	}
}

// TestApproveRefusesAnotherNetworksRecord: an untrusted signature spoils a
// record, so approve refuses one it cannot place in its own log.
func TestApproveRefusesAnotherNetworksRecord(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("rotate", "group-secret")
	pending := filepath.Join(dir, "rotate-group-secret.rec")

	stranger := newCLI(t)
	stranger.mustRun("create", "elsewhere")
	_, err := stranger.run("approve", "--yes", pending)
	if err == nil || !strings.Contains(err.Error(), "another network") {
		t.Fatalf("a stranger's approval got %v", err)
	}
	second.mustRun("approve", "--yes", pending)
	first.mustRun("apply", pending)
}

// TestApproveRefusesABrokenStore separates "this machine holds no network" —
// the air-gapped signing machine, which must work — from a damaged log, which
// must not pass for it.
func TestApproveRefusesABrokenStore(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("rotate", "group-secret")
	corrupt(t, first)
	if _, err := first.run("approve", "--yes", filepath.Join(dir, "rotate-group-secret.rec")); err == nil {
		t.Fatal("approved while the local log was corrupt")
	}
}

// A record on an older parent is refused before anyone signs it: it can no
// longer apply, and a signature cannot be taken back.
func TestApproveRefusesAChangeStartedBeforeTheLatest(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("rotate", "group-secret")
	stale := filepath.Join(dir, "rotate-group-secret.rec")

	// The admin set changes underneath the pending record. A change to the
	// admin set is approved only where the log is held, so second gets a
	// copy of it.
	third := regexp.MustCompile(`(nid:\S+)`).FindString(first.mustRun("admins", "new", "third"))
	first.mustRun("admins", "add", "third", third)
	copyTree(t, filepath.Join(first.home, logDir), filepath.Join(second.home, logDir))
	second.mustRun("approve", "--yes", filepath.Join(dir, "admin-add-third.rec"))
	first.mustRun("apply", filepath.Join(dir, "admin-add-third.rec"))

	before, err := os.ReadFile(stale)
	if err != nil {
		t.Fatal(err)
	}
	_, err = first.run("approve", "--yes", stale)
	if err == nil || !strings.Contains(err.Error(), "outdated by a later change") {
		t.Fatalf("approving a stale record: %v", err)
	}
	if after, _ := os.ReadFile(stale); !bytes.Equal(before, after) {
		t.Fatal("the stale record was signed")
	}
	if _, err := first.run("apply", stale); err == nil {
		t.Fatal("a stale record was applied")
	}

	// A change already in the log is said to be, not approved again.
	mustContain(t, second.mustRun("approve", "--yes", filepath.Join(dir, "admin-add-third.rec")),
		"in the log already")
	out := first.mustRun("apply", filepath.Join(dir, "admin-add-third.rec"))
	mustContain(t, out, "in the log already")
	if strings.Contains(out, ": applied") {
		t.Fatalf("a change already in the log was applied again:\n%s", out)
	}
}

// An admin sees what a record does before signing it, whatever the file is
// called: here a member hands over an admin key for itself as its "rotation".
func TestApproveShowsWhatItSigns(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	admin := newCLI(t)
	admin.mustRun("create", "home")
	auth := openLog(t, admin)
	intruder, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aum, err := auth.Builder().AddAdminKey(types.AdminKey{Public: intruder.Public(), Votes: 1, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	disguised := filepath.Join(dir, "rotate-phone.rec")
	if err := writeNewRecordFile(disguised, &aum); err != nil {
		t.Fatal(err)
	}
	out, err := admin.answer("n", "approve", disguised)
	if err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	mustContain(t, out, "new admin key", "gives the admin key phone", "not approved")
	if _, ok := openLog(t, admin).State().Admin(intruder.Public()); ok {
		t.Fatal("the disguised admin key was approved")
	}
	if _, err := admin.run("approve", disguised); err == nil {
		t.Fatal("approve signed without a terminal to ask on and without --yes")
	}
}

// A machine without the log cannot show what a change to the admin set does,
// so it does not approve one.
func TestApproveRefusesAuthorityChangesWithoutALog(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("admins", "quorum", "1")
	pending, _ := filepath.Glob(filepath.Join(dir, "*.rec"))
	if len(pending) != 1 {
		t.Fatalf("pending records: %v", pending)
	}
	out, err := second.run("approve", "--yes", pending[0])
	if err == nil || !strings.Contains(err.Error(), "approve it where the log is") {
		t.Fatalf("an air-gapped approval of a threshold change: %v\n%s", err, out)
	}
}

// Without the log a removal is refused too: whether the device is a voucher,
// and the last or one the threshold needs, only the log says.
func TestApproveRefusesARemovalWithoutALog(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--device", "laptop", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("remove", "laptop", "--yes")
	pending, _ := filepath.Glob(filepath.Join(dir, "*.rec"))
	if len(pending) != 1 {
		t.Fatalf("pending records: %v", pending)
	}
	out, err := second.run("approve", "--yes", pending[0])
	if err == nil || !strings.Contains(err.Error(), "approve it where the log is") {
		t.Fatalf("an air-gapped approval of a removal: %v\n%s", err, out)
	}
}

// Approving a removal where the log is says the device is a voucher, and
// warns before the last one goes, as proposing it does.
func TestApproveSaysARemovalTakesAVoucher(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--voucher")
	auth := openLog(t, c)
	removal, err := auth.Builder().RemoveNode(nodeKeysOf(t, c).Identity.Public(), sealer())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "remove-phone.rec")
	if err := writeRecordFile(path, &removal); err != nil {
		t.Fatal(err)
	}
	out := c.mustRun("approve", "--yes", "--no-apply", path)
	mustContain(t, out, "removes the device laptop (", "), voucher", "last voucher")
}

// A change that takes a device's routes away says so: shown only when there
// are routes, it would read as a change of roles alone.
func TestEffectShowsRoutesTakenAway(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	auth := openLog(t, c)
	self := nodeKeysOf(t, c).Identity.Public()
	routes := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	with, err := auth.Builder().SetNodeRoutes(self, []types.Role{types.RoleAdmin}, routes)
	if err != nil {
		t.Fatal(err)
	}
	h, err := openHome(c.home)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := h.adminKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := with.Sign(admins[0]); err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(with); err != nil {
		t.Fatal(err)
	}
	without, err := auth.Builder().SetNodeRoutes(self, []types.Role{types.RoleAdmin}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&without, auth.State(), time.Now().Unix()), "\n"), "from [192.168.1.0/24] to none")
}

func TestApprovalsNeededNamesEverythingMissing(t *testing.T) {
	t.Parallel()
	st := log.SignatureStatus{Votes: 0, Quorum: 2, Unsigned: []types.Identity{{1}}}
	mustContain(t, approvalsNeeded(st, nil, &types.AUM{}), "2 more votes", "own signature")
}

// What admins and a keystore with no admin key refuse, they refuse with the
// next step rather than the log's own words, and nothing is written.
func TestRefusalsSayWhatToDoNext(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	phone := enrollDevice(t, c, "phone")
	if _, err := phone.run("remove", "laptop", "--yes"); err == nil || !strings.Contains(err.Error(), "no admin key of this network") {
		t.Fatalf("a keystore with no admin key: %v", err)
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, "*.rec")); len(entries) != 0 {
		t.Fatalf("a change with no votes was written out: %v", entries)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"admins", "quorum", "2"}, "juist admins add NAME KEY"},
		{[]string{"admins", "vouchers", "2"}, "juist grant DEVICE voucher"},
		{[]string{"admins", "add", "bob", "nid:short"}, "bad key"},
	} {
		if _, err := c.run(tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("juist %q: %v, want %q", tc.args, err, tc.want)
		}
	}
	mustContain(t, c.mustRun("rotate", "abandon"), "no rotation pending")
}

// A removal started before the latest change is refused like any other
// stale record: it would fork the log where it was started and, winning
// there as a revocation does, undo every change since, removals included.
func TestALateRemovalIsRefusedToo(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	phone := enrollDevice(t, first, "phone")
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("remove", "phone", "--yes")
	first.mustRun("rotate", "group-secret")
	copyTree(t, filepath.Join(first.home, logDir), filepath.Join(second.home, logDir))
	second.mustRun("approve", "--yes", filepath.Join(dir, "rotate-group-secret.rec"))
	first.mustRun("approve", filepath.Join(dir, "rotate-group-secret.rec"))

	removal := filepath.Join(dir, "remove-phone.rec")
	before, _ := os.ReadFile(removal)
	if _, err := second.run("approve", "--yes", removal); err == nil ||
		!strings.Contains(err.Error(), "outdated by a later change") {
		t.Fatalf("a late removal: %v", err)
	}
	if after, _ := os.ReadFile(removal); !bytes.Equal(before, after) {
		t.Fatal("the late removal was signed")
	}
	if !openLog(t, first).State().IsMember(nodeKeysOf(t, phone).Identity.Public()) {
		t.Fatal("the late removal applied")
	}
}

// A file that fails does not strand the fully approved ones before it.
func TestApprovedRecordsApplyWhenALaterFileFails(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("rotate", "group-secret")
	second.mustRun("approve", "--yes", filepath.Join(dir, "rotate-group-secret.rec"))
	epoch := openLog(t, first).State().Epoch()
	if _, err := first.run("approve", filepath.Join(dir, "rotate-group-secret.rec"), filepath.Join(dir, "missing.rec")); err == nil {
		t.Fatal("a missing file was no error")
	}
	if openLog(t, first).State().Epoch() == epoch {
		t.Fatal("the fully approved record before the failing file was not applied")
	}
}
