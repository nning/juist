package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// daemonStatus is a daemon device's status as its operator sees it.
func daemonStatus(t *testing.T, d *daemonDevice) *ipc.Status {
	t.Helper()
	resp, err := ipc.Call(d.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil || resp.Status == nil {
		t.Fatalf("status: %v", err)
	}
	return resp.Status
}

// joinDaemon invites a daemon device into host's network, with args to the
// invite, and joins it as name.
func joinDaemon(t *testing.T, host, guest *daemonDevice, name string, args ...string) {
	t.Helper()
	inv := host.start(append([]string{"invite", "--no-lan", "--port", "0", "--yes"}, args...)...)
	link := inv.waitFor(t, linkRE)[1]
	guest.mustRun("join", link, "--name", name)
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
}

// eventually runs check until it holds, or fails the test after a while.
func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	eventuallyWithin(t, 20*time.Second, what, check)
}

func eventuallyWithin(t *testing.T, d time.Duration, what string, check func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); !check(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, d)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// twoAdmins is a network of two admin devices, alice's founding one and
// bob's, each with the admin's own keystore, where every change needs both.
func twoAdmins(t *testing.T) (alice, bob *daemonDevice) {
	t.Helper()
	alice, bob, _ = twoAdminsAnd(t, 0)
	return alice, bob
}

// twoAdminsAnd is twoAdmins with n more admin devices, which hold no admin key.
func twoAdminsAnd(t *testing.T, n int) (alice, bob *daemonDevice, more []*daemonDevice) {
	t.Helper()
	alice, bob = newDaemonDevice(t, nil), newDaemonDevice(t, nil)
	key := regexp.MustCompile(`juist admins add bob (nid:\S+)`).FindStringSubmatch(bob.mustRun("admins", "new", "bob"))[1]
	alice.mustRun("create", "home", "--device", "a", "--admin-name", "alice", "--admin", "bob="+key)
	joinDaemon(t, alice, bob, "b", "--voucher")
	for i := range n {
		d := newDaemonDevice(t, nil)
		joinDaemon(t, alice, d, fmt.Sprintf("c%d", i), "--voucher")
		more = append(more, d)
	}
	mustContain(t, bob.mustRun("admins", "receive"), "changes waiting for bob reach key bob@home")
	eventually(t, "alice's device hears of bob's encryption key", func() bool {
		out, _ := alice.run("log")
		return strings.Contains(out, "encryption key of an admin key") ||
			strings.Contains(out, "set-admin-recipient")
	})
	alice.mustRun("admins", "quorum", "2", "--yes")
	eventually(t, "bob's device hears of the quorum", func() bool {
		out, _ := bob.run("admins")
		return strings.Contains(out, "Quorum        2 of 2 votes")
	})
	return alice, bob, more
}

// A change proposed on one admin device waits on the other, which says so,
// asks before signing, and applies it with the vote that completes the
// quorum.
func TestAChangeWaitsOnTheOtherAdminDevice(t *testing.T) {
	t.Parallel()
	alice, bob := twoAdmins(t)
	mustContain(t, alice.mustRun("network", "rename", "office"), "needs 1 more vote, from bob",
		"on an admin device or with the file", "juist approve\n")
	eventually(t, "the rename waits on bob's device", func() bool {
		out, _ := bob.run("health")
		return strings.Contains(out, "1 change waits for your vote: renames the network \"home\" to \"office\", "+
			"proposed by alice")
	})
	mustContain(t, bob.mustRun("status"), "hint: 1 change waits for your vote: juist approve")
	// Nothing is signed unasked: without a terminal, or answered no.
	if _, err := bob.run("approve"); err == nil || !strings.Contains(err.Error(), "needs an answer from a terminal") {
		t.Fatalf("approve without a terminal: %v", err)
	}
	if _, err := bob.run("approve", "--yes"); err == nil || !strings.Contains(err.Error(), "--yes and --no-apply take files") {
		t.Fatalf("approve --yes: %v", err)
	}
	out, err := bob.answer("n", "approve")
	if err != nil {
		t.Fatalf("approve, answered no: %v\n%s", err, out)
	}
	mustContain(t, out, "renaming of the network, proposed by alice", `renames the network "home" to "office"`,
		"not approved")
	out, err = bob.answer("y", "approve")
	if err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	mustContain(t, out, "signed as bob", "applied")
	eventually(t, "alice's device hears of the rename", func() bool {
		out, _ := alice.run("network")
		return strings.Contains(out, "office")
	})
	mustContain(t, bob.mustRun("approve"), "no change waits for your vote")
	if out := alice.mustRun("status"); strings.Contains(out, "waits for your vote") {
		t.Fatalf("the applied change still waits:\n%s", out)
	}
}

// An invite that waits for the other admin goes on once they approve on
// their own device, and a device without the admin role holds nothing of it.
func TestAnInviteGoesOnWithAVoteFromAnotherAdminDevice(t *testing.T) {
	t.Parallel()
	alice, bob := twoAdmins(t)
	inv := alice.start("invite", "--no-lan", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	guest := newDaemonDevice(t, nil)
	joined := guest.start("join", link, "--name", "phone")
	eventually(t, "the admission waits on bob's device", func() bool {
		out, _ := bob.run("health")
		return strings.Contains(out, `admits the device "phone"`)
	})
	out, err := bob.answer("y", "approve")
	if err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	mustContain(t, out, "device admission, proposed by alice", "applied")
	if out, err := joined.wait(t); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	mustContain(t, alice.mustRun("rotate", "group-secret"), "needs 1 more vote")
	eventually(t, "the rotation waits on bob's device", func() bool {
		out, _ := bob.run("status")
		return strings.Contains(out, "waits for your vote")
	})
	if st, err := guest.run("status"); err != nil || strings.Contains(st, "waits for your vote") {
		t.Fatalf("the phone's status: %v\n%s", err, st)
	}
	if n := daemonStatus(t, guest).Waiting; n != 0 {
		t.Fatalf("a device without the admin role holds %d waiting changes", n)
	}
}

// An admin key without an encryption key is hinted at, and then given one,
// once.
func TestAnAdminGivesItsEncryptionKeyOnce(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	alice, err := c.home2().createAdminKey("alice@home", false)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := log.Genesis("home", 1, []types.AdminKey{{Public: alice.Public(), Signing: new(alice.SigningKey()), Endorsement: alice.Endorsement(), Votes: 1, Holder: "alice"}},
		[]types.Hash{{1}}, nil, sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := genesis.Sign(alice); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Create(st, genesis); err != nil {
		t.Fatal(err)
	}
	mustContain(t, c.mustRun("admins"), "hint: for changes waiting for your vote to reach you: juist admins receive")
	mustContain(t, c.mustRun("admins", "receive"), "changes waiting for alice reach key alice@home")
	if k, _ := openLog(t, c).State().Admin(alice.Public()); k.Recipient == nil {
		t.Fatal("the admin key has no encryption key")
	}
	if out := c.mustRun("admins"); strings.Contains(out, "admins receive") {
		t.Fatalf("still hinted at:\n%s", out)
	}
	mustContain(t, c.mustRun("admins", "receive"), "unchanged")
}

// A change about an admin device reaches the other admin devices, and never
// that one.
func TestAChangeNeverReachesTheDeviceItIsAbout(t *testing.T) {
	t.Parallel()
	alice, bob, more := twoAdminsAnd(t, 1)
	mustContain(t, alice.mustRun("revoke", "b", "voucher"), "needs 1 more vote")
	eventually(t, "the change waits on the other admin device", func() bool {
		return daemonStatus(t, more[0]).Waiting == 1
	})
	// The push that reached the other device reaches this one as soon.
	for range 20 {
		if n := daemonStatus(t, bob).Waiting; n != 0 {
			t.Fatalf("the device the change is about holds %d copies of it", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// heldCopies decodes the copies a daemon device holds.
func heldCopies(t *testing.T, d *daemonDevice) []*waiting.Change {
	t.Helper()
	resp, err := ipc.Call(d.sock, ipc.Request{Command: ipc.CmdWaiting})
	if err != nil {
		t.Fatal(err)
	}
	var out []*waiting.Change
	for _, b := range resp.Waiting {
		c, err := waiting.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// An admission waits on the admin devices only a little longer than its
// invite runs, however long the invite was offered for.
func TestAnAdmissionWaitsNoLongerThanItsInvite(t *testing.T) {
	t.Parallel()
	alice, bob := twoAdmins(t)
	inv := alice.start("invite", "--no-lan", "--port", "0", "--yes", "--expires", "7d")
	link := inv.waitFor(t, linkRE)[1]
	guest := newDaemonDevice(t, nil)
	guest.start("join", link, "--name", "phone")
	eventually(t, "the admission waits on bob's device", func() bool { return len(heldCopies(t, bob)) == 1 })
	c := heldCopies(t, bob)[0]
	if left := time.Duration(c.Expires-c.Issued) * time.Second; left > admissionHold {
		t.Fatalf("the admission waits %v, beyond the %v it is renewed for", left, admissionHold)
	}
}

// threeAdmins is a network of alice's, bob's and carol's admin devices, each
// admin's keystore on their own, where every change needs all three.
func threeAdmins(t *testing.T) (alice, bob, carol *daemonDevice) {
	t.Helper()
	alice, bob, carol = newDaemonDevice(t, nil), newDaemonDevice(t, nil), newDaemonDevice(t, nil)
	keyOf := func(d *daemonDevice, name string) string {
		return regexp.MustCompile(`juist admins add \S+ (nid:\S+)`).FindStringSubmatch(d.mustRun("admins", "new", name))[1]
	}
	alice.mustRun("create", "home", "--device", "a", "--voucher", "--admin-name", "alice",
		"--admin", "bob="+keyOf(bob, "bob"), "--admin", "carol="+keyOf(carol, "carol"))
	joinDaemon(t, alice, bob, "b", "--voucher")
	joinDaemon(t, alice, carol, "c", "--voucher")
	bob.mustRun("admins", "receive")
	eventually(t, "carol's device hears of bob's key", func() bool {
		out, _ := carol.run("log")
		return strings.Count(out, "encryption key of an admin key") == 1
	})
	carol.mustRun("admins", "receive")
	eventually(t, "alice's device hears of both keys", func() bool {
		out, _ := alice.run("log")
		return strings.Count(out, "encryption key of an admin key") == 2
	})
	alice.mustRun("admins", "quorum", "3", "--yes")
	eventually(t, "the others hear of the quorum", func() bool {
		b, _ := bob.run("admins")
		c, _ := carol.run("admins")
		return strings.Contains(b, "Quorum        3 of 3") && strings.Contains(c, "Quorum        3 of 3")
	})
	return alice, bob, carol
}

// A second admin's approval of the file is carried too, so that the third
// needs to add only their own.
func TestApprovingTheFileCarriesTheSignature(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	alice, bob, carol := threeAdmins(t)
	alice.mustRun("network", "rename", "office")
	mustContain(t, bob.mustRun("approve", "--yes", filepath.Join(dir, "rename.rec")), "signed as bob", "needs 1 more vote")
	eventually(t, "bob's copy reaches carol", func() bool { return len(heldCopies(t, carol)) == 2 })
	out, err := carol.answer("y", "approve")
	if err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	mustContain(t, out, "signed as carol", "applied", "proposed by alice")
}

// While an invite runs, its admission gathers votes on the admin devices
// however short each copy's wait, and once it ends, approving its file
// hands nothing on.
func TestAnAdmissionGathersVotesWhileItsInviteRuns(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	alice, bob, carol := threeAdmins(t)
	// Long enough for a vote to reach alice under load before its copy lapses.
	alice.admissionHold = 30 * time.Second
	inv := alice.start("invite", "--no-lan", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	guest := newDaemonDevice(t, nil)
	joined := guest.start("join", link, "--name", "phone")
	eventually(t, "the admission waits on bob's device", func() bool { return len(heldCopies(t, bob)) == 1 })
	out, err := bob.answer("y", "approve")
	approved := time.Now()
	if err != nil {
		t.Fatalf("bob approves: %v\n%s", err, out)
	}
	mustContain(t, out, "needs 1 more vote")
	// Past bob's own copy's wait, which no copy he held outlasts by more
	// than a hold: what carol approves is alice's, renewed with bob's vote.
	time.Sleep(time.Until(approved.Add(alice.admissionHold + time.Second)))
	for _, c := range heldCopies(t, carol) {
		if c.Signer != c.Proposer {
			t.Fatalf("bob's copy outlived its wait: issued %d, expires %d, now %d", c.Issued, c.Expires,
				time.Now().Unix())
		}
	}
	// Alice's copy renewed with bob's vote may reach carol a round later.
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Second) {
		out, err = carol.answer("y", "approve")
		if err != nil {
			t.Fatalf("carol approves: %v\n%s", err, out)
		}
		if strings.Contains(out, "applied") || time.Now().After(deadline) {
			break
		}
	}
	mustContain(t, out, "device admission, proposed by alice", "applied")
	if out, err := joined.wait(t); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}

	// A second invite, ended before anyone approved.
	inv = alice.start("invite", "--no-lan", "--port", "0", "--yes")
	link = inv.waitFor(t, linkRE)[1]
	late := newDaemonDevice(t, nil)
	late.start("join", link, "--name", "tablet")
	eventually(t, "the second admission waits on bob's device", func() bool { return len(heldCopies(t, bob)) == 1 })
	record := filepath.Join(dir, "add-tablet.rec")
	if err := copyFile(record, record+".kept"); err != nil {
		t.Fatal(err)
	}
	inv.cancel()
	_, _ = inv.wait(t)
	eventuallyWithin(t, alice.admissionHold+20*time.Second, "the copies of the ended invite's admission lapse", func() bool {
		return len(heldCopies(t, bob)) == 0 && len(heldCopies(t, carol)) == 0
	})
	bob.mustRun("approve", "--yes", record+".kept")
	if n := len(heldCopies(t, bob)); n != 0 {
		t.Fatalf("approving an ended invite's admission from its file handed on %d copies", n)
	}
}

// A vote reaching the inviting device is handed on with its admission at
// once, not at the next renewal, by when the copy carrying it may have lapsed.
func TestAVoteReachingTheInviteIsHandedOnAtOnce(t *testing.T) {
	t.Parallel()
	alice, bob, carol := threeAdmins(t)
	alice.admissionHold = 2 * time.Minute
	inv := alice.start("invite", "--no-lan", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	guest := newDaemonDevice(t, nil)
	joined := guest.start("join", link, "--name", "phone")
	alices := func() *waiting.Change {
		for _, c := range heldCopies(t, carol) {
			if c.Signer == c.Proposer {
				return c
			}
		}
		return nil
	}
	eventually(t, "the admission waits on bob's and carol's devices", func() bool {
		return len(heldCopies(t, bob)) == 1 && alices() != nil
	})
	first := alices().Issued
	out, err := bob.answer("y", "approve")
	if err != nil {
		t.Fatalf("bob approves: %v\n%s", err, out)
	}
	mustContain(t, out, "needs 1 more vote")
	eventually(t, "alice's copy with bob's vote reaches carol", func() bool {
		c := alices()
		return c != nil && c.Issued > first
	})
	if out, err = carol.answer("y", "approve"); err != nil {
		t.Fatalf("carol approves: %v\n%s", err, out)
	}
	mustContain(t, out, "applied")
	if out, err := joined.wait(t); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
}

// renewalReader answers once the copies of an admission held when its admin
// was asked have lapsed and a renewed one has reached their device.
type renewalReader struct {
	t     *testing.T
	d     *daemonDevice
	asked bool
	reply *strings.Reader
}

func (r *renewalReader) Read(p []byte) (int, error) {
	if !r.asked {
		r.asked = true
		shown := time.Now().Unix()
		for _, c := range heldCopies(r.t, r.d) {
			shown = max(shown, c.Expires)
		}
		eventually(r.t, "the shown copy lapses and a renewed one arrives", func() bool {
			copies := heldCopies(r.t, r.d)
			return time.Now().Unix() > shown && len(copies) == 1 && copies[0].Expires > shown
		})
	}
	return r.reply.Read(p)
}

// An admission approved after the copy its admin was shown lapsed, while a
// renewed copy waits, is approved, with as long to go as the renewed copy.
func TestAnAdmissionRenewedWhileAskedIsApproved(t *testing.T) {
	t.Parallel()
	alice, bob := twoAdmins(t)
	alice.admissionHold = 6 * time.Second
	inv := alice.start("invite", "--no-lan", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	guest := newDaemonDevice(t, nil)
	joined := guest.start("join", link, "--name", "phone")
	// Between one copy's lapse and the next's arrival, nothing waits to be
	// asked about.
	eventually(t, "bob is asked about the admission", func() bool {
		var out syncBuffer
		a := bob.cli.app(&out, "y\n")
		a.in = &renewalReader{t: t, d: bob, reply: strings.NewReader("y\n")}
		err := a.main([]string{"--home", bob.home, "--socket", bob.sock, "approve"})
		if strings.Contains(out.String(), "no change waits for your vote") {
			return false
		}
		if err != nil || !strings.Contains(out.String(), "applied") {
			t.Fatalf("approve after a renewal: %v\n%s", err, out.String())
		}
		return true
	})
	if out, err := joined.wait(t); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
}

// A --key naming no key here says so, rather than that nothing waits.
func TestApproveWithAKeyThatIsNotHere(t *testing.T) {
	t.Parallel()
	alice, bob := twoAdmins(t)
	alice.mustRun("network", "rename", "office")
	eventually(t, "the rename waits on bob's device", func() bool { return len(heldCopies(t, bob)) == 1 })
	if _, err := bob.run("approve", "--key", "typo"); err == nil || !strings.Contains(err.Error(), `no admin key "typo"`) {
		t.Fatalf("approve --key typo: %v", err)
	}
}

// A clockReader advances the test's clock as it is read: an answer given
// after d.
type clockReader struct {
	t     *testing.T
	d     time.Duration
	reply *strings.Reader
}

func (r *clockReader) Read(p []byte) (int, error) {
	if r.d > 0 {
		advance(r.t, r.d)
		r.d = 0
	}
	return r.reply.Read(p)
}

// A change that expired while its admin was asked is not signed.
func TestAChangeThatExpiresWhileAskedIsNotSigned(t *testing.T) {
	t.Parallel()
	alice, bob := twoAdmins(t)
	alice.mustRun("network", "rename", "office")
	eventually(t, "the rename waits on bob's device", func() bool { return len(heldCopies(t, bob)) == 1 })
	var out syncBuffer
	a := bob.cli.app(&out, "y\n")
	a.in = &clockReader{t: t, d: waiting.MaxLifetime + time.Hour, reply: strings.NewReader("y\n")}
	err := a.main([]string{"--home", bob.home, "--socket", bob.sock, "approve"})
	if err != nil || !strings.Contains(out.String(), "expired while you were asked; not approved") {
		t.Fatalf("approve past the expiry: %v\n%s", err, out.String())
	}
	if len(heldCopies(t, bob)) != 1 {
		t.Fatal("a copy of the change was carried after it expired")
	}
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o644)
}

// M5c's exit criterion: after a move at once, every device that has applied
// it accepts the moved one at its new address only, the moved one holds that
// alone, and another device's transition runs on.
func TestAMoveAtOnceReachesEveryDevice(t *testing.T) {
	t.Parallel()
	alice, phone, tablet := newDaemonDevice(t, nil), newDaemonDevice(t, nil), newDaemonDevice(t, nil)
	alice.mustRun("create", "home", "--device", "laptop")
	joinDaemon(t, alice, phone, "phone")
	joinDaemon(t, alice, tablet, "tablet")
	alice.mustRun("network", "renumber", "tablet", "198.18.4.8", "--yes")
	mustContain(t, alice.mustRun("network", "renumber", "phone", "198.18.4.9", "--finish", "--yes"),
		"phone moved to 198.18.4.9; 198.18.4.2 retired")
	wgOf := func(d *daemonDevice) types.WGKey { return nodeKeysOf(t, &cli{t: t, home: d.state}).Public.WireGuard }
	host := netip.MustParsePrefix
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the phone's allowed IPs: alice %v, tablet %v; none where it is no peer",
				alice.mgr.allowed(wgOf(phone)), tablet.mgr.allowed(wgOf(phone)))
		}
	})
	for _, d := range []*daemonDevice{alice, tablet} {
		eventually(t, "the phone's peers accept it at its new address only", func() bool {
			got := d.mgr.allowed(wgOf(phone))
			return slices.Contains(got, host("198.18.4.9/32")) && !slices.Contains(got, host("198.18.4.2/32"))
		})
	}
	for _, d := range []*daemonDevice{alice, phone} {
		eventually(t, "the tablet's old address still works", func() bool {
			got := d.mgr.allowed(wgOf(tablet))
			return slices.Contains(got, host("198.18.4.3/32")) && slices.Contains(got, host("198.18.4.8/32"))
		})
	}
	eventually(t, "the phone holds its new address alone", func() bool {
		addrs := daemonStatus(t, phone).Addrs
		return slices.Contains(addrs, host("198.18.4.9/32")) && !slices.Contains(addrs, host("198.18.4.2/32"))
	})
}
