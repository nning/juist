package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A vouching threshold is set like the quorum, and bounded by the admin
// devices there are.
func TestAdminsVouchers(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--voucher")
	if _, err := c.run("admins", "vouchers", "2"); err == nil {
		t.Fatal("a threshold of two admin devices was set with one")
	}
	mustContain(t, c.mustRun("admins", "vouchers", "1"), "vouchers 1")
	mustContain(t, c.mustRun("admins"), "Vouchers      1 of 1")
	if openLog(t, c).State().Vouchers() != 1 {
		t.Fatal("the threshold did not apply")
	}
}

// Two laptops of one person: each gets its own admin key, and with the
// default quorum either approves a change alone.
func TestEitherOfTwoLaptopsApprovesAlone(t *testing.T) {
	t.Parallel()
	laptop1 := newCLI(t)
	laptop1.mustRun("create", "home", "--device", "laptop1")
	laptop2 := enrollDevice(t, laptop1, "laptop2")
	enrollDevice(t, laptop1, "phone")
	add := regexp.MustCompile(`juist admins add laptop2 (nid:\S+)`).FindStringSubmatch(
		laptop2.mustRun("admins", "new", "laptop2"))
	if add == nil {
		t.Fatal("admins new printed no command to run")
	}
	mustContain(t, laptop1.mustRun("admins", "add", "laptop2", add[1]), "added laptop2's key, 1 vote")
	// laptop2's device hears of the change as juistd would bring it.
	copyTree(t, filepath.Join(laptop1.home, logDir), filepath.Join(laptop2.home, logDir))
	mustContain(t, laptop2.mustRun("remove", "phone", "--yes"), "removed phone")
}

// Two people with two devices each, and changes needing two votes: one
// person approving on both their devices is still one vote.
func TestTwoPeopleWithTwoDevicesEach(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	alice := newCLI(t)
	alice.mustRun("create", "home", "--admin-name", "alice")
	alice2, a2 := adminKeyOf(t, "alice")
	bob1, b1 := adminKeyOf(t, "bob")
	_, b2 := adminKeyOf(t, "bob")
	mustContain(t, alice.mustRun("admins", "add", "alice", a2), "added a key of alice's; 2 keys")
	alice.mustRun("admins", "add", "bob", b1)
	mustContain(t, alice.mustRun("admins", "add", "bob", b2), "added a key of bob's; 2 keys")
	alice.mustRun("admins", "quorum", "2", "--yes")
	mustContain(t, alice.mustRun("admins"), "alice", "1 of 2 keys", "bob", "2 of 2 votes")

	change := filepath.Join(dir, "rotate-group-secret.rec")
	mustContain(t, alice.mustRun("rotate", "group-secret"), "needs 1 more vote")
	// alice's other device adds her key, and her vote is still the one.
	mustContain(t, alice2.mustRun("approve", "--yes", change), "signed as")
	if _, err := alice.run("approve", change); err == nil || !strings.Contains(err.Error(), "needs 1 more vote, from bob") {
		t.Fatalf("alice alone, on both her devices: %v", err)
	}
	bob1.mustRun("approve", "--yes", change)
	mustContain(t, alice.mustRun("approve", change), "applied")
}

// One person running a network alone can require two of their devices for
// every change.
func TestOnePersonCanRequireTwoDevices(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	laptop := newCLI(t)
	laptop.mustRun("create", "home", "--admin-name", "alice")
	desktop, d := adminKeyOf(t, "alice")
	_, p := adminKeyOf(t, "alice")
	laptop.mustRun("admins", "add", "alice", d)
	laptop.mustRun("admins", "add", "alice", p)
	if _, err := laptop.run("admins", "require", "alice", "4"); err == nil || !strings.Contains(err.Error(), "holds only 3 keys") {
		t.Fatalf("requiring more keys than alice holds: %v", err)
	}
	laptop.mustRun("admins", "require", "alice", "2")
	mustContain(t, laptop.mustRun("admins"), "2 of 3 keys")

	change := filepath.Join(dir, "rotate-group-secret.rec")
	mustContain(t, laptop.mustRun("rotate", "group-secret"), "needs 1 more vote, from 1 more of alice's keys (1 of 2 signed)")
	desktop.mustRun("approve", "--yes", change)
	mustContain(t, laptop.mustRun("approve", change), "applied")
}

// Requiring every key a person holds is warned about: one lost device then
// leaves only the break-glass secrets.
func TestRequiringEveryKeyIsWarnedAbout(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--admin-name", "alice")
	_, k := adminKeyOf(t, "alice")
	c.mustRun("admins", "add", "alice", k)
	if _, err := c.run("admins", "require", "alice", "2"); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("needing every key alice holds went unasked: %v", err)
	}
	mustContain(t, c.mustRun("admins", "require", "alice", "2", "--yes"), "losing one device",
		"locks the network")
}

// A lost device's key is removed, and the person keeps their vote with the
// keys they still hold; one that needs more keys than it would keep is told
// what to lower first, never the quorum.
func TestALostDevicesKeyIsRemoved(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--admin-name", "alice")
	_, lost := adminKeyOf(t, "alice")
	_, kept := adminKeyOf(t, "alice")
	c.mustRun("admins", "add", "alice", lost)
	c.mustRun("admins", "add", "alice", kept)
	c.mustRun("admins", "require", "alice", "3", "--yes")
	_, err := c.run("admins", "remove", lost)
	if err == nil || !strings.Contains(err.Error(), "juist admins require alice 2") {
		t.Fatalf("removing a key alice needs: %v", err)
	}
}

func TestAPersonKeepsTheirVoteWhenOneKeyGoes(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--admin-name", "alice")
	_, lost := adminKeyOf(t, "alice")
	c.mustRun("admins", "add", "alice", lost)
	mustContain(t, c.mustRun("admins", "remove", lost), "removed a key of alice's; 1 key left")
	if openLog(t, c).State().TotalVotes() != 1 {
		t.Fatal("alice lost her vote with one of her keys")
	}
}

// Every admin key names the machine it is kept on: the one it is created on
// by default, or what the person adding it says.
func TestAdminKeysNameTheirMachine(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	other := newCLI(t)
	add := regexp.MustCompile(`juist admins add alice (nid:\S+) --on nas`).FindStringSubmatch(
		other.mustRun("admins", "new", "alice", "--on", "nas"))
	if add == nil {
		t.Fatal("admins new printed no command naming the machine")
	}
	if _, err := c.run("admins", "add", "alice", add[1], "--on", "no such"); err == nil {
		t.Error("a machine name with a space was accepted")
	}
	c.mustRun("admins", "add", "alice", add[1], "--on", "nas")
	out := c.mustRun("admins")
	mustContain(t, out, "ON", "laptop", "nas")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "laptop") != strings.Contains(line, "(here)") {
			t.Errorf("the key on this machine is not listed as laptop's:\n%s", out)
		}
	}
	for _, k := range openLog(t, c).State().Admins() {
		if k.Holder != "alice" {
			t.Errorf("key %v belongs to %q, want alice", k.Public.ShortString(), k.Holder)
		}
	}
	// A key added without --on names no machine it cannot know.
	_, key := adminKeyOf(t, "bob")
	c.mustRun("admins", "add", "bob", key)
	if !regexp.MustCompile(`bob\s+1\s+its key\s+-\s+nid:`).MatchString(c.mustRun("admins")) {
		t.Errorf("bob's key names a machine:\n%s", c.mustRun("admins"))
	}

	// Where a change waits for a key, it says which machine holds it.
	c.mustRun("admins", "require", "alice", "2", "--yes")
	mustContain(t, c.mustRun("rotate", "group-secret"), "1 more of alice's keys on nas (1 of 2 signed)")
}
