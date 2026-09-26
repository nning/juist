package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/statedir"
)

// juistd does not run next to admin keys: it is the side attackers reach.
func TestTheDaemonRefusesAKeystore(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	_, err := daemon.NewService(daemon.ServiceOptions{Home: c.home})
	if err == nil || !strings.Contains(err.Error(), "holds admin keys") {
		t.Fatalf("a daemon over a keystore: %v", err)
	}
}

// TestUnreadableKeysAreReportedNotIgnored: a key file that is there but will
// not load is an error everywhere, never "this device has no keys".
func TestUnreadableKeysAreReportedNotIgnored(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	path := filepath.Join(c.home, nodeKeysFile)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"rotate"}, {"devices"}, {"status"}} {
		if _, err := c.run(args...); err == nil || !strings.Contains(err.Error(), "mode 644") {
			t.Errorf("juist %s: got %v, want the mode named", strings.Join(args, " "), err)
		}
	}
	mustContain(t, c.mustRun("log", "verify"), "mode 644")
}

func TestUnreadableStagedKeysAreReportedOnApply(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	admin := newCLI(t)
	admin.mustRun("init", "home")
	phone := enrollDevice(t, admin, "phone")
	phone.mustRun("rotate")
	pending := filepath.Join(dir, "rotate-phone.rec")
	admin.mustRun("approve", "--yes", pending)
	if err := os.Chmod(filepath.Join(phone.home, nodeKeysFile+stagedSuffix), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := phone.run("apply", pending); err == nil || !strings.Contains(err.Error(), "mode 644") {
		t.Fatalf("apply got %v, want the staged file's mode named", err)
	}
}

// TestHomeIsOwnerOnly: the home holds admin keys and break-glass secrets.
func TestHomeIsOwnerOnly(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	err := filepath.WalkDir(c.home, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if e.IsDir() || strings.HasSuffix(path, ".key") || strings.HasSuffix(path, ".keys") ||
			strings.HasSuffix(path, ".secrets") {
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s is mode %o", path, info.Mode().Perm())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSharedWritableHomeRefused(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	if err := os.Chmod(c.home, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := c.run("devices"); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("a world-writable home got %v", err)
	}
	os.Chmod(c.home, 0o700)
	c.mustRun("devices")
}

func TestAWritableAdminsDirIsRefused(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	admins := filepath.Join(c.home, adminsDir)
	if err := os.Chmod(admins, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(admins, 0o700) })
	if _, err := c.run("log", "verify"); err == nil || !strings.Contains(err.Error(), adminsDir) {
		t.Fatalf("a group-writable admins directory got %v", err)
	}
}

// A running daemon's state directory is its own: --home pointing there does
// not open it as a local device, and no key of the person's is written there.
func TestTheDaemonsStateDirectoryIsNotAKeystore(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("init", "home", "--device", "laptop")
	var out syncBuffer
	a := (&cli{t: t, home: d.state}).app(&out, "")
	if err := a.main([]string{"--home", d.state, "status"}); err == nil &&
		strings.Contains(out.String(), "juistd is not running") {
		t.Fatalf("the daemon's state directory was opened as a local device:\n%s", out.String())
	}
	out = syncBuffer{}
	_ = (&cli{t: t, home: d.state}).app(&out, "").main([]string{"--home", d.state, "admins", "new", "oops"})
	if _, err := os.Stat(filepath.Join(d.state, adminsDir, "oops.key")); err == nil {
		t.Fatal("an admin key was written into the daemon's state directory")
	}
}

// A reset forgets the network and the device's keys and keeps the admin keys,
// which are the person's. A member is reset only with --force.
func TestResetStartsOverAndKeepsAdminKeys(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	before := c.mustRun("devices", "--keys")
	if _, err := c.run("reset", "--yes"); err == nil || !strings.Contains(err.Error(), "still a member") {
		t.Fatalf("a member was reset without --force: %v", err)
	}
	out := c.mustRun("reset", "--yes", "--force")
	mustContain(t, out, "reset", "admin keys kept")
	if _, err := os.Stat(filepath.Join(c.home, logDir)); !os.IsNotExist(err) {
		t.Errorf("the log survived the reset (%v)", err)
	}
	if entries, err := os.ReadDir(filepath.Join(c.home, keys.AdminsDir)); err != nil || len(entries) == 0 {
		t.Errorf("the admin keys went with the reset (%v)", err)
	}
	if _, err := c.run("devices"); err == nil {
		t.Error("a reset device still lists devices")
	}
	c.mustRun("init", "again")
	if after := c.mustRun("devices", "--keys"); after == before {
		t.Error("the device kept its keys through the reset")
	}
}

// A reset of a home a stopped daemon ran from leaves none of the daemon's
// state: the old operator and the old network's group secrets go too.
func TestAResetClearsAStoppedDaemonsState(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	for _, name := range statedir.StateFiles {
		if err := os.WriteFile(filepath.Join(c.home, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.mustRun("reset", "--yes", "--force")
	for _, name := range statedir.StateFiles {
		if _, err := os.Stat(filepath.Join(c.home, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived the reset (%v)", name, err)
		}
	}
}
