package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/internal/plumber"
)

// asMain has the test binary run as juistd, as the split re-executes it.
const asMain = "JUISTD_TEST_AS_MAIN"

// garble has the daemon open a device, then send its helper a frame no
// helper takes, and destroy the device once told to stop; envDump has it
// write its environment.
const (
	garble  = "JUISTD_TEST_GARBLE"
	envDump = "JUISTD_TEST_ENV"
)

func garbled(pidfile string) {
	raw, _ := syscall.Dup(3)
	c, err := plumber.NewClient(os.NewFile(3, "helper"))
	if err != nil {
		os.Exit(2)
	}
	f, err := c.OpenTUN("juist5", 1280)
	if err != nil {
		os.Exit(3)
	}
	defer f.Close()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)
	os.WriteFile(pidfile, []byte(strconv.Itoa(os.Getpid())), 0o644)
	syscall.Write(raw, []byte{0xff, 0xff, 0xff, 0xff})
	<-stop
	c.Destroy("juist5")
}

func TestMain(m *testing.M) {
	if os.Getenv(asMain) != "" {
		if pidfile := os.Getenv(garble); pidfile != "" && os.Getenv(plumber.EnvFD) != "" {
			garbled(pidfile)
			return
		}
		if envfile := os.Getenv(envDump); envfile != "" && os.Getenv(plumber.EnvFD) != "" {
			sid, _ := unix.Getsid(0)
			os.WriteFile(envfile, []byte(strings.Join(os.Environ(), "\n")+fmt.Sprintf("\nSID=%d\n", sid)), 0o644)
			return
		}
		main()
		return
	}
	os.Exit(m.Run())
}

// start runs juistd as root, without a device.
func start(t *testing.T, env ...string) *exec.Cmd {
	t.Helper()
	if os.Getuid() != 0 {
		if os.Getenv("JUIST_REQUIRE_OS_PLUMBING") != "" {
			t.Fatal("needs root, and JUIST_REQUIRE_OS_PLUMBING is set")
		}
		t.Skip("needs root")
	}
	u, err := user.Lookup(runAs)
	if err != nil {
		t.Skipf("needs the %s user: %v", runAs, err)
	}
	home := t.TempDir()
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, d := range []string{filepath.Dir(home), home} {
		os.Chmod(d, 0o755)
	}
	if err := os.Chown(home, uid, gid); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "--home", home, "--socket", filepath.Join(home, "d.sock"), "--tun", "",
		"--no-dht", "--no-discovery", "--no-stun")
	cmd.Env = append(append(os.Environ(), asMain+"=1"), env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// started is [start]ed juistd with the daemon it split off.
func started(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	cmd := start(t)
	u, _ := user.Lookup(runAs)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("pgrep", "-P", strconv.Itoa(cmd.Process.Pid)).Output()
		if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			owner, _ := exec.Command("ps", "-o", "uid=", "-p", strconv.Itoa(pid)).Output()
			// Gone already is a daemon told to stop, as it may be at once.
			if got := strings.TrimSpace(string(owner)); got != "" && got != u.Uid {
				t.Fatalf("the daemon runs as uid %s, want %s", got, u.Uid)
			}
			return cmd, pid
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no daemon split off")
	return nil, 0
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// Started as root, juistd runs the daemon as juist; asked to stop, both do.
func TestRootSplitsOffTheDaemon(t *testing.T) {
	cmd, daemon := started(t)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("stopping: %v", err)
	}
	if alive(daemon) {
		t.Error("the daemon outlived juistd")
	}
}

// A helper that stops serving, as on a frame it cannot take, takes the
// daemon with it rather than leave it without plumbing.
func TestAHelperThatStopsServingStopsTheDaemon(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "daemon.pid")
	os.Chmod(filepath.Dir(pidfile), 0o777)
	cmd := start(t, garble+"="+pidfile)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("juistd exited cleanly")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("juistd went on after its helper stopped serving")
	}
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatalf("the daemon wrote no pid: %v", err)
	}
	if daemon, _ := strconv.Atoi(string(b)); daemon == 0 || alive(daemon) {
		t.Errorf("the daemon %q outlived its helper's serving", b)
	}
}

// The daemon does not outlive its helper, whose plumbing it would lack.
func TestTheDaemonGoesWithItsHelper(t *testing.T) {
	cmd, daemon := started(t)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	deadline := time.Now().Add(15 * time.Second)
	for alive(daemon) {
		if time.Now().After(deadline) {
			t.Fatal("the daemon outlived its helper")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Root gets help, which needs no --home.
func TestRootGetsHelp(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	cmd := exec.Command(os.Args[0], "--help")
	cmd.Env = append(os.Environ(), asMain+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Usage: juistd") {
		t.Errorf("help as root (%v):\n%s", err, out)
	}
}

// The daemon gets none of root's directories or credentials, only what it
// needs of the environment, and a session of its own, apart from root's
// terminal.
func TestTheDaemonGetsNoneOfRootsEnvironment(t *testing.T) {
	envfile := filepath.Join(t.TempDir(), "env")
	os.Chmod(filepath.Dir(envfile), 0o777)
	cmd := start(t, envDump+"="+envfile, "XDG_CONFIG_HOME=/root/.config", "SSH_AUTH_SOCK=/tmp/agent", "AWS_SECRET_ACCESS_KEY=x")
	cmd.Wait()
	b, err := os.ReadFile(envfile)
	if err != nil {
		t.Fatalf("the daemon wrote no environment: %v", err)
	}
	env := string(b)
	for _, gone := range []string{"XDG_", "SSH_AUTH_SOCK", "AWS_"} {
		if strings.Contains(env, gone) {
			t.Errorf("the daemon got %s:\n%s", gone, env)
		}
	}
	if !strings.Contains(env, "HOME=") || !strings.Contains(env, "PATH=") {
		t.Errorf("the daemon lacks HOME or PATH:\n%s", env)
	}
	own, _ := unix.Getsid(0)
	if strings.Contains(env, fmt.Sprintf("\nSID=%d\n", own)) {
		t.Errorf("the daemon shares root's session %d", own)
	}
}

// A juist user with root's uid or group is refused, which would keep root's
// rights in the daemon.
func TestAJuistUserOfRootsIsRefused(t *testing.T) {
	for _, u := range []user.User{{Username: "juist", Uid: "0", Gid: "829"}, {Username: "juist", Uid: "829", Gid: "0"}} {
		if _, err := credential(&u); err == nil {
			t.Errorf("uid %s gid %s taken", u.Uid, u.Gid)
		}
	}
}

// Started as root without --home, juistd says what to give rather than
// keep its state where no one looks.
func TestRootNeedsAHome(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	cmd := exec.Command(os.Args[0], "--tun", "")
	cmd.Env = append(os.Environ(), asMain+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "needs --home") {
		t.Errorf("without --home (%v):\n%s", err, out)
	}
}
