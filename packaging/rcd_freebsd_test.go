package packaging

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nning/juist/internal/plumber"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		if os.Getenv("JUIST_REQUIRE_OS_PLUMBING") != "" {
			t.Fatal("needs root, and JUIST_REQUIRE_OS_PLUMBING is set")
		}
		t.Skip("needs root")
	}
}

// The rc.d script runs an instance with its own home, socket and the options
// juistd_args gives, under daemon(8), and reports and stops it.
func TestTheRCScriptRunsAnInstance(t *testing.T) {
	requireRoot(t)
	home := "/var/db/juist/juist9"
	if _, err := os.Stat(home); err == nil {
		t.Skipf("%s is in use", home)
	}
	t.Cleanup(func() { os.Remove(home); os.Remove("/var/log/juistd.juist9.log") })
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "juistd")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"$@\" > "+argsFile+"\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rc := func(verb string) (string, error) {
		cmd := exec.Command("/bin/sh", "freebsd/juistd", verb, "juist9")
		cmd.Env = append(os.Environ(), "juistd_bin="+fake, "juistd_args=--verbose -f 72h")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := rc("onestart"); err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	t.Cleanup(func() { rc("onestop") })
	var args []byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if args, _ = os.ReadFile(argsFile); len(args) > 0 {
			break
		}
	}
	want := "--instance juist9 --home /var/db/juist/juist9 --socket /var/run/juist/juist9.sock --verbose -f 72h"
	if got := strings.TrimSpace(string(args)); got != want {
		t.Errorf("juistd got %q, want %q", got, want)
	}
	if out, err := rc("onestatus"); err != nil || !strings.Contains(out, "is running") {
		t.Errorf("status: %v\n%s", err, out)
	}
	if out, err := rc("onestop"); err != nil {
		t.Errorf("stop: %v\n%s", err, out)
	}
	if out, err := rc("onestatus"); err == nil {
		t.Errorf("stopped, the status says:\n%s", out)
	}
}

// leaveHost has the test binary serve and refuse egress on juist8, and exit.
const leaveHost = "JUIST_TEST_LEAVE_HOST"

func TestMain(m *testing.M) {
	if os.Getenv(leaveHost) != "" {
		if err := leave(); err != nil {
			println(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func leave() error {
	h := plumber.FreeBSD{}
	if _, _, err := h.OpenTUN("juist8", 1280); err != nil {
		return err
	}
	local := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if err := h.SetServe("juist8", plumber.ServeSpec{Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Local: local}); err != nil {
		return err
	}
	return h.SetEgress("juist8", plumber.EgressSpec{Mode: plumber.EgressRefused, Local: local,
		Capture: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/7")}}, 870)
}

func sysctl(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command("/sbin/sysctl", "-n", key).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func pfctl(args ...string) string {
	out, _ := exec.Command("/sbin/pfctl", args...).CombinedOutput()
	return string(out)
}

// "clear" takes away what a juistd that did not stop cleanly holds of the
// host, a refusing guard among it, and puts forwarding and pf back as found.
func TestTheRCScriptClearsWhatAJuistdLeft(t *testing.T) {
	requireRoot(t)
	if exec.Command("pgrep", "-q", "-x", "juistd").Run() == nil {
		t.Skip("a juistd runs")
	}
	if _, err := os.Stat("/var/run/juistd.host"); err == nil {
		t.Skip("/var/run/juistd.host is in use")
	}
	forwarding := sysctl(t, "net.inet.ip.forwarding")
	pfWas := strings.Contains(pfctl("-s", "info"), "Status: Enabled")
	// Set up by a process that exits without undoing it, as a juistd that
	// failed does.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), leaveHost+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setting up (%v):\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("/sbin/ifconfig", "juist8", "destroy").Run() })
	if sysctl(t, "net.inet.ip.forwarding") != "1" {
		t.Fatal("serving, the host does not forward")
	}
	out, err := exec.Command("/bin/sh", "freebsd/juistd", "clear").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "juistd: cleared" {
		t.Fatalf("clear (%v):\n%s", err, out)
	}
	if exec.Command("/sbin/ifconfig", "juist8").Run() == nil {
		t.Error("the device is left")
	}
	for _, a := range []string{"juist/juist8", "juist/juist8_egress"} {
		if rules := pfctl("-a", a, "-s", "rules"); strings.TrimSpace(rules) != "" {
			t.Errorf("%s holds:\n%s", a, rules)
		}
	}
	if got := sysctl(t, "net.inet.ip.forwarding"); got != forwarding {
		t.Errorf("forwarding is %s, was %s", got, forwarding)
	}
	if got := strings.Contains(pfctl("-s", "info"), "Status: Enabled"); got != pfWas {
		t.Errorf("pf enabled: %v, was %v", got, pfWas)
	}
	if _, err := os.Stat("/var/run/juistd.host"); err == nil {
		t.Error("the host's state is left")
	}
}

// An instance's home, in the juist user's directory, is not followed as root
// where that user made it a link: root's files stay root's.
func TestAnInstanceHomeFollowsNoLink(t *testing.T) {
	requireRoot(t)
	home := "/var/db/juist/juist7"
	if _, err := os.Lstat(home); err == nil {
		t.Skipf("%s is in use", home)
	}
	victim := t.TempDir()
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, home); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(home); os.Remove("/var/log/juistd.juist7.log") })
	fake := filepath.Join(t.TempDir(), "juistd")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rc := func(verb string) {
		cmd := exec.Command("/bin/sh", "freebsd/juistd", verb, "juist7")
		cmd.Env = append(os.Environ(), "juistd_bin="+fake)
		cmd.CombinedOutput()
	}
	rc("onestart")
	rc("onestop")
	var st syscall.Stat_t
	if err := syscall.Stat(victim, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 0 || st.Mode&0o777 == 0o700 {
		t.Errorf("the link's target became uid %d, mode %o", st.Uid, st.Mode&0o777)
	}
}

// "clear" leaves everything be while a daemon(8) of juistd's lives, which
// would start a juistd again on the host it cleared.
func TestClearWaitsForASupervisedJuistd(t *testing.T) {
	requireRoot(t)
	if exec.Command("pgrep", "-q", "-x", "juistd").Run() == nil {
		t.Skip("a juistd runs")
	}
	pidfile := "/var/run/juistd.juist6.pid"
	if _, err := os.Stat(pidfile); err == nil {
		t.Skipf("%s is in use", pidfile)
	}
	sup := exec.Command("sleep", "60")
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sup.Process.Kill(); sup.Wait(); os.Remove(pidfile) })
	if err := os.WriteFile(pidfile, []byte(strconv.Itoa(sup.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "freebsd/juistd", "clear").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "a juistd runs") {
		t.Errorf("cleared beside a supervised juistd (%v):\n%s", err, out)
	}
}
