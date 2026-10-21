package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
)

// systemd starts the terminator by juistd's file, from a fresh install on;
// an upgrade moves a terminator enabled the old way to it, and enables
// nothing else.
func TestTheTerminatorStartsByItsPath(t *testing.T) {
	b, err := os.ReadFile("systemd/juist-serve.path")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\nPathExists=" + ipc.TerminatorWanted + "\n", "\nUnit=juist-serve.service\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("juist-serve.path lacks %q", strings.TrimSpace(want))
		}
	}
	sb := newSandbox(t)
	sb.run("postinst", "configure")
	if calls := sb.calls(); !strings.Contains(calls, "systemctl enable --now juist-serve.path") {
		t.Fatalf("a fresh install left the terminator's path off:\n%s", calls)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); strings.Contains(calls, "juist-serve.path") {
		t.Fatalf("an upgrade enabled the terminator's path:\n%s", calls)
	}
	if err := os.WriteFile(filepath.Join(sb.root, "enabled"), []byte("juist-serve.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); !strings.Contains(calls, "systemctl disable --quiet juist-serve.service\n") ||
		!strings.Contains(calls, "systemctl enable --now juist-serve.path\n") {
		t.Fatalf("an upgrade left the terminator enabled the old way:\n%s", calls)
	}
}

// serve.sh starts the terminator and stops it.
func TestServeScriptStartsAndStops(t *testing.T) {
	sb := newSandbox(t)
	run := func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{"serve.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
	if calls, err := run("on"); err != nil || !strings.Contains(calls, "systemctl enable --now --quiet juist-serve.path") {
		t.Fatalf("on (%v):\n%s", err, calls)
	}
	if calls, err := run("off"); err != nil || !strings.Contains(calls, "systemctl disable --now juist-serve.path juist-serve.service") {
		t.Fatalf("off (%v):\n%s", err, calls)
	}
	if calls, err := run("open"); err == nil {
		t.Fatalf("an unknown action succeeded:\n%s", calls)
	}
}
