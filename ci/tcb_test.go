package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// tcb runs tcb.sh on a module of one package, a, placed by scope.
func tcb(t *testing.T, scope string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs go for the TCB script")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.org/m\n\ngo 1.22\n",
		"a/a.go":      "package a\n",
		"audit-scope": scope,
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("tcb.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, "go", "audit-scope", "100")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The public tree has no private/, which the audit scope still places.
func TestTCBPassesPrivateAbsentFromThePublicTree(t *testing.T) {
	if out, err := tcb(t, "core a\nout private/publish publishing tooling\n"); err != nil {
		t.Fatalf("tcb failed on a private/ entry the tree lacks: %v\n%s", err, out)
	}
}

func TestTCBRefusesAPackageThatIsGone(t *testing.T) {
	out, err := tcb(t, "core a\nout gone/pkg moved\n")
	if err == nil || !strings.Contains(out, "gone/pkg in audit-scope is no package of the module") {
		t.Fatalf("tcb passed a placed package that does not exist: %v\n%s", err, out)
	}
}
