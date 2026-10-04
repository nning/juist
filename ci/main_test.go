//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A worktree's copy is a repository of its own, at its HEAD, with the
// changes not committed still changes: the packages take their version and
// time from it.
func TestAWorktreeArrivesAsARepository(t *testing.T) {
	dir := t.TempDir()
	git := func(in string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = in
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@t", "HOME="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	main := filepath.Join(dir, "main")
	os.MkdirAll(main, 0o755)
	git(main, "init", "-q")
	os.WriteFile(filepath.Join(main, "a"), []byte("a\n"), 0o644)
	git(main, "add", "a")
	git(main, "commit", "-q", "-m", "a")
	wt := filepath.Join(dir, "wt")
	git(main, "worktree", "add", "-q", wt)
	os.WriteFile(filepath.Join(wt, "a"), []byte("changed\n"), 0o644)
	head := git(wt, "rev-parse", "HEAD")

	home := filepath.Join(dir, "vm")
	os.MkdirAll(home, 0o755)
	t.Chdir(wt)
	steps := treeSteps()
	sent := make([][]byte, len(steps))
	for i, s := range steps {
		var err error
		if sent[i], err = s.src.Output(); err != nil {
			t.Fatal(err)
		}
	}
	// The VM has no main repository for a worktree's .git to name.
	if err := os.Rename(main, main+".elsewhere"); err != nil {
		t.Fatal(err)
	}
	for i, s := range steps {
		dst := exec.Command("sh", "-c", s.script)
		dst.Env = append(os.Environ(), "HOME="+home)
		dst.Stdin = strings.NewReader(string(sent[i]))
		if out, err := dst.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", s.script, err, out)
		}
	}
	copy := filepath.Join(home, "juist")
	if got := git(copy, "rev-parse", "HEAD"); got != head {
		t.Errorf("the copy is at %q, the worktree at %q", got, head)
	}
	if got := git(copy, "status", "--porcelain"); got != "M a" {
		t.Errorf("the copy's changes: %q", got)
	}
}
