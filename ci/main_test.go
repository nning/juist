//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A worktree's snapshot is a repository of its own, at its HEAD, with the
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

	t.Chdir(wt)
	copy := filepath.Join(dir, "snapshot")
	if err := snapshot(copy); err != nil {
		t.Fatal(err)
	}
	// The VM has no main repository for a worktree's .git to name.
	if err := os.Rename(main, main+".elsewhere"); err != nil {
		t.Fatal(err)
	}
	if got := git(copy, "rev-parse", "HEAD"); got != head {
		t.Errorf("the copy is at %q, the worktree at %q", got, head)
	}
	if got := git(copy, "status", "--porcelain"); got != "M a" {
		t.Errorf("the copy's changes: %q", got)
	}
}

func TestStagesArePickedInTheirOrder(t *testing.T) {
	for _, c := range []struct {
		only, from string
		want       []string
		fails      bool
	}{
		{want: stageOrder},
		{only: "lab,vm", want: []string{stageVM, stageLab}},
		{from: "lab", want: []string{stageLab, stageBuild}},
		{only: "lab,nope", fails: true},
		{from: "nope", fails: true},
		{only: "vm", from: "lab", fails: true},
	} {
		got, err := pickStages(c.only, c.from)
		if (err != nil) != c.fails || !slices.Equal(got, c.want) {
			t.Errorf("pickStages(%q, %q) = %v, %v", c.only, c.from, got, err)
		}
	}
}

// A run is a closing one only where it ran every stage and make check in
// the VM.
func TestOnlyAWholeRunCloses(t *testing.T) {
	for _, c := range []struct {
		o       options
		checkVM bool
		closing bool
	}{
		{options{stages: stageOrder}, true, true},
		{options{stages: stageOrder, fast: true}, false, false},
		{options{stages: stageOrder[1:]}, true, false},
		{options{stages: stageOrder, targets: []string{"ci"}}, true, false},
	} {
		r := &runner{o: c.o, checkVM: c.checkVM}
		if got := r.what() == "every stage"; got != c.closing {
			t.Errorf("%+v, make check in the VM %v: %q", c.o, c.checkVM, r.what())
		}
	}
}

// Beside the lab, the VM and the lab take whole cores of those this process
// may use, no core's threads serving both.
func TestTheVMAndTheLabShareNoCore(t *testing.T) {
	if _, err := exec.LookPath("taskset"); err != nil {
		t.Skip("no taskset here")
	}
	alone := func(c int) string { return strconv.Itoa(c) }
	for _, c := range []struct {
		name    string
		allowed []int
		coreOf  func(int) string
		count   string
		vm, lab []int
	}{
		{"four cores", []int{0, 1, 2, 3}, alone, "", []int{0, 1}, []int{2, 3}},
		{"a cpuset not from 0", []int{4, 5, 6, 7}, alone, "", []int{4, 5}, []int{6, 7}},
		{"siblings i and i+4", []int{0, 1, 2, 3, 4, 5, 6, 7}, func(c int) string { return strconv.Itoa(c % 4) }, "",
			[]int{0, 1, 4, 5}, []int{2, 3, 6, 7}},
		{"one for the lab", []int{0, 1, 2, 3}, alone, "1", []int{0, 1, 2}, []int{3}},
		{"none for the lab", []int{0, 1, 2, 3}, alone, "0", nil, nil},
		{"all for the lab", []int{0, 1, 2, 3}, alone, "4", nil, nil},
		{"one CPU", []int{0}, alone, "", nil, nil},
		{"no count", []int{0, 1, 2, 3}, alone, "x", nil, nil},
	} {
		vm, lab := cpuSplit(c.allowed, c.coreOf, c.count)
		if !slices.Equal(vm, c.vm) || !slices.Equal(lab, c.lab) {
			t.Errorf("%s: the VM on %v, the lab on %v; want %v and %v", c.name, vm, lab, c.vm, c.lab)
		}
	}
}

// A run its steps all stopped in, as an interrupt stops them, failed.
func TestAnInterruptedRunFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if err := outcome(ctx, errStopped, nil); err != nil {
		t.Errorf("a step stopped while the run goes on: %v", err)
	}
	cancel()
	if err := outcome(ctx, errStopped, errStopped); err == nil {
		t.Error("an interrupted run passed")
	}
	if err := outcome(ctx, errors.New("make vet: exit status 2"), errStopped); err == nil || !strings.Contains(err.Error(), "vet") {
		t.Errorf("the step that failed: %v", err)
	}
}

// A kept VM outlives this process; any other goes with it.
func TestOnlyAKeptVMOutlivesTheRun(t *testing.T) {
	if qemuAttr(true).Pdeathsig != 0 || !qemuAttr(true).Setpgid || qemuAttr(false).Pdeathsig == 0 {
		t.Errorf("kept %+v, not kept %+v", qemuAttr(true), qemuAttr(false))
	}
}

func TestMakeRefusesWhatItWouldIgnore(t *testing.T) {
	for _, f := range []string{"stages", "from", "fast", "lab"} {
		if alone(map[string]bool{"make": true, f: true}) == nil {
			t.Errorf("-make with -%s", f)
		}
	}
	if err := alone(map[string]bool{"make": true, "keep": true}); err != nil {
		t.Error(err)
	}
	if err := alone(map[string]bool{"fast": true, "stages": true}); err != nil {
		t.Error(err)
	}
}

// What the lab writes into its copy, its builds and git's index among it,
// leaves the snapshot the VM is sent as it was.
func TestTheLabWritesIntoACopyOfItsOwn(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.WriteFile(filepath.Join(src, "a"), []byte("a\n"), 0o644)
	t.Chdir(src)
	tree, lab := filepath.Join(dir, "tree"), filepath.Join(dir, "lab")
	if err := snapshots(tree, lab, true); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(lab, "build"), 0o755)
	os.WriteFile(filepath.Join(lab, ".git", "index"), []byte("changed"), 0o644)
	if _, err := os.Stat(filepath.Join(tree, "build")); err == nil {
		t.Error("the lab's build is in the snapshot")
	}
	if b, _ := os.ReadFile(filepath.Join(tree, ".git", "index")); string(b) == "changed" {
		t.Error("the lab's index is the snapshot's")
	}
}

// A file git is told to take as unchanged changes the tree's hash as any.
func TestTheTreesHashSeesFilesTakenAsUnchanged(t *testing.T) {
	dir := t.TempDir()
	tree, _ := filepath.Abs("tree.sh")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@t", "HOME="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	hash := func() string {
		t.Helper()
		cmd := exec.Command("sh", tree)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	os.WriteFile(filepath.Join(dir, "a"), []byte("a\n"), 0o644)
	git("add", "a")
	git("commit", "-q", "-m", "a")
	before := hash()
	git("update-index", "--assume-unchanged", "a")
	os.WriteFile(filepath.Join(dir, "a"), []byte("changed\n"), 0o644)
	if hash() == before {
		t.Error("a file taken as unchanged left the hash as it was")
	}
	if got := git("status", "--porcelain"); got != "" {
		t.Errorf("the hash changed the index: %q", got)
	}
}

// make check stamps a pass only with the steps and flags the Makefile gives.
func TestOnlyAWholeCheckIsStamped(t *testing.T) {
	asIs := func(env []string, args ...string) bool {
		t.Helper()
		cmd := exec.Command("make", append([]string{"-s", "--no-print-directory", "-C", "..", "print-CHECK_AS_IS"}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(string(out), "yes")
	}
	for _, k := range []string{"MAKEFLAGS", "CHECK_STEPS", "TEST_FLAGS", "GO", "GOFLAGS", "GOTOOLCHAIN", "CGO_ENABLED",
		"ACTIONLINT_VERSION", "CMDS", "TCB_BUDGET"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	if !asIs(nil) || !asIs(nil, "-k") {
		t.Error("make check as the Makefile gives it is not stamped")
	}
	for _, c := range []struct {
		env  []string
		args []string
	}{
		{args: []string{"CHECK_STEPS=vet"}},
		{args: []string{"TEST_FLAGS=-short"}},
		{env: []string{"GOFLAGS=-tags=x"}},
		{env: []string{"GOTOOLCHAIN=local"}},
		{args: []string{"-n"}},
		{args: []string{"-i"}},
		{args: []string{"-e"}},
		{args: []string{"TCB_BUDGET=999999"}},
		{args: []string{"CMDS="}},
		{env: []string{"GO=go"}},
	} {
		if asIs(c.env, c.args...) {
			t.Errorf("stamped with %v %v", c.env, c.args)
		}
	}
}

// make -n check runs no step, so stamps nothing.
func TestADryCheckStampsNothing(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("make", "-n", "-C", "..", "check", "BUILDDIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make -n check: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "check.stamp")); err == nil {
		t.Error("make -n check stamped the tree")
	}
}

// make check taken from the stamp still runs the host-network probes,
// whichever stages run, and under the race detector.
func TestAStampedCheckKeepsTheHostNetworkProbes(t *testing.T) {
	r := &runner{o: options{stages: []string{stageCheck}, fast: true, lab: "host"}}
	steps, err := r.steps(stageCheck)
	if err != nil || !slices.Equal(steps, []string{"test-host-net"}) {
		t.Errorf("make check from the stamp runs %v, %v", steps, err)
	}
	out, err := exec.Command("make", "-n", "-s", "--no-print-directory", "-C", "..", "test-host-net").Output()
	if err != nil || !strings.Contains(string(out), "-race") || !strings.Contains(string(out), "JUIST_REQUIRE_HOST_NET=1") {
		t.Errorf("make test-host-net runs %s, %v", out, err)
	}
}

// Two make check runs at once hash their trees into files of their own.
func TestEachCheckHashesItsOwnTree(t *testing.T) {
	tree := func() string {
		out, err := exec.Command("make", "-s", "--no-print-directory", "-C", "..", "print-CHECK_TREE").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	if a, b := tree(), tree(); a == b {
		t.Errorf("two runs share %s", a)
	}
}

// make ci-vm runs the runner so that a signal to make reaches it.
func TestMakeCIVMExecsTheRunner(t *testing.T) {
	out, err := exec.Command("make", "-n", "-s", "--no-print-directory", "-C", "..", "ci-vm").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "exec build/ci-runner") || strings.Contains(string(out), "go run") {
		t.Errorf("make ci-vm runs:\n%s", out)
	}
}

// The lab's group goes whole once its shell is told to go, as it is when
// this process dies: what runs under its jobs too.
func TestTheLabsGroupGoesWhole(t *testing.T) {
	pid := filepath.Join(t.TempDir(), "pid")
	cmd := group("sh", "-c", `sh -c 'echo $$ > `+pid+`; exec sleep 300' & wait`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var grandchild int
	for deadline := time.Now().Add(10 * time.Second); grandchild == 0; time.Sleep(50 * time.Millisecond) {
		if b, err := os.ReadFile(pid); err == nil && len(b) > 1 {
			grandchild, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		if time.Now().After(deadline) {
			t.Fatal("the job did not start")
		}
	}
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	for deadline := time.Now().Add(10 * time.Second); syscall.Kill(grandchild, 0) == nil; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			syscall.Kill(grandchild, syscall.SIGKILL)
			t.Fatal("what ran under the lab's job outlived its group")
		}
	}
	// Stopped by the signal, not crashed by its trap taking it again.
	if ws := cmd.ProcessState.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Errorf("the group's shell ended %v", cmd.ProcessState)
	}
}
