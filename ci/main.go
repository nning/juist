//go:build linux

// Command ci runs CI on a machine of our own, in stages, cheapest first, and
// stops at the first that fails. The VM's stages run in a Fedora VM under KVM
// that it sets up on first use; the lab, make interop, runs beside them on
// this host. Both test one snapshot of the working tree. Run it from the
// repository's root (make ci-vm); it logs to build/ci.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nning/juist/internal/testvm"
	"golang.org/x/sys/unix"
)

// The VM's base disk, pinned by its sum, from Fedora's signed CHECKSUM file.
const (
	imageURL = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/" +
		"Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
	imageSum = "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
)

// provision is run once on a new VM, as ci with sudo: what the stages need.
// A change to it sets the VM up again.
const provision = `set -e
sudo dnf install -y -q git make tar gzip xz gcc rpm-build systemd-rpm-macros dpkg \
	iproute iputils iptables-nft nftables openssh-clients qemu-system-x86-core qemu-img chromium iperf3
sudo usermod -aG kvm ci
`

// The stages, in the order they run.
const (
	stageVM    = "vm"    // what only the VM shows: the host-network probes and the privileged tests
	stageCheck = "check" // make check's steps
	stageLab   = "lab"   // make interop
	stageBuild = "build" // the cross builds, govulncheck and the packages
)

var stageOrder = []string{stageVM, stageCheck, stageLab, stageBuild}

// errStopped ends a step because another failed.
var errStopped = errors.New("stopped: another step failed")

type options struct {
	keep    bool
	targets []string // made in the VM instead of the stages
	stages  []string
	fast    bool   // take make check from this host's stamp
	lab     string // "host" or "vm"
}

func main() {
	keep := flag.Bool("keep", false, "leave the VM running, for ssh -p PORT ci@127.0.0.1 with the cache's key")
	targets := flag.String("make", "", "make these targets in the VM, in order, instead of the stages")
	only := flag.String("stages", "", "run these stages alone, comma-separated: "+strings.Join(stageOrder, ", "))
	from := flag.String("from", "", "begin at this stage, the ones before it having passed on this tree")
	fast := flag.Bool("fast", false, "take make check from this host's stamp where it names the tree")
	lab := flag.String("lab", "host", "where the lab runs: host, beside the VM, or vm, nested in it")
	flag.Parse()
	o := options{keep: *keep, targets: strings.Fields(*targets), fast: *fast, lab: *lab}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	err := alone(set)
	if err == nil {
		o.stages, err = pickStages(*only, *from)
	}
	if err == nil && o.lab != "host" && o.lab != "vm" {
		err = fmt.Errorf("-lab %s: host or vm", o.lab)
	}
	if err == nil {
		err = run(o)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ci-vm: %v\n", err)
		os.Exit(1)
	}
}

// alone refuses the flags that -make, given among set, would ignore.
func alone(set map[string]bool) error {
	if !set["make"] {
		return nil
	}
	for _, f := range []string{"stages", "from", "fast", "lab"} {
		if set[f] {
			return fmt.Errorf("-make runs its targets alone, without -%s", f)
		}
	}
	return nil
}

// pickStages is the stages to run, in order: only's, or every stage from
// from on.
func pickStages(only, from string) ([]string, error) {
	if only != "" && from != "" {
		return nil, errors.New("-stages and -from exclude each other")
	}
	if only != "" {
		names := strings.Split(only, ",")
		for _, s := range names {
			if !slices.Contains(stageOrder, s) {
				return nil, fmt.Errorf("no stage %q: %s", s, strings.Join(stageOrder, ", "))
			}
		}
		var picked []string
		for _, s := range stageOrder {
			if slices.Contains(names, s) {
				picked = append(picked, s)
			}
		}
		return picked, nil
	}
	if from == "" {
		return stageOrder, nil
	}
	i := slices.Index(stageOrder, from)
	if i < 0 {
		return nil, fmt.Errorf("no stage %q: %s", from, strings.Join(stageOrder, ", "))
	}
	return stageOrder[i:], nil
}

// A runner is one run: its snapshot, its log and its clock.
type runner struct {
	o       options
	cache   string
	tree    string // the snapshot the VM and the lab test
	labTree string // the lab's copy of it, which the lab's builds and git change
	rev     string
	logDir  string
	name    string // the run's log's, without .log
	out     io.Writer
	checkVM bool  // make check runs in the VM, not taken from the stamp
	vmCPUs  []int // the host's CPUs the VM runs on beside the lab, none for any
	labCPUs []int // and the lab

	mu    sync.Mutex
	times []string
}

func (r *runner) say(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.out, "ci-vm: "+format+"\n", a...)
}

// timed runs fn as the step what, saying how long it took.
func (r *runner) timed(what string, fn func() error) error {
	start := time.Now()
	err := fn()
	took := time.Since(start).Round(time.Second)
	if errors.Is(err, errStopped) {
		r.say("%s stopped after %v", what, took)
		return err
	}
	r.mu.Lock()
	r.times = append(r.times, fmt.Sprintf("%s %v", what, took))
	r.mu.Unlock()
	if err != nil {
		r.say("%s failed after %v (load %s)", what, took, load())
		return fmt.Errorf("%s: %w", what, err)
	}
	r.say("%s passed in %v (load %s)", what, took, load())
	return nil
}

// load is this host's load average over the last minute, which says where a
// step was slow for want of CPU.
func load() string {
	b, _ := os.ReadFile("/proc/loadavg")
	if f := strings.Fields(string(b)); len(f) > 0 {
		return f[0]
	}
	return "?"
}

func run(o options) error {
	cache, err := cacheDir()
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(cache, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fmt.Println("ci-vm: waiting for another make ci-vm on this host")
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
			return err
		}
	}
	rev, err := revision()
	if err != nil {
		return err
	}
	r := &runner{o: o, cache: cache, tree: filepath.Join(cache, "tree"), labTree: filepath.Join(cache, "lab-tree"),
		rev: rev, logDir: filepath.Join("build", "ci"),
		name: time.Now().UTC().Format("20060102-150405") + "-" + rev}
	if err := os.MkdirAll(r.logDir, 0o755); err != nil {
		return err
	}
	logPath := filepath.Join(r.logDir, r.name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	r.out = io.MultiWriter(os.Stdout, logFile)

	// An interrupt ends the run as a failed step would: the lab, in a process
	// group of its own, would go on without it. A second ends it at once.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() { <-ctx.Done(); stop() }()
	start := time.Now()
	err = r.run(ctx)
	took := time.Since(start).Round(time.Second)
	r.say("steps: %s", strings.Join(r.times, ", "))
	if err != nil {
		r.say("%v", err)
		r.say("failed after %v; log: %s", took, logPath)
		return errors.New("a step failed")
	}
	r.say("%s passed at %s in %v; log: %s", r.what(), rev, took, logPath)
	return nil
}

// what names what the run ran, for its last line: a closing run is every
// stage, make check in the VM.
func (r *runner) what() string {
	if len(r.o.targets) > 0 {
		return "make " + strings.Join(r.o.targets, " ")
	}
	if slices.Equal(r.o.stages, stageOrder) && r.checkVM {
		return "every stage"
	}
	s := "stages " + strings.Join(r.o.stages, " ")
	if slices.Contains(r.o.stages, stageCheck) && !r.checkVM {
		s += ", make check from this host's stamp"
	}
	return s + " (not a closing run)"
}

// hereAfterLab is the build stage's steps that run on this host after the
// lab, on its CPUs, where both run here.
func (r *runner) hereAfterLab() []string {
	if r.labHere() && slices.Contains(r.o.stages, stageBuild) {
		return []string{"cross", "govulncheck"}
	}
	return nil
}

// labHere reports whether the lab runs on this host, beside the VM.
func (r *runner) labHere() bool {
	return len(r.o.targets) == 0 && r.o.lab == "host" && slices.Contains(r.o.stages, stageLab)
}

func (r *runner) run(parent context.Context) error {
	if r.labHere() {
		r.vmCPUs, r.labCPUs = cpuSplit(allowedCPUs(), coreOf, envOr("JUIST_CI_LAB_CPUS", ""))
	}
	if err := r.timed("snapshot", func() error { return snapshots(r.tree, r.labTree, r.labHere()) }); err != nil {
		return err
	}
	r.checkVM = true
	if r.o.fast && slices.Contains(r.o.stages, stageCheck) {
		if why := r.unstamped(); why != "" {
			r.say("make check runs in the VM: %s", why)
		} else {
			r.say("make check passed on this tree here, says %s", stampFile)
			r.checkVM = false
		}
	}
	// The VM's steps, in order.
	var steps []string
	if len(r.o.targets) > 0 {
		steps = r.o.targets
	} else {
		for _, s := range r.o.stages {
			if s == stageLab && r.labHere() {
				continue
			}
			st, err := r.steps(s)
			if err != nil {
				return err
			}
			steps = append(steps, st...)
		}
	}

	// The lab, the longest stage, runs here from the start, beside the VM's;
	// the first step to fail ends the others.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wg sync.WaitGroup
	var labErr error
	if r.labHere() {
		if len(r.labCPUs) > 0 {
			r.say("the VM on CPUs %s, the lab on %s", cpuList(r.vmCPUs), cpuList(r.labCPUs))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			labErr = r.timed("lab: make interop-packages", func() error { return r.local(ctx, "interop-packages", "packages") })
			if labErr == nil {
				labErr = r.timed("lab: make interop-run", func() error {
					return r.local(ctx, "interop-run", "lab", "INTEROP_FLAGS=-failfast")
				})
			}
			// The lab's CPUs then take the builds that need no Fedora.
			for _, t := range r.hereAfterLab() {
				if labErr == nil {
					labErr = r.timed("here: make "+t, func() error { return r.local(ctx, t, t) })
				}
			}
			if labErr != nil {
				cancel()
			}
		}()
	}
	vmErr := r.inVM(ctx, steps)
	if vmErr != nil {
		cancel()
	}
	wg.Wait()
	return outcome(parent, vmErr, labErr)
}

// outcome is the run's error: its steps' failures, not the steps they
// stopped, or the interrupt that stopped them all.
func outcome(parent context.Context, errs ...error) error {
	var failed []error
	for _, err := range errs {
		if err != nil && !errors.Is(err, errStopped) {
			failed = append(failed, err)
		}
	}
	if len(failed) == 0 && parent.Err() != nil {
		return errors.New("interrupted")
	}
	return errors.Join(failed...)
}

// inVM boots the VM where there are steps for it and makes them.
func (r *runner) inVM(ctx context.Context, steps []string) error {
	if len(steps) == 0 {
		return nil
	}
	var v *vm
	err := r.timed("boot", func() error {
		var err error
		v, err = boot(ctx, r.cache, r.size(), r.say)
		return err
	})
	if err != nil {
		return err
	}
	if r.o.keep {
		r.say("the VM stays up: ssh -i %s -p %d ci@127.0.0.1", v.key, v.ssh)
	} else {
		defer v.stop()
	}
	if err := r.timed("toolchain", func() error { return v.toolchain(r.say) }); err != nil {
		return err
	}
	if err := r.timed("send", func() error { return v.sendTree(r.tree) }); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errStopped
	}
	return r.make(ctx, v, steps)
}

// A size is the VM's: its memory in MiB, its CPUs, the host's CPUs it runs
// on, none for any, and whether it outlives this process.
type size struct {
	mem, cpus string
	on        []int
	keep      bool
}

// size is the VM's: less memory where the lab runs here, needing none of it,
// and CPUs of its own, which the lab's VMs then do not share: a guest whose
// CPUs other guests take runs its race tests many times slower.
func (r *runner) size() size {
	if len(r.vmCPUs) == 0 {
		mem := "8192"
		if r.labHere() {
			mem = "6144"
		}
		return size{mem: envOr("JUIST_CI_MEM", mem), cpus: envOr("JUIST_CI_CPUS", strconv.Itoa(runtime.NumCPU())), keep: r.o.keep}
	}
	return size{mem: envOr("JUIST_CI_MEM", "6144"), cpus: envOr("JUIST_CI_CPUS", strconv.Itoa(len(r.vmCPUs))),
		on: r.vmCPUs, keep: r.o.keep}
}

// cpuSplit is which of allowed the VM and the lab each run on where the lab
// runs here, by whole cores, as coreOf groups them, so that no core's
// threads serve both: labCount of them the lab's, half by default. It sets
// nothing apart, returning none, where that leaves either none or there is
// no taskset.
func cpuSplit(allowed []int, coreOf func(int) string, labCount string) (vm, lab []int) {
	if _, err := exec.LookPath("taskset"); err != nil {
		return nil, nil
	}
	want := len(allowed) / 2
	if labCount != "" {
		n, err := strconv.Atoi(labCount)
		if err != nil {
			return nil, nil
		}
		want = n
	}
	var cores [][]int
	index := map[string]int{}
	for _, c := range slices.Sorted(slices.Values(allowed)) {
		k := coreOf(c)
		if i, ok := index[k]; ok {
			cores[i] = append(cores[i], c)
			continue
		}
		index[k] = len(cores)
		cores = append(cores, []int{c})
	}
	split := len(cores)
	for n := 0; split > 0 && n < want; split-- {
		n += len(cores[split-1])
	}
	if want < 1 || split < 1 || split == len(cores) {
		return nil, nil
	}
	vm, lab = slices.Concat(cores[:split]...), slices.Concat(cores[split:]...)
	slices.Sort(vm)
	slices.Sort(lab)
	return vm, lab
}

// allowedCPUs is the CPUs this process may run on.
func allowedCPUs() []int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil
	}
	var cpus []int
	for c := 0; c < len(set)*64 && len(cpus) < set.Count(); c++ {
		if set.IsSet(c) {
			cpus = append(cpus, c)
		}
	}
	return cpus
}

// coreOf names the core CPU c is a thread of, from sysfs, or c itself where
// that does not say.
func coreOf(c int) string {
	dir := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/topology/", c)
	pkg, err1 := os.ReadFile(dir + "physical_package_id")
	core, err2 := os.ReadFile(dir + "core_id")
	if err1 != nil || err2 != nil {
		return strconv.Itoa(c)
	}
	return strings.TrimSpace(string(pkg)) + "/" + strings.TrimSpace(string(core))
}

// cpuList is cpus as taskset takes them.
func cpuList(cpus []int) string {
	s := make([]string, len(cpus))
	for i, c := range cpus {
		s[i] = strconv.Itoa(c)
	}
	return strings.Join(s, ",")
}

// steps are stage's make targets, each a step, an environment before the
// target where it needs one.
func (r *runner) steps(stage string) ([]string, error) {
	switch stage {
	case stageVM:
		return []string{"ci-deps", "test-os-plumbing-sudo"}, nil
	case stageCheck:
		// Of make check taken from the stamp, what this host may have
		// skipped: the host-network probes, required.
		if !r.checkVM {
			return []string{"test-host-net"}, nil
		}
		out, err := exec.Command("make", "-s", "--no-print-directory", "-C", r.tree, "print-CHECK_STEPS").Output()
		if err != nil {
			return nil, fmt.Errorf("make print-CHECK_STEPS: %w", err)
		}
		var steps []string
		for _, s := range strings.Fields(string(out)) {
			steps = append(steps, "JUIST_REQUIRE_HOST_NET=1 "+s)
		}
		return steps, nil
	case stageLab:
		// One pair at a time in the VM's memory.
		return []string{"INTEROP_PAIRS=1 INTEROP_FLAGS=-failfast interop"}, nil
	case stageBuild:
		// The lab builds the .deb and the FreeBSD package where it runs.
		switch {
		case len(r.hereAfterLab()) > 0:
			return []string{"rpm"}, nil
		case slices.Contains(r.o.stages, stageLab):
			return []string{"cross", "govulncheck", "rpm"}, nil
		}
		return []string{"cross", "govulncheck", "rpm", "deb", "pkg-freebsd"}, nil
	}
	return nil, fmt.Errorf("no stage %q", stage)
}

// stampFile is where make check records the tree it passed on.
const stampFile = "build/check.stamp"

// unstamped says why this host's make check did not pass on the snapshot's
// tree, or "" where it did.
func (r *runner) unstamped() string {
	b, err := os.ReadFile(stampFile)
	if err != nil {
		return "no " + stampFile
	}
	tree, err := treeHash(r.tree)
	if err != nil {
		return err.Error()
	}
	if strings.TrimSpace(string(b)) != tree {
		return stampFile + " names another tree"
	}
	return ""
}

// treeHash is the tree in dir's, as ci/tree.sh prints it.
func treeHash(dir string) (string, error) {
	cmd := exec.Command("sh", "ci/tree.sh")
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ci/tree.sh: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// make makes each of targets in the VM, a step each.
func (r *runner) make(ctx context.Context, v *vm, targets []string) error {
	for _, t := range targets {
		env, target := "", t
		if i := strings.LastIndex(t, " "); i >= 0 {
			env, target = t[:i+1], t[i+1:]
		}
		script := "set -e\nexport PATH=/usr/local/go/bin:$HOME/go/bin:$PATH\ncd ~/juist\n" +
			env + "make --no-print-directory " + target + "\n"
		if err := r.timed("make "+target, func() error { return v.runCtx(ctx, script, r.out) }); err != nil {
			return err
		}
	}
	return nil
}

// local makes target with vars in the snapshot on this host, logging to a
// file of its own, whose last lines a failure shows.
func (r *runner) local(ctx context.Context, target, name string, vars ...string) error {
	logPath := filepath.Join(r.logDir, r.name+"-"+name+".log")
	f, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	r.say("lab: make %s here, logging to %s", target, logPath)
	args := append([]string{"make", "--no-print-directory", target}, vars...)
	if len(r.labCPUs) > 0 {
		args = append([]string{"taskset", "-c", cpuList(r.labCPUs)}, args...)
	}
	cmd := group(args...)
	cmd.Dir = r.labTree
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return errStopped
	}
	if err != nil {
		r.say("lab: the last of %s:\n%s", logPath, tail(logPath, 60))
	}
	return err
}

// group runs args in a process group of its own, which a failure elsewhere
// stops whole, and which goes whole with this process, however it ends:
// the shell it is under then stops the group.
func group(args ...string) *exec.Cmd {
	cmd := exec.Command("sh", append([]string{"-c", `trap 'trap - TERM HUP; kill 0' TERM HUP; "$@" & wait $!`, "sh"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	return cmd
}

// tail is the last n lines of the file at path.
func tail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

// cacheDir is where the base image, the VM's disk and its key are kept:
// $JUIST_CI_CACHE, or juist-ci in the user's cache directory.
func cacheDir() (string, error) {
	dir := os.Getenv("JUIST_CI_CACHE")
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "juist-ci")
	}
	return dir, os.MkdirAll(dir, 0o700)
}

// revision is HEAD's short hash, with -dirty where the tree differs from it.
func revision() (string, error) {
	b, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("not in the repository's root: %w", err)
	}
	rev := strings.TrimSpace(string(b))
	if st, _ := exec.Command("git", "status", "--porcelain").Output(); len(st) > 0 {
		rev += "-dirty"
	}
	return rev, nil
}

// A vm is the CI VM, booted from the cache's disk.
type vm struct {
	cache, key string
	ssh        int
	cmd        *exec.Cmd
	exited     chan struct{}
}

// boot starts the VM, sized sz, setting it up first where its disk is new or
// was set up by another image or provisioning.
func boot(ctx context.Context, cache string, sz size, say func(string, ...any)) (*vm, error) {
	v := &vm{cache: cache, key: filepath.Join(cache, "id_ed25519")}
	if _, err := os.Stat(v.key); err != nil {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "juist-ci", "-f", v.key).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ssh-keygen: %v: %s", err, out)
		}
	}
	base := filepath.Join(cache, filepath.Base(imageURL))
	if err := fetchChecked(ctx, base, say); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(imageSum + provision))
	setup := hex.EncodeToString(sum[:8])
	disk, marker := filepath.Join(cache, "vm.qcow2"), filepath.Join(cache, "provisioned")
	if b, err := os.ReadFile(marker); err != nil || strings.TrimSpace(string(b)) != setup {
		say("setting up a new VM from %s", filepath.Base(imageURL))
		os.Remove(disk)
		os.Remove(marker)
		if out, err := exec.Command(qemuImg(), "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", disk, "60G").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("qemu-img: %v: %s", err, out)
		}
	}
	pub, err := os.ReadFile(v.key + ".pub")
	if err != nil {
		return nil, err
	}
	seed, stopSeed, err := seedServer(string(pub))
	if err != nil {
		return nil, err
	}
	defer stopSeed()
	if err := v.start(disk, seed, sz, say); err != nil {
		return nil, err
	}
	if err := v.up(ctx, 10*time.Minute); err != nil {
		v.stop()
		return nil, err
	}
	if _, err := os.Stat(marker); err != nil {
		say("installing what the jobs need")
		if err := v.runCtx(ctx, "cloud-init status --wait >/dev/null || true\n"+provision, io.Discard); err != nil {
			v.stop()
			return nil, fmt.Errorf("setting the VM up: %w", err)
		}
		if err := os.WriteFile(marker, []byte(setup+"\n"), 0o600); err != nil {
			v.stop()
			return nil, err
		}
		// Joined to kvm only from the next login on.
		v.stop()
		return boot(ctx, cache, sz, say)
	}
	return v, nil
}

// fetchChecked has the pinned image at path, fetched once and checked on
// every run.
func fetchChecked(ctx context.Context, path string, say func(string, ...any)) error {
	if _, err := os.Stat(path); err != nil {
		say("fetching %s", imageURL)
		if err := testvm.Fetch(ctx, imageURL, path); err != nil {
			return err
		}
	}
	if err := testvm.Check(path, sha256.New, imageSum); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// seedServer serves cloud-init's NoCloud seed on the host's loopback, which
// qemu's user network reaches as 10.0.2.2: the user ci, with pubkey and sudo.
func seedServer(pubkey string) (string, func(), error) {
	userData := "#cloud-config\nhostname: juist-ci\nssh_pwauth: false\nusers:\n  - name: ci\n" +
		"    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - " +
		strings.TrimSpace(pubkey) + "\n"
	port, stop, err := testvm.ServeSeed("juist-ci", userData)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("http://10.0.2.2:%d/", port), stop, nil
}

// start boots qemu on disk, sized sz, with KVM where /dev/kvm opens.
func (v *vm) start(disk, seed string, sz size, say func(string, ...any)) error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	v.ssh = l.Addr().(*net.TCPAddr).Port
	l.Close()
	accel := []string{"-accel", "kvm", "-cpu", "host"}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		f.Close()
	} else {
		say("no KVM here (%v): emulating, which takes hours", err)
		accel = []string{"-accel", "tcg,thread=multi"}
	}
	args := append([]string{"-machine", "q35", "-smp", sz.cpus, "-m", sz.mem}, accel...)
	args = append(args,
		"-drive", "file="+disk+",if=virtio",
		"-netdev", fmt.Sprintf("user,id=n0,hostfwd=tcp:127.0.0.1:%d-:22", v.ssh),
		"-device", "virtio-net-pci,netdev=n0",
		"-smbios", "type=1,serial=ds=nocloud-net;s="+seed,
		"-nographic", "-serial", "file:"+filepath.Join(v.cache, "console.log"),
		"-monitor", "none", "-display", "none")
	v.cmd = exec.Command(envOr("QEMU", "qemu-system-x86_64"), args...)
	if len(sz.on) > 0 {
		v.cmd = exec.Command("taskset", append([]string{"-c", cpuList(sz.on), v.cmd.Path}, args...)...)
	}
	v.cmd.SysProcAttr = qemuAttr(sz.keep)
	log, err := os.Create(filepath.Join(v.cache, "qemu.log"))
	if err != nil {
		return err
	}
	v.cmd.Stdout, v.cmd.Stderr = log, log
	if err := v.cmd.Start(); err != nil {
		log.Close()
		return err
	}
	v.exited = make(chan struct{})
	go func() { v.cmd.Wait(); log.Close(); close(v.exited) }()
	return nil
}

// qemuAttr has qemu go with this process, however it ends, but where the VM
// is kept, which a terminal's interrupt then does not reach either.
func qemuAttr(keep bool) *syscall.SysProcAttr {
	if keep {
		return &syscall.SysProcAttr{Setpgid: true}
	}
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// up waits for the VM's ssh, or for ctx to end.
func (v *vm) up(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := v.run("true", io.Discard); err == nil {
			return nil
		}
		select {
		case <-v.exited:
			b, _ := os.ReadFile(filepath.Join(v.cache, "qemu.log"))
			return fmt.Errorf("qemu exited:\n%s", b)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no ssh after %v; see %s", timeout, filepath.Join(v.cache, "console.log"))
		}
		select {
		case <-ctx.Done():
			return errStopped
		case <-time.After(time.Second):
		}
	}
}

// stop powers the VM off, and kills it where it does not go within a minute.
func (v *vm) stop() {
	_ = v.run("sudo systemctl poweroff", io.Discard)
	select {
	case <-v.exited:
	case <-time.After(time.Minute):
		v.cmd.Process.Kill()
		<-v.exited
	}
}

// remote is ssh running command on the VM as ci, killed with ctx.
func (v *vm) remote(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
		"-i", v.key, "-p", strconv.Itoa(v.ssh), "ci@127.0.0.1", command)
}

// run runs script on the VM as ci, writing what it says to out.
func (v *vm) run(script string, out io.Writer) error {
	return v.runCtx(context.Background(), script, out)
}

// runCtx is run, ended with ctx.
func (v *vm) runCtx(ctx context.Context, script string, out io.Writer) error {
	cmd := v.remote(ctx, "bash -s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if ctx.Err() != nil {
		return errStopped
	}
	return err
}

// toolchain has the VM hold this host's Go, as /usr/local/go.
func (v *vm) toolchain(say func(string, ...any)) error {
	b, err := exec.Command("go", "env", "GOROOT", "GOVERSION").Output()
	if err != nil {
		return fmt.Errorf("go env: %w", err)
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return fmt.Errorf("go env said %q", b)
	}
	goroot, version := f[0], f[1]
	var have bytes.Buffer
	_ = v.run("head -1 /usr/local/go/VERSION 2>/dev/null", &have)
	if strings.TrimSpace(have.String()) == version {
		return nil
	}
	say("copying %s", version)
	return v.pipe(exec.Command("tar", "-C", goroot, "-cf", "-", "."),
		"sudo rm -rf /usr/local/go && sudo mkdir -p /usr/local/go && sudo tar -C /usr/local/go -xf -")
}

// sendTree replaces ~/juist on the VM with the snapshot in dir.
func (v *vm) sendTree(dir string) error {
	return v.pipe(exec.Command("tar", "-C", dir, "-cf", "-", "."),
		"rm -rf ~/juist && mkdir ~/juist && tar -C ~/juist -xf -")
}

// snapshot replaces dir with the working tree, what git tracks or would, as
// it is now, and the repository: what the VM and the lab test.
func snapshot(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, s := range treeSteps() {
		if err := pipe(s.src, exec.Command("sh", "-c", s.script, "sh", dir)); err != nil {
			return err
		}
	}
	return nil
}

// snapshots makes the snapshot in tree and, where lab is set, a copy of it
// in labTree, which the lab changes as the VM is sent tree.
func snapshots(tree, labTree string, lab bool) error {
	if err := snapshot(tree); err != nil || !lab {
		return err
	}
	if err := os.RemoveAll(labTree); err != nil {
		return err
	}
	if out, err := exec.Command("cp", "-a", tree, labTree).CombinedOutput(); err != nil {
		return fmt.Errorf("cp: %v: %s", err, out)
	}
	return nil
}

// A step is what src writes, which script takes, the directory it fills as
// its $1.
type step struct {
	src    *exec.Cmd
	script string
}

// treeSteps copy the working tree and its repository. A worktree's .git is a
// file naming a directory elsewhere, which would leave the copy no
// repository; HEAD's history goes as a bundle then.
func treeSteps() []step {
	if fi, err := os.Stat(".git"); err == nil && fi.IsDir() {
		return []step{{exec.Command("sh", "-c",
			"{ git ls-files -co --exclude-standard -z; find .git -print0; } | tar --null --no-recursion --ignore-failed-read -T - -cf -"),
			`mkdir -p "$1" && tar -C "$1" -xf -`}}
	}
	return []step{
		{exec.Command("sh", "-c", "git ls-files -co --exclude-standard -z | tar --null --no-recursion --ignore-failed-read -T - -cf -"),
			`mkdir -p "$1" && tar -C "$1" -xf -`},
		{exec.Command("git", "bundle", "create", "-", "HEAD"),
			`cd "$1" && cat > .head.bundle && git init -q && git fetch -q .head.bundle HEAD && ` +
				"git reset -q FETCH_HEAD && rm .head.bundle"},
	}
}

// pipe sends what src writes to script on the VM.
func (v *vm) pipe(src *exec.Cmd, script string) error {
	return pipe(src, v.remote(context.Background(), script))
}

// pipe runs dst on what src writes.
func pipe(src, dst *exec.Cmd) error {
	r, err := src.StdoutPipe()
	if err != nil {
		return err
	}
	var srcErr, dstErr bytes.Buffer
	src.Stderr, dst.Stdin, dst.Stderr = &srcErr, r, &dstErr
	if err := src.Start(); err != nil {
		return err
	}
	if err := dst.Run(); err != nil {
		src.Process.Kill()
		src.Wait()
		return fmt.Errorf("%s: %v: %s", strings.Join(dst.Args, " "), err, dstErr.Bytes())
	}
	if err := src.Wait(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(src.Args, " "), err, srcErr.Bytes())
	}
	return nil
}

func qemuImg() string { return envOr("QEMU_IMG", "qemu-img") }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
