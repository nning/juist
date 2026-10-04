//go:build linux

// Command ci runs every CI job, make ci and make interop, in a Fedora VM under
// KVM that it sets up on first use, so that no hosted runner is needed. Run
// it from the repository's root (make ci-vm); it logs to build/ci.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The VM's base disk, pinned by its sum, from Fedora's signed CHECKSUM file.
const (
	imageURL = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/" +
		"Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
	imageSum = "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
)

// provision is run once on a new VM, as ci with sudo: what make ci and make
// interop need. A change to it sets the VM up again.
const provision = `set -e
sudo dnf install -y -q git make tar gzip xz gcc rpm-build systemd-rpm-macros dpkg \
	iproute iputils iptables-nft nftables openssh-clients qemu-system-x86-core qemu-img
sudo usermod -aG kvm ci
`

// jobs is what a run does in the VM, in the tree it was given: make each of
// targets.
func jobs(targets []string) string {
	s := "set -e\nexport PATH=/usr/local/go/bin:$HOME/go/bin:$PATH\ncd ~/juist\n"
	for _, t := range targets {
		s += "make " + t + "\n"
	}
	return s
}

func main() {
	keep := flag.Bool("keep", false, "leave the VM running, for ssh -p PORT ci@127.0.0.1 with the cache's key")
	targets := flag.String("make", "ci interop", "the make targets to run, in order")
	flag.Parse()
	if err := run(*keep, strings.Fields(*targets)); err != nil {
		fmt.Fprintf(os.Stderr, "ci-vm: %v\n", err)
		os.Exit(1)
	}
}

func run(keep bool, targets []string) error {
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
		return errors.New("another make ci-vm runs on this host")
	}
	rev, err := revision()
	if err != nil {
		return err
	}
	logPath := filepath.Join("build", "ci", time.Now().UTC().Format("20060102-150405")+"-"+rev+".log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	out := io.MultiWriter(os.Stdout, logFile)
	say := func(format string, a ...any) { fmt.Fprintf(out, "ci-vm: "+format+"\n", a...) }

	start := time.Now()
	v, err := boot(cache, say)
	if err != nil {
		return err
	}
	if keep {
		say("the VM stays up: ssh -i %s -p %d ci@127.0.0.1", v.key, v.ssh)
	} else {
		defer v.stop()
	}
	if err := v.toolchain(say); err != nil {
		return err
	}
	say("copying the working tree at %s", rev)
	if err := v.sendTree(); err != nil {
		return err
	}
	err = v.run(jobs(targets), out)
	took := time.Since(start).Round(time.Second)
	if err != nil {
		say("failed after %v; log: %s", took, logPath)
		return errors.New("a job failed")
	}
	say("make %s passed at %s in %v; log: %s", strings.Join(targets, " "), rev, took, logPath)
	return nil
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

// boot starts the VM, setting it up first where its disk is new or was set
// up by another image or provisioning.
func boot(cache string, say func(string, ...any)) (*vm, error) {
	v := &vm{cache: cache, key: filepath.Join(cache, "id_ed25519")}
	if _, err := os.Stat(v.key); err != nil {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "juist-ci", "-f", v.key).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ssh-keygen: %v: %s", err, out)
		}
	}
	base := filepath.Join(cache, filepath.Base(imageURL))
	if err := fetchChecked(base, say); err != nil {
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
	if err := v.start(disk, seed, say); err != nil {
		return nil, err
	}
	if err := v.up(10 * time.Minute); err != nil {
		v.stop()
		return nil, err
	}
	if _, err := os.Stat(marker); err != nil {
		say("installing what the jobs need")
		if err := v.run("cloud-init status --wait >/dev/null || true\n"+provision, io.Discard); err != nil {
			v.stop()
			return nil, fmt.Errorf("setting the VM up: %w", err)
		}
		if err := os.WriteFile(marker, []byte(setup+"\n"), 0o600); err != nil {
			v.stop()
			return nil, err
		}
		// Joined to kvm only from the next login on.
		v.stop()
		return boot(cache, say)
	}
	return v, nil
}

// fetchChecked has the pinned image at path, fetched once and checked on
// every run.
func fetchChecked(path string, say func(string, ...any)) error {
	if _, err := os.Stat(path); err != nil {
		say("fetching %s", imageURL)
		resp, err := (&http.Client{Timeout: time.Hour}).Get(imageURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", imageURL, resp.Status)
		}
		f, err := os.Create(path + ".part")
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Rename(path+".part", path); err != nil {
			return err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != imageSum {
		os.Remove(path)
		return fmt.Errorf("%s: sum %s, want %s", path, got, imageSum)
	}
	return nil
}

// seedServer serves cloud-init's NoCloud seed on the host's loopback, which
// qemu's user network reaches as 10.0.2.2: the user ci, with pubkey and sudo.
func seedServer(pubkey string) (string, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	userData := "#cloud-config\nhostname: juist-ci\nssh_pwauth: false\nusers:\n  - name: ci\n" +
		"    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - " +
		strings.TrimSpace(pubkey) + "\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/meta-data", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "instance-id: juist-ci\nlocal-hostname: juist-ci\n")
	})
	mux.HandleFunc("/user-data", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, userData) })
	mux.HandleFunc("/vendor-data", func(http.ResponseWriter, *http.Request) {})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	port := l.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("http://10.0.2.2:%d/", port), func() { srv.Close() }, nil
}

// start boots qemu on disk, with KVM where /dev/kvm opens; JUIST_CI_CPUS and
// JUIST_CI_MEM, in MiB, size it.
func (v *vm) start(disk, seed string, say func(string, ...any)) error {
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
	cpus := envOr("JUIST_CI_CPUS", strconv.Itoa(runtime.NumCPU()))
	args := append([]string{"-machine", "q35", "-smp", cpus, "-m", envOr("JUIST_CI_MEM", "8192")}, accel...)
	args = append(args,
		"-drive", "file="+disk+",if=virtio",
		"-netdev", fmt.Sprintf("user,id=n0,hostfwd=tcp:127.0.0.1:%d-:22", v.ssh),
		"-device", "virtio-net-pci,netdev=n0",
		"-smbios", "type=1,serial=ds=nocloud-net;s="+seed,
		"-nographic", "-serial", "file:"+filepath.Join(v.cache, "console.log"),
		"-monitor", "none", "-display", "none")
	v.cmd = exec.Command(envOr("QEMU", "qemu-system-x86_64"), args...)
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

// up waits for the VM's ssh.
func (v *vm) up(timeout time.Duration) error {
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
		time.Sleep(3 * time.Second)
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

// remote is ssh running command on the VM as ci.
func (v *vm) remote(command string) *exec.Cmd {
	return exec.Command("ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
		"-i", v.key, "-p", strconv.Itoa(v.ssh), "ci@127.0.0.1", command)
}

// run runs script on the VM as ci, writing what it says to out.
func (v *vm) run(script string, out io.Writer) error {
	cmd := v.remote("bash -s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
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

// sendTree replaces ~/juist on the VM with the working tree: what git
// tracks or would, as it is now, and the repository.
func (v *vm) sendTree() error {
	for _, s := range treeSteps() {
		if err := v.pipe(s.src, s.script); err != nil {
			return err
		}
	}
	return nil
}

// A step is what src writes, which script takes on the VM.
type step struct {
	src    *exec.Cmd
	script string
}

// treeSteps send the working tree and its repository. A worktree's .git is a
// file naming a directory elsewhere, which would leave the copy no
// repository; HEAD's history goes as a bundle then.
func treeSteps() []step {
	if fi, err := os.Stat(".git"); err == nil && fi.IsDir() {
		return []step{{exec.Command("sh", "-c",
			"{ git ls-files -co --exclude-standard -z; find .git -print0; } | tar --null --ignore-failed-read -T - -cf -"),
			"rm -rf ~/juist && mkdir ~/juist && tar -C ~/juist -xf -"}}
	}
	return []step{
		{exec.Command("sh", "-c", "git ls-files -co --exclude-standard -z | tar --null --ignore-failed-read -T - -cf -"),
			"rm -rf ~/juist && mkdir ~/juist && tar -C ~/juist -xf -"},
		{exec.Command("git", "bundle", "create", "-", "HEAD"),
			"cd ~/juist && cat > .head.bundle && git init -q && git fetch -q .head.bundle HEAD && " +
				"git reset -q FETCH_HEAD && rm .head.bundle"},
	}
}

// pipe sends what src writes to script on the VM.
func (v *vm) pipe(src *exec.Cmd, script string) error {
	dst := v.remote(script)
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
		return fmt.Errorf("%s: %v: %s", script, err, dstErr.Bytes())
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
