//go:build interop && linux

package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nning/juist/internal/testvm"
)

// An image is a VM's base disk, pinned by its sum, and what is installed on
// it once, before any run boots it.
type image struct {
	url   string
	sum   string
	hash  func() hash.Hash
	setup string
}

var (
	freebsdImage = image{
		url:  "https://download.freebsd.org/releases/CI-IMAGES/14.5-RELEASE/amd64/Latest/FreeBSD-14.5-RELEASE-amd64-BASIC-CI-ufs.raw.xz",
		sum:  "d3797afea543f53faac72f0b35fdc5c00f7e898cc8058b828eca251885239917",
		hash: sha256.New,
		setup: `set -e
cp /etc/resolv.conf /tmp/resolv.conf; [ -z "$DNS" ] || echo "nameserver $DNS" > /etc/resolv.conf
env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null
cp /tmp/resolv.conf /etc/resolv.conf
# The lab's LAN has no DHCP server for its NIC to wait a minute on at boot.
sysrc -q ifconfig_vtnet1=up >/dev/null
echo 'MaxSessions 64' >> /etc/ssh/sshd_config`,
	}
	debianImage = image{
		url:  "https://cloud.debian.org/images/cloud/bookworm/20260923-2610/debian-12-genericcloud-amd64-20260923-2610.qcow2",
		sum:  "3d94c9dd66d8a283fde060b8810373b7ae04038b956ee00d553d1ae564f6fbdeaa2fd6e7404e87e53348b5a9509170f3ea7c0731ba737590c5c4cb8d559a47f8",
		hash: sha512.New,
		// No timer of apt's takes dpkg's lock from a test's dpkg -i.
		setup: `set -e
cloud-init status --wait >/dev/null || true
systemctl disable -q --now apt-daily.timer apt-daily-upgrade.timer
if [ -n "$DNS" ]; then
	mv /etc/resolv.conf /tmp/resolv.conf; echo "nameserver $DNS" > /etc/resolv.conf
	trap 'rm -f /etc/resolv.conf; mv /tmp/resolv.conf /etc/resolv.conf' EXIT
fi
apt-get update -q >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -q tcpdump libndpi-bin >/dev/null
apt-get clean
echo 'MaxSessions 64' >> /etc/ssh/sshd_config`,
	}
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func need(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is not set; make interop sets it", key)
	}
	return v
}

// The lab's disks, set up once for every test of the run.
type disks struct {
	fb, lx string
	key    string // root's on lx
}

var (
	disksMu   sync.Mutex
	disksDone *disks
	disksErr  error
)

// labDisks is the provisioned disks in JUIST_INTEROP_CACHE, set up where they
// are not, and the key lx's lets root in by.
func labDisks(t *testing.T) disks {
	t.Helper()
	disksMu.Lock()
	defer disksMu.Unlock()
	if disksDone != nil {
		return *disksDone
	}
	if disksErr != nil {
		t.Fatalf("the disks: %v", disksErr)
	}
	cache := need(t, "JUIST_INTEROP_CACHE")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	// One lab at a time sets the cache up.
	lock, err := os.OpenFile(filepath.Join(cache, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	d := disks{key: filepath.Join(cache, "id_ed25519")}
	if _, err := os.Stat(d.key); err != nil {
		sh(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "juist-interop", "-f", d.key)
	}
	pub, err := os.ReadFile(d.key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, img := range []image{freebsdImage, debianImage} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var path string
			path, errs[i] = provisioned(cache, img, string(pub), t.Logf)
			if i == 0 {
				d.fb = path
			} else {
				d.lx = path
			}
		}()
	}
	wg.Wait()
	if disksErr = errors.Join(errs...); disksErr != nil {
		t.Fatal(disksErr)
	}
	t.Logf("lab: the disks checked in %v", time.Since(start).Round(100*time.Millisecond))
	if err := useDisks(cache, d); err != nil {
		t.Fatal(err)
	}
	disksDone = &d
	return d
}

// inUse is held shared by every lab of this host while it runs.
var inUse *os.File

// useDisks marks the cache's disks in use until this process ends, having
// first removed the set-ups d's replace where no other lab runs to boot them.
func useDisks(cache string, d disks) error {
	f, err := os.OpenFile(filepath.Join(cache, "in-use"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		for _, keep := range []string{d.fb, d.lx} {
			stem := keep[:strings.LastIndex(keep, "-")]
			old, _ := filepath.Glob(stem + "-*.qcow2*")
			for _, o := range old {
				if !strings.HasPrefix(o, keep) {
					os.Remove(o)
				}
			}
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		f.Close()
		return err
	}
	inUse = f
	return nil
}

// provisioned is img set up, in cache: the image fetched once, converted to
// qcow2 once where it is not, and set up once by its setup script, each
// derived disk kept beside a sum of its own that every run checks.
func provisioned(cache string, img image, pub string, logf func(string, ...any)) (string, error) {
	name := filepath.Base(img.url)
	stem := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".xz"), ".raw"), ".qcow2")
	key := sha256.Sum256([]byte(img.sum + "\n" + img.setup + "\n" + pub + "\n" + seedUserData))
	disk := filepath.Join(cache, fmt.Sprintf("%s-%x.qcow2", stem, key[:6]))
	src := filepath.Join(cache, name)
	if checked(disk) == nil {
		if base, err := backing(disk); err == nil {
			if base == src && testvm.Check(src, img.hash, img.sum) == nil || base != src && checked(base) == nil {
				return disk, nil
			}
		}
	}
	if _, err := os.Stat(src); err != nil {
		logf("fetching %s", img.url)
		if err := testvm.Fetch(context.Background(), img.url, src); err != nil {
			return "", err
		}
	}
	if err := testvm.Check(src, img.hash, img.sum); err != nil {
		os.Remove(src)
		return "", err
	}
	base := src
	if !strings.HasSuffix(name, ".qcow2") {
		base = filepath.Join(cache, stem+".qcow2")
		if checked(base) != nil {
			logf("converting %s", name)
			raw := filepath.Join(cache, stem+".raw")
			defer os.Remove(raw)
			if out, err := exec.Command("sh", "-c", `xz -dc -T0 "$1" > "$2"`, "xz", src, raw).CombinedOutput(); err != nil {
				return "", fmt.Errorf("xz: %v: %s", err, out)
			}
			if out, err := exec.Command(env("QEMU_IMG", "qemu-img"), "convert", "-f", "raw", "-O", "qcow2", raw, base+".part").CombinedOutput(); err != nil {
				return "", fmt.Errorf("qemu-img convert: %v: %s", err, out)
			}
			if err := keep(base); err != nil {
				return "", err
			}
		}
	}
	logf("setting up %s", filepath.Base(disk))
	if err := provision(cache, img, base, disk+".part", pub); err != nil {
		os.Remove(disk + ".part")
		return "", fmt.Errorf("setting up %s: %w", name, err)
	}
	if err := keep(disk); err != nil {
		return "", err
	}
	return disk, nil
}

// provision boots an overlay of base at disk, runs img's setup in it and
// powers it off.
func provision(cache string, img image, base, disk, pub string) error {
	if out, err := exec.Command(env("QEMU_IMG", "qemu-img"), "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", disk, "20G").CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img: %v: %s", err, out)
	}
	freebsd := img.url == freebsdImage.url
	dir, err := os.MkdirTemp("", "jlab")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	// On the user network the lab gives it, whose lease it then keeps.
	v := &vm{name: "setup", freebsd: freebsd, mac: "52:54:00:77:00:09", net: "10.0.3.0/24", dir: dir,
		key: filepath.Join(cache, "id_ed25519")}
	if freebsd {
		v.net = "10.0.4.0/24"
	}
	seed := ""
	if !freebsd {
		port, stop, err := serveSeed("lx", pub)
		if err != nil {
			return err
		}
		defer stop()
		seed = fmt.Sprintf("http://10.0.3.2:%d/", port)
	}
	ports := make([]int, 2)
	for i := range ports {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		ports[i] = c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
	}
	if err := v.start(disk, ports[0], ports[1], seed); err != nil {
		return err
	}
	defer func() {
		v.cmd.Process.Kill()
		<-v.exited
	}()
	if err := v.up(20 * time.Minute); err != nil {
		return err
	}
	// JUIST_INTEROP_DNS, where set, resolves in place of the host's resolver.
	if out, err := v.try("DNS="+os.Getenv("JUIST_INTEROP_DNS")+"\n"+img.setup+"\nsync", 30*time.Minute); err != nil {
		b, _ := os.ReadFile(filepath.Join(dir, v.name+".console"))
		return fmt.Errorf("%v\n%s\nconsole, last:\n%s", err, out, b[max(0, len(b)-3000):])
	}
	off := "systemctl poweroff"
	if freebsd {
		off = "shutdown -p now"
	}
	v.try(off, time.Minute)
	select {
	case <-v.exited:
		return nil
	case <-time.After(3 * time.Minute):
		return errors.New("not powered off after 3 minutes")
	}
}

// backing is the disk qcow2 at path is an overlay of.
func backing(path string) (string, error) {
	out, err := exec.Command(env("QEMU_IMG", "qemu-img"), "info", "--output=json", path).Output()
	if err != nil {
		return "", err
	}
	const k = `"backing-filename": "`
	i := bytes.Index(out, []byte(k))
	if i < 0 {
		return "", errors.New("no backing file")
	}
	rest := out[i+len(k):]
	return string(rest[:bytes.IndexByte(rest, '"')]), nil
}

// keep moves path.part to path, with the sum checked beside it.
func keep(path string) error {
	s, err := testvm.Sum(path+".part", sha256.New)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".sum", []byte(s+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(path+".part", path)
}

// checked fails unless the file at path holds the sum kept beside it.
func checked(path string) error {
	want, err := os.ReadFile(path + ".sum")
	if err != nil {
		return err
	}
	return testvm.Check(path, sha256.New, strings.TrimSpace(string(want)))
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// freePort is a port of 127.0.0.1 free by network, "tcp", "udp" or "both".
func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "both" {
		for range 100 {
			p := freePort(t, "tcp")
			if c, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
				c.Close()
				return p
			}
		}
		t.Fatal("no port free by TCP and UDP")
	}
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// A vm is one node of the lab: its disk an overlay on a base image, ssh
// forwarded from the host, and a second NIC on the lab's LAN.
type vm struct {
	name    string
	freebsd bool
	lanAddr string // on the lab's LAN, 10.77.0.0/24
	mac     string
	net     string // qemu's user network, distinct per VM
	dir     string
	key     string
	ssh     int
	mux     string // the ssh master's socket, where one runs
	https   int    // the host's port forwarded to 443, by TCP and UDP, where set
	tcpOnly int    // and one forwarded to 443 by TCP alone
	cmd     *exec.Cmd
	exited  chan struct{}
}

// httpsFwd forwards v.https on the host to v's 443, by TCP and UDP, and
// v.tcpOnly by TCP alone.
func (v *vm) httpsFwd() string {
	if v.https == 0 {
		return ""
	}
	return fmt.Sprintf(",hostfwd=tcp:127.0.0.1:%d-:443,hostfwd=udp:127.0.0.1:%d-:443,hostfwd=tcp:127.0.0.1:%d-:443",
		v.https, v.https, v.tcpOnly)
}

// boot starts v on an overlay of baseDisk, its LAN a UDP socket on port mine
// that sends to peer's; seed, where set, is its cloud-init seed's URL. It is
// gone with the test.
func (v *vm) boot(t *testing.T, baseDisk string, mine, peer int, seed string) {
	t.Helper()
	disk := filepath.Join(v.dir, v.name+".qcow2")
	sh(t, env("QEMU_IMG", "qemu-img"), "create", "-q", "-f", "qcow2", "-b", baseDisk, "-F", "qcow2", disk, "20G")
	if err := v.start(disk, mine, peer, seed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		v.cmd.Process.Kill()
		<-v.exited
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(v.dir, v.name+".console"))
			if len(b) > 3000 {
				b = b[len(b)-3000:]
			}
			t.Logf("%s's console, last:\n%s", v.name, b)
		}
	})
}

// start runs qemu on disk.
func (v *vm) start(disk string, mine, peer int, seed string) error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	v.ssh = l.Addr().(*net.TCPAddr).Port
	l.Close()
	accel := []string{"-accel", "tcg,thread=multi"}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		f.Close()
		accel = []string{"-accel", "kvm", "-cpu", "host"}
	}
	args := append([]string{"-machine", "q35", "-smp", "2", "-m", "2048"}, accel...)
	args = append(args,
		"-drive", "file="+disk+",if=virtio",
		"-netdev", fmt.Sprintf("user,id=n0,net=%s,hostfwd=tcp:127.0.0.1:%d-:22%s", v.net, v.ssh, v.httpsFwd()),
		"-device", "virtio-net-pci,netdev=n0",
		"-netdev", fmt.Sprintf("socket,id=n1,udp=127.0.0.1:%d,localaddr=127.0.0.1:%d", peer, mine),
		"-device", "virtio-net-pci,netdev=n1,mac="+v.mac,
		"-nographic", "-serial", "file:"+filepath.Join(v.dir, v.name+".console"),
		"-monitor", "none", "-display", "none")
	if seed != "" {
		args = append(args, "-smbios", "type=1,serial=ds=nocloud-net;s="+seed)
	}
	v.cmd = exec.Command(env("QEMU", "qemu-system-x86_64"), args...)
	// Gone with the test, even where a timeout ends it without cleanups.
	v.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	log, err := os.Create(filepath.Join(v.dir, v.name+".qemu.log"))
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

func (v *vm) sshArgs(script string) []string {
	args := []string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
		"-i", v.key, "-p", strconv.Itoa(v.ssh)}
	if v.mux != "" {
		// Where the master went, a command connects by itself.
		args = append(args, "-o", "ControlMaster=no", "-o", "ControlPath="+v.mux)
	}
	return append(args, "root@127.0.0.1", script)
}

// try runs script as root on v, and says what it wrote.
func (v *vm) try(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", v.sshArgs(script)...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		err = fmt.Errorf("timed out after %v", timeout)
	}
	return string(out), err
}

// run is [try], failing t.
func (v *vm) run(t *testing.T, script string) string {
	t.Helper()
	start := time.Now()
	out, err := v.try(script, 5*time.Minute)
	if err != nil {
		t.Fatalf("%s: %s: %v\n%s", v.name, script, err, out)
	}
	if took := time.Since(start); took >= 3*time.Second {
		waited(t.Name(), v.name+": running "+strings.ReplaceAll(script[:min(len(script), 60)], "\n", "; "), took)
	}
	return out
}

// put copies local to remote on v.
func (v *vm) put(t *testing.T, local, remote string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh", v.sshArgs(fmt.Sprintf("cat > %s && chmod %o %s", remote, mode, remote))...)
	cmd.Stdin = bytes.NewReader(b)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: copying %s: %v\n%s", v.name, local, err, out)
	}
}

// eventually runs script on v until ok takes what it wrote, or fails t
// after timeout with the last of it. A wait of seconds is logged, and
// counted in the run's longest.
func (v *vm) eventually(t *testing.T, what string, timeout time.Duration, script string, ok func(string) bool) string {
	t.Helper()
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		out, err := v.try(script, 2*time.Minute)
		if err == nil && ok(out) {
			if took := time.Since(start); took >= 5*time.Second {
				t.Logf("lab: %s: %s after %v", v.name, what, took.Round(100*time.Millisecond))
				waited(t.Name(), v.name+": "+what, took)
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s, not after %v: %s: %v\n%s", v.name, what, timeout, script, err, out)
		}
		time.Sleep(time.Second)
	}
}

// up waits for v's ssh.
func (v *vm) up(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		out, err := v.try("true", 30*time.Second)
		if err == nil {
			break
		}
		select {
		case <-v.exited:
			b, _ := os.ReadFile(filepath.Join(v.dir, v.name+".qemu.log"))
			return fmt.Errorf("%s: qemu exited:\n%s", v.name, b)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: no ssh after %v: %v %s", v.name, timeout, err, out)
		}
		time.Sleep(time.Second)
	}
	return nil
}

// multiplex has one ssh connection carry every command to v from here on,
// until the test ends.
func (v *vm) multiplex(t *testing.T) error {
	// A path short enough for a socket's; the master forks off, its output
	// to a file, which no command waits on.
	dir, err := os.MkdirTemp("", "jm")
	if err != nil {
		return err
	}
	mux := filepath.Join(dir, v.name)
	args := slices.Concat([]string{"-M", "-N", "-f", "-o", "ControlPersist=yes", "-o", "ControlPath=" + mux}, v.sshArgs("")[:len(v.sshArgs(""))-1])
	log, err := os.Create(filepath.Join(v.dir, v.name+".ssh.log"))
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command("ssh", args...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("%s: the ssh master: %v", v.name, err)
	}
	v.mux = mux
	t.Cleanup(func() {
		exec.Command("ssh", "-o", "ControlPath="+mux, "-O", "exit", "root@127.0.0.1").Run()
		os.RemoveAll(dir)
	})
	return nil
}

// both runs fn for each VM at once, and fails t with every error.
func both(t *testing.T, vms []*vm, fn func(*vm) error) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, len(vms))
	for i, v := range vms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fn(v)
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
}

// seedServer serves cloud-init's NoCloud seed to a Debian VM on the host's
// loopback, which qemu's user network reaches as its .2, for the test.
func seedServer(t *testing.T, hostname, pubkey string) int {
	t.Helper()
	port, stop, err := serveSeed(hostname, pubkey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return port
}

// seedUserData is cloud-init's user-data, a VM's hostname and root's pubkey
// to fill in; a disk set up by another is set up again.
const seedUserData = "#cloud-config\nhostname: %s\ndisable_root: false\nssh_pwauth: false\n" +
	"users:\n  - name: root\n    ssh_authorized_keys:\n      - %s\n"

// serveSeed serves the seed of a VM named hostname whose root pubkey lets in.
func serveSeed(hostname, pubkey string) (int, func(), error) {
	return testvm.ServeSeed(hostname, fmt.Sprintf(seedUserData, hostname, strings.TrimSpace(pubkey)))
}

// The run's waits of seconds, by test.
var (
	waitsMu sync.Mutex
	waits   = map[string][]wait{}
)

type wait struct {
	what string
	took time.Duration
}

func waited(test, what string, took time.Duration) {
	top := strings.SplitN(test, "/", 2)[0]
	waitsMu.Lock()
	defer waitsMu.Unlock()
	waits[top] = append(waits[top], wait{test[len(top):] + " " + what, took})
}

// logWaits logs t's longest waits and commands and their sum, which says
// where the lab's time goes.
func logWaits(t *testing.T) {
	waitsMu.Lock()
	w := slices.Clone(waits[t.Name()])
	waitsMu.Unlock()
	slices.SortFunc(w, func(a, b wait) int { return int(b.took - a.took) })
	var sum time.Duration
	var top []string
	for i, x := range w {
		sum += x.took
		if i < 25 {
			top = append(top, fmt.Sprintf("  %v%s", x.took.Round(100*time.Millisecond), x.what))
		}
	}
	t.Logf("lab: %d waits of seconds, %v in all; the longest:\n%s", len(w), sum.Round(time.Second), strings.Join(top, "\n"))
}
