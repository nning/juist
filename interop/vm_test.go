//go:build interop && linux

package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// An image is a VM's base disk, pinned by its sum.
type image struct {
	url  string
	sum  string
	hash func() hash.Hash
}

var (
	freebsdImage = image{
		url:  "https://download.freebsd.org/releases/CI-IMAGES/14.5-RELEASE/amd64/Latest/FreeBSD-14.5-RELEASE-amd64-BASIC-CI-ufs.raw.xz",
		sum:  "d3797afea543f53faac72f0b35fdc5c00f7e898cc8058b828eca251885239917",
		hash: sha256.New,
	}
	debianImage = image{
		url:  "https://cloud.debian.org/images/cloud/bookworm/20260923-2610/debian-12-genericcloud-amd64-20260923-2610.qcow2",
		sum:  "3d94c9dd66d8a283fde060b8810373b7ae04038b956ee00d553d1ae564f6fbdeaa2fd6e7404e87e53348b5a9509170f3ea7c0731ba737590c5c4cb8d559a47f8",
		hash: sha512.New,
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

// base is img's disk as qcow2, from what the cache holds of it, fetched once
// and checked against its sum on every run: a raw image is converted into
// work each time, so that the cache holds nothing unchecked.
func base(t *testing.T, cache, work string, img image) string {
	t.Helper()
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(img.url)
	src := filepath.Join(cache, name)
	if _, err := os.Stat(src); err != nil {
		t.Logf("fetching %s", img.url)
		if err := fetch(img.url, src); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	h := img.hash()
	io.Copy(h, f)
	f.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != img.sum {
		os.Remove(src)
		t.Fatalf("%s: sum %s, want %s", name, got, img.sum)
	}
	if strings.HasSuffix(src, ".qcow2") {
		return src
	}
	raw := filepath.Join(work, strings.TrimSuffix(name, ".xz"))
	sh(t, "sh", "-c", `xz -dc -T0 "$1" > "$2"`, "xz", src, raw)
	defer os.Remove(raw)
	out := strings.TrimSuffix(raw, ".raw") + ".base.qcow2"
	sh(t, env("QEMU_IMG", "qemu-img"), "convert", "-f", "raw", "-O", "qcow2", raw, out)
	return out
}

func fetch(url, to string) error {
	resp, err := (&http.Client{Timeout: time.Hour}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	f, err := os.Create(to + ".part")
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
	return os.Rename(to+".part", to)
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func freePort(t *testing.T, network string) int {
	t.Helper()
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
	cmd     *exec.Cmd
	exited  chan struct{}
}

// boot starts v from the base image, its LAN a UDP socket on port mine that
// sends to peer's; seed, where set, is its cloud-init seed's URL.
func (v *vm) boot(t *testing.T, baseDisk string, mine, peer int, seed string) {
	t.Helper()
	disk := filepath.Join(v.dir, v.name+".qcow2")
	sh(t, env("QEMU_IMG", "qemu-img"), "create", "-q", "-f", "qcow2", "-b", baseDisk, "-F", "qcow2", disk, "20G")
	v.ssh = freePort(t, "tcp")
	accel := []string{"-accel", "tcg,thread=multi"}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		f.Close()
		accel = []string{"-accel", "kvm", "-cpu", "host"}
	}
	args := append([]string{"-machine", "q35", "-smp", "2", "-m", "2048"}, accel...)
	args = append(args,
		"-drive", "file="+disk+",if=virtio",
		"-netdev", fmt.Sprintf("user,id=n0,net=%s,hostfwd=tcp:127.0.0.1:%d-:22", v.net, v.ssh),
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
		t.Fatal(err)
	}
	v.cmd.Stdout, v.cmd.Stderr = log, log
	if err := v.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	v.exited = make(chan struct{})
	go func() { v.cmd.Wait(); close(v.exited) }()
	t.Cleanup(func() {
		v.cmd.Process.Kill()
		<-v.exited
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(v.dir, v.name+".console"))
			if len(b) > 3000 {
				b = b[len(b)-3000:]
			}
			t.Logf("%s's console, last:\n%s", v.name, b)
		}
	})
}

func (v *vm) sshArgs(script string) []string {
	return []string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
		"-i", v.key, "-p", strconv.Itoa(v.ssh), "root@127.0.0.1", script}
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
	out, err := v.try(script, 5*time.Minute)
	if err != nil {
		t.Fatalf("%s: %s: %v\n%s", v.name, script, err, out)
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
// after timeout with the last of it.
func (v *vm) eventually(t *testing.T, what string, timeout time.Duration, script string, ok func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		out, err := v.try(script, 2*time.Minute)
		if err == nil && ok(out) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s, not after %v: %s: %v\n%s", v.name, what, timeout, script, err, out)
		}
		time.Sleep(3 * time.Second)
	}
}

// up waits for v's ssh.
func (v *vm) up(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		out, err := v.try("true", 30*time.Second)
		if err == nil {
			return nil
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
		time.Sleep(5 * time.Second)
	}
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
// loopback, which qemu's user network reaches as its .2.
func seedServer(t *testing.T, hostname, pubkey string) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	userData := fmt.Sprintf("#cloud-config\nhostname: %s\ndisable_root: false\nssh_pwauth: false\n"+
		"users:\n  - name: root\n    ssh_authorized_keys:\n      - %s\n", hostname, strings.TrimSpace(pubkey))
	mux := http.NewServeMux()
	mux.HandleFunc("/meta-data", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "instance-id: %s\nlocal-hostname: %s\n", hostname, hostname)
	})
	mux.HandleFunc("/user-data", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, userData) })
	mux.HandleFunc("/vendor-data", func(w http.ResponseWriter, r *http.Request) {})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().(*net.TCPAddr).Port
}
