//go:build interop && linux

package interop

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// TestDemo records the README's demo, a laptop on Debian and a NAS on
// FreeBSD forming a network, as an asciinema cast at JUIST_DEMO_CAST; make
// demo runs it. Every command runs for real; only pauses longer than a
// second are shortened.
func TestDemo(t *testing.T) {
	cast := os.Getenv("JUIST_DEMO_CAST")
	if cast == "" {
		t.Skip("JUIST_DEMO_CAST is not set; make demo sets it")
	}
	nas, laptop := labPair(t, "nas", "laptop")

	r := newRecorder(80, 26, "laptop · Debian 12", "nas · FreeBSD 14")
	left, right := r.panes[0], r.panes[1]
	time.Sleep(time.Second)
	r.run(t, laptop, left, "juist create home", nil)

	same := make(chan string, 1)
	invited := make(chan error, 1)
	codeRE := regexp.MustCompile(`juist join (\d+(?:-[a-z]+){3})`)
	code := make(chan string, 1)
	go func() {
		invited <- r.runE(laptop, left, "juist invite", func(out string, answer io.Writer) {
			if m := codeRE.FindStringSubmatch(stripANSI(out)); m != nil {
				select {
				case code <- m[1]:
				default:
				}
			}
			if strings.HasSuffix(strings.TrimRight(stripANSI(out), " "), "same? [y/N]") {
				select {
				case same <- "":
					go func() {
						time.Sleep(2 * time.Second)
						r.typeInto(left, "y\n")
						io.WriteString(answer, "y\r")
					}()
				default:
				}
			}
		})
	}()
	var c string
	select {
	case c = <-code:
	case err := <-invited:
		t.Fatalf("the invite ended with no code: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("the invite printed no code")
	}
	time.Sleep(1500 * time.Millisecond)
	r.run(t, nas, right, "juist join "+c, nil)
	if err := <-invited; err != nil {
		t.Fatal(err)
	}

	addr := strings.TrimSpace(laptop.run(t, `ip -4 -br addr show juist0 | awk '{print $3}' | cut -d/ -f1`))
	time.Sleep(time.Second)
	r.run(t, nas, right, "juist status", nil)
	r.run(t, nas, right, "ping -c 3 "+addr, nil)
	time.Sleep(4 * time.Second)
	r.mark()

	if err := r.write(cast); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", cast)
}

// A recorder writes two terminals side by side into one cast, in real time
// but with every pause cut to maxGap.
type recorder struct {
	mu     sync.Mutex
	w, h   int
	panes  [2]*pane
	events [][3]any
	clock  float64
	last   time.Time
}

type pane struct {
	x     int
	lines []string
}

const maxGap = 1.0

func newRecorder(w, h int, titles ...string) *recorder {
	r := &recorder{w: w, h: h, last: time.Now()}
	var head strings.Builder
	head.WriteString("\x1b[?25l\x1b[2J\x1b[H")
	for i, title := range titles {
		r.panes[i] = &pane{x: 1 + i*(w+1), lines: []string{""}}
		fmt.Fprintf(&head, "\x1b[1;%dH\x1b[7m %-*s\x1b[0m", r.panes[i].x, w-1, title)
	}
	for row := 2; row <= h; row++ {
		fmt.Fprintf(&head, "\x1b[%d;%dH\x1b[2m│\x1b[0m", row, w+1)
	}
	r.emit(head.String())
	return r
}

func (r *recorder) emit(s string) {
	now := time.Now()
	r.clock += min(now.Sub(r.last).Seconds(), maxGap)
	r.last = now
	r.events = append(r.events, [3]any{float64(int(r.clock*1000)) / 1000, "o", s})
}

// mark records the time since the last output, so that the cast ends there.
func (r *recorder) mark() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.emit("")
}

// put appends s to p and redraws it.
func (r *recorder) put(p *pane, s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s = strings.ReplaceAll(s, "\r", "")
	for _, part := range strings.SplitAfter(s, "\n") {
		if part == "" {
			continue
		}
		last := &p.lines[len(p.lines)-1]
		*last += strings.TrimSuffix(part, "\n")
		for visible(*last) > r.w-1 {
			head, tail := cut(*last, r.w-1)
			*last = head
			p.lines = append(p.lines, tail)
			last = &p.lines[len(p.lines)-1]
		}
		if strings.HasSuffix(part, "\n") {
			p.lines = append(p.lines, "")
		}
	}
	rows := r.h - 1
	if len(p.lines) > rows {
		p.lines = p.lines[len(p.lines)-rows:]
	}
	var b strings.Builder
	for i := 0; i < rows; i++ {
		line := ""
		if i < len(p.lines) {
			line = p.lines[i]
		}
		fmt.Fprintf(&b, "\x1b[%d;%dH%s\x1b[0m%s", i+2, p.x, line, strings.Repeat(" ", r.w-1-visible(line)))
	}
	r.emit(b.String())
}

func (r *recorder) typeInto(p *pane, s string) {
	for _, c := range s {
		r.put(p, string(c))
		time.Sleep(45 * time.Millisecond)
	}
}

func (r *recorder) run(t *testing.T, v *vm, p *pane, cmd string, watch func(string, io.Writer)) {
	t.Helper()
	if err := r.runE(v, p, cmd, watch); err != nil {
		t.Fatal(err)
	}
}

// runE types cmd at v's prompt in p and runs it on a terminal, showing what it
// writes. watch sees everything written so far, and may answer.
func (r *recorder) runE(v *vm, p *pane, cmd string, watch func(string, io.Writer)) error {
	r.put(p, "\x1b[1m"+v.name+"#\x1b[0m ")
	time.Sleep(400 * time.Millisecond)
	r.typeInto(p, cmd)
	time.Sleep(300 * time.Millisecond)
	r.put(p, "\n")
	c := exec.Command("ssh", append([]string{"-tt"}, v.sshArgs("stty -echo; TERM=xterm-256color exec "+cmd)...)...)
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	c.Stderr = c.Stdout
	if err := c.Start(); err != nil {
		return err
	}
	var all strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := out.Read(buf)
		if n > 0 {
			all.Write(buf[:n])
			r.put(p, string(buf[:n]))
			if watch != nil {
				watch(all.String(), in)
			}
		}
		if err != nil {
			break
		}
	}
	if err := c.Wait(); err != nil {
		return fmt.Errorf("%s: %s: %v\n%s", v.name, cmd, err, all.String())
	}
	return nil
}

func (r *recorder) write(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	head, _ := json.Marshal(map[string]any{"version": 2, "width": 2*r.w + 1, "height": r.h,
		"env": map[string]string{"TERM": "xterm-256color"}})
	var b strings.Builder
	b.Write(head)
	b.WriteString("\n")
	for _, e := range r.events {
		line, _ := json.Marshal(e)
		b.Write(line)
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func visible(s string) int { return utf8.RuneCountInString(stripANSI(s)) }

// cut splits s after n visible runes, keeping escapes whole.
func cut(s string, n int) (string, string) {
	i := 0
	for i < len(s) && n > 0 {
		if loc := ansiRE.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 {
			i += loc[1]
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n--
	}
	return s[:i], s[i:]
}

// labPair boots the lab's two VMs, a FreeBSD one named fbName and a Debian
// one named lxName, on one LAN, with the packages installed and juistd up.
func labPair(t *testing.T, fbName, lxName string) (fb, lx *vm) {
	t.Helper()
	work := need(t, "JUIST_INTEROP_WORK")
	deb := need(t, "JUIST_INTEROP_DEB")
	pkg := need(t, "JUIST_INTEROP_PKG")
	cache := need(t, "JUIST_INTEROP_CACHE")
	os.RemoveAll(work)
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(work, "key")
	sh(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	pub, _ := os.ReadFile(key + ".pub")
	fbBase, lxBase := base(t, cache, work, freebsdImage), base(t, cache, work, debianImage)

	fb = &vm{name: fbName, freebsd: true, lanAddr: "10.77.0.1", mac: "52:54:00:77:00:01", net: "10.0.4.0/24", dir: work, key: key}
	lx = &vm{name: lxName, lanAddr: "10.77.0.3", mac: "52:54:00:77:00:03", net: "10.0.3.0/24", dir: work, key: key}
	vms := []*vm{fb, lx}
	pa, pb := freePort(t, "udp"), freePort(t, "udp")
	fb.boot(t, fbBase, pa, pb, "")
	lx.boot(t, lxBase, pb, pa, fmt.Sprintf("http://10.0.3.2:%d/", seedServer(t, lxName, string(pub))))
	both(t, vms, func(v *vm) error { return v.up(20 * time.Minute) })

	fb.put(t, pkg, "/tmp/juist.pkg", 0o644)
	lx.put(t, deb, "/tmp/juist.deb", 0o644)
	both(t, vms, func(v *vm) error {
		script := `set -e
hostname ` + fbName + `; sysrc -q hostname=` + fbName + ` >/dev/null
ifconfig vtnet1 inet 10.77.0.1/24 up
pkg -N >/dev/null 2>&1 || env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null
pkg add /tmp/juist.pkg >/dev/null
sysrc -q juistd_enable=YES >/dev/null; service juistd start >/dev/null`
		if !v.freebsd {
			script = `set -e
cloud-init status --wait >/dev/null || true
hostnamectl hostname ` + lxName + `
dev=$(ip -br link | awk '$3 == "52:54:00:77:00:03" {print $1}')
ip link set $dev up; ip addr add 10.77.0.3/24 dev $dev
dpkg -i /tmp/juist.deb >/dev/null
systemctl is-active juistd >/dev/null`
		}
		if out, err := v.try(script, 15*time.Minute); err != nil {
			return fmt.Errorf("%s: setting up: %v\n%s", v.name, err, out)
		}
		return nil
	})
	for _, v := range vms {
		v.eventually(t, "juistd answers", 2*time.Minute, "juist status", func(string) bool { return true })
	}
	return fb, lx
}
