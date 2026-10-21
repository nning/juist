// Command idle measures what the Android app sends and receives while the
// phone idles, screen off and on battery, in the emulator beside ten members
// on this host, one restarting every few minutes, and fails where a scenario
// passes its budget. Run it from the
// repository's root (make android-idle); it logs to build/idle.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	anacrolix "github.com/anacrolix/dht/v2"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// Datagrams and segments an hour, both ways, juist may cost while the phone
// idles: what docs/12-validating.md records under "The last privileged run",
// with headroom for the emulator's spread.
var budget = map[string]int{
	"no relay": 20000,
	"relay":    11000,
}

// members is how many juistd the phone idles beside: a household's
// network, whose log sync two members hid.
var members = 10

// churn is how often a member restarts, as a laptop waking does, which
// every member hears of: the emulator brings its Wi-Fi back from airplane
// mode only with the screen on.
var churn = 3 * time.Minute

const (
	app     = "io.juist.debug"
	capture = "/data/local/tmp/idle.pcap"
	// settle is how long the phone idles before the capture starts: the
	// pace it saves at, not the minutes after the screen went off and a
	// relay granted came to be everyone's home.
	settle = 5 * time.Minute
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// A second signal ends the tool at once.
	context.AfterFunc(ctx, cancel)
	interrupted = ctx
	apk := flag.String("apk", "android/app/build/outputs/apk/debug/app-x86_64-debug.apk", "the debug APK")
	bin := flag.String("bin", "build/idle/bin", "where juist and juistd are built")
	minutes := flag.Int("minutes", 35, "how long to capture, at least the longest saving interval")
	scenarios := flag.String("scenarios", "no relay,relay", "the scenarios to run, comma-separated")
	keep := flag.Bool("keep", false, "leave the emulator running")
	flag.IntVar(&members, "members", members, "how many members beside the phone")
	flag.DurationVar(&churn, "churn", churn, "how often a member restarts while the phone idles, zero never")
	flag.Parse()
	if err := run(ctx, *apk, *bin, time.Duration(*minutes)*time.Minute, strings.Split(*scenarios, ","), *keep); err != nil {
		fmt.Fprintln(os.Stderr, "idle:", err)
		cancel()
		os.Exit(1)
	}
}

func run(ctx context.Context, apk, bin string, length time.Duration, scenarios []string, keep bool) error {
	out := "build/idle"
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, s := range scenarios {
		if _, ok := budget[s]; !ok {
			return fmt.Errorf("no scenario %q", s)
		}
	}
	if err := build(bin); err != nil {
		return err
	}
	stop, err := emulator(out, keep)
	if err != nil {
		return err
	}
	defer stop()
	var failed []string
	for _, s := range scenarios {
		r, err := scenario(ctx, s, apk, bin, filepath.Join(out, strings.ReplaceAll(s, " ", "-")), length)
		if err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
		fmt.Println(r.String())
		if r.perHour() > budget[s] {
			failed = append(failed, fmt.Sprintf("%s: %d an hour, over the budget of %d", s, r.perHour(), budget[s]))
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	fmt.Println("idle: within budget")
	return nil
}

func build(bin string) error {
	cmd := exec.Command("go", "build", "-o", bin+"/", "./cmd/juist", "./cmd/juistd")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// sdkTool is name on PATH, or in dir of the Android SDK where it is not.
func sdkTool(name, dir string) string {
	if _, err := exec.LookPath(name); err != nil && os.Getenv("ANDROID_HOME") != "" {
		return filepath.Join(os.Getenv("ANDROID_HOME"), dir, name)
	}
	return name
}

// adb runs adb with args on the emulator alone, never a phone attached
// beside it, returning what it printed.
func adb(args ...string) (string, error) {
	out, err := exec.Command(sdkTool("adb", "platform-tools"), append([]string{"-e"}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("adb %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return string(out), nil
}

func shell(script string) (string, error) { return adb("shell", script) }

// emulator boots the AVD juist where no device is attached, and returns how
// to stop what it started.
func emulator(out string, keep bool) (func(), error) {
	if state, _ := adb("get-state"); strings.TrimSpace(state) == "device" {
		return func() {}, nil
	}
	log, err := os.Create(filepath.Join(out, "emulator.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(sdkTool("emulator", "emulator"), "-avd", "juist", "-no-window", "-no-audio", "-no-boot-anim",
		"-gpu", "swiftshader_indirect", "-no-snapshot")
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the emulator: %w", err)
	}
	stop := func() {
		if !keep {
			adb("emu", "kill")
			cmd.Wait()
		}
		log.Close()
	}
	if err := waitFor(5*time.Minute, "the emulator to boot", func() bool {
		s, _ := shell("getprop sys.boot_completed")
		return strings.TrimSpace(s) == "1"
	}); err != nil {
		stop()
		return nil, err
	}
	return stop, nil
}

// sleep waits for d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// interrupted ends with a signal; what waits gives up on it.
var interrupted = context.Background()

func waitFor(limit time.Duration, what string, ok func() bool) error {
	for deadline := time.Now().Add(limit); !ok(); {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %v waiting for %s", limit, what)
		}
		if err := sleep(interrupted, 2*time.Second); err != nil {
			return err
		}
	}
	return nil
}

// A member is a juistd on this host, on a network stack of its own.
type member struct {
	name, home string
	port       int // the data plane's; the gossip and relay ports follow it
	cmd        *exec.Cmd
	web        net.Listener
}

func (m *member) sock() string { return filepath.Join(m.home, "daemon.sock") }

// env is what the CLI runs against m with: its juistd, and a keystore of its own.
func (m *member) env() []string {
	return append(os.Environ(), "JUIST_HOME="+m.home+"-keys", "JUIST_SOCKET="+m.sock())
}

func startMember(bin, dir, name string, port int) (*member, error) {
	m := &member{name: name, home: filepath.Join(dir, name), port: port}
	os.RemoveAll(m.home)
	os.RemoveAll(m.home + "-keys")
	if err := os.MkdirAll(m.home, 0o700); err != nil {
		return nil, err
	}
	// What the member serves, so that it runs a network stack of its own.
	web, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	m.web = web
	log, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		return nil, err
	}
	m.cmd = exec.Command(filepath.Join(bin, "juistd"), "--home", m.home, "--verbose",
		"--port", strconv.Itoa(port), "--gossip-port", strconv.Itoa(port+1), "--relay-port", strconv.Itoa(port+2),
		"--serve", "web="+web.Addr().String())
	m.cmd.Stdout, m.cmd.Stderr = log, log
	if err := m.cmd.Start(); err != nil {
		return nil, err
	}
	return m, waitFor(time.Minute, name+"'s juistd", func() bool {
		_, err := ipc.Call(m.sock(), ipc.Request{Command: ipc.CmdStatus})
		return err == nil
	})
}

func (m *member) stopDaemon() {
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Signal(os.Interrupt)
		m.cmd.Wait()
	}
}

// restart stops m's juistd and starts it again on the same state.
func (m *member) restart(bin string) error {
	m.stopDaemon()
	log, err := os.OpenFile(m.home+".log", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	args := m.cmd.Args
	m.cmd = exec.Command(filepath.Join(bin, "juistd"), args[1:]...)
	m.cmd.Stdout, m.cmd.Stderr = log, log
	if err := m.cmd.Start(); err != nil {
		return err
	}
	return waitFor(time.Minute, m.name+"'s juistd", func() bool {
		_, err := ipc.Call(m.sock(), ipc.Request{Command: ipc.CmdStatus})
		return err == nil
	})
}

func (m *member) stop() {
	m.stopDaemon()
	if m.web != nil {
		m.web.Close()
	}
}

// juist runs the CLI against m's juistd and keystore.
func (m *member) juist(bin string, args ...string) error {
	cmd := exec.Command(filepath.Join(bin, "juist"), args...)
	cmd.Env = m.env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("juist %s on %s: %w: %s", strings.Join(args, " "), m.name, err, bytes.TrimSpace(out))
	}
	return nil
}

func (m *member) status() (*ipc.Status, error) {
	resp, err := ipc.Call(m.sock(), ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		return nil, err
	}
	return resp.Status, nil
}

var linkRE = regexp.MustCompile(`juist:[A-Za-z0-9_.@:-]+`)

// invite has from invite name, and runs join with the link it prints until
// the invite ends.
func invite(bin string, from *member, name string, join func(link string) error) error {
	cmd := exec.Command(filepath.Join(bin, "juist"), "invite", name, "--expires", "15m", "--yes")
	cmd.Env = from.env()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var printed bytes.Buffer
	cmd.Stderr = &printed
	if err := cmd.Start(); err != nil {
		return err
	}
	links := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(io.TeeReader(stdout, &printed))
		for sc.Scan() {
			if l := linkRE.FindString(sc.Text()); l != "" {
				select {
				case links <- l:
				default:
				}
			}
		}
	}()
	select {
	case l := <-links:
		if err := join(l); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return err
		}
	case <-time.After(time.Minute):
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("juist invite printed no link: %s", printed.String())
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("juist invite %s: %w: %s", name, err, printed.String())
	}
	return nil
}

// A report is what the capture counted, by what it was.
type report struct {
	scenario string
	length   time.Duration
	counts   map[string]int
	bytes    map[string]int
	answered time.Duration // a member's ping of the phone at the end, zero unanswered
	stats    string
}

// uncounted marks what the budget leaves out: the link's own traffic and
// what Android itself sends.
const uncounted = " (Android's, not counted)"

func (r *report) total() int {
	n := 0
	for k, c := range r.counts {
		if !strings.HasSuffix(k, uncounted) {
			n += c
		}
	}
	return n
}

func (r *report) perHour() int {
	return int(float64(r.total()) * float64(time.Hour) / float64(r.length))
}

func (r *report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d datagrams and segments an hour over %v", r.scenario, r.perHour(), r.length)
	keys := make([]string, 0, len(r.counts))
	for k := range r.counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "\n  %-20s %6d an hour, %6d KB", k, int(float64(r.counts[k])*float64(time.Hour)/float64(r.length)),
			int(float64(r.bytes[k])*float64(time.Hour)/float64(r.length))/1000)
	}
	if r.answered > 0 {
		fmt.Fprintf(&b, "\n  woken by a member's ping, the phone answered in %v", r.answered.Round(time.Millisecond))
	}
	return b.String()
}

func scenario(ctx context.Context, name, apk, bin, dir string, length time.Duration) (_ *report, err error) {
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var ms []*member
	defer func() {
		for _, m := range ms {
			m.stop()
		}
	}()
	for i := range max(members, 2) {
		m, err := startMember(bin, dir, string(rune('a'+i)), 41743+10*i)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	a, b := ms[0], ms[1]
	if err := a.juist(bin, "create", "idle", "--device", "a"); err != nil {
		return nil, err
	}
	for _, m := range ms[1:] {
		if err := invite(bin, a, m.name, func(link string) error {
			return m.juist(bin, "join", link, "--name", m.name)
		}); err != nil {
			return nil, err
		}
	}
	if name == "relay" {
		if err := a.juist(bin, "grant", "a", "relay"); err != nil {
			return nil, err
		}
	}

	if _, err := adb("root"); err != nil {
		return nil, err
	}
	waitFor(time.Minute, "adb as root", func() bool { _, err := shell("true"); return err == nil })
	shell("dumpsys battery reset; input keyevent 224; wm dismiss-keyguard")
	adb("uninstall", app)
	if _, err := adb("install", "-r", "-g", apk); err != nil {
		return nil, err
	}
	if _, err := shell("appops set " + app + " ACTIVATE_VPN allow"); err != nil {
		return nil, err
	}
	if err := invite(bin, a, "phone", func(link string) error { return joinPhone(link) }); err != nil {
		return nil, err
	}
	adb("logcat", "-c")
	logcat := exec.Command(sdkTool("adb", "platform-tools"), "-e", "logcat", "-v", "time")
	if f, err := os.Create(filepath.Join(dir, "logcat.txt")); err == nil {
		logcat.Stdout = f
		if logcat.Start() == nil {
			defer func() { logcat.Process.Kill(); logcat.Wait(); f.Close() }()
		}
	}
	phone, err := waitLive(a, b, "phone")
	if err != nil {
		return nil, err
	}

	// However the scenario ends, the phone is left charging, screen on,
	// capturing nothing, the app stopped and the capture gone.
	defer shell("pkill tcpdump; dumpsys battery reset; input keyevent 224; am force-stop " + app +
		"; rm -f " + capture + " /sdcard/ui.xml")
	if _, err := shell("dumpsys battery unplug; input keyevent 223"); err != nil {
		return nil, err
	}
	if err := sleep(ctx, settle); err != nil {
		return nil, err
	}
	iface, err := phoneInterface()
	if err != nil {
		return nil, err
	}
	shell("dumpsys batterystats --reset; rm -f " + capture)
	if _, err := shell(fmt.Sprintf("nohup tcpdump -i %s -n -U -w %s >/dev/null 2>&1 &", iface, capture)); err != nil {
		return nil, err
	}
	start := time.Now()
	if err := idleFor(ctx, length, bin, ms); err != nil {
		return nil, err
	}
	shell("pkill tcpdump; for i in $(seq 50); do pgrep -x tcpdump >/dev/null || break; sleep 0.2; done; pkill -9 tcpdump")
	r := &report{scenario: name, length: time.Since(start)}
	// The phone, screen off, is woken by a member's packet and answers it.
	resp, err := ipc.Call(a.sock(), ipc.Request{Command: ipc.CmdPing, Ping: phone})
	if err == nil && resp.Ping != nil && resp.Ping.Micros > 0 {
		r.answered = time.Duration(resp.Ping.Micros) * time.Microsecond
	}
	text, err := shell("tcpdump -n -tt -q -r " + capture)
	if err != nil {
		return nil, err
	}
	os.WriteFile(filepath.Join(dir, "capture.txt"), []byte(text), 0o644)
	ports := make([]int, len(ms))
	for i, m := range ms {
		ports[i] = m.port
	}
	r.counts, r.bytes = classify(text, ports)
	for _, f := range []struct {
		port string
		kind string
		ours func(record string) bool
	}{
		{"5353", "mDNS", func(rec string) bool { return strings.Contains(rec, mdns.Service) }},
		{"53", "DNS", oursDNS},
	} {
		verbose, err := shell("tcpdump -n -tt -vv -r " + capture + " udp port " + f.port)
		if err != nil {
			return nil, err
		}
		if n := min(notOurs(verbose, f.ours), r.counts[f.kind]); n > 0 {
			r.counts[f.kind] -= n
			r.counts[f.kind+uncounted] = n
		}
	}
	if r.stats, err = shell("dumpsys batterystats " + app); err == nil {
		os.WriteFile(filepath.Join(dir, "batterystats.txt"), []byte(r.stats), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "report.txt"), []byte(r.String()+"\n"), 0o644)
	if r.answered == 0 {
		return r, errors.New("the phone, screen off, did not answer a member's ping")
	}
	return r, nil
}

// idleFor waits out length, restarting one of ms but the first two, which
// the scenarios' relay and the ping need, every churn in turn.
func idleFor(ctx context.Context, length time.Duration, bin string, ms []*member) error {
	if churn <= 0 || len(ms) < 3 {
		return sleep(ctx, length)
	}
	for i, end := 0, time.Now().Add(length); time.Until(end) > 0; i++ {
		if err := sleep(ctx, min(churn, time.Until(end))); err != nil {
			return err
		}
		if err := ms[2+i%(len(ms)-2)].restart(bin); err != nil {
			return err
		}
	}
	return nil
}

// joinPhone opens link in the app and joins.
func joinPhone(link string) error {
	open := func() { shell("am start -a android.intent.action.VIEW -d '" + link + "' " + app) }
	open()
	return tap("Join", 5*time.Minute, open)
}

// boundsOf finds the bounds of the first view whose text is text in dump.
func boundsOf(dump, text string) (x, y int, ok bool) {
	re := regexp.MustCompile(`text="` + regexp.QuoteMeta(text) + `"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"`)
	m := re.FindStringSubmatch(dump)
	if m == nil {
		return 0, 0, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return (n(m[1]) + n(m[3])) / 2, (n(m[2]) + n(m[4])) / 2, true
}

// tap taps the first view whose text is text, once one shows, answering
// "Wait" to a dialog saying an app is not responding, as the emulator's
// System UI is under load, and calling again while none shows.
func tap(text string, limit time.Duration, again func()) error {
	var x, y int
	tries := 0
	if err := waitFor(limit, "a view saying "+text, func() bool {
		dump, err := shell("uiautomator dump /sdcard/ui.xml >/dev/null && cat /sdcard/ui.xml")
		if err != nil {
			return false
		}
		if wx, wy, ok := boundsOf(dump, "Wait"); ok && strings.Contains(dump, "responding") {
			shell(fmt.Sprintf("input tap %d %d", wx, wy))
			return false
		}
		var ok bool
		if x, y, ok = boundsOf(dump, text); ok {
			return true
		}
		if tries++; tries%5 == 0 && again != nil {
			again()
		}
		return false
	}); err != nil {
		return err
	}
	_, err := shell(fmt.Sprintf("input tap %d %d", x, y))
	return err
}

// waitLive waits until both members reach the device named name, and
// returns its identity.
func waitLive(a, b *member, name string) (types.Identity, error) {
	var id types.Identity
	err := waitFor(5*time.Minute, "both members to reach "+name, func() bool {
		for _, m := range []*member{a, b} {
			st, err := m.status()
			if err != nil {
				return false
			}
			found := false
			for _, d := range st.Devices {
				if d.Name != name {
					continue
				}
				id = d.Identity
				for _, r := range st.Reach {
					if r.Identity == d.Identity && r.Live {
						found = true
					}
				}
			}
			if !found {
				return false
			}
		}
		return true
	})
	return id, err
}

// phoneInterface is the interface the phone's default route leaves by.
func phoneInterface() (string, error) {
	out, err := shell("ip route get 8.8.8.8")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if i := slices.Index(f, "dev"); i >= 0 && i+1 < len(f) {
		return f[i+1], nil
	}
	return "", fmt.Errorf("no default route on the phone: %s", out)
}

var lineRE = regexp.MustCompile(`IP6? (\S+) > (\S+): (UDP|tcp|TCP|ICMP|icmp)`)

// classify counts tcpdump's lines by what they carry, members' data planes
// at ports and the ports beside them.
func classify(text string, ports []int) (map[string]int, map[string]int) {
	counts, sizes := map[string]int{}, map[string]int{}
	member := func(p int) string {
		for _, m := range ports {
			switch p {
			case m:
				return "members' data plane"
			case m + 1:
				return "members' log sync"
			case m + 2:
				return "member relay"
			}
		}
		return ""
	}
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "reading from"), strings.TrimSpace(line) == "":
			continue
		case strings.Contains(line, " ARP, "):
			counts["ARP"+uncounted]++
			continue
		case strings.Contains(line, " ICMP") && !mentionsPort(line, ports):
			counts["ICMP"+uncounted]++
			continue
		case strings.Contains(line, " ICMP"):
			counts["ICMP"]++
			continue
		}
		m := lineRE.FindStringSubmatch(line)
		if m == nil {
			counts["other"]++
			continue
		}
		src, dst := portOf(m[1]), portOf(m[2])
		kind := strings.ToLower(m[3])
		var what string
		switch {
		case member(dst) != "":
			what = member(dst)
		case member(src) != "":
			what = member(src)
		case src == 53 || dst == 53:
			what = "DNS"
		case src == 5353 || dst == 5353:
			what = "mDNS"
		case src == 3478 || dst == 3478 || src == 19302 || dst == 19302:
			what = "STUN"
		case kind == "udp":
			what = "other UDP"
		default:
			what = "other " + kind
		}
		counts[what]++
		if f := strings.Fields(line); len(f) > 0 {
			n, _ := strconv.Atoi(f[len(f)-1])
			sizes[what] += n
		}
	}
	return counts, sizes
}

// notOurs counts the datagrams in tcpdump's verbose reading that ours does
// not take for juist's: Android's own, as adbd's advertisement of _adb._tcp
// or its lookups of names juist does not ask.
func notOurs(text string, ours func(record string) bool) int {
	start := regexp.MustCompile(`^\d+\.\d+ IP`)
	n := 0
	var rec strings.Builder
	flush := func() {
		if r := rec.String(); r != "" && !ours(r) {
			n++
		}
		rec.Reset()
	}
	for _, line := range strings.Split(text, "\n") {
		if start.MatchString(line) {
			flush()
		}
		rec.WriteString(line)
	}
	flush()
	return n
}

// oursDNS reports whether a DNS record names what juist looks up: the STUN
// servers and the public DHT's routers.
func oursDNS(rec string) bool {
	names := slices.Concat(rendezvous.DefaultSTUN, anacrolix.DefaultGlobalBootstrapHostPorts)
	return slices.ContainsFunc(names, func(s string) bool {
		host, _, _ := strings.Cut(s, ":")
		return strings.Contains(rec, host+".")
	})
}

var portRE = regexp.MustCompile(`(?:port |\.)(\d+)\b`)

// mentionsPort reports whether an ICMP line quotes a packet to or from one
// of juist's ports: the phone's, the members', or a STUN server's.
func mentionsPort(line string, ports []int) bool {
	all := []int{daemon.DefaultListenPort, 3478, 19302}
	for _, p := range ports {
		all = append(all, p, p+1, p+2)
	}
	m := portRE.FindAllStringSubmatch(line, -1)
	return slices.ContainsFunc(m, func(g []string) bool {
		p, _ := strconv.Atoi(g[1])
		return slices.Contains(all, p)
	})
}

// portOf is the port of tcpdump's address.port, zero for none.
func portOf(s string) int {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return 0
	}
	if _, err := netip.ParseAddr(s[:i]); err != nil {
		return 0
	}
	p, _ := strconv.Atoi(strings.TrimSuffix(s[i+1:], ":"))
	return p
}
