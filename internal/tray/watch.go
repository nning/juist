package tray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// A watcher asks the host's juistds for their status, and juist itself for
// what only the CLI judges: health's warnings and status's lines.
type watcher struct {
	c             Config
	poll, recheck time.Duration
	juistMu       sync.Mutex

	mu   sync.Mutex
	nets map[int]*network
	seen map[int]bool // answered in a network since the tray started
	keys map[int]string
	last map[int]time.Time
}

// pollEvery is how often juistd is asked for its status.
var pollEvery = 3 * time.Second

func newWatcher(c Config) *watcher {
	return &watcher{c: c, poll: pollEvery, recheck: time.Minute,
		nets: map[int]*network{}, seen: map[int]bool{}, keys: map[int]string{}, last: map[int]time.Time{}}
}

func (w *watcher) instances() []int {
	if w.c.Only {
		return []int{0}
	}
	out := make([]int, instance.Max+1)
	for n := range out {
		out[n] = n
	}
	return out
}

// run polls until ctx ends, sending what it found on each change, and at
// once when kick says something was changed.
func (w *watcher) run(ctx context.Context, kick <-chan struct{}, out chan<- []network) {
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		w.round(ctx, out)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// round asks every socket once, sends what changed, then runs juist where a
// network's state changed or its last check is old, and sends that.
func (w *watcher) round(ctx context.Context, out chan<- []network) {
	var due []int
	now := time.Now()
	for _, n := range w.instances() {
		st := w.status(ctx, n)
		w.mu.Lock()
		switch {
		case st != nil && st.InNetwork:
			w.seen[n] = true
		case st != nil && n != 0:
			// Out of a network, it shows no more, stopped later too: the
			// tray cannot tell an instance still enabled.
			delete(w.seen, n)
			delete(w.nets, n)
		}
		if st == nil && n != 0 && w.seen[n] && !exists(w.c.Home(n)) {
			// Removed, as by juist reset: gone as from juist status.
			delete(w.nets, n)
			delete(w.seen, n)
			delete(w.keys, n)
			delete(w.last, n)
			w.mu.Unlock()
			continue
		}
		nw := w.nets[n]
		if nw == nil {
			// Another instance shows once in a network, as juist status
			// lists it.
			if n != 0 && !w.seen[n] {
				w.mu.Unlock()
				continue
			}
			nw = &network{n: n}
			w.nets[n] = nw
		}
		nw.st = st
		key := ""
		if st == nil {
			nw.checked, nw.warnings, nw.summary = false, nil, nil
		} else {
			key = fmt.Sprint(head(st), networkMenu(network{n: n, st: st}, false))
		}
		if st != nil && (key != w.keys[n] || now.Sub(w.last[n]) >= w.recheck) {
			due = append(due, n)
		}
		w.keys[n] = key
		w.mu.Unlock()
	}
	send(ctx, out, w.snapshot())
	if len(due) == 0 {
		return
	}
	for _, n := range due {
		warnings, werr := w.health(ctx, n)
		summary, serr := w.summary(ctx, n)
		w.mu.Lock()
		if nw := w.nets[n]; nw != nil && nw.st != nil {
			if werr == nil {
				nw.checked, nw.warnings = true, warnings
			}
			if serr == nil {
				nw.summary = summary
			}
			w.last[n] = now
		}
		w.mu.Unlock()
	}
	send(ctx, out, w.snapshot())
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func send(ctx context.Context, out chan<- []network, nets []network) {
	select {
	case out <- nets:
	case <-ctx.Done():
	}
}

func (w *watcher) snapshot() []network {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []network
	for _, n := range w.instances() {
		if nw := w.nets[n]; nw != nil {
			c := *nw
			c.warnings, c.summary = slices.Clone(nw.warnings), slices.Clone(nw.summary)
			out = append(out, c)
		}
	}
	return out
}

// lenient decodes a status that may carry fields of a newer juistd: a tray
// started before an update goes on reading the updated one.
var lenient = func() cbor.DecMode {
	m, err := cbor.DecOptions{MaxArrayElements: 1 << 16}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

func (w *watcher) status(ctx context.Context, n int) *ipc.Status {
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", w.c.SocketOf(n))
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := ipc.WriteMessage(c, &ipc.Request{Command: ipc.CmdStatus}, ipc.MaxRequest); err != nil {
		return nil
	}
	raw, err := ipc.ReadMessage(c, ipc.MaxResponse)
	if err != nil {
		return nil
	}
	var resp ipc.Response
	if err := lenient.Unmarshal(raw, &resp); err != nil || resp.Err != "" {
		return nil
	}
	ipc.MakePrintable(&resp)
	return resp.Status
}

// args are juist's arguments for cmd in instance n's network, which they
// name: juist may know an instance down that the tray does not show.
func (w *watcher) args(n int, cmd ...string) []string {
	if w.c.Only {
		return append([]string{"--socket", w.c.SocketOf(0)}, cmd...)
	}
	return append([]string{"--network", instance.Name(n)}, cmd...)
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// juistRun runs juist and returns its stdout and stderr, colourless.
func (w *watcher) juistRun(ctx context.Context, timeout time.Duration, args ...string) (stdout, stderr string, err error) {
	w.juistMu.Lock()
	defer w.juistMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout, stderr, err = w.c.Juist(ctx, args)
	return ansi.ReplaceAllString(stdout, ""), ansi.ReplaceAllString(stderr, ""), err
}

// health is juist health's warnings for instance n.
func (w *watcher) health(ctx context.Context, n int) ([]string, error) {
	_, stderr, err := w.juistRun(ctx, 30*time.Second, w.args(n, "health")...)
	if err != nil {
		return nil, err
	}
	return warningsIn(stderr), nil
}

func warningsIn(stderr string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		if w, ok := strings.CutPrefix(strings.TrimSpace(l), "warning: "); ok {
			out = append(out, w)
		}
	}
	return out
}

// summary is juist status's first block of lines for instance n.
func (w *watcher) summary(ctx context.Context, n int) ([]string, error) {
	stdout, _, err := w.juistRun(ctx, 30*time.Second, w.args(n, "status")...)
	if err != nil {
		return nil, err
	}
	return firstBlock(stdout), nil
}

func firstBlock(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, " \t\r")
		if l == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return out
}

// do runs what a click asked for in instance n's network and returns what
// to tell the user, "" for nothing.
func (w *watcher) do(ctx context.Context, act action) (summary, body string) {
	var cmd []string
	switch act.kind {
	case actExitUse:
		cmd = []string{"exit", "use", act.arg}
	case actExitOff:
		cmd = []string{"exit", "off"}
	default:
		return "", ""
	}
	stdout, stderr, err := w.juistRun(ctx, 2*time.Minute, w.args(act.n, cmd...)...)
	var lines []string
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	switch {
	case err != nil && strings.TrimSpace(stdout) != "":
		return strings.TrimSpace(firstLine(stdout)), strings.Join(lines, "\n")
	case err != nil:
		return "the exit node was not changed", strings.Join(lines, "\n")
	case len(warningsIn(stderr)) > 0:
		return strings.TrimSpace(firstLine(stdout)), strings.Join(lines, "\n")
	}
	return "", ""
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// news is what is new in now since before for a notification: each alarm
// raised since, and the warnings juist health gave no earlier check. A first
// check is news only for its alarms.
func news(before, now network) (alarms, warnings []string) {
	was := alarmsOf(before.st)
	for _, a := range alarmsOf(now.st) {
		if !slices.Contains(was, a) {
			alarms = append(alarms, a)
		}
	}
	if !before.checked || !now.checked {
		return alarms, nil
	}
	for _, w := range now.warnings {
		if !slices.Contains(before.warnings, w) && !slices.Contains(alarms, w) {
			warnings = append(warnings, w)
		}
	}
	return alarms, warnings
}

// alarmsOf is each alarm s raises, as juist status says it in red.
func alarmsOf(s *ipc.Status) []string {
	if s == nil || !s.InNetwork {
		return nil
	}
	var out []string
	add := func(on bool, text string) {
		if on {
			out = append(out, text)
		}
	}
	add(s.Alarm != "", s.Alarm)
	add(s.Disabled != "", "the network was ended with a break-glass secret")
	add(s.NotMember, "this device was removed from the network")
	add(s.SchemaAlarm != "", s.SchemaAlarm)
	add(s.Refused, "the network refused this device a catch-up")
	add(s.Overtaken, "this device is too far behind the network")
	if s.Exit != nil && s.Exit.Failed != "" {
		out = append(out, "internet traffic may leave directly: "+s.Exit.Failed)
	}
	return out
}

// copyText puts s on the desktop's clipboard with whichever tool is there.
func copyText(s string) error {
	tools := [][]string{{"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}}
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		tools = append([][]string{{"wl-copy"}}, tools...)
	}
	for _, t := range tools {
		path, err := exec.LookPath(t[0])
		if err != nil {
			continue
		}
		// No pipe of ours on its output: the tool stays to serve the
		// clipboard, and would hold it open.
		cmd := exec.Command(path, t[1:]...)
		cmd.Stdin = strings.NewReader(s)
		return cmd.Run()
	}
	return errors.New("copying needs wl-clipboard, xclip or xsel")
}
