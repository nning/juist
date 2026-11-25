package tray

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// A fakeDaemon answers status on a socket, as juistd does, until stopped.
type fakeDaemon struct {
	path  string
	mu    sync.Mutex
	st    *ipc.Status
	newer bool
	ln    net.Listener
}

func newFakeDaemon(t *testing.T, path string, st *ipc.Status) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{path: path, st: st}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	d.start(t)
	t.Cleanup(d.stop)
	return d
}

func (d *fakeDaemon) start(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("unix", d.path)
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.ln = ln
	d.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				raw, err := ipc.ReadMessage(c, ipc.MaxRequest)
				if err != nil {
					return
				}
				req, err := ipc.DecodeRequest(raw)
				if err != nil || req.Command != ipc.CmdStatus {
					ipc.WriteMessage(c, ipc.Response{Err: "no"}, ipc.MaxResponse)
					return
				}
				d.mu.Lock()
				st, newer := *d.st, d.newer
				d.mu.Unlock()
				if !newer {
					ipc.WriteMessage(c, ipc.Response{Status: &st}, ipc.MaxResponse)
					return
				}
				// A newer juistd's: a field this build does not know.
				ipc.WriteMessage(c, map[int]any{2: &st, 99: "new"}, ipc.MaxResponse)
			}()
		}
	}()
}

func (d *fakeDaemon) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln != nil {
		d.ln.Close()
		d.ln = nil
		os.Remove(d.path)
	}
}

func (d *fakeDaemon) set(st *ipc.Status) {
	d.mu.Lock()
	d.st = st
	d.mu.Unlock()
}

// fakeJuist is a juist that logs its arguments to calls and answers health
// with the warnings in $dir/warnings.
func fakeJuist(t *testing.T, dir string) (path, calls string) {
	t.Helper()
	path, calls = filepath.Join(dir, "juist"), filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> ` + calls + `
case "$*" in
*health) cat ` + filepath.Join(dir, "warnings") + ` >&2 2>/dev/null; echo "nothing needs attention" ;;
*status) printf 'home · connected\nThis device  laptop  100.70.0.1\n\nhint: z\n' ;;
*"exit use srv") echo "juist: srv does not serve as an exit node" >&2; exit 1 ;;
*"exit use"*) echo "internet via fb"; echo "warning: fb is offline; internet traffic waits for it" >&2 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, calls
}

// testConfig watches sock, with the default instance's beside it as juist's
// layout has them, and runs the juist at path.
func testConfig(sock string, only bool, path string) Config {
	run := filepath.Dir(filepath.Dir(sock))
	return Config{
		SocketOf: func(n int) string {
			if n == 0 {
				return sock
			}
			return filepath.Join(run, instance.Name(n), filepath.Base(sock))
		},
		Home: func(int) string { return "/nonexistent" },
		Only: only,
		Juist: func(ctx context.Context, args []string) (string, string, error) {
			var o, e strings.Builder
			cmd := exec.CommandContext(ctx, path, args...)
			cmd.Stdout, cmd.Stderr = &o, &e
			err := cmd.Run()
			return o.String(), e.String(), err
		},
	}
}

func readCalls(t *testing.T, path string) []string {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func drain(ch chan []network) []network {
	var last []network
	for {
		select {
		case last = <-ch:
		default:
			return last
		}
	}
}

func TestWatcherFollowsJuistd(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "run")
	sock := filepath.Join(run, "juist", "juistd.sock")
	d := newFakeDaemon(t, sock, operated())
	juist, calls := fakeJuist(t, dir)
	w := newWatcher(testConfig(sock, false, juist))
	ctx := context.Background()
	out := make(chan []network, 8)

	w.round(ctx, out)
	nets := drain(out)
	if len(nets) != 1 || nets[0].st == nil || !nets[0].checked || len(nets[0].warnings) > 0 {
		t.Fatalf("first round: %+v", nets)
	}
	if got := nets[0].summary; !slices.Equal(got, []string{"home · connected", "This device laptop 100.70.0.1"}) {
		t.Errorf("summary %q", got)
	}
	if got := readCalls(t, calls); !slices.Equal(got, []string{"--network juist0 health", "--network juist0 status"}) {
		t.Errorf("juist ran as %q", got)
	}

	// Nothing changed and the last check is fresh: juist is not run again.
	w.round(ctx, out)
	if got := readCalls(t, calls); len(got) != 2 {
		t.Errorf("juist ran again for nothing: %q", got)
	}

	// The state changes: juist health runs at once, and its warning shows.
	os.WriteFile(filepath.Join(dir, "warnings"), []byte("warning: DNS goes around fb\nhint: x\n"), 0o644)
	st := operated()
	st.Exit.Node, st.Exit.Name = fb, "fb"
	d.set(st)
	w.round(ctx, out)
	nets = drain(out)
	if v := render(nets); v.icon != (icon{base: baseExit, badge: badgeWarning}) {
		t.Errorf("after the change the icon is %+v, nets %+v", v.icon, nets)
	}

	// juistd stops: off, and back once it answers again, without a restart.
	d.stop()
	w.round(ctx, out)
	if v := render(drain(out)); v.icon != (icon{}) || v.title != "juist: juistd not running" {
		t.Errorf("stopped: icon %+v, title %q", v.icon, v.title)
	}
	d.start(t)
	w.round(ctx, out)
	if v := render(drain(out)); v.icon.base != baseExit {
		t.Errorf("started again: icon %+v", v.icon)
	}

	// A second instance in a network joins the menu; the CLI is then told
	// which network it is about.
	homes := filepath.Join(dir, "state")
	w.c.Home = func(n int) string { return filepath.Join(homes, instance.Name(n)) }
	os.MkdirAll(w.c.Home(2), 0o700)
	d2 := newFakeDaemon(t, w.c.SocketOf(2), operated())
	os.Remove(calls)
	w.round(ctx, out)
	if nets := drain(out); len(nets) != 2 || nets[1].n != 2 {
		t.Fatalf("with a second instance: %+v", nets)
	}
	if got := readCalls(t, calls); !slices.Contains(got, "--network juist2 health") {
		t.Errorf("juist ran as %q", got)
	}

	// Stopped, it stays, as not running; removed with its home, it goes.
	d2.stop()
	w.round(ctx, out)
	if got := labels(render(drain(out)).menu); !slices.Contains(got, "juist2 · juistd not running") {
		t.Errorf("stopped, the menu is %q", got)
	}
	os.RemoveAll(w.c.Home(2))
	w.round(ctx, out)
	if nets := drain(out); len(nets) != 1 || nets[0].n != 0 {
		t.Errorf("removed, the networks are %+v", nets)
	}
}

// A juistd of a newer build than juist tray's still shows: its status
// carries fields this build does not know.
func TestANewerJuistdShows(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juistd.sock")
	d := newFakeDaemon(t, sock, operated())
	d.newer = true
	juist, _ := fakeJuist(t, dir)
	w := newWatcher(testConfig(sock, true, juist))
	if st := w.status(context.Background(), 0); st == nil || st.SelfName != "laptop" {
		t.Fatalf("a newer juistd's status reads as %+v", st)
	}
}

func TestClicksRunJuist(t *testing.T) {
	dir := t.TempDir()
	juist, calls := fakeJuist(t, dir)
	w := newWatcher(testConfig(filepath.Join(dir, "juistd.sock"), true, juist))
	ctx := context.Background()

	if s, b := w.do(ctx, action{kind: actExitUse, arg: "fb"}); s != "internet via fb" || b != "warning: fb is offline; internet traffic waits for it" {
		t.Errorf("a warning after the choice says %q, %q", s, b)
	}
	if s, b := w.do(ctx, action{kind: actExitUse, arg: "srv"}); s != "the exit node was not changed" || b != "juist: srv does not serve as an exit node" {
		t.Errorf("a refused choice says %q, %q", s, b)
	}
	if s, _ := w.do(ctx, action{kind: actExitOff}); s != "" {
		t.Errorf("a quiet change says %q", s)
	}
	sock := "--socket " + filepath.Join(dir, "juistd.sock")
	want := []string{sock + " exit use fb", sock + " exit use srv", sock + " exit off"}
	if got := readCalls(t, calls); !slices.Equal(got, want) {
		t.Errorf("juist ran as %q, want %q", got, want)
	}

	w = newWatcher(testConfig(filepath.Join(dir, "juistd.sock"), false, juist))
	// The network is named always: juist may know an instance down that
	// the tray does not show.
	if got := w.args(0, "exit", "off"); !slices.Equal(got, []string{"--network", "juist0", "exit", "off"}) {
		t.Errorf("juist runs as %q", got)
	}
}

func TestWatcherRunsUntilCancelled(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juistd.sock")
	newFakeDaemon(t, sock, operated())
	juist, _ := fakeJuist(t, dir)
	w := newWatcher(testConfig(sock, true, juist))
	w.poll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	out, done := make(chan []network), make(chan struct{})
	go func() { w.run(ctx, nil, out); close(done) }()
	for range 3 {
		<-out
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("still running")
	}
}

// An instance made for a join that failed, out of a network while it ran,
// goes from the menu with its home, as from juist status.
func TestAnInstanceRemovedBeforeItJoinedGoes(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juist", "juistd.sock")
	newFakeDaemon(t, sock, operated())
	juist, _ := fakeJuist(t, dir)
	w := newWatcher(testConfig(sock, false, juist))
	w.c.Home = func(n int) string { return filepath.Join(dir, "state", instance.Name(n)) }
	os.MkdirAll(w.c.Home(1), 0o700)
	d1 := newFakeDaemon(t, w.c.SocketOf(1), &ipc.Status{SelfName: "laptop", Joining: true})
	ctx, out := context.Background(), make(chan []network, 8)
	w.round(ctx, out)
	drain(out)
	d1.stop()
	os.RemoveAll(w.c.Home(1))
	w.round(ctx, out)
	if got := labels(render(drain(out)).menu); slices.Contains(got, "juist1 · juistd not running") {
		t.Errorf("a removed instance that never joined stays: %q", got)
	}
}

// An instance that left its network and was then disabled and stopped goes,
// its home left behind, as from juist status. Stopped alone, still enabled,
// juist status lists it as not running; the tray does not.
func TestAnInstanceThatLeftThenStoppedGoes(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juist", "juistd.sock")
	newFakeDaemon(t, sock, operated())
	juist, _ := fakeJuist(t, dir)
	w := newWatcher(testConfig(sock, false, juist))
	w.c.Home = func(n int) string { return filepath.Join(dir, "state", instance.Name(n)) }
	os.MkdirAll(w.c.Home(1), 0o700)
	in := operated()
	in.NetworkName = "work"
	d1 := newFakeDaemon(t, w.c.SocketOf(1), in)
	ctx, out := context.Background(), make(chan []network, 8)
	w.round(ctx, out)
	drain(out)
	d1.set(&ipc.Status{Derived: ipc.Derived{SelfName: "laptop"}})
	w.round(ctx, out)
	drain(out)
	d1.stop()
	w.round(ctx, out)
	if got := labels(render(drain(out)).menu); slices.Contains(got, "juist1 · juistd not running") {
		t.Errorf("an instance that left its network stays once stopped: %q", got)
	}
}
