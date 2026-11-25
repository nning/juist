//go:build (linux && !android) || freebsd

package tray

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/godbus/dbus/v5"
)

// busName keeps a second tray in the same session from starting.
const busName = "io.github.nning.juist.Tray"

const watcherName = "org.kde.StatusNotifierWatcher"

// Supported says whether the tray runs here.
const Supported = true

// replacedEvery is how often the tray asks whether juist was replaced.
var replacedEvery = 5 * time.Second

func run(ctx context.Context, w *watcher, c Config) error {
	errOut := c.Stderr
	conn, err := dbus.SessionBus()
	if err != nil {
		return fmt.Errorf("no desktop session: %v", err)
	}
	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("D-Bus: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New("juist tray already runs in this session")
	}
	// fyne.io/systray logs in no form of juist's; what matters, juist tray
	// says itself.
	log.SetOutput(io.Discard)
	t := &tray{w: w, conn: conn, errOut: errOut, kick: make(chan struct{}, 1), quit: make(chan struct{})}
	// The item's Id is its title when it is exported, which start does
	// before any state is shown.
	systray.SetTitle("juist")
	start, end := systray.RunWithExternalLoop(nil, nil)
	start()
	go t.watchForBar()
	t.ready()
	tick := time.NewTicker(replacedEvery)
	defer tick.Stop()
	err = nil
wait:
	for {
		select {
		case <-t.quit:
			break wait
		case <-ctx.Done():
			break wait
		case <-tick.C:
			if c.Replaced != nil && c.Replaced() {
				err = ErrReplaced
				break wait
			}
		}
	}
	t.stop()
	t.finish(end)
	return err
}

// noBarGrace is how long a status bar starting with the session has to
// appear before juist tray says none shows its icon.
var noBarGrace = 10 * time.Second

func (t *tray) watchForBar() {
	select {
	case <-time.After(noBarGrace):
	case <-t.quit:
		return
	}
	if !t.hasOwner(watcherName) {
		fmt.Fprintln(t.errOut, "warning: no status bar here shows juist's icon")
		fmt.Fprintln(t.errOut, "hint: on GNOME, turn on the AppIndicator extension, then log in again")
		t.notify("No status bar shows juist's icon", "On GNOME, turn on the AppIndicator extension, then log in again.")
	}
	tick := time.NewTicker(registerEvery)
	defer tick.Stop()
	for {
		t.register()
		select {
		case <-tick.C:
		case <-t.quit:
			return
		}
	}
}

// registerEvery is how often the tray makes sure the bar knows its item.
var registerEvery = 5 * time.Second

// register registers the item with a bar's watcher that does not list it.
// fyne.io/systray registers again when a watcher starts, unless it starts
// in the moment before systray listens for that, as a bar starting with
// the session may.
func (t *tray) register() {
	if !t.hasOwner(watcherName) {
		return
	}
	obj := t.conn.Object(watcherName, "/StatusNotifierWatcher")
	v, err := obj.GetProperty(watcherName + ".RegisteredStatusNotifierItems")
	if err != nil {
		return
	}
	items, _ := v.Value().([]string)
	for _, it := range items {
		name, _, _ := strings.Cut(it, "/")
		if slices.Contains(t.conn.Names(), name) {
			return
		}
	}
	obj.Call(watcherName+".RegisterStatusNotifierItem", 0, "/StatusNotifierItem")
}

type tray struct {
	w      *watcher
	conn   *dbus.Conn
	errOut io.Writer
	kick   chan struct{}
	cancel context.CancelFunc
	quit   chan struct{}
	once   sync.Once
	ended  bool // set by finish; show then leaves the item alone

	mu     sync.Mutex
	shown  view
	built  bool
	nets   map[int]network
	acting sync.Mutex
}

func (t *tray) hasOwner(name string) bool {
	var has bool
	err := t.conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, name).Store(&has)
	return err == nil && has
}

// stop ends the watcher and, once, the tray's wait.
func (t *tray) stop() {
	t.once.Do(func() {
		t.cancel()
		close(t.quit)
	})
}

func (t *tray) ready() {
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	updates := make(chan []network)
	go t.w.run(ctx, t.kick, updates)
	go func() {
		for nets := range updates {
			t.show(nets)
		}
	}()
}

// finish runs end, which closes the item's connection, once no update is
// being shown, and keeps any later one from touching the item. It waits
// for no watcher, which may be held up in juist.
func (t *tray) finish(end func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ended = true
	end()
}

// A note is a notification to send.
type note struct {
	summary string
	lines   []string
}

// show shows nets, then notifies of what is news, outside the lock that
// finish takes: a notification daemon that does not answer holds up no end.
func (t *tray) show(nets []network) {
	for _, n := range t.update(nets) {
		if err := t.notify(n.summary, strings.Join(n.lines, "\n")); err != nil {
			for _, l := range n.lines {
				fmt.Fprintf(t.errOut, "warning: %s\n", l)
			}
		}
	}
}

func (t *tray) update(nets []network) (notes []note) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return nil
	}
	// A network the watcher dropped is news again once back.
	seen := map[int]network{}
	for _, nw := range nets {
		alarms, warnings := news(t.nets[nw.n], nw)
		for _, n := range []note{{"juist: alarm", alarms}, {"juist: warning", warnings}} {
			if len(n.lines) == 0 {
				continue
			}
			if len(shown(nets)) > 1 {
				n.summary += " in " + networkName(nw)
			}
			notes = append(notes, n)
		}
		seen[nw.n] = nw
	}
	t.nets = seen
	v := render(nets)
	if !t.built || v.icon != t.shown.icon {
		systray.SetIcon(iconPNG(v.icon))
	}
	if !t.built || v.title != t.shown.title {
		systray.SetTitle(v.title)
	}
	if !t.built || v.tooltip != t.shown.tooltip {
		systray.SetTooltip(v.tooltip)
	}
	if !t.built || !reflect.DeepEqual(v.menu, t.shown.menu) {
		systray.ResetMenu()
		t.build(v.menu, nil)
	}
	t.shown, t.built = v, true
	return notes
}

func (t *tray) build(items []item, parent *systray.MenuItem) {
	for _, it := range items {
		if it.sep {
			if parent == nil {
				systray.AddSeparator()
			} else {
				parent.AddSeparator()
			}
			continue
		}
		// A lone "_" marks an access key in a dbusmenu label.
		label := strings.ReplaceAll(it.label, "_", "__")
		var mi *systray.MenuItem
		switch {
		case parent == nil && it.checkbox:
			mi = systray.AddMenuItemCheckbox(label, "", it.checked)
		case parent == nil:
			mi = systray.AddMenuItem(label, "")
		case it.checkbox:
			mi = parent.AddSubMenuItemCheckbox(label, "", it.checked)
		default:
			mi = parent.AddSubMenuItem(label, "")
		}
		if !it.enabled() {
			mi.Disable()
		}
		t.build(it.sub, mi)
		if it.act.kind != actNone {
			go func(act action, clicked <-chan struct{}) {
				for range clicked {
					go t.click(act)
				}
			}(it.act, mi.ClickedCh)
		}
	}
}

func (t *tray) click(act action) {
	switch act.kind {
	case actQuit:
		t.stop()
		return
	case actCopy:
		if err := copyText(act.arg); err != nil && t.notify("Not copied", err.Error()) != nil {
			fmt.Fprintf(t.errOut, "warning: not copied: %v\n", err)
		}
		return
	}
	// One change at a time, each judged by juist as the person's own.
	t.acting.Lock()
	defer t.acting.Unlock()
	if summary, body := t.w.do(context.Background(), act); summary != "" {
		if err := t.notify(summary, body); err != nil {
			fmt.Fprintln(t.errOut, body)
		}
	}
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// notify shows a desktop notification; an error says none could be shown.
func (t *tray) notify(summary, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	obj := t.conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	// A server may read the body as markup.
	body = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(body)
	return obj.CallWithContext(ctx, "org.freedesktop.Notifications.Notify", 0, "juist", uint32(0), "", summary, body,
		[]string{}, map[string]dbus.Variant{}, int32(-1)).Err
}
