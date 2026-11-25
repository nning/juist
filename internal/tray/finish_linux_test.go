//go:build linux && !android

package tray

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// The tray ends at once though its watcher is held up in a juist that does
// not heed the cancel, as one waiting on a stalled juistd; and an update
// shown after it ended leaves the item alone, whose connection is closed.
func TestTheTrayEndsWithoutWaitingForJuist(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juist", "juistd.sock")
	newFakeDaemon(t, sock, operated())
	c := testConfig(sock, false, "")
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	c.Juist = func(context.Context, []string) (string, string, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return "", "", nil
	}
	tr := &tray{w: newWatcher(c), kick: make(chan struct{}, 1), quit: make(chan struct{})}
	tr.ready()
	<-entered
	start := time.Now()
	tr.stop()
	ended := false
	tr.finish(func() { ended = true })
	if d := time.Since(start); !ended || d > time.Second {
		t.Errorf("ending took %v, ended %v", d, ended)
	}
	tr.mu.Lock()
	tr.built = false
	tr.mu.Unlock()
	tr.show([]network{{st: operated()}})
	if tr.built {
		t.Error("an update after the end touched the item")
	}
}
