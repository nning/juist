package resolved

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/nning/juist/internal/firewalld/firewalldtest"
)

// Each time resolved takes its name on the bus, as it does starting again,
// the watcher says so; another name taken says nothing.
func TestARestartedResolvedIsSeen(t *testing.T) {
	bus := firewalldtest.Start(t)
	restarts := make(chan struct{}, 8)
	var watching atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchRestarts(ctx, func() (*dbus.Conn, error) { return dbus.Connect(bus.Addr) },
			func(on bool) { watching.Store(on) }, func() { restarts <- struct{}{} })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	seen := func(want bool, what string) {
		t.Helper()
		select {
		case <-restarts:
			if !want {
				t.Fatalf("%s was taken for a restart", what)
			}
		case <-time.After(time.Second):
			if want {
				t.Fatalf("%s went unseen", what)
			}
		}
	}
	// Subscribing is taken for a restart gone by unseen.
	seen(true, "subscribing")
	if !watching.Load() {
		t.Fatal("subscribed, the watcher says it does not watch")
	}
	for i := range 2 {
		c := bus.Connect(t)
		if _, err := c.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil {
			t.Fatal(err)
		}
		seen(true, "resolved starting")
		if i == 0 {
			c.Close()
			seen(false, "resolved stopping")
		}
	}
	other := bus.Connect(t)
	if _, err := other.RequestName("org.example.Other", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	seen(false, "another name")
}
