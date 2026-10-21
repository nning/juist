package resolved

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

// The bus is dialled again redialFirst after a connection fails or drops,
// doubling up to redialMost while it keeps failing.
const (
	redialFirst = 5 * time.Second
	redialMost  = 10 * time.Minute
)

// WatchRestarts calls restarted each time resolved takes its bus name, as it
// does when it starts again, having forgotten what its links were given, and
// each time it subscribes on a connection to the bus, as a restart may have
// gone by unseen, until ctx ends. watching hears whether it is subscribed.
func WatchRestarts(ctx context.Context, watching func(bool), restarted func()) {
	watchRestarts(ctx, func() (*dbus.Conn, error) { return dbus.ConnectSystemBus(dbus.WithContext(ctx)) }, watching, restarted)
}

func watchRestarts(ctx context.Context, dial func() (*dbus.Conn, error), watching func(bool), restarted func()) {
	gap := redialFirst
	for {
		if watchOnce(ctx, dial, watching, restarted) {
			gap = redialFirst
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(gap):
		}
		gap = min(2*gap, redialMost)
	}
}

// watchOnce watches over one connection until it drops or ctx ends,
// reporting whether it subscribed.
func watchOnce(ctx context.Context, dial func() (*dbus.Conn, error), watching func(bool), restarted func()) bool {
	conn, err := dial()
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.AddMatchSignal(dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, busName)); err != nil {
		return false
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	watching(true)
	defer watching(false)
	restarted()
	for {
		select {
		case <-ctx.Done():
			return true
		case sig, ok := <-signals:
			if !ok {
				return true
			}
			if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
				continue
			}
			if name, _ := sig.Body[0].(string); name != busName {
				continue
			}
			if owner, _ := sig.Body[2].(string); owner != "" {
				restarted()
			}
		}
	}
}
