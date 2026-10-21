package daemon

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/discovery/mdns"
)

// sendCounter is a discovery socket that counts what is sent and receives
// nothing.
type sendCounter struct {
	mu     sync.Mutex
	sent   int
	closed chan struct{}
	once   sync.Once
}

func (c *sendCounter) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *sendCounter) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent++
	return len(b), nil
}

func (c *sendCounter) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *sendCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

// An announcement that changes, or connectivity that does, takes LAN
// discovery back to its first interval, which it has slowed down from while
// nothing changed.
func TestAChangeWakesTheBeacon(t *testing.T) {
	// Not parallel: it counts datagrams in a window, which contention stretches.
	const interval = 20 * time.Millisecond
	sock := &sendCounter{closed: make(chan struct{})}
	f := newReconcileFixtureWith(t, 2, func(o *Options) {
		o.DisableDiscovery = false
		o.Discovery = &mdns.Options{Conn: sock, Interval: interval}
	})
	if err := f.d.Reconcile(); err != nil { // adopts the epoch the beacon names
		t.Fatal(err)
	}
	go f.d.beacon.Run(t.Context())
	if _, ok := f.d.announcement(); !ok {
		t.Fatal("no announcement")
	}
	woken := func(what string, change func()) {
		t.Helper()
		time.Sleep(50 * interval)
		before := sock.count()
		change()
		time.Sleep(10 * interval)
		if n := sock.count() - before; n < 3 {
			t.Fatalf("%d datagrams in %v after %s, want the first interval's pace", n, 10*interval, what)
		}
	}

	woken("the announcement changed", func() {
		f.mgr.mu.Lock()
		f.mgr.eps = append(f.mgr.eps, netip.MustParseAddrPort("198.51.100.7:41641"))
		f.mgr.mu.Unlock()
		if _, ok := f.d.announcement(); !ok {
			t.Fatal("no announcement")
		}
	})
	woken("connectivity changed", f.d.onConnectivityChange)
}

// While saving, LAN discovery sends nothing unasked; back from saving, it
// announces this device at once.
func TestSavingQuietsTheBeacon(t *testing.T) {
	// Not parallel: it counts datagrams in a window, which contention stretches.
	const interval = 20 * time.Millisecond
	sock := &sendCounter{closed: make(chan struct{})}
	pace := NewPace()
	f := newReconcileFixtureWith(t, 2, func(o *Options) {
		o.DisableDiscovery = false
		o.Discovery = &mdns.Options{Conn: sock, Interval: interval}
		o.Pace = pace
	})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	go f.d.beacon.Run(t.Context())
	pace.SetSaving(true)
	f.d.followPace()
	time.Sleep(5 * interval)
	before := sock.count()
	f.d.beacon.Wake()
	time.Sleep(20 * interval)
	if n := sock.count() - before; n > 0 {
		t.Fatalf("saving, LAN discovery sent %d datagrams in %v", n, 20*interval)
	}
	pace.SetSaving(false)
	f.d.followPace()
	time.Sleep(10 * interval)
	if n := sock.count() - before; n < 3 {
		t.Fatalf("%d datagrams in %v back from saving, want the first interval's pace", n, 10*interval)
	}
}
