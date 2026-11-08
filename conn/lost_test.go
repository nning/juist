package conn

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/key"
)

// failingTUN fails its next read with what fail is sent, as a device whose
// netlink socket overflowed does.
type failingTUN struct {
	*echoTUN
	fail chan error
}

func (d *failingTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case err := <-d.fail:
		return 0, err
	case <-d.closed:
		return 0, io.EOF
	}
}

func newLostManager(t *testing.T, dev tun.Device, lost chan<- error) Manager {
	t.Helper()
	mgr, err := New(Options{
		Self: Self{
			ID:       1,
			NodeKey:  key.NewNode(),
			DiscoKey: key.NewDisco(),
			Addrs:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Tun:    dev,
		Logf:   quietLogf(t, "n1: "),
		OnLost: func(err error) { lost <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

// A device that fails ends the engine, which leaves the manager refusing
// every peer set: the caller hears of it, and why.
func TestAFailedDeviceIsReported(t *testing.T) {
	dev := &failingTUN{echoTUN: newEchoTUN(), fail: make(chan error, 1)}
	lost := make(chan error, 2)
	mgr := newLostManager(t, dev, lost)
	defer mgr.Close()

	dev.fail <- fmt.Errorf("failed to receive netlink message: %w", syscall.ENOBUFS)
	select {
	case err := <-lost:
		if !strings.Contains(err.Error(), "no buffer space available") {
			t.Errorf("reported %q, which does not say why", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the engine closed itself and nothing was reported")
	}
	mgr.Close()
	select {
	case err := <-lost:
		t.Errorf("reported a second time: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// Closing the manager is no loss.
func TestCloseIsNotReportedAsLost(t *testing.T) {
	lost := make(chan error, 1)
	mgr := newLostManager(t, newEchoTUN(), lost)
	mgr.Close()
	select {
	case err := <-lost:
		t.Errorf("Close reported as a loss: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}
