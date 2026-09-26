package daemon

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The gossip port is bound to each overlay address on one port, and an
// address the host does not hold is skipped rather than failing the rest.
func TestListenOverlayBindsEachAddressOnOnePort(t *testing.T) {
	addrs := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("192.0.2.77/32"), // held by no interface
		netip.MustParsePrefix("::1/128"),
	}
	ln, err := listenOverlay(addrs, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := portOf(ln.Addr())
	for _, host := range []string{"127.0.0.1", "::1"} {
		c, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			if host == "::1" {
				t.Logf("no IPv6 loopback here: %v", err)
				continue
			}
			t.Fatalf("dialing %s: %v", host, err)
		}
		a, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		a.Close()
		c.Close()
	}
	if _, err := listenOverlay([]netip.Prefix{netip.MustParsePrefix("192.0.2.77/32")}, 0); err == nil {
		t.Error("listening succeeded on no address at all")
	}
}

// flakyListener fails its first accept the way a descriptor shortage does.
type flakyListener struct {
	net.Listener
	failed bool
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if !f.failed {
		f.failed = true
		return nil, syscall.EMFILE
	}
	return f.Listener.Accept()
}

// An accept error that passes does not stop the listener: log sync runs on it
// alone, and one that stopped would take the device out of every sync.
func TestAFailedAcceptDoesNotStopTheListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := newMultiListener([]net.Listener{&flakyListener{Listener: inner}})
	defer m.Close()
	if _, err := m.Accept(); !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("the first accept returned %v, want the listener's error", err)
	}
	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		a, err := m.Accept()
		if err == nil {
			a.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("accept after the error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the listener stopped accepting after one error")
	}
}
