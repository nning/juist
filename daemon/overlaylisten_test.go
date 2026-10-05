package daemon

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
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
	m.start()
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

// A listener the system took down, as Android does a VPN device's when it
// replaces the device, fails every accept with EINVAL; it is opened again.
func TestAListenerTakenDownIsOpenedAgain(t *testing.T) {
	dead := &deadListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	var again net.Listener
	m := newMultiListener([]net.Listener{dead})
	m.reopen = func(int) (net.Listener, error) {
		var err error
		again, err = net.Listen("tcp", "127.0.0.1:0")
		return again, err
	}
	m.start()
	defer m.Close()
	got := make(chan error, 1)
	go func() {
		for {
			c, err := m.Accept()
			if errors.Is(err, net.ErrClosed) {
				got <- err
				return
			}
			if err == nil {
				c.Close()
				got <- nil
				return
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		ln := m.lns[0]
		m.mu.Unlock()
		if ln != dead {
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the listener taken down was not opened again")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing accepted on the listener opened again")
	}
	if !dead.closed.Load() {
		t.Error("the listener taken down was left open")
	}
}

// A deadListener fails every accept as a socket Android destroyed does.
type deadListener struct {
	addr   net.Addr
	closed atomic.Bool
}

func (d *deadListener) Accept() (net.Conn, error) {
	if d.closed.Load() {
		return nil, net.ErrClosed
	}
	time.Sleep(time.Millisecond)
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EINVAL)}
}

func (d *deadListener) Close() error   { d.closed.Store(true); return nil }
func (d *deadListener) Addr() net.Addr { return d.addr }
