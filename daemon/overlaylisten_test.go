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
	m.listen = func(netip.AddrPort) (net.Listener, error) {
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
		ln := m.lns[0].ln
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

// Rebinding opens the new addresses on the port and closes the old ones,
// while what was accepted stays connected.
func TestRebindMovesTheListener(t *testing.T) {
	ln, err := listenOverlay([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(portOf(ln.Addr()))
	held, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()

	// Of the loopback, FreeBSD holds 127.0.0.1 alone.
	if err := ln.(*multiListener).rebind([]netip.Prefix{netip.MustParsePrefix("::1/128")}); err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("::1", port))
	if err != nil {
		t.Fatalf("the new address: %v", err)
	}
	defer c.Close()
	if a, err := ln.Accept(); err != nil {
		t.Fatal(err)
	} else {
		a.Close()
	}
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port)); err == nil {
		c.Close()
		t.Error("the old address still listens")
	}
	if _, err := held.Write([]byte("x")); err != nil {
		t.Errorf("a connection accepted before: %v", err)
	}
	b := make([]byte, 1)
	accepted.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := accepted.Read(b); err != nil {
		t.Errorf("a connection accepted before: %v", err)
	}
}

// An address rebind cannot bind yet, as one the device does not hold yet, is
// listened at once it can be.
func TestRebindTakesAnAddressOnceItCan(t *testing.T) {
	var ready atomic.Bool
	later := netip.MustParseAddr("::1")
	listen := func(ap netip.AddrPort) (net.Listener, error) {
		if ap.Addr() == later && !ready.Load() {
			return nil, syscall.EADDRNOTAVAIL
		}
		return net.Listen("tcp", ap.String())
	}
	m, err := listenEach(listen, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	} else {
		ln.Close()
	}
	if err := m.rebind([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.PrefixFrom(later, 128)}); err == nil {
		t.Fatal("an address that could not be bound was not reported")
	}
	ready.Store(true)
	at := net.JoinHostPort(later.String(), strconv.Itoa(portOf(m.Addr())))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", at)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never listened at %s: %v", at, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if a, err := m.Accept(); err != nil {
		t.Fatal(err)
	} else {
		a.Close()
	}
}

// newMultiListener accepts from lns once started.
func newMultiListener(lns []net.Listener) *multiListener {
	m := &multiListener{conns: make(chan net.Conn), errs: make(chan error, len(lns)), closed: make(chan struct{})}
	for _, ln := range lns {
		m.lns = append(m.lns, &slot{ln: ln})
	}
	return m
}
