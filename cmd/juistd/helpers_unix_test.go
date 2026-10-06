//go:build unix

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/ipc"
)

// The root parent listens for the terminator where juistd says this device
// serves, and nowhere else.
func TestTheBinderListensWhereNamesAreServed(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := probe.Addr().(*net.TCPAddr).AddrPort()
	probe.Close()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := net.FileConn(os.NewFile(uintptr(fds[0]), "binder"))
	if err != nil {
		t.Fatal(err)
	}
	child, err := net.FileConn(os.NewFile(uintptr(fds[1]), "terminator"))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	defer child.Close()
	serving := func(context.Context) (*ipc.Published, error) {
		return &ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
			Addrs: []netip.Addr{served.Addr()}, Port: served.Port()}}}, nil
	}
	go serveBinds(context.Background(), parent.(*net.UnixConn), func(ctx context.Context, addr string) (*os.File, error) {
		return bindServed(ctx, addr, serving)
	})
	b := &binder{c: child.(*net.UnixConn)}

	ln, err := b.listen("tcp", served.String())
	if err != nil {
		t.Fatalf("where a name is served: %v", err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", served.String())
	if err != nil {
		t.Fatalf("the listener handed over takes nothing: %v", err)
	}
	c.Close()
	// Port 80 where a name is served, to redirect it; binding it needs root.
	if ln, err := b.listen("tcp", netip.AddrPortFrom(served.Addr(), httpPort).String()); err == nil {
		ln.Close()
	} else if strings.Contains(err.Error(), "serves nothing") {
		t.Errorf("port 80 where a name is served: %v", err)
	}
	for _, addr := range []string{netip.AddrPortFrom(served.Addr(), served.Port()+1).String(), "0.0.0.0:443", "nonsense",
		"127.0.0.2:80"} {
		if ln, err := b.listen("tcp", addr); err == nil {
			ln.Close()
			t.Errorf("the binder listened at %s", addr)
		} else if !strings.Contains(err.Error(), "serves nothing") && !strings.Contains(err.Error(), "no address") {
			t.Errorf("at %s: %v", addr, err)
		}
	}
}

// The binder listens for a terminator where a name published by TCP goes,
// and on no port 80 for it, which it does not redirect.
func TestTheBinderListensWhereTCPIsPassed(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := probe.Addr().(*net.TCPAddr).AddrPort()
	probe.Close()
	b := binderPair(t, func(context.Context) (*ipc.Published, error) {
		return &ipc.Published{TCP: []ipc.PublishedTarget{{Name: "mc.pub.example.org",
			Addrs: []netip.Addr{served.Addr()}, Port: served.Port(), Public: 25565}}}, nil
	})
	ln, err := b.listen("tcp", served.String())
	if err != nil {
		t.Fatalf("where a name is passed by TCP: %v", err)
	}
	ln.Close()
	if _, err := b.listen("tcp", netip.AddrPortFrom(served.Addr(), httpPort).String()); err == nil ||
		!strings.Contains(err.Error(), "serves nothing") {
		t.Errorf("port 80 beside a name passed by TCP: %v", err)
	}
}

// The ingress's root parent listens on 443 and 80, and on a port juistd says
// a name is published on by TCP, on every address, and on no other port.
func TestTheIngressBindsThePublicPorts(t *testing.T) {
	probe, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	public := uint16(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()
	published := func(context.Context) (*ipc.Published, error) {
		return &ipc.Published{TCP: []ipc.PublishedTarget{{Name: "mc.pub.example.org", Port: 25565, Public: public}}}, nil
	}
	f, err := bindPublic(context.Background(), ":"+strconv.Itoa(int(public)), published)
	if err != nil {
		t.Fatalf("a port published by TCP: %v", err)
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if ap := ln.Addr().(*net.TCPAddr).AddrPort(); !ap.Addr().IsUnspecified() || ap.Port() != public {
		t.Errorf("listening at %v", ap)
	}
	for _, addr := range []string{":" + strconv.Itoa(int(public)+1), "127.0.0.1:" + strconv.Itoa(int(public)), ":0",
		"nonsense", ":65536"} {
		if f, err := bindPublic(context.Background(), addr, published); err == nil {
			f.Close()
			t.Errorf("bound %s", addr)
		}
	}
	// 443 and 80 are an ingress's whatever is published; binding them needs root.
	for _, addr := range []string{":443", ":80"} {
		f, err := bindPublic(context.Background(), addr, func(context.Context) (*ipc.Published, error) {
			return nil, errors.New("not asked")
		})
		if err == nil {
			f.Close()
		} else if strings.Contains(err.Error(), "asked") || strings.Contains(err.Error(), "published") {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

// A public port another program holds on one address is no port the
// ingress takes on every address, which on BSD it could beside it.
func TestTheIngressTakesNoPortHeldOnOneAddress(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port := uint16(held.Addr().(*net.TCPAddr).Port)
	published := func(context.Context) (*ipc.Published, error) {
		return &ipc.Published{TCP: []ipc.PublishedTarget{{Name: "mc.pub.example.org", Port: 25565, Public: port}}}, nil
	}
	if f, err := bindPublic(context.Background(), ":"+strconv.Itoa(int(port)), published); err == nil {
		f.Close()
		t.Error("bound every address beside a program holding one")
	} else if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("%v, not EADDRINUSE", err)
	}
}

// dropAs is the test binary's cue to drop to a user and say who it is.
const dropAs = "JUIST_TEST_DROP_TO"

func init() {
	if name := os.Getenv(dropAs); name != "" {
		if err := dropTo(name); err != nil {
			println(err.Error())
			os.Exit(1)
		}
		println(os.Getuid(), os.Geteuid(), os.Getgid())
		os.Exit(0)
	}
}

// Started as root, a helper becomes its user for good.
func TestAHelperDropsRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody here")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), dropAs+"=nobody")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if want := u.Uid + " " + u.Uid + " " + u.Gid; strings.TrimSpace(string(out)) != want {
		t.Errorf("dropped to %q, want %q", out, want)
	}
}

// binderPair is a binder serving serving, and its terminator's end.
func binderPair(t *testing.T, serving func(context.Context) (*ipc.Published, error)) *binder {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := net.FileConn(os.NewFile(uintptr(fds[0]), "binder"))
	if err != nil {
		t.Fatal(err)
	}
	child, err := net.FileConn(os.NewFile(uintptr(fds[1]), "terminator"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Close(); child.Close() })
	go serveBinds(context.Background(), parent.(*net.UnixConn), func(ctx context.Context, addr string) (*os.File, error) {
		return bindServed(ctx, addr, serving)
	})
	return &binder{c: child.(*net.UnixConn)}
}

func freeAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func servedAt(aps ...netip.AddrPort) func(context.Context) (*ipc.Published, error) {
	return func(context.Context) (*ipc.Published, error) {
		p := &ipc.Published{}
		for _, ap := range aps {
			p.Names = append(p.Names, ipc.PublishedTarget{Name: "n", Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()})
		}
		return p, nil
	}
}

// An answer to a request given up on is no answer to the next; a binder
// answers every request however many came before; and what it binds does
// not take an address another program listens on.
func TestTheBinderAnswersEachRequestAlone(t *testing.T) {
	defer func(d time.Duration) { bindWait = d }(bindWait)
	a, b := freeAddr(t), freeAddr(t)
	slow := make(chan struct{})
	first := true
	var mu sync.Mutex
	bd := binderPair(t, func(ctx context.Context) (*ipc.Published, error) {
		mu.Lock()
		wait := first
		first = false
		mu.Unlock()
		if wait {
			<-slow
		}
		return servedAt(a, b)(ctx)
	})
	bindWait = 100 * time.Millisecond
	if _, err := bd.listen("tcp", a.String()); err == nil {
		t.Fatal("a request answered late was taken")
	}
	close(slow)
	bindWait = 5 * time.Second
	ln, err := bd.listen("tcp", b.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := ln.Addr().(*net.TCPAddr).AddrPort(); got != b {
		t.Errorf("asked for %v, got a listener at %v", b, got)
	}
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := unix.GetsockoptInt(int(f.Fd()), unix.SOL_SOCKET, unix.SO_REUSEADDR); err != nil || v != 0 {
		t.Errorf("the listener reuses its address: %d, %v", v, err)
	}
	f.Close()
	ln.Close()

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	hb := binderPair(t, servedAt(held.Addr().(*net.TCPAddr).AddrPort()))
	if _, err := hb.listen("tcp", held.Addr().String()); !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("a port another program holds: %v", err)
	}

	refused := netip.MustParseAddrPort("127.0.0.1:1")
	for i := 0; i < 30000; i++ {
		if _, err := bd.listen("tcp", refused.String()); err == nil {
			t.Fatal("an address not served was bound")
		}
	}
	ln, err = bd.listen("tcp", a.String())
	if err != nil {
		t.Fatalf("after many requests: %v", err)
	}
	ln.Close()
}

// The terminator hears when its root parent is gone.
func TestTheTerminatorHearsItsParentGo(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envBinder, strconv.Itoa(fds[1]))
	t.Setenv(envBinderLifeline, strconv.Itoa(int(r.Fd())))
	b, gone, err := inheritedBinder()
	if err != nil || b == nil {
		t.Fatalf("%v, %v", b, err)
	}
	defer b.c.Close()
	select {
	case <-gone:
		t.Fatal("gone with its parent there")
	case <-time.After(50 * time.Millisecond):
	}
	w.Close()
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the parent's going went unheard")
	}
}
