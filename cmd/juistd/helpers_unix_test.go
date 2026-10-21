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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

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

// An answer from the binder carrying other than one descriptor whole, in one
// message, is no listener and leaves none of what arrived open.
func TestABindersExtraDescriptorsAreClosed(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	dup := func() int {
		fd, err := unix.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		return fd
	}
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sp[0])
	defer unix.Close(sp[1])
	// sent is what a read with room for room bytes of control messages
	// takes of oob sent, and its flags.
	sent := func(oob []byte, room int) ([]byte, int) {
		if err := unix.Sendmsg(sp[0], []byte{0}, oob, nil, 0); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, room)
		_, oobn, flags, _, err := unix.Recvmsg(sp[1], make([]byte, 1), got, 0)
		if err != nil {
			t.Fatal(err)
		}
		return got[:oobn], flags
	}
	carried := func(oob []byte) []int {
		var fds []int
		for len(oob) >= unix.CmsgLen(0) {
			hdr, data, rest, err := unix.ParseOneSocketControlMessage(oob)
			if err != nil {
				break
			}
			got, _ := unix.ParseUnixRights(&unix.SocketControlMessage{Header: hdr, Data: data})
			fds, oob = append(fds, got...), rest
		}
		return fds
	}
	one, flags := sent(unix.UnixRights(dup()), unix.CmsgSpace(4*4))
	if f := receivedFile(one, flags, "one"); f == nil {
		t.Fatal("one descriptor was not taken")
	} else {
		f.Close()
	}
	unreadable := make([]byte, unix.CmsgSpace(0))
	(*unix.Cmsghdr)(unsafe.Pointer(&unreadable[0])).SetLen(1 << 20)
	twoInOne, twoFlags := sent(unix.UnixRights(dup(), dup()), unix.CmsgSpace(4*4))
	truncated, truncFlags := sent(unix.UnixRights(dup(), dup()), unix.CmsgLen(4))
	if truncFlags&unix.MSG_CTRUNC == 0 {
		t.Fatal("a read with room for one descriptor of two was not truncated")
	}
	// Linux keeps the descriptors that fit, FreeBSD none of them.
	truncKept := len(carried(truncated))
	if truncKept > 1 {
		t.Fatalf("a read with room for one descriptor carried %d", truncKept)
	}
	for _, tc := range []struct {
		name  string
		oob   []byte
		flags int
		want  int
	}{
		{"two in one message", twoInOne, twoFlags, 2},
		{"one in each of two", slices.Concat(unix.UnixRights(dup()), unix.UnixRights(dup())), 0, 2},
		{"one before an unreadable message", slices.Concat(unix.UnixRights(dup()), unreadable), 0, 1},
		{"one of two, truncated", truncated, truncFlags, truncKept},
	} {
		fds := carried(tc.oob)
		if len(fds) != tc.want {
			t.Fatalf("%s: %d descriptors carried, want %d", tc.name, len(fds), tc.want)
		}
		if f := receivedFile(tc.oob, tc.flags, tc.name); f != nil {
			f.Close()
			t.Errorf("%s: taken as a listener", tc.name)
		}
		for _, fd := range fds {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				unix.Close(fd)
				t.Errorf("%s: descriptor %d left open", tc.name, fd)
			}
		}
	}
}

// A child that dies of the stop it was asked to make stopped as asked; one
// that exits failing, is killed, or was not asked did not.
func TestAStopAskedForIsNoFailure(t *testing.T) {
	exited := func(sig syscall.Signal, script string) error {
		cmd := exec.Command("sh", "-c", script)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if sig != 0 {
			cmd.Process.Signal(sig)
		}
		return cmd.Wait()
	}
	term, kill, failed := exited(syscall.SIGTERM, "exec sleep 60"), exited(syscall.SIGKILL, "exec sleep 60"), exited(0, "exit 1")
	if err := stoppedAsAsked(term, true); err != nil {
		t.Errorf("stopped by the stop asked for: %v", err)
	}
	for _, c := range []struct {
		name  string
		err   error
		asked bool
	}{{"stopped unasked", term, false}, {"killed", kill, true}, {"failing", failed, true}} {
		if stoppedAsAsked(c.err, c.asked) == nil {
			t.Errorf("%s (%v), taken as stopped", c.name, c.err)
		}
	}
}
