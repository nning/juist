package ingress

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
)

// banner is a service that speaks first, as SSH or SMTP do, then echoes.
type banner struct {
	ln       net.Listener
	got      chan []byte
	accepted chan struct{}
}

func newBanner(t *testing.T) *banner {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &banner{ln: ln, got: make(chan []byte, 8), accepted: make(chan struct{}, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted <- struct{}{}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("hello\n"))
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						b.got <- slices.Clone(buf[:n])
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return b
}

func (b *banner) published(name string, public uint16, proxy bool) ipc.PublishedTarget {
	ap := b.ln.Addr().(*net.TCPAddr).AddrPort()
	return ipc.PublishedTarget{Name: name, Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port(), Proxy: proxy, Public: public}
}

// freePort is a port nothing listens on at 127.0.0.1 just now.
func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// loopback binds public ports on 127.0.0.1, where a test reaches them.
func loopback(port uint16) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
}

func at(port uint16) string { return "127.0.0.1:" + strconv.Itoa(int(port)) }

// dialRead connects to port and reads n bytes.
func dialRead(t *testing.T, port uint16, n int) (net.Conn, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", at(port))
	if err != nil {
		t.Fatalf("dialing the public port: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("reading from the public port: %v", err)
	}
	return c, buf
}

// A name published by TCP is passed on its public port at once, the
// service speaking first, and both ways after; another port takes nothing.
func TestAPortPassesTCPAtOnce(t *testing.T) {
	b := newBanner(t)
	public := freePort(t)
	src := &source{p: &ipc.Published{TCP: []ipc.PublishedTarget{b.published("mc.pub.example.org", public, false)}}}
	startIngressWith(t, src, Options{Listen: loopback})
	c, got := dialRead(t, public, 6)
	if string(got) != "hello\n" {
		t.Fatalf("the client got %q first", got)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got := <-b.got; string(got) != "ping" {
		t.Errorf("the service got %q", got)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(c, echo); err != nil || string(echo) != "ping" {
		t.Errorf("the client got %q back, %v", echo, err)
	}
	waitFor(t, "the port said to be listened on", func() bool {
		return slices.Equal(src.report().Listening, []uint16{public})
	})
}

// Where the name asks for it, the service learns the client's address from
// a PROXY protocol v2 header, before anything else.
func TestAPortSaysWhoTheClientIs(t *testing.T) {
	tg := newTarget(t)
	public := freePort(t)
	pt := tg.published("mc.pub.example.org", true)
	pt.Public = public
	src := &source{p: &ipc.Published{TCP: []ipc.PublishedTarget{pt}}}
	startIngressWith(t, src, Options{Listen: loopback})
	c, err := net.Dial("tcp", at(public))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	got := <-tg.got
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x7f\x00\x00\x01")
	if !bytes.HasPrefix(got, sig) || len(got) != 29 || got[28] != 'x' {
		t.Fatalf("the service got %q", got)
	}
}

// A name withdrawn, or moved to another port, ends its connections, and a
// port no name is published on any longer is closed, which juistd hears.
func TestAWithdrawnPortCloses(t *testing.T) {
	b := newBanner(t)
	public, moved := freePort(t), freePort(t)
	src := &source{p: &ipc.Published{TCP: []ipc.PublishedTarget{b.published("mc.pub.example.org", public, false)}}}
	startIngressWith(t, src, Options{Listen: loopback})
	c, _ := dialRead(t, public, 6)

	src.set(&ipc.Published{TCP: []ipc.PublishedTarget{b.published("mc.pub.example.org", moved, false)}})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection on the port the name left: %v", err)
	}
	waitFor(t, "the new port listened on", func() bool { return slices.Equal(src.report().Listening, []uint16{moved}) })
	c, _ = dialRead(t, moved, 6)
	waitFor(t, "the old port closed", func() bool {
		d, err := net.Dial("tcp", at(public))
		if err == nil {
			d.Close()
		}
		return err != nil
	})

	src.set(&ipc.Published{})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection for a withdrawn name: %v", err)
	}
	waitFor(t, "no port said to be listened on", func() bool { return len(src.report().Listening) == 0 })
	if d, err := net.Dial("tcp", at(moved)); err == nil {
		d.Close()
		t.Error("the withdrawn name's port still takes connections")
	}
}

// A juistd that stops answering ends the connections, and the public port
// is held still, serving nothing, so that no other program takes what the
// host's firewall lets in; a name whose target does not serve it is held
// so too.
func TestASilentJuistdHoldsThePorts(t *testing.T) {
	b := newBanner(t)
	public, idle := freePort(t), freePort(t)
	unserved := b.published("game.pub.example.org", idle, false)
	unserved.Addrs = nil
	src := &source{p: &ipc.Published{TCP: []ipc.PublishedTarget{b.published("mc.pub.example.org", public, false), unserved}}}
	var l lines
	startIngressWith(t, src, Options{Listen: loopback, Access: l.add})
	waitFor(t, "both ports listened on", func() bool { return len(src.report().Listening) == 2 })
	closedAtOnce := func(port uint16) {
		t.Helper()
		c, err := net.Dial("tcp", at(port))
		if err != nil {
			t.Fatalf("port %d is not held: %v", port, err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n > 0 || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("port %d served: %d, %v", port, n, err)
		}
	}
	closedAtOnce(idle)
	l.find(t, fmt.Sprintf(` %d "game.pub.example.org" not served`, idle))

	c, _ := dialRead(t, public, 6)
	src.mu.Lock()
	src.silent = true
	src.mu.Unlock()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a connection with juistd silent: %v", err)
	}
	closedAtOnce(public)
	if r := src.report(); len(r.Listening) != 2 {
		t.Errorf("silent, the ingress said it listens on %v", r.Listening)
	}
}

// A public port another program holds is said to juistd and logged once,
// and taken once it is free.
func TestAPortAnotherProgramHoldsIsSaid(t *testing.T) {
	b := newBanner(t)
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	public := uint16(held.Addr().(*net.TCPAddr).Port)
	src := &source{p: &ipc.Published{TCP: []ipc.PublishedTarget{b.published("mc.pub.example.org", public, false)}}}
	var logged lines
	startIngressWith(t, src, Options{Listen: loopback, Logf: logged.add})
	waitFor(t, "the port said to be held", func() bool { return slices.Equal(src.report().Unbound, []uint16{public}) })
	logged.find(t, fmt.Sprintf("ingress: listening on port %d for mc.pub.example.org", public))
	held.Close()
	waitFor(t, "the port taken once free", func() bool {
		r := src.report()
		return len(r.Unbound) == 0 && slices.Equal(r.Listening, []uint16{public})
	})
	logged.mu.Lock()
	n := 0
	for _, l := range logged.got {
		if bytes.Contains([]byte(l), []byte("listening on port")) {
			n++
		}
	}
	logged.mu.Unlock()
	if n != 1 {
		t.Errorf("said %d times", n)
	}
	dialRead(t, public, 6)
}

// Each connection on a public port is logged with its client, port, name,
// outcome, bytes and duration; one host holds a few at once there too.
func TestAPortLogsAndBoundsEachConnection(t *testing.T) {
	b := newBanner(t)
	public := freePort(t)
	src := &source{p: &ipc.Published{TCP: []ipc.PublishedTarget{b.published("mc.pub.example.org", public, false)}}}
	var l lines
	startIngressWith(t, src, Options{Listen: loopback, Access: l.add, MaxPerSource: 1})
	c, _ := dialRead(t, public, 6)
	<-b.accepted
	second, err := net.Dial("tcp", at(public))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a second connection from the host: %v", err)
	}
	l.find(t, "access: tcp 127.0.0.1:", fmt.Sprintf(" %d refused: too many connections from it", public))
	select {
	case <-b.accepted:
		t.Error("the service took the second connection")
	default:
	}
	c.Close()
	l.find(t, "access: tcp 127.0.0.1:", fmt.Sprintf(` %d "mc.pub.example.org" spliced up=0 down=6 `, public))
}
