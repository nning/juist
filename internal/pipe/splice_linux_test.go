package pipe

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TCP to TCP moves within the kernel, whole; anything else is the caller's.
func TestTCPToTCPIsSpliced(t *testing.T) {
	a, in := tcpPair(t)
	out, b := tcpPair(t)
	want := make([]byte, 4<<20)
	rand.Read(want)
	go func() {
		a.Write(want)
		a.(*net.TCPConn).CloseWrite()
	}()
	var moved atomic.Bool
	got := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(b)
		got <- b
	}()
	rerr, werr, ok := splice(out, in, &moved)
	if !ok || rerr != nil || werr != nil {
		t.Fatalf("spliced %v: %v, %v", ok, rerr, werr)
	}
	out.(*net.TCPConn).CloseWrite()
	if b := <-got; !bytes.Equal(b, want) || !moved.Load() {
		t.Fatalf("%d bytes of %d arrived, moved %v", len(b), len(want), moved.Load())
	}
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	if _, _, ok := splice(x, in, &moved); ok {
		t.Error("spliced to what is no TCP connection")
	}
}

// pipes counts the pipes this process holds open.
func pipes(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	n := 0
	for _, fd := range fds {
		if l, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); strings.HasPrefix(l, "pipe:") {
			n++
		}
	}
	return n
}

// A spliced connection that went quiet holds no pipe: an ingress keeps
// thousands.
func TestAQuietSplicedJoinHoldsNoPipe(t *testing.T) {
	before := pipes(t)
	for range 20 {
		a, joinA := tcpPair(t)
		joinB, b := tcpPair(t)
		go Join(context.Background(), joinA, joinB, time.Minute)
		a.Write([]byte("x"))
		buf := make([]byte, 1)
		b.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(b, buf); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := pipes(t) - before; n > 0 {
		t.Errorf("20 quiet joins hold %d pipes", n)
	}
}

// A source reset rather than ended fails its way: the other end is closed,
// not told the stream ended whole.
func TestAResetSourceIsNoEnd(t *testing.T) {
	a, in := tcpPair(t)
	out, b := tcpPair(t)
	var moved atomic.Bool
	a.(*net.TCPConn).SetLinger(0)
	a.Close()
	time.Sleep(50 * time.Millisecond)
	rerr, werr, ok := splice(out, in, &moved)
	if !ok || rerr == nil || werr != nil {
		t.Fatalf("spliced %v: read %v, write %v; want the reset as the read's failure", ok, rerr, werr)
	}
	_ = b
}
