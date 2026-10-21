package pipe

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// tcpPair is two ends of one TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// A transfer one way longer than the idle time goes through whole, its other
// way quiet and open; a connection quiet both ways is closed.
func TestJoinIdlesBothWaysAtOnce(t *testing.T) {
	client, inA := tcpPair(t)
	inB, server := tcpPair(t)
	idle := 100 * time.Millisecond
	done := make(chan struct{})
	go func() {
		Join(context.Background(), inA, inB, idle)
		close(done)
	}()
	go func() {
		chunk := make([]byte, 1024)
		for end := time.Now().Add(5 * idle); time.Now().Before(end); time.Sleep(idle / 5) {
			if _, err := server.Write(chunk); err != nil {
				return
			}
		}
		server.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(client)
	if err != nil || len(got) < 20*1024 {
		t.Fatalf("the client got %d bytes, %v", len(got), err)
	}
	// The quiet way stayed open: the server still hears the client.
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := server.Read(make([]byte, 1)); n != 1 {
		t.Fatalf("the quiet way was closed: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a connection quiet both ways stays")
	}
}

// A way that fails ends both at once, not at the idle time.
func TestAFailedWayEndsBoth(t *testing.T) {
	client, inA := tcpPair(t)
	inB, server := tcpPair(t)
	done := make(chan struct{})
	go func() {
		Join(context.Background(), inA, inB, time.Minute)
		close(done)
	}()
	_ = inA.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a failed way left the other open")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Error("the server's way is open")
	}
	_ = client
}

// A way that cannot write half-closes, and what the other way carries still
// arrives whole.
func TestAWayThatCannotWriteLetsTheOtherFinish(t *testing.T) {
	client, inA := tcpPair(t)
	inB, server := tcpPair(t)
	_ = inB.(*net.TCPConn).CloseWrite() // writes to the server fail from here on
	go Join(context.Background(), inA, inB, time.Minute)
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	answer := make([]byte, 1<<20)
	for i := range answer {
		answer[i] = byte(i)
	}
	go func() {
		_, _ = server.Write(answer)
		server.Close()
	}()
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, _ := io.ReadAll(client)
	if len(got) != len(answer) {
		t.Errorf("the client got %d of the answer's %d bytes", len(got), len(answer))
	}
}

// What a way carries arrives whole and in order, in bursts and trickles.
func TestJoinCarriesEverything(t *testing.T) {
	a, joinA := tcpPair(t)
	joinB, b := tcpPair(t)
	go Join(context.Background(), joinA, joinB, time.Minute)
	want := make([]byte, 3<<20)
	rand.Read(want)
	go func() {
		for i := 0; i < len(want); {
			n := min(len(want)-i, 1+i%(70<<10))
			a.Write(want[i : i+n])
			i += n
		}
		a.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%d bytes of %d arrived, equal %v: %v", len(got), len(want), bytes.Equal(got, want), err)
	}
}

// A quiet connection holds no large buffer: an ingress keeps thousands.
func TestAQuietJoinHoldsLittle(t *testing.T) {
	const n = 200
	var ends []net.Conn
	t.Cleanup(func() {
		for _, c := range ends {
			c.Close()
		}
	})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range n {
		a, joinA := net.Pipe()
		joinB, b := net.Pipe()
		ends = append(ends, a, b, joinA, joinB)
		go Join(context.Background(), joinA, joinB, time.Minute)
		a.Write([]byte("x"))
		buf := make([]byte, 1)
		io.ReadFull(b, buf)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if per := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n; per > 16<<10 {
		t.Errorf("a quiet join holds %d bytes", per)
	}
}
