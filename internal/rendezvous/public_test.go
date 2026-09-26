package rendezvous

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

// TestMeetingThroughThePublicDHT meets through the real DHT and public STUN
// servers. It needs the internet, so it runs only when asked:
//
//	JUIST_PUBLIC_TESTS=1 go test -run PublicDHT -v ./internal/rendezvous
func TestMeetingThroughThePublicDHT(t *testing.T) {
	if os.Getenv("JUIST_PUBLIC_TESTS") == "" {
		t.Skip("set JUIST_PUBLIC_TESTS=1 to use the public DHT and STUN servers")
	}
	o := Options{Keys: testKeys(t), STUN: []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}, Logf: t.Logf}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	ln, err := Listen(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Logf("the host joined the DHT after %v", time.Since(start).Round(time.Second))
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	c, err := Dial(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("met after %v at %v", time.Since(start).Round(time.Second), c.RemoteAddr())
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s := <-got; s != "hello" {
		t.Fatalf("the host read %q", s)
	}
}
