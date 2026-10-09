package relay

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRefusedHandshakesAreLoggedOncePerInterval(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	now := time.Unix(1_800_000_000, 0)
	l := newServerErrorLog(logf, func() time.Time { return now })
	for range 500 {
		l.Print("http: TLS handshake error from 192.0.2.1:4000: remote error: tls: bad certificate")
	}
	l.Print("http: Accept error: too many open files")
	now = now.Add(handshakeLogEvery)
	l.Print("http: TLS handshake error from 192.0.2.1:4001: remote error: tls: bad certificate")
	if len(lines) != 3 {
		t.Fatalf("logged %d lines, want 3:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[2], "499 more") {
		t.Fatalf("the next handshake line does not count the ones left out: %q", lines[2])
	}
	if !strings.Contains(lines[1], "Accept error") {
		t.Fatalf("another server error was held back: %q", lines[1])
	}
}
