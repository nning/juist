package forward

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/underlay"
)

// The dial to a member's relay leaves by the underlay, protected where a VPN
// would take it.
func TestTheDialToTheRelayIsProtected(t *testing.T) {
	var n atomic.Int64
	underlay.ProtectWith(func(uintptr) error { n.Add(1); return nil })
	t.Cleanup(func() { underlay.ProtectWith(nil) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	_, _, _ = dial(context.Background(), []netip.AddrPort{ln.Addr().(*net.TCPAddr).AddrPort()}, "/",
		&tls.Config{InsecureSkipVerify: true}, time.Second)
	if n.Load() != 1 {
		t.Errorf("%d sockets protected, want 1", n.Load())
	}
}
