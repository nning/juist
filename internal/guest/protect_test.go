package guest

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/nning/juist/internal/underlay"
)

// The join's dial leaves by the underlay, protected where a VPN would take it.
func TestTheDialToTheHostIsProtected(t *testing.T) {
	var n atomic.Int64
	underlay.ProtectWith(func(uintptr) error { n.Add(1); return nil })
	t.Cleanup(func() { underlay.ProtectWith(nil) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := direct([]netip.AddrPort{ln.Addr().(*net.TCPAddr).AddrPort()})[0](context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if n.Load() != 1 {
		t.Errorf("%d sockets protected, want 1", n.Load())
	}
}
