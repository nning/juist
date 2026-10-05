package rendezvous

import (
	"sync/atomic"
	"testing"

	"github.com/nning/juist/internal/underlay"
)

// The rendezvous socket leaves by the underlay, protected where a VPN would
// take it.
func TestTheRendezvousSocketIsProtected(t *testing.T) {
	var n atomic.Int64
	underlay.ProtectWith(func(uintptr) error { n.Add(1); return nil })
	t.Cleanup(func() { underlay.ProtectWith(nil) })
	s, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	if n.Load() != 1 {
		t.Errorf("%d sockets protected, want 1", n.Load())
	}
}
