package dht

import (
	"sync/atomic"
	"testing"

	"github.com/nning/juist/internal/underlay"
)

// The DHT's socket leaves by the underlay, protected where a VPN would take it.
func TestTheDHTSocketIsProtected(t *testing.T) {
	var n atomic.Int64
	underlay.ProtectWith(func(uintptr) error { n.Add(1); return nil })
	t.Cleanup(func() { underlay.ProtectWith(nil) })
	s, err := newStore(nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if n.Load() != 1 {
		t.Errorf("%d sockets protected, want 1", n.Load())
	}
}
