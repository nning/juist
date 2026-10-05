package mdns

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/nning/juist/internal/underlay"
)

// The mDNS socket is protected where a VPN would take it.
func TestTheMulticastSocketIsProtected(t *testing.T) {
	var n atomic.Int64
	underlay.ProtectWith(func(uintptr) error { n.Add(1); return nil })
	t.Cleanup(func() { underlay.ProtectWith(nil) })
	pc, err := listenMulticast(netip.MustParseAddrPort("224.0.0.251:0"), "")
	if err != nil {
		t.Skipf("no multicast here: %v", err)
	}
	pc.Close()
	if n.Load() != 1 {
		t.Errorf("%d sockets protected, want 1", n.Load())
	}
}
