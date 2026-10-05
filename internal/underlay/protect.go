package underlay

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

var protect atomic.Pointer[func(fd uintptr) error]

// ProtectWith has f keep every socket the core opens on the underlay out of a
// VPN that routes more than the overlay, as Android's VpnService.protect
// does; nil protects none. Set it before the first such socket opens.
func ProtectWith(f func(fd uintptr) error) {
	if f == nil {
		protect.Store(nil)
		return
	}
	protect.Store(&f)
}

// Control is a [net.Dialer]'s or [net.ListenConfig]'s Control for a socket on
// the underlay: it protects the socket where [ProtectWith] says how.
func Control(_, _ string, c syscall.RawConn) error {
	f := protect.Load()
	if f == nil {
		return nil
	}
	var err error
	if cerr := c.Control(func(fd uintptr) { err = (*f)(fd) }); cerr != nil {
		return cerr
	}
	return err
}

// ListenPacket is [net.ListenPacket] on the underlay.
func ListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: Control}
	return lc.ListenPacket(context.Background(), network, address)
}

// Dialer dials on the underlay, giving up after timeout.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: Control}
}
