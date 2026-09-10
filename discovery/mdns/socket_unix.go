//go:build unix

package mdns

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseAddr lets the mDNS port be shared: every responder on the host binds
// 5353, so demanding it exclusively either fails or breaks whatever was there.
// SO_REUSEPORT is set as well where it exists, because on the BSDs
// SO_REUSEADDR alone does not permit two sockets on one wildcard address.
func reuseAddr(_, _ string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			setErr = err
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}
