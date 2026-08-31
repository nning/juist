//go:build unix

package mdns

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseAddr lets the mDNS port be shared.
//
// 5353 is a well-known port that every mDNS responder on the host binds, so a
// socket that demands it exclusively either fails to start or breaks whatever
// was already there. SO_REUSEPORT is set as well where it exists, because on
// the BSDs SO_REUSEADDR alone does not permit two sockets on one wildcard
// address and port; a kernel without it simply reports an error we ignore, and
// SO_REUSEADDR carries the case on its own.
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
