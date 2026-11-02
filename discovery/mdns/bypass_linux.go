//go:build linux && !android

package mdns

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

// markUnderlay keeps control-plane beacons out of discovery copies.
func markUnderlay(c syscall.RawConn) error {
	var setErr error
	if err := c.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tsconst.LinuxBypassMarkNum)
	}); err != nil {
		return err
	}
	if errors.Is(setErr, unix.EPERM) || errors.Is(setErr, unix.EACCES) {
		return nil
	}
	return setErr
}
