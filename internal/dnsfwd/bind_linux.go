//go:build linux

package dnsfwd

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func bindTo(c syscall.RawConn, device string) error {
	var err error
	cerr := c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1); err != nil {
			if err = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1); err != nil {
				return
			}
		}
		if device != "" {
			err = unix.BindToDevice(int(fd), device)
		}
	})
	if cerr != nil {
		return cerr
	}
	return err
}
