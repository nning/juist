//go:build darwin || freebsd

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID reads the connecting process's user ID with LOCAL_PEERCRED, the BSD
// equivalent of SO_PEERCRED. Like it, the credentials are those recorded when
// the connection was made.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("daemon: reading peer credentials: %w", err)
	}
	var (
		cred    *unix.Xucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("daemon: reading peer credentials: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("daemon: LOCAL_PEERCRED: %w", credErr)
	}
	return cred.Uid, nil
}

// peerCredSupported: the kernel reports every caller here.
const peerCredSupported = true
