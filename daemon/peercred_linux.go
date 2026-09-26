//go:build linux

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID reads the connecting process's user ID from the kernel.
//
// SO_PEERCRED is recorded at connect time, so it cannot be raced by the caller
// exec'ing something else afterwards. Android is GOOS=linux and uses this path
// too, though its IPC is in-process (docs/04-architecture.md).
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("daemon: reading peer credentials: %w", err)
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("daemon: reading peer credentials: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("daemon: SO_PEERCRED: %w", credErr)
	}
	return cred.Uid, nil
}

// peerCredSupported: the kernel reports every caller here.
const peerCredSupported = true
