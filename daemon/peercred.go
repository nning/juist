package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// checkPeerCred verifies who is on the other end of an IPC connection.
//
// docs/04-architecture.md requires it: "peer identity verified via SO_PEERCRED
// (Linux) / LOCAL_PEERCRED (FreeBSD)". The socket's 0600 mode inside a 0700
// directory is the primary control, and this is what makes it a check rather
// than an assumption — it still holds if the directory's mode is loosened
// while the daemon is running, which is exactly the state a file-mode-only
// defence cannot detect.
//
// The policy is narrow because the daemon's authority is narrow: only the user
// running the daemon, or root, may call it. There is nothing here worth
// delegating — the daemon holds no admin keys and cannot authorize a
// membership change (docs/04-architecture.md, key custody).
func checkPeerCred(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		// Only a unix socket is ever listened on, so this means a test
		// substituted something. Refuse rather than skip the check.
		return fmt.Errorf("daemon: ipc connection is %T, not a unix socket", c)
	}
	uid, err := peerUID(uc)
	if errors.Is(err, errPeerCredUnsupported) {
		// Documented per platform in peercred_other.go: the file mode is
		// the control there. Not a reason to refuse the call.
		return nil
	}
	if err != nil {
		return err
	}
	if self := uint32(os.Getuid()); uid != self && uid != 0 {
		return fmt.Errorf("daemon: refusing an ipc call from uid %d; this daemon runs as uid %d", uid, self)
	}
	return nil
}

// errPeerCredUnsupported reports a platform with no credential-passing call
// wired up here.
var errPeerCredUnsupported = errors.New("daemon: peer credentials are not available on this platform")
