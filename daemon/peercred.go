package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// checkPeerCred verifies who is on the other end of an IPC connection. The
// socket's 0600 mode in a 0700 directory is the primary control; this still
// holds if the directory is loosened while the daemon runs, which a
// mode-only defence cannot detect. Only the user running the daemon, or root,
// may call it.
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
