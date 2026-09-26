package daemon

import (
	"errors"
	"fmt"
	"net"
)

// peerOf identifies the process on the other end of an IPC connection. Only a
// unix socket is ever listened on, so anything else means a test substituted
// something, and is refused rather than waved through.
func peerOf(c net.Conn) (caller, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return caller{}, fmt.Errorf("daemon: ipc connection is %T, not a unix socket", c)
	}
	uid, err := peerUID(uc)
	if errors.Is(err, errPeerCredUnsupported) {
		// Documented in peercred_other.go: the socket is 0600 there.
		return caller{}, nil
	}
	if err != nil {
		return caller{}, err
	}
	return caller{uid: uid, known: true}, nil
}

// errPeerCredUnsupported reports a platform with no credential-passing call
// wired up here.
var errPeerCredUnsupported = errors.New("daemon: peer credentials are not available on this platform")
