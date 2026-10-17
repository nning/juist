//go:build !linux && !darwin && !freebsd

package daemon

import "net"

// peerUID has no implementation on this platform, so the IPC socket's 0600
// mode inside a 0700 directory is the whole control. Every platform v1 commits
// to (docs/05-roadmap.md M25: Linux, FreeBSD, Android) has a real
// implementation above; this exists so the package still builds elsewhere
// rather than silently dropping the check on a platform that has one.
func peerUID(*net.UnixConn) (uint32, error) { return 0, errPeerCredUnsupported }

// peerCredSupported: nothing reports callers here, so the socket is 0600.
const peerCredSupported = false
