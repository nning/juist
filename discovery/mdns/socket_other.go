//go:build !unix

package mdns

import "syscall"

// reuseAddr has no implementation here, so binding the mDNS port is exclusive
// and will fail if another responder already holds it. Every platform v1
// commits to (docs/05-roadmap.md M32) is a unix and uses the real one above.
func reuseAddr(_, _ string, _ syscall.RawConn) error { return nil }
