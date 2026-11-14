//go:build freebsd || darwin

package dnsfwd

import "syscall"

// bindTo binds to no device: FreeBSD has no binding a socket to one, and the
// exit node's pf anchor takes the forwarder's port by the tunnel alone; on
// macOS the resolver listens at the device's own addresses alone.
func bindTo(syscall.RawConn, string) error { return nil }
