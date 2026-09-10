// Package nettest gates tests on host network features CI's Linux runners
// have and a macOS or BSD laptop does not: each gate skips with its reason,
// or fails when [RequireEnv] is set.
package nettest

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

// RequireEnv is the environment variable that turns every skip in this
// package into a failure. Separate from conn's JUIST_REQUIRE_OS_PLUMBING,
// which gates root and a real device and is set by a different CI job.
const RequireEnv = "JUIST_REQUIRE_HOST_NET"

// SkipUnlessRequired skips t with the given reason, or fails it when
// [RequireEnv] is set.
func SkipUnlessRequired(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(RequireEnv) != "" {
		t.Fatalf("%s is set, but: %s", RequireEnv, fmt.Sprintf(format, args...))
	}
	t.Skipf(format, args...)
}

// HasLoopbackAddr reports whether the host accepts a bind to addr. Linux
// makes all of 127.0.0.0/8 local; macOS and the BSDs configure 127.0.0.1
// alone.
func HasLoopbackAddr(addr netip.Addr) bool {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: addr.AsSlice()})
	if err != nil {
		return false
	}
	c.Close()
	return true
}
