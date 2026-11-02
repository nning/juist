//go:build linux && !android

package mdns

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

func TestTheBeaconSocketStaysOnTheUnderlay(t *testing.T) {
	c, err := listenMulticast(netip.MustParseAddrPort("224.0.0.251:0"), "")
	if err != nil {
		t.Skipf("multicast socket unavailable: %v", err)
	}
	defer c.Close()
	rc, err := c.(*groupConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var readErr error
	if err := rc.Control(func(fd uintptr) { mark, readErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) }); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	if mark == 0 {
		var setErr error
		if err := rc.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tsconst.LinuxBypassMarkNum)
		}); err != nil {
			t.Fatal(err)
		}
		if errors.Is(setErr, unix.EPERM) || errors.Is(setErr, unix.EACCES) {
			t.Skip("SO_MARK needs CAP_NET_ADMIN or CAP_NET_RAW")
		}
		if setErr != nil {
			t.Fatal(setErr)
		}
	}
	if mark != tsconst.LinuxBypassMarkNum {
		t.Fatalf("socket mark %x", mark)
	}
}
