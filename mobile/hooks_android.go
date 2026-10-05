package mobile

import (
	"fmt"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"

	"github.com/nning/juist/internal/underlay"
)

// protectBy keeps the core's sockets on the underlay out of the tunnel by p:
// the data plane's through netns, the DHT's, the rendezvous's and the join's
// through underlay.
func protectBy(p Platform) {
	protect := func(fd int) error {
		if !p.Protect(int32(fd)) {
			return fmt.Errorf("VpnService.protect refused descriptor %d", fd)
		}
		return nil
	}
	netns.SetAndroidProtectFunc(protect)
	underlay.ProtectWith(func(fd uintptr) error { return protect(int(fd)) })
}

// defaultRouteVia records the interface Android routes the internet by,
// which netmon cannot read from the kernel in an app.
func defaultRouteVia(iface string) { netmon.UpdateLastKnownDefaultRouteInterface(iface) }
