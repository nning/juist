//go:build !linux || android

package conn

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
	_ "tailscale.com/wgengine/router/osrouter" // registers the OS router router.New builds
)

// closeUnstartedRouter does nothing: Tailscale's routers may panic when closed
// before Up.
func closeUnstartedRouter(router.Router) {}

func newOSRouter(logf logger.Logf, dev tun.Device, mon *netmon.Monitor, ht *health.Tracker, bus *eventbus.Bus) (router.Router, error) {
	return router.New(logf, dev, mon, ht, bus)
}
