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

// newOSRouter ignores the instance: Tailscale's router here routes in the
// host's one table, so instances are kept apart by their prefixes alone.
func newOSRouter(logf logger.Logf, dev tun.Device, mon *netmon.Monitor, ht *health.Tracker, bus *eventbus.Bus,
	_ int) (router.Router, error) {
	return router.New(logf, dev, mon, ht, bus)
}

// ClearEgress does nothing: this platform's router routes no exit node.
func ClearEgress(int) error { return nil }

// RefuseEgress refuses nothing: no platform but Linux uses an exit node.
func RefuseEgress(int) error { return nil }
