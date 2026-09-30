//go:build !freebsd

package conn

import (
	"errors"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"
)

// tunNeeds is what creating a device takes here.
const tunNeeds = "/dev/net/tun and CAP_NET_ADMIN"

func newPlumbed(Plumber, string, int, int, logger.Logf) (tun.Device, router.Router, error) {
	return nil, nil, errors.New("conn: a plumber is FreeBSD's alone")
}
