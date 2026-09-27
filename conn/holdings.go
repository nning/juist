package conn

import "net/netip"

// A Holding is what another juist instance on this host has put into the
// kernel: the addresses on its device and the routes in its table. Two
// instances whose networks claim one address cannot both route it — the
// lower instance's table wins — so an instance checks these before it
// starts; see [InstanceHoldings].
type Holding struct {
	// Instance is the instance's number, and Device its TUN device.
	Instance int
	Device   string

	// Prefixes are single-host prefixes for its addresses, and its routes as
	// installed.
	Prefixes []netip.Prefix
}
