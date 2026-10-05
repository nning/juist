//go:build !android

package mobile

// protectBy and defaultRouteVia have nothing to do off Android, where no VPN
// routes the core's own sockets and netmon reads the routes itself.
func protectBy(Platform) {}

func defaultRouteVia(string) {}
