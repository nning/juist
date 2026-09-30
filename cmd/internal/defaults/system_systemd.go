//go:build !freebsd && !freebsdman

package defaults

// SystemHome is the packaged service's state directory, and TunPrivilege
// what creating a device takes.
const (
	SystemHome   = "/var/lib/juist"
	TunPrivilege = "CAP_NET_ADMIN"
)
