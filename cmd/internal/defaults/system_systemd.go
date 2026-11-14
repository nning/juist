//go:build !freebsd && !freebsdman && !darwin

package defaults

// SystemHome is the packaged service's state directory, SystemUser the
// user its daemon runs as, and TunPrivilege what creating a device takes.
const (
	SystemHome   = "/var/lib/juist"
	SystemUser   = "juist"
	TunPrivilege = "CAP_NET_ADMIN"
)
