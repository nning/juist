//go:build freebsd || freebsdman

package defaults

// SystemHome is the packaged service's state directory, SystemUser the
// user its daemon runs as, and TunPrivilege what creating a device takes.
const (
	SystemHome   = "/var/db/juist"
	SystemUser   = "juist"
	TunPrivilege = "root, which juistd keeps for a helper and drops for the daemon"
)
