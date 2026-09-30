//go:build freebsd || freebsdman

package defaults

// SystemHome is the packaged service's state directory, and TunPrivilege
// what creating a device takes.
const (
	SystemHome   = "/var/db/juist"
	TunPrivilege = "root, which juistd keeps for a helper and drops for the daemon"
)
