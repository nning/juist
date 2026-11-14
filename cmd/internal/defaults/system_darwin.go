package defaults

// SystemHome is the packaged service's state directory, SystemUser the
// user its daemon runs as, and TunPrivilege what creating a device takes.
const (
	SystemHome   = "/var/db/juist"
	SystemUser   = "_juist"
	TunPrivilege = "root"
)
