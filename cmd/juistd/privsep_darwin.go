package main

import (
	"strings"

	"github.com/nning/juist/internal/plumber"
)

// permHint is what gives a device's creation the right it lacked.
const permHint = `creating %q needs root: start juistd as root, which runs the daemon as _juist, the LaunchDaemon, or --tun ""`

// helperHost is what the root helper plumbs for the daemon of uid, and
// serviceStart what starts the packaged service.
func helperHost(uid int) plumber.Host { return plumber.Darwin{Daemon: uid} }

const serviceStart = "sudo launchctl kickstart -k system/io.nning.juist.juistd"

func addUserHint(as string) string {
	if as == defaultUser {
		return "curl -fsSL https://juist.nning.io/install | sh makes it"
	}
	return "sudo /Library/juist/setup.sh instance start " + strings.TrimPrefix(as, "_") + " makes it"
}
