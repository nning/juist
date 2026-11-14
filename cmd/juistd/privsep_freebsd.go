package main

import "github.com/nning/juist/internal/plumber"

// permHint is what gives a device's creation the right it lacked.
const permHint = `creating %q needs root: start juistd as root, which runs the daemon as juist, the packaged service, or --tun ""`

// helperHost is what the root helper plumbs for a daemon, and serviceStart
// what starts the packaged service.
func helperHost(int) plumber.Host { return plumber.FreeBSD{} }

const serviceStart = "service juistd start"

func addUserHint(as string) string {
	return "pw useradd " + as + " -d /var/db/" + as + " -s /usr/sbin/nologin, a system user, as the package makes it"
}
