//go:build !freebsd && !freebsdman

package main

// privilegeText says what creating the device takes, and serviceFiles what
// runs the packaged service.
const privilegeText = `It creates a real TUN device and programs the host's routes, which needs
/dev/net/tun and CAP_NET_ADMIN; the packaged service runs it as the juist
user with that capability and no other. With --tun "" it runs without a
device, as tests and a one-machine demo do.`

var serviceFiles = [2]string{"juistd.service, juistd@.service", "The systemd units."}
