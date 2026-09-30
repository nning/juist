//go:build freebsd || freebsdman

package main

// privilegeText says what creating the device takes, and serviceFiles what
// runs the packaged service.
const privilegeText = `It creates a real TUN device and programs the host's routes, which needs
root. Started as root, it keeps a helper as root that creates juist's
devices, sets their addresses and routes and destroys them, and runs the
daemon as the juist user, which does the rest. With --tun "" it runs
without a device, as tests and a one-machine demo do.`

var serviceFiles = [2]string{"/usr/local/etc/rc.d/juistd", "The rc.d script: juistd_enable, and juistd_instances for the others."}
