package main

// privilegeText says what creating the device takes, and serviceFiles what
// runs the packaged service.
const privilegeText = `It creates a utun device and programs the host's routes, which needs root.
Started as root, it keeps a helper as root that creates juist's device,
sets its addresses and routes and destroys it, and runs the daemon as the
_juist user, which does the rest. With --tun "" it runs without a device,
as tests and a one-machine demo do.`

var serviceFiles = [2]string{"/Library/LaunchDaemons/io.nning.juist.juistd.plist", "The LaunchDaemon."}
