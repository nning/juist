//go:build !freebsd && !freebsdman

package main

// Help on what serving and exit nodes do to the host, which differs by its
// service manager.
const (
	servesSetUp = "sets the host up with sudo where needed"
	exitFooter  = `An admin makes a device an exit node: juist grant DEVICE exit. It
carries public addresses alone, so the LAN stays direct; where
systemd-resolved runs, it takes DNS too, but for the LAN's own domain. Where
it cannot be used, traffic is refused, not sent directly.`
	exitUseAbout = `
Send this device's internet traffic through DEVICE, and its DNS too where
systemd-resolved runs. The LAN and the network's devices stay direct, and so
do answers to connections from the internet, as to ssh; --isolate sends those
through DEVICE too, and stops where that would end the ssh session it runs
in. Where DEVICE cannot carry the traffic, it is refused, not sent directly;
--force chooses one that does not serve yet, or ends the session.`
	exitServeAbout = `
Carry the network's internet traffic, where an admin made this device an
exit node. Where the host does not forward yet, sudo sets that up and lets
the traffic through the firewall; --stop stops, and undoes it.`
	subnetServeAbout = `
Route the subnets the network grants this device for its members. Where the
host does not forward yet, sudo sets that up and lets the traffic through
the firewall; --stop stops, and undoes it.`
)
