//go:build !freebsd && !freebsdman

package main

// Help on what serving and exit nodes do to the host, which differs by its
// service manager.
const (
	servesSetUp = "sets the host up with sudo where needed"
	exitFooter  = `An admin makes a device an exit node: juist grant DEVICE exit. It carries
only traffic to public addresses, so the LAN stays direct. It carries DNS
too, except for the LAN's own domain if systemd-resolved runs. If the exit
node cannot be used, traffic is refused, not sent directly.`
	exitUseAbout = `
Send this device's internet traffic and DNS through DEVICE. The LAN and the
network's devices stay direct. So do answers to connections from the
internet, such as ssh. --isolate sends those through DEVICE too; it refuses
if that would end the ssh session it runs in. If DEVICE cannot carry the
traffic, it is refused, not sent directly. --force chooses a DEVICE that
does not serve yet, or ends the session anyway.`
	exitServeAbout = `
Carry the network's internet traffic, if an admin made this device an exit
node. If the host does not forward yet, sudo sets that up and opens the
firewall for it. --stop stops and undoes it.`
	subnetServeAbout = `
Route the subnets the network grants this device, for the other members. If
the host does not forward yet, sudo sets that up and opens the firewall for
it. --stop stops and undoes it.`
)
