//go:build !freebsd && !freebsdman

package main

// Help on what serving and exit nodes do to the host, which differs by its
// service manager.
const (
	servesSetUp = "sets the host up with sudo where needed"
	exitFooter  = `An admin makes a device an exit node: juist grant DEVICE exit. It carries
traffic to public addresses and DNS (but not the LAN's domain where
systemd-resolved runs); the LAN stays direct. If the exit node cannot be
used, traffic is refused, not sent directly.`
	exitUseAbout = `
Send this device's internet traffic and DNS through DEVICE. The LAN, the
network, and answers to connections from the internet (such as ssh) stay
direct; --isolate sends those through DEVICE too, unless that would end the
ssh session it runs in. If DEVICE cannot carry the traffic, it is refused,
not sent directly. --force uses a DEVICE that does not serve yet, or ends
the session anyway.`
	exitServeAbout = `
Carry the network's internet traffic, if an admin made this device an exit
node. Sets up forwarding and the firewall with sudo where needed. --stop
stops and undoes it.`
	subnetServeAbout = `
Route the subnets the network grants this device, for the other members.
Sets up forwarding and the firewall with sudo where needed. --stop stops and
undoes it.`
)
