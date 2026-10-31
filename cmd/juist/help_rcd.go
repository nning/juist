//go:build freebsd || freebsdman

package main

// Help on what serving and exit nodes do to the host, which differs by its
// service manager.
const (
	servesSetUp = "juistd sets the host up"
	exitFooter  = `An admin makes a device an exit node: juist grant DEVICE exit. It carries
only traffic to public addresses, so the LAN stays direct, and DNS too. If
the exit node cannot be used, traffic is refused, not sent directly.`
	exitUseAbout = `
Send this device's internet traffic and DNS through DEVICE. The LAN and the
network's devices stay direct. So do answers to connections from the
internet, such as ssh. --isolate sends those through DEVICE too; it refuses
if that would end the ssh session it runs in. If DEVICE cannot carry the
traffic, it is refused, not sent directly. --force chooses a DEVICE that
does not serve yet, or ends the session anyway.`
	exitServeAbout = `
Carry the network's internet traffic, if an admin made this device an exit
node. While it serves, juistd makes the host forward and masquerades in its
own pf rules. --stop stops and undoes it.`
	subnetServeAbout = `
Route the subnets the network grants this device, for the other members.
While it serves, juistd makes the host forward and masquerades in its own pf
rules. --stop stops and undoes it.`
)
