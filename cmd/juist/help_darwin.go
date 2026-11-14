package main

// Help on what serving and exit nodes do to the host, which differs by its
// service manager.
const (
	servesSetUp = "not on macOS"
	exitFooter  = `An admin makes a device an exit node: juist grant DEVICE exit. It carries
only traffic to public addresses, so the LAN stays direct, and DNS too. If
the exit node cannot be used, traffic is refused, not sent directly. A Mac
uses one but cannot be one.`
	exitUseAbout = `
Send this device's internet traffic and DNS through DEVICE. The LAN and the
network stay direct; on a Mac, answers to connections from the internet,
such as ssh, go through DEVICE too, with or without --isolate. If DEVICE
cannot carry the traffic, it is refused, not sent directly. --force uses a
DEVICE that does not serve yet, or ends the ssh session it runs in anyway.`
	exitServeAbout = `
Carry the network's internet traffic, if an admin made this device an exit
node. Not on macOS yet.`
	subnetServeAbout = `
Route the subnets the network grants this device, for the other members.
Not on macOS yet.`
)
