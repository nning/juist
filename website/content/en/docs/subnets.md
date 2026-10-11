---
title: Subnet routers
linkTitle: Subnet routers
description: Reach the LAN behind one member, such as a printer at home, from every device in the network.
lead: A subnet router is a member that passes traffic from the network on to the LAN it sits in. Your laptop can then reach the printer at home from anywhere, even though the printer runs no juist.
---

## How it works

Your NAS at home is a member, a device that belongs to your network
([How juist works]({{< relref "docs/how-it-works" >}})). The printer next to it
is not, because it runs no juist. A subnet router lets other members reach such
devices anyway: the NAS takes their traffic out of the tunnel and passes it on
to its LAN, `192.168.1.0/24` in this example. Such a range of addresses is
called a subnet.

A device becomes a subnet router in two steps. First an admin, a person whose
key approves changes to the network, assigns the subnet to the device. Then
the device's [operator]({{< relref "docs/operator" >}}), the local user who
manages it without sudo, agrees by running `juist subnet serve` on it.

To the devices on the LAN, the connections come from the NAS, so they need no
configuration.

## Setting up a subnet router

{{< step on="an admin's device" >}}
Have nas route its LAN for the network:

```sh
juist subnet add nas 192.168.1.0/24
```

If a change needs more than one admin, it waits for the others
([how changes are approved]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="nas" as="the subnet router" >}}
Agree to route the subnets the network assigns to this device:

```sh
juist subnet serve
```

The first time, it asks to run a setup script with sudo, which turns on IP
forwarding and lets the traffic through the firewall. Then it prints
`routing 192.168.1.0/24`.
{{< /step >}}

{{< step on="laptop" >}}
Nothing to do here. Every member picks up the route by itself, and
`juist subnet` shows it:

```console
$ juist subnet
PREFIX          ROUTER  STATE
192.168.1.0/24  nas     in use
```
{{< /step >}}

## Your own LAN takes precedence

A member that already has its own route to those addresses keeps using it.
When your laptop is at home on `192.168.1.0/24`, it talks to the printer
directly, not through the NAS. `juist subnet` then says
`this device reaches it by a route of its own`.

## Notes

- `juist subnet` lists every subnet, its router, and its state on this device.
  `juist status` sums this up in the `Subnets` line.
- On an admin's device, `juist subnet remove nas 192.168.1.0/24` removes the
  subnet again.
- `juist subnet serve --stop` stops routing on the router and undoes the
  setup.
- After `juist subnet off`, a device reaches none of the subnets through the
  network, and the host routes those addresses as it did before.
  `juist subnet on` undoes this.
- Two members cannot route overlapping subnets, and a subnet cannot overlap the
  network's own addresses. For the whole internet (`0.0.0.0/0`), use an
  [exit node]({{< relref "docs/exit-nodes" >}}).
- Without an [access policy]({{< relref "docs/access" >}}), every member
  reaches a routed subnet. With one, a device reaches only the addresses that
  a rule such as `pass from laptop to 192.168.1.0/24` allows, and the router
  forwards only that traffic.
- When a device uses an exit node, traffic to a routed subnet still goes
  through the subnet's router.
- Subnet routers run on Linux, and on FreeBSD with pf.
- Docker drops routed traffic to its containers. `juist subnet serve` warns
  when a subnet contains a Docker network.
- Hosts in the subnet can reach the members, but not the router's own juist
  address: on Linux, the router answers on it only through the tunnel.

## Troubleshooting

On a device that cannot reach a subnet, `juist subnet` gives the reason after
`not in use:`:

| Reason | What to do |
|---|---|
| `its router cannot be reached` | bring the router back online |
| `its router's operator has not agreed to route it` | run `juist subnet serve` on the router |
| `subnets are off on this device` | run `juist subnet on` |
| `the access policy passes none of it to this device` | add a rule for the subnet ([Access policy]({{< relref "docs/access" >}})) |
| `this device's view of the network is stale` | bring a voucher back online, a device that confirms the network's state is current; see [Status]({{< relref "docs/status" >}}) |

On the router itself, `not routed: not agreed to on this device` means
`juist subnet serve` has not run there yet. As long as no subnet has been
assigned to the router, `juist subnet serve` prints
`will route once an admin grants this device a subnet`.
