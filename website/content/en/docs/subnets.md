---
title: Subnet routers
linkTitle: Subnet routers
description: Reach the LAN behind one member, such as a printer at home, from every device of the network.
lead: A subnet router is a member that passes traffic from the network on to the LAN it sits in. Your laptop can then reach the printer at home from anywhere, though the printer runs no juist.
---

## What it is

Your NAS at home is a member, a device that belongs to your network
([How juist works]({{< relref "docs/how-it-works" >}})). The printer next to it
is not; it runs no juist. A subnet router lets every member reach such devices
anyway: the NAS takes their traffic out of the tunnel and passes it on to its
LAN, `192.168.1.0/24` in this example. A subnet is such a range of addresses.

Two steps make a device a subnet router. An admin, a person whose key approves
changes to the network, adds the subnet to the device. Then the device's
operator agrees by running `juist subnet serve` there. The
[operator]({{< relref "docs/operator" >}}) is the local user who manages a
device without sudo.

The devices on the LAN see the connections come from the NAS, so they need no
setting of their own.

## Setting up a subnet router

{{< step on="an admin's device" >}}
Have nas route its LAN for every member:

```sh
juist subnet add nas 192.168.1.0/24
```

Where a change needs more than one admin, it waits for the others
([how changes are approved]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="nas" as="the subnet router" >}}
Agree to route what the network gives this device:

```sh
juist subnet serve
```

The first time, it asks to run a setup script with sudo, which turns on IP
forwarding and lets the traffic through the firewall. Then it prints
`routing 192.168.1.0/24`.
{{< /step >}}

{{< step on="laptop" >}}
Nothing to run. Every member takes the route by itself; `juist subnet` shows it:

```console
$ juist subnet
PREFIX          ROUTER  STATE
192.168.1.0/24  nas     in use
```
{{< /step >}}

## Your own LAN stays your own

A member that reaches those addresses by a route of its own keeps using that
route. When your laptop is at home on `192.168.1.0/24` itself, it talks to the
printer directly and not through the NAS. `juist subnet` then says
`this device reaches it by a route of its own`.

## Good to know

- `juist subnet` lists every subnet, its router, and what this device makes of
  it. `juist status` sums it up in the line `Subnets`.
- `juist subnet remove nas 192.168.1.0/24`, on an admin's device, takes the
  subnet away again.
- `juist subnet serve --stop` stops routing on the router and undoes the
  setup.
- `juist subnet off` on one device reaches none of the subnets through the
  network, and the host routes them as before. `juist subnet on` undoes it.
- Two members cannot route overlapping subnets, and a subnet cannot overlap the
  network's own addresses. For the whole internet (`0.0.0.0/0`), use an
  [exit node]({{< relref "docs/exit-nodes" >}}).
- Every member reaches a routed subnet: there are no access rules (ACLs)
  that limit who may.
- Beside an exit node, a routed subnet still goes through its router.
- Subnet routers run on Linux, and on FreeBSD with pf.
- Docker drops routed traffic to its containers. `juist subnet serve` warns
  when a subnet holds a Docker network.
- Hosts in the subnet reach the members, but not the router's own juist
  address: on Linux it answers only through the tunnel.

## If something goes wrong

`juist subnet` gives the reason after `not in use:` on the device that cannot
reach a subnet:

| It says | What to do |
|---|---|
| `its router cannot be reached` | bring the router back online |
| `its router's operator has not agreed to route it` | run `juist subnet serve` on the router |
| `subnets are off on this device` | `juist subnet on` |
| `this device's view of the network is stale` | bring a voucher, a device that confirms the network's state is current, back online; see [Status]({{< relref "docs/status" >}}) |

On the router itself, `not routed: not agreed to on this device` means
`juist subnet serve` has not run there yet. `juist subnet serve` prints
`will route once an admin grants this device a subnet` while no subnet has
been added to it.
