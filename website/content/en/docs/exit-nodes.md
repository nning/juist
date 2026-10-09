---
title: Exit nodes
linkTitle: Exit nodes
description: Send a device's internet traffic through another member of the network, and let a member carry it for the others.
lead: An exit node is a device of your network that carries the others' internet traffic. In a café, your laptop can go online through your VPS instead of the café's network.
---

## What it is

Normally a device goes online from wherever it is. With an exit node, it first
sends its internet traffic through the tunnel to another member, a device that
belongs to your network ([How juist works]({{< relref "docs/how-it-works" >}})).
That member sends it on. Websites then see the exit node's address, and the
café's network sees only encrypted traffic.

Two steps make a device an exit node. An admin, a person whose key approves
changes to the network, gives the device the role `exit`. A role is a permission the network
records for one device. Then the device's operator agrees by running
`juist exit serve` on it. The [operator]({{< relref "docs/operator" >}}) is the
local user who manages a device without sudo.

Each device decides for itself whether it uses an exit node. Nothing changes
on a device until you run `juist exit use` there.

## Setting up an exit node

{{< step on="an admin's device" >}}
Give the VPS the role:

```sh
juist grant vps exit
```

Where a change needs more than one admin, it waits for the others
([how changes are approved]({{< relref "docs/admins" >}})).
{{< /step >}}

{{< step on="vps" as="the exit node" >}}
Agree to carry the network's internet traffic:

```sh
juist exit serve
```

The first time, it asks to run a setup script with sudo. The script turns on
IP forwarding and lets the forwarded traffic through the firewall. Then it
prints `serving as an exit node`.
{{< /step >}}

{{< step on="laptop" >}}
Send this device's internet traffic through the VPS:

```sh
juist exit use vps
```

It prints `internet via vps`. Where systemd-resolved runs, the line
`Exit node` in `juist status` now says `vps, DNS too`.
{{< /step >}}

Back in your own network, `juist exit off` sends the traffic directly again
and prints `internet direct`.

## What goes through it, and what stays direct

- Traffic to public internet addresses goes through the exit node.
- DNS goes through it too, where systemd-resolved runs on the device. Names of
  the LAN's own domain, such as your router's, are still asked on the LAN.
- Your LAN and the network's own devices stay direct.
- Answers to connections from the internet, as to ssh on this device, also
  stay direct, so the device is still reached at its own address.
- `juist exit use vps --isolate` sends those answers through the exit node as
  well. It stops where that would end the ssh session you run it in.

## It fails closed

When the exit node you chose cannot be used, internet traffic is refused, not
sent directly. That happens when it is offline, has stopped serving, has lost
its role, or when this device's view of the network is stale. DNS lookups then
go nowhere rather than to the LAN. Going direct is your choice, with
`juist exit off`.

## Good to know

- `juist exit` lists the exit nodes, whether each serves, and the one in use.
- `juist exit use vps --force` chooses vps even though it does not serve yet,
  or though the choice would end your ssh session.
- `juist exit serve --stop` stops serving and undoes the setup.
  `juist revoke vps exit`, on an admin's device, takes the role back.
- A device that uses an exit node serves as none. A device in
  [several networks]({{< relref "docs/networks" >}}) sends the internet through
  one network only.
- Without an [access policy]({{< relref "docs/access" >}}) every member may
  use an exit node. With one, a device uses only the exit nodes a rule such
  as `pass from laptop to internet via vps` passes it, and the exit node
  forwards only that.
- A firewall configured by hand on the exit node must let in UDP and TCP 41646
  on `juist0`, where it answers its members' DNS
  ([Relays, ports and firewalls]({{< relref "docs/relays" >}})).
- An exit node that also runs Tailscale answers its members' DNS as the
  internet does. It never asks Tailscale's resolver, which would answer
  names of its tailnet with addresses its members cannot reach.
- On FreeBSD, exit nodes work with pf, and DNS goes through resolvconf.
- A clean stop of juistd lifts the refusal, so during a restart of the service
  traffic goes direct for a moment.

## If something goes wrong

| You see | What to do |
|---|---|
| `juist status`: `Exit node` says `vps, internet refused: …` | bring vps back, or `juist exit off` to go direct |
| `juist exit use vps`: `vps does not serve as an exit node` | run `juist exit serve` on vps, or add `--force` |
| `juist status`: `Exit node` says `vps, internet refused: the access policy does not let this device use it` | add a rule `pass from … to internet via vps` ([Access policy]({{< relref "docs/access" >}})) |
| on vps, `juist status`: `this device does not serve: IP forwarding is off on this host` | run `juist exit serve` again, which sets it up with sudo |
| `warning: DNS goes to …, outside the tunnel: systemd-resolved refused juistd` | install the package, whose polkit rule allows juistd that, and polkit |
| `warning: strict reverse-path filtering on … drops the exit node's answers` | run the `sudo sysctl -w …` line the hint prints |

After `internet refused:` the status gives the reason, such as
`it cannot be reached`, `its operator has not agreed to serve` or
`the network has not made it an exit node`.
