---
title: Exit nodes
linkTitle: Exit nodes
description: Send a device's internet traffic through another member of the network, and let a member carry it for the others.
lead: An exit node is a device in your network that carries the other devices' internet traffic. In a café, your laptop can go online through your VPS instead of the café's network.
---

## How it works

Normally a device goes online from wherever it is. With an exit node, it first
sends its internet traffic through the tunnel to another member, a device that
belongs to your network ([How juist works]({{< relref "docs/how-it-works" >}})).
That member sends it on. Websites then see the exit node's address, and the
café's network sees only encrypted traffic.

A device becomes an exit node in two steps. First an admin, a person whose key
approves changes to the network, gives it the role `exit`. A role is a
permission the network records for one device. Then the device's
[operator]({{< relref "docs/operator" >}}), the local user who manages it
without sudo, agrees by running `juist exit serve` on it.

Each device decides for itself whether to use an exit node. Nothing changes on
a device until you run `juist exit use` on it.

## Setting up an exit node

{{< step on="an admin's device" >}}
Give the VPS the role:

```sh
juist grant vps exit
```

If a change needs more than one admin, it waits for the others
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

It prints `internet via vps`. Where systemd-resolved runs, the `Exit node`
line in `juist status` now says `vps, DNS too`.
{{< /step >}}

Back on your own network, `juist exit off` sends the traffic directly again
and prints `internet direct`.

## What goes through the exit node

- Traffic to public internet addresses goes through the exit node.
- DNS goes through it too, if systemd-resolved runs on the device. Names in the
  LAN's own domain, such as your router's, are still resolved on the LAN.
- Traffic to your LAN and to the network's devices stays direct.
- Replies to connections from the internet, such as an ssh session to this
  device, also stay direct, so the device stays reachable at its own address.
- `juist exit use vps --isolate` sends those replies through the exit node as
  well. It refuses if that would end the ssh session you run it in.

## When the exit node is unavailable

If the exit node you chose cannot be used, internet traffic is blocked, not
sent directly. This happens when the exit node is offline, has stopped
serving or has lost its role, or when this device's view of the network is
stale. DNS lookups then go nowhere rather than to the LAN. Going direct is
your decision: run `juist exit off`.

## Notes

- `juist exit` lists the exit nodes, whether each is serving, and which one is
  in use.
- `juist exit use vps --force` chooses vps even if it is not serving yet, or if
  the choice would end your ssh session.
- `juist exit serve --stop` stops serving and undoes the setup. On an admin's
  device, `juist revoke vps exit` takes the role away.
- A device that uses an exit node cannot be one itself. A device in
  [several networks]({{< relref "docs/networks" >}}) sends its internet traffic
  through only one of them.
- Without an [access policy]({{< relref "docs/access" >}}), every member may
  use an exit node. With one, a device can use only the exit nodes that a rule
  such as `pass from laptop to internet via vps` allows, and the exit node
  forwards only that traffic.
- If you configured the exit node's firewall by hand, it must allow UDP and TCP
  41646 on `juist0`, where the exit node answers its members' DNS queries
  ([Relays, ports and firewalls]({{< relref "docs/relays" >}})).
- If the exit node also runs Tailscale, it answers its members' DNS queries
  through the host's regular DNS servers. It never asks Tailscale's resolver,
  which would answer tailnet names with addresses the members cannot reach.
- On FreeBSD, exit nodes work with pf, and DNS goes through resolvconf.
- On Linux, an exit node or subnet router turns on UDP GRO forwarding on the
  network interface of its default route, the same as `ethtool -K eth0
  rx-udp-gro-forwarding on rx-gro-list off`, so that it forwards UDP traffic
  such as QUIC in batches. When it stops serving, it restores the interface's
  previous settings. Both changes are logged.
- When juistd stops cleanly, it lifts the block, so while the service restarts,
  traffic goes direct for a moment.

## Troubleshooting

| You see | What to do |
|---|---|
| `juist status`: `Exit node` says `vps, internet refused: …` | bring vps back online, or run `juist exit off` to go direct |
| `juist exit use vps`: `vps does not serve as an exit node` | run `juist exit serve` on vps, or add `--force` |
| `juist status`: `Exit node` says `vps, internet refused: the access policy does not let this device use it` | add a rule `pass from … to internet via vps` ([Access policy]({{< relref "docs/access" >}})) |
| on vps, `juist status`: `this device does not serve: IP forwarding is off on this host` | run `juist exit serve` again, which sets it up with sudo |
| `warning: DNS goes to …, outside the tunnel: systemd-resolved refused juistd` | install juist from the package, whose polkit rule allows juistd this, and install polkit |
| `warning: strict reverse-path filtering on … drops the exit node's answers` | run the `sudo sysctl -w …` line from the hint |

After `internet refused:`, the status gives the reason, such as
`it cannot be reached`, `its operator has not agreed to serve` or
`the network has not made it an exit node`.
