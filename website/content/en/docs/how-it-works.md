---
title: How juist works
linkTitle: How juist works
description: The ideas the other pages build on, in plain words, from the network and its devices to freshness.
lead: juist joins your devices into one private network, with no server in the middle. This page explains the few ideas every other page builds on.
---

## The network and its devices {#network}

A **network** is a group of your devices that reach each other through
encrypted tunnels, wherever they are: a laptop, a NAS at home, a VPS.

Each device in a network is a **member**. You create a network on one device
with `juist create`, and add the others with an
[invite]({{< relref "docs/invites" >}}). A network has a name, such as `home`.
If you give none, juist picks two random words, such as `belfast-hazardous`.

A device can be in several networks at once, for example a home network and a
work one. See [Several networks]({{< relref "docs/networks" >}}).

## Two programs: juist and juistd {#programs}

juist comes as two programs.

`juistd` is the daemon. It runs in the background on every device, holds
the device's own keys and its copy of the network's log, and keeps the tunnels
up. On Linux the package starts it when you install it, and it waits until you
create or join a network.

`juist` is the command you type. It asks juistd to do things, and it holds
your admin keys if you are an admin.

Any local user may run `juist status`. Every other command is for root and for
the device's **operator**: one local user, named with `juist set --operator`,
who then manages the device without sudo. See
[The operator]({{< relref "docs/operator" >}}).

## The membership log {#the-membership-log}

Who belongs to the network is written in the **membership log**: a list of
signed changes, such as "admit nas" or "remove phone". Each change is chained
to the one before it, so nobody can quietly rewrite or reorder the history.

Every device holds a copy of the log and checks every change itself. It does
not trust the device that sent the change, or the path it came by. A change
counts only when enough admins have signed it.

`juist log` lists the changes, and who approved each one.

## Admins and the quorum {#admins}

An **admin** is a person who may change the network: admit or remove devices,
give roles, rename it. Whoever runs `juist create` is its first admin.

An admin signs changes with an admin key. The keys live in the admin's
keystore, `~/.config/juist` in their home directory, on each machine they
approve from. juistd never holds them. A key never leaves the machine it was
made on, so an admin with two laptops has a key on each.

The **quorum** is how many admin votes a change needs. It is 1 by default, so
one admin decides alone. After `juist admins quorum 2`, every change needs two
votes, for example from two people. A change that needs more votes waits until
the other admins approve it with `juist approve`. See
[Admins]({{< relref "docs/admins" >}}).

## Roles {#roles}

Every member reaches every other member. A **role** gives a device one more
job. An admin gives it with `juist grant DEVICE ROLE` and takes it back with
`juist revoke`.

| Role | What the device does |
|---|---|
| `voucher` | Confirms every hour that the network's state is current, so that cut-off devices notice. See [freshness](#freshness-and-vouchers) below. |
| `relay` | Passes traffic between devices that cannot reach each other directly. See [Relays]({{< relref "docs/relays" >}}). |
| `exit` | Carries other devices' internet traffic, once its operator agrees. See [Exit nodes]({{< relref "docs/exit-nodes" >}}). |
| `ingress` | Takes connections from the internet for the names devices publish. See [Publishing services]({{< relref "docs/publishing" >}}). |
| `service` | A service member: a juistd of its own beside one published service. Every device keeps it from opening any connection. See [Publishing services]({{< relref "docs/publishing" >}}). |
| `publish` | Shares under the device's own name at once, without an admin each time: `juist share`, `juist publish PORT`. See [Publishing services]({{< relref "docs/publishing" >}}). |

Being an admin is not a role of a device. An admin is a person with keys, and
a voucher is a device that holds no admin key.

A device can also route the LAN behind it for the other members. That is set
with `juist subnet add` rather than a role. See
[Subnet routers]({{< relref "docs/subnets" >}}).

## How devices find each other {#discovery}

Before two devices can connect, each needs to know where the other one is.
There is no server to ask, so juist looks in three places:

- on the local network (LAN), where devices announce themselves;
- through other members, which pass on where they last reached a device;
- through the public BitTorrent DHT, a large public directory on the internet,
  for members a device has lost track of.

What devices leave in the DHT is encrypted. The DHT sees addresses, never
contents, and nothing it returns can change who belongs to the network.

## How devices connect {#connections}

Traffic between two members goes through a WireGuard tunnel. WireGuard is the
VPN protocol that encrypts it, end to end between the two devices.

Most devices sit behind a router that does NAT, which keeps connections from
outside away. juist punches through it, so that the two devices connect
directly. To learn its own public address, juistd asks public STUN servers by
default.

Where the two devices cannot reach each other directly, they relay through a
member the network granted `relay`, never through a third party. The relay
sees only encrypted WireGuard traffic.

Behind NAT, nothing needs opening in a firewall. A device with a public
address needs 41643/udp open. The other ports are on the
[Relays]({{< relref "docs/relays" >}}) page.

How the tunnels are built, and what juist takes from WireGuard and Tailscale
for them, is on the [Architecture]({{< relref "docs/architecture" >}}) page.

## Addresses in the network {#addresses}

Each member has two addresses in the network, and `juist devices` lists them.

- An IPv4 address, such as `198.18.36.2`. `juist create` picks a random block
  in `198.18.0.0/15`, such as `198.18.36.0/22`. The first device gets the
  first address, and each device admitted after it the next free one. Admins
  can move these addresses with `juist network renumber`.
- An IPv6 address, such as `fd84:7a1f:97ee:21a8:2ab0:e8e:caa0:b306`, worked
  out from the device's identity key. Renumbering does not move it; only
  `juist rotate identity` does.

## Names {#names}

Where systemd-resolved runs, every member is reachable by name as
`DEVICE.NETWORK.juist`, such as `laptop.home.juist`, or as `laptop` alone:

```sh
ssh laptop.home.juist
```

Admins can also point public names, such as `mail.example.org`, at members.
See [Names]({{< relref "docs/names" >}}).

## Freshness and vouchers {#freshness-and-vouchers}

When an admin removes a device, each member drops its tunnel to that device on
hearing of the removal. A member that is cut off from the rest may not hear of
it, and would keep talking to the removed device.

**Freshness** puts a limit on that. Every hour, each voucher signs a short
statement of how the network looked at that moment. A member holding such a
statement from the last 48 hours is fresh. A member without one is stale: it
keeps tunnels only to vouchers until it hears from one again. So a removed
device can be carried along for 48 hours at most.

This has three consequences:

- Keep at least one voucher online. The device that created the network is its
  first voucher. If every voucher is offline for more than 48 hours, all other
  members fall back to tunnels with vouchers only.
- With one voucher, you trust that it is honest. After
  `juist admins vouchers 2`, a member is fresh only with statements from two
  vouchers, so one lying voucher is not enough.
- A network with no voucher does not check freshness at all.

`juist status` shows the state in its `Freshness` line, for example
`vouched just now, valid 48h` or `expired; vouchers only`.

## Terms {#terms}

| Term | Meaning |
|---|---|
| network | Your devices that reach each other through juist, under one name |
| member | A device in the network |
| juistd | The daemon on every device; holds the device's keys and log |
| juist | The command you type |
| operator | The one local user who may manage a device without sudo |
| membership log | The signed list of every change to the network, checked by every device |
| change | One entry in the log, such as admitting or removing a device |
| admin | A person who may sign changes |
| admin key | An admin's signing key, kept in their keystore on one machine |
| keystore | `~/.config/juist`, where your admin keys live |
| quorum | How many admin votes a change needs |
| role | An extra job for a device: voucher, relay, exit, ingress, service or publish |
| invite | A code or link that lets one new device join |
| freshness | Whether a device has heard from a voucher in the last 48 hours |
| voucher | A device that confirms every hour that the network's state is current |
| relay | A member that passes traffic between members that cannot reach each other |
