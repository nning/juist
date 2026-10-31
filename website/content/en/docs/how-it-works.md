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
If you don't give one, juist picks two random words, such as
`belfast-hazardous`.

A device can be in several networks at the same time, for example a home
network and a work network. See [Several networks]({{< relref "docs/networks" >}}).

## Two programs: juist and juistd {#programs}

juist comes as two programs.

`juistd` is the daemon. It runs in the background on every device, holds
the device's keys and its copy of the network's log, and keeps the tunnels
up. On Linux the package starts it when you install it, and it waits until you
create or join a network.

`juist` is the command you type. It tells juistd what to do, and it holds
your admin keys if you are an admin.

Any local user can run `juist status` and `juist health`. All other commands
need root or the device's **operator**: a local user, set with
`juist set --operator`, who can then manage the device without sudo. See
[The operator]({{< relref "docs/operator" >}}).

## The membership log {#the-membership-log}

Who belongs to the network is recorded in the **membership log**: a list of
signed changes, such as "admit nas" or "remove phone". Each change is chained
to the one before it, so nobody can quietly rewrite or reorder the history.

Every device holds a copy of the log and checks every change itself. It
trusts neither the device that sent the change nor the path it took. A change
counts only when enough admins have signed it.

`juist log` lists the changes and who approved each one.

So that the log does not grow forever, juist records a **checkpoint** about
every 256 changes: the whole state of the network as one change. Each device
checks it against its own copy, and older parts of the log are dropped once
every device has it. Like any change, a checkpoint needs the quorum.

## Admins and the quorum {#admins}

An **admin** is a person who may change the network: admit or remove devices,
assign roles, rename it. Whoever runs `juist create` becomes its first admin.

An admin signs changes with an admin key. The keys live in the admin's
**keystore**, `~/.config/juist` in their home directory, on each machine they
approve from. juistd never holds them. A key leaves its machine only as a
backup line, so an admin with two laptops has a key on each.

The **quorum** is the number of admin votes a change needs. It is 1 by
default. After `juist admins quorum 2`, every change needs two votes, for
example from two people. A change that still needs votes waits until other
admins approve it with `juist approve`. See [Admins]({{< relref "docs/admins" >}}).

## Roles {#roles}

Every member can reach every other member, unless an
[access policy]({{< relref "docs/access" >}}) says otherwise. A **role** gives
a device an extra job. An admin grants it with `juist grant DEVICE ROLE` and
takes it back with `juist revoke`.

| Role | What the device does |
|---|---|
| `voucher` | Confirms every hour that the network's state is current, so that cut-off devices notice. See [freshness](#freshness-and-vouchers) below. |
| `relay` | Passes traffic between devices that cannot reach each other directly. See [Relays]({{< relref "docs/relays" >}}). |
| `exit` | Carries other devices' internet traffic, once its operator agrees. See [Exit nodes]({{< relref "docs/exit-nodes" >}}). |
| `ingress` | Accepts connections from the internet for published names. See [Publishing services]({{< relref "docs/publishing" >}}). |
| `service` | A service member: a separate juistd next to one published service. No device accepts a connection it opens. See [Service members]({{< relref "docs/service-member" >}}). |
| `publish` | Shares under the device's own name without asking an admin each time. See [Sharing]({{< relref "docs/sharing" >}}). |

A role decides which device may serve as an exit node or relay. An access
policy, if there is one, decides which devices may use it.

Admin is not a device role: an admin is a person with keys. A voucher is a
device and holds no admin key.

Routing the LAN behind a device is set up with `juist subnet add`, not with a
role. See [Subnet routers]({{< relref "docs/subnets" >}}).

## How devices find each other {#discovery}

There is no server to ask where a device is, so juist looks in three
places:

- on the local network (LAN), where devices announce themselves;
- through other members, which pass on where they last reached a device;
- at the network's relays, and only then in the public BitTorrent DHT, a
  large public directory on the internet, for members a device has lost
  track of.

What devices store in the DHT is encrypted and of equal size. The DHT sees
addresses, never contents, and nothing it returns can change who belongs to
the network.

## How devices connect {#connections}

Traffic between two members goes through a WireGuard tunnel, encrypted end
to end. juist punches through NAT so that the two devices connect directly.
To learn its own public address, juistd asks public STUN servers.

If two devices cannot reach each other directly, their traffic goes through a
member with the `relay` role, never through a third party. The relay sees
only encrypted WireGuard traffic.

Behind NAT, you open nothing in a firewall. A device with a public address
needs 41643/udp open. [Relays]({{< relref "docs/relays" >}}) lists the other
ports, and [Architecture]({{< relref "docs/architecture" >}}) explains how
the tunnels are built.

## Addresses in the network {#addresses}

Each member has two addresses in the network, and `juist devices` lists them.

- An IPv4 address, such as `198.18.36.2`, from a random block in
  `198.18.0.0/15` that `juist create` picks. Each new device gets the next
  free address. Admins can move them with `juist network renumber`.
- An IPv6 address, such as `fd84:7a1f:97ee:21a8:2ab0:e8e:caa0:b306`, derived
  from the device's identity key. Renumbering does not change it; only
  `juist rotate identity` does.

## Names {#names}

On Linux and FreeBSD, every member can be reached by name as
`DEVICE.NETWORK.juist`, such as `laptop.home.juist`, or simply as `laptop`:

```sh
ssh laptop.home.juist
```

Under an access policy, a device has names only for the members it keeps a
tunnel with. Admins can also point public names, such as `mail.example.org`,
at members. See [Names]({{< relref "docs/names" >}}).

## Freshness and vouchers {#freshness-and-vouchers}

When an admin removes a device, each member drops its tunnel to it as soon
as it learns of the removal. A member cut off from the rest may not learn of
it and keeps talking to the removed device.

**Freshness** limits that. Every hour, each **voucher** signs a statement of
the network's current state. A member holding such a statement from the last
48 hours is fresh. Without one it is stale and keeps tunnels only to vouchers
until it hears from one again. So a removed device stays connected for 48
hours at most.

What follows from this:

- A new network has no voucher and does not check freshness. A removal still
  reaches every device once it talks to one that knows, but without a time
  limit. `juist create --voucher` makes the first device a voucher.
- Make only always-on devices vouchers, such as a VPS or a home server. If
  too few vouchers are online for 48 hours, every other member falls back to
  tunnels to vouchers only. A network of laptops and phones that are often
  off is better off without vouchers.
- With a single voucher, you trust that it is honest. After
  `juist admins vouchers 2`, a member is fresh only with statements from two
  vouchers, so one lying voucher is not enough. Keep a spare: two of three
  vouchers, on hosts that fail independently, not two machines at the same
  provider.
- A relay can cut a device off from the others. If one voucher is enough,
  do not make a relay the voucher: that one machine could cut a device off
  and keep it fresh.

`juist status` shows the state in its `Freshness` line, for example
`vouched just now, valid 48h`, `expired; vouchers only` or `unchecked: no
voucher`. `juist health` warns a day ahead: `freshness ends in 20h unless 2
vouchers vouch again`.

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
| exit node | A member that carries other devices' internet traffic; see [Exit nodes]({{< relref "docs/exit-nodes" >}}) |
| ingress | A member with a public address that passes connections from the internet to published names; see [Publishing services]({{< relref "docs/publishing" >}}) |
| service member | A separate juistd next to a published service, which no device accepts connections from; see [Service members]({{< relref "docs/service-member" >}}) |
| invite | A code or link that lets one new device join |
| freshness | Whether enough vouchers have confirmed a device's view in the last 48 hours |
| voucher | A device that confirms every hour that the network's state is current |
| relay | A member that passes traffic between members that cannot reach each other |
| schema | The numbered format of the log's changes; see [Updating juist]({{< relref "docs/updating" >}}) |
