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

Every 256 changes, juist records a **checkpoint** after the admin's change:
the whole state as one change, which each device checks against its own copy.
Once every device has it, the devices drop what lies before the checkpoint
before it, so the log stays short. Where the quorum is more than one vote,
the checkpoint waits for the other admins' votes like any change.

## Admins and the quorum {#admins}

An **admin** is a person who may change the network: admit or remove devices,
assign roles, rename it. Whoever runs `juist create` becomes its first admin.

An admin signs changes with an admin key. The keys live in the admin's
keystore, `~/.config/juist` in their home directory, on each machine they
approve from. juistd never holds them. A key leaves the machine it was created
on only as a backup line, so an admin with two laptops has a separate key on
each.

The **quorum** is the number of admin votes a change needs. It is 1 by
default, so a single admin can decide. After `juist admins quorum 2`, every
change needs two votes, for example from two people. A change that still
needs votes waits until other admins approve it with `juist approve`. See
[Admins]({{< relref "docs/admins" >}}).

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
| `ingress` | Accepts connections from the internet for the names that devices publish. See [Publishing services]({{< relref "docs/publishing" >}}). |
| `service` | A service member: a separate juistd running beside one published service. No device accepts a connection it opens. See [Publishing services]({{< relref "docs/publishing" >}}). |
| `publish` | Shares under the device's own name right away, without asking an admin each time: `juist share`, `juist publish PORT`. See [Publishing services]({{< relref "docs/publishing" >}}). |

A role decides which device may serve as an exit node or relay. If there is
an access policy, the policy decides which devices may use it.

Admin is not a device role. An admin is a person with keys, while a voucher
is a device and holds no admin key.

A device can also route the LAN behind it for the other members. You set
that up with `juist subnet add`, not with a role. See
[Subnet routers]({{< relref "docs/subnets" >}}).

## How devices find each other {#discovery}

Before two devices can connect, each needs to know where the other one is.
There is no server to ask, so juist looks in three places:

- on the local network (LAN), where devices announce themselves;
- through other members, which pass on where they last reached a device;
- at the network's relays, and only then in the public BitTorrent DHT, a
  large public directory on the internet, for members a device has lost
  track of.

What devices store in the DHT is encrypted, and every entry is the same
size. The DHT sees addresses, never contents, and
nothing it returns can change who belongs to the network.

## How devices connect {#connections}

Traffic between two members goes through a WireGuard tunnel. WireGuard is the
VPN protocol that encrypts it end to end between the two devices.

Most devices sit behind a router that does NAT, which blocks incoming
connections. juist punches through it so that the two devices connect
directly. To learn its own public address, juistd asks public STUN servers by
default.

Where two devices cannot reach each other directly, their traffic goes
through a member that has the `relay` role, never through a third party. The
relay sees only encrypted WireGuard traffic.

Behind NAT, you don't need to open anything in a firewall. A device with a
public address needs 41643/udp open. The other ports are listed on the
[Relays]({{< relref "docs/relays" >}}) page.

The [Architecture]({{< relref "docs/architecture" >}}) page explains how the
tunnels are built and what juist takes from WireGuard and Tailscale for them.

## Addresses in the network {#addresses}

Each member has two addresses in the network, and `juist devices` lists them.

- An IPv4 address, such as `198.18.36.2`. `juist create` picks a random block
  in `198.18.0.0/15`, such as `198.18.36.0/22`. The first device gets the
  first address, and each device admitted after it gets the next free one.
  Admins can move these addresses with `juist network renumber`.
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

When an admin removes a device, each member drops its tunnel to that device as
soon as it learns of the removal. A member that is cut off from the rest may
not learn of it, and would keep talking to the removed device.

**Freshness** puts a limit on that. Every hour, each voucher signs a short
statement of how the network looked at that moment. A member holding such a
statement from the last 48 hours is fresh. A member without one is stale: it
keeps tunnels only to vouchers until it hears from one again. So a removed
device stays connected for 48 hours at most.

This has four consequences:

- A new network has no voucher, so it does not check freshness at all.
  A removal still reaches every device once it is in touch with one that
  knows about it, but there is no limit on how long a cut-off device can take.
  `juist create --voucher` makes the first device a voucher.
- Only make devices vouchers that are always on, such as a VPS or a home
  server. If too few vouchers are online for 48 hours, every other member
  falls back to tunnels to vouchers only. A network of laptops and phones
  that are often off is better off without vouchers.
- With a single voucher, you trust that it is honest. After
  `juist admins vouchers 2`, a member is fresh only with statements from two
  vouchers, so one lying voucher is not enough. Keep a spare: two of three
  vouchers, on hosts that fail independently, not two machines at the same
  provider.
- A relay can cut a device off from the others. If one voucher is enough, do
  not make a relay the voucher, or that one machine could both cut a device
  off and keep it fresh.

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
| invite | A code or link that lets one new device join |
| freshness | Whether enough vouchers have confirmed a device's view in the last 48 hours |
| voucher | A device that confirms every hour that the network's state is current |
| relay | A member that passes traffic between members that cannot reach each other |
