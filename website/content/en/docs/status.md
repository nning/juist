---
title: Status and devices
linkTitle: Status and devices
description: See whether a device is connected, which devices are in the network, and every change made to it.
lead: Three commands tell you how things stand. juist status shows this device and what needs attention, juist devices lists every device, and juist log shows every change and who approved it.
---

## What it is

Your network is the group of devices that belong together; each of them is a
**member**. Every member keeps its own copy of the network's log, the signed
list of every change (see [How juist works]({{< relref "docs/how-it-works" >}})).
The commands on this page read that log and ask the daemon, `juistd`, the
program that keeps the tunnels up, how things stand right now.

Start with `juist status` whenever something seems wrong. It names the problem
and prints a `hint:` line with the command that fixes it.

## Checking a device

{{< step on="laptop" >}}
See whether this device is connected, and what needs attention:

```sh
juist status
```

```console
$ juist status
home · connected
  This device   laptop  198.18.36.1  fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0
  Devices       3 others, all heard from
  Tunnels       3 of 3 live
  Relays        1 available, via vps
  Names         home.juist
  Freshness     vouched 12m ago, valid 48h
  Ports         udp/41643
  Updated       just now

NAME                  IPV4         IPV6                                    ROLES                            REACHED
laptop (this device)  198.18.36.1  fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0  -                                -
nas                   198.18.36.2  fd4c:8a21:e3f:77c0:1e4b:a923:6d05:f18e  voucher, names mail.example.org  direct
vps                   198.18.36.3  fd4c:8a21:e3f:c2d9:84f1:3b6a:e057:29dc  voucher, relay                   direct
phone                 198.18.36.4  fd4c:8a21:e3f:e83:5a7d:f12c:9b46:d371   -                                relayed
```

The first line names the network and its state. Below come the details, the
device table, and then any warnings, each with a hint.
{{< /step >}}

The state on the first line is one of these:

| State | Meaning |
|---|---|
| `connected` | everything works |
| `waiting for peers` | there are other devices, but none has been heard from yet |
| `no tunnel up` | other devices are known, but no tunnel to them carries traffic |
| `limited` | this device's view may be out of date, so it keeps tunnels only to vouchers (see Freshness below) |
| `disabled` | the network was ended with a break-glass secret; start over with `juist reset` |
| `removed` | this device is no longer in the network |
| `juistd not running` | the daemon is not running; start it (see [Troubleshooting]({{< relref "docs/troubleshooting" >}})) |

## What each line means

- `This device`: its name and its addresses in the network, IPv4 first, then IPv6.
- `Devices`: how many other devices there are, and how many of them have been heard from.
- `Tunnels`: how many tunnels carried traffic at the last check. juistd checks every 30 seconds, but where both ends have a relay it asks a quiet tunnel only every 5 minutes, so that a laptop's radio can sleep.
- `Relays`: how many devices may relay, and which one this device uses. A [relay]({{< relref "docs/relays" >}}) passes traffic between two devices that cannot reach each other directly.
- `HTTPS`: on a device that sends nothing but HTTPS, the relays on 443 it goes through, and its proxy. See [HTTPS alone]({{< relref "docs/https-only" >}}).
- `Relay name`: the public name this device's relay serves on 443, and whether it does yet.
- `Exit node`: which device carries this device's internet traffic, if any. See [Exit nodes]({{< relref "docs/exit-nodes" >}}).
- `Names`: the domain under which this device finds the others, such as `home.juist`, or why it cannot. See [Names]({{< relref "docs/names" >}}).
- `Freshness`: when a voucher last confirmed that this device's view of the network is current, and how long that stays valid. A voucher is a device the network trusts to confirm this, every hour. After 48 hours without one, the line reads `expired; vouchers only`; a day before, a warning says when. Where no device vouches, the line reads `unchecked: no voucher`, and where two devices may relay, a hint suggests them as vouchers. See [Removing a device]({{< relref "docs/remove" >}}).
- `Published`: the names published on this device that it serves, or why
  not. See [Publishing services]({{< relref "docs/publishing" >}}).
- `Ingress`: on an ingress, whether it runs, the names it serves, the ports
  it passes by TCP, and those another program holds.
- `Sharing`: what this device shares under its own name, a file or
  directory with its link, until when, or why it reaches nobody.
- `Ports`: the ports juistd listens on. `udp/41643` is the one for the tunnels.
- `Updated`: when juistd last applied the network's state.

Lines such as `Subnets`, `Published` or `Renumbering` appear only while those
features are in use.

## Listing the devices

`juist devices` prints the same table on its own:

```sh
juist devices
```

`ROLES` shows what the network allows each device to do, such as `voucher`,
`relay` or `exit`, then its subnets, names and the names it publishes, as
`publishes docs.example.org` or, past two, `publishes 3 names`, and `-` for
none. `REACHED` says how juistd reached the
device at its last check:

| `REACHED` | Meaning |
|---|---|
| `direct` | a direct tunnel works |
| `relayed` | the tunnel goes through a relay |
| `no answer` | the device did not answer: it is offline, or a firewall blocks it |
| `offline`, `offline, heard 3h ago` | the device is most likely offline, and has said nothing since |
| `not heard from` | the device has not announced where to reach it yet |
| `not checked yet` | juistd has not checked yet |
| `not connected` | the device was heard from, but has no tunnel, for example while this device's view is out of date |
| `-` | this device itself |

Under an [access policy]({{< relref "docs/access" >}}), `juist devices` and
`juist status` list this device and the members it keeps a tunnel with, and
`juist devices` ends with
`hint: 2 more devices the access policy keeps apart from this one: juist devices --all`.

`juist devices --keys` adds each device's identity key, which
[`juist remove`]({{< relref "docs/remove" >}}) also accepts.

## Seeing every change

```console
$ juist log
   0  network creation                             K2JS2DNGYZWZ
      approved by alice
   1  device admission: nas                        EU7V5XCUUOSO
      approved by alice
   2  device admission: vps                        QH4T7MWD2LXA
      approved by alice
   3  change of a device's roles or subnets: vps   MMOPGHJRKJ7D
      approved by alice
4 changes
```

Each entry is one change, with the admins whose keys approved it. An admin is
a person whose key may approve changes (see [Admins]({{< relref "docs/admins" >}})).
`juist log verify` checks the whole log again.

## The daemon's own log

```sh
journalctl -u juistd
```

This shows what juistd itself reports. A second network on the same device has
its own daemon, `juistd@juist1`, with its own log.

## Good to know

- Any local user may run `juist status`. A user who is not root or the
  device's [operator]({{< relref "docs/operator" >}}) sees it without the
  device table, followed by a `read-only` hint.
- `juist devices`, `juist log` and every other command are for root and the operator.
- On a device in [several networks]({{< relref "docs/networks" >}}),
  `juist status` and `juist devices` show each network in turn.
  `juist devices work` shows one.

## If something goes wrong

`juist status` puts warnings below the table, each followed by a `hint:` line.
[Troubleshooting]({{< relref "docs/troubleshooting" >}}) lists the common ones
and what to do.
