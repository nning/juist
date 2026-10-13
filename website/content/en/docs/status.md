---
title: Status and devices
linkTitle: Status and devices
description: See whether a device is connected, which devices are in the network, and every change made to it.
lead: Three commands tell you how things stand. juist status shows this device and what needs attention, juist devices lists every device, and juist log shows every change and who approved it.
---

Your network is a group of devices that belong together, and each of them is
a **member**. Every member keeps its own copy of the network's log, the signed
list of every change (see [How juist works]({{< relref "docs/how-it-works" >}})).
The commands on this page read that log, and ask the daemon `juistd`, the
program that keeps the tunnels up, about the current state.

Whenever something seems wrong, start with `juist status`. It names the problem
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
  Devices       3 others
  Relays        1 available, via vps
  Names         home.juist
  Freshness     vouched 12m ago, valid 48h
  Ports         udp/41643
  Updated       just now
```

The first line shows the network's name and its state. The details follow,
then any warnings, each with a hint.
{{< /step >}}

The state on the first line is one of these:

| State | Meaning |
|---|---|
| `connected` | everything works |
| `waiting for peers` | there are other devices, but none of them has been heard from yet |
| `no tunnel up` | other devices are known, but no tunnel to them carries traffic |
| `limited` | this device's view may be out of date, so it keeps tunnels only to vouchers (see `Freshness` below) |
| `disabled` | the network was ended with a break-glass secret; start over with `juist reset` |
| `removed` | this device is no longer in the network |
| `juistd not running` | the daemon is not running; start it (see [Troubleshooting]({{< relref "docs/troubleshooting" >}})) |

## What each line means

- `This device`: its name and its addresses in the network, IPv4 first, then IPv6.
- `Devices`: how many other devices there are, and how many of them had no
  tunnel carrying traffic at the last check; `juist devices` says why.
  juistd checks every 30 seconds. If both ends have a relay, it checks a quiet
  tunnel only every 5 minutes, so that a laptop's radio can sleep.
- `Relays`: how many devices may relay, and which one this device uses. A [relay]({{< relref "docs/relays" >}}) passes traffic between two devices that cannot reach each other directly.
- `HTTPS`: on a device that sends only HTTPS, the relays on port 443 it uses, and its proxy. See [HTTPS only]({{< relref "docs/https-only" >}}).
- `Relay name`: the public name this device's relay serves on port 443. Root and the operator also see whether it serves it yet.
- `Exit node`: which device carries this device's internet traffic, if any. See [Exit nodes]({{< relref "docs/exit-nodes" >}}).
- `Names`: the domain under which this device finds the others, such as `home.juist`, or why it cannot. See [Names]({{< relref "docs/names" >}}).
- `Freshness`: when a voucher last confirmed that this device's view of the
  network is current, and how long that confirmation stays valid. A voucher
  is a device the network trusts to confirm this every hour. After 48 hours
  without a confirmation, the line reads `expired; vouchers only`. A warning
  appears a day before that. If no device vouches, the line reads
  `unchecked: no voucher`, and if at least two devices may relay, a hint
  suggests making them vouchers. See
  [Removing a device]({{< relref "docs/remove" >}}).
- `Published`: the published names this device serves, or why it does not
  serve them. See [Publishing services]({{< relref "docs/publishing" >}}).
- `Ingress`: on an ingress, whether it runs, the names it serves, the ports
  it passes on by TCP, and any ports another program holds.
- `Sharing`: how many shares this device has (`juist share` lists them), or
  why nobody can reach them.
- `Ports`: the ports juistd listens on. `udp/41643` is the one for the tunnels.
- `Updated`: when juistd last applied the network's state.

Lines such as `Subnets`, `Published` or `Renumbering` appear only while those
features are in use.

## Listing the devices

`juist devices` lists every device in a table:

```console
$ juist devices
NAME                  IPV4         REACHED  ROLES
laptop (this device)  198.18.36.1  -        -
nas                   198.18.36.2  direct   voucher, names, publishes
vps                   198.18.36.3  direct   voucher, relay
phone                 198.18.36.4  relayed  -
```

`ROLES` lists, for each device:

- the roles the network gives it, such as `voucher`, `relay` or `exit`;
- its subnets;
- `names` if public names point at it ([`juist names`]({{< relref "docs/names" >}}) lists them);
- `publishes` if it publishes names ([`juist publish`]({{< relref "docs/publishing" >}}) lists them);
- `-` if none of these apply.

On a narrow terminal the roles wrap within their column. On an even narrower
one, such as a phone's, each device takes up several lines.

`REACHED` says how juistd reached the device at its last check:

| `REACHED` | Meaning |
|---|---|
| `direct` | a direct tunnel works |
| `relayed` | the tunnel goes through a relay |
| `outdated` | the device runs an older juist, and is unreachable until it is updated |
| `no answer` | the device did not answer: it is offline, or a firewall blocks it |
| `offline`, `offline, heard 3h ago` | the device is most likely offline and has not been heard from since |
| `not heard from` | the device has not announced where to reach it yet |
| `not checked yet` | juistd has not checked yet |
| `not connected` | the device was heard from, but has no tunnel, for example while this device's view is out of date |
| `-` | this device itself |

With an [access policy]({{< relref "docs/access" >}}), `juist devices`
lists only this device and the members it has a tunnel with, and ends with
`hint: 2 more devices the access policy keeps apart from this one: juist devices --all`.

`juist devices -6` adds each device's IPv6 address. `juist devices --keys`
adds its identity key, which [`juist remove`]({{< relref "docs/remove" >}})
also accepts.

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

Each entry is one change, followed by the admins whose keys approved it. An
admin is a person whose key may approve changes (see
[Admins]({{< relref "docs/admins" >}})).

`juist log show` shows what a single change did and which keys signed it.
Give the change by its number, by -N counting back from the last (`-1` is the
latest), or by the start of its hash:

```console
$ juist log show 3
   3  change of a device's roles or subnets: vps
      gives vps (nid:QH4T7MWD…) the role relay
      approved by alice, with nid:Kc3vR8dE…
      hash MMOPGHJRKJ7DTZ2QWLQ6N5LXGZ4VQ3RJ4M2B7ZPXS2YQFG6C5WDA
```

Each change is described against the network as it was just before, so a
change to the access policy shows up as a diff. The log contains no times,
because no change carries a signed date. `juist log verify` checks the whole
log again.

## The daemon's log

```sh
journalctl -u juistd
```

This shows what juistd itself reports. A second network on the same device has
its own daemon, `juistd@juist1`, with its own log.

## Notes

- Any local user may run `juist status`. A user who is neither root nor the
  device's [operator]({{< relref "docs/operator" >}}) sees a `read-only`
  hint below the output.
- `juist devices`, `juist log` and all other commands are only for root and
  the operator.
- On a device in [several networks]({{< relref "docs/networks" >}}),
  `juist status` and `juist devices` show each network in turn.
  `juist devices work` shows just one.

## Troubleshooting

`juist status` lists warnings below the details, each followed by a `hint:`
line. [Troubleshooting]({{< relref "docs/troubleshooting" >}}) explains the
common ones and what to do about them.
