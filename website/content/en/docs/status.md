---
title: Status and devices
linkTitle: Status and devices
description: See whether a device is connected, what needs attention, which devices are in the network, and every change made to it.
lead: Four commands tell you how things stand. juist status shows this device, juist health says what needs attention, juist devices lists every device, and juist log shows every change and who approved it.
---

These commands ask the daemon `juistd` how things stand, and read the
device's copy of the
[membership log]({{< relref "docs/how-it-works" >}}#the-membership-log).
If something seems wrong, start with `juist health`. It names each problem,
mostly with a `hint:` line that fixes it.

Any local user may run `juist status` and `juist health`. All other commands
are for root and the device's [operator]({{< relref "docs/operator" >}}). On a
device in [several networks]({{< relref "docs/networks" >}}), the commands
show each network in turn; `juist devices work` shows just one.

## Checking a device

{{< step on="laptop" >}}
See whether this device is connected:

```sh
juist status
```

```console
$ juist status
home · connected
  This device   laptop  198.18.36.1  fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0
  Devices       3 others
  Relays        1 available, via vps
  Names         laptop.home.juist
  Freshness     vouched 12m ago, valid 48h
  Ports         udp/41643
  Schema        20
  Updated       just now
```

The first line shows the network's name and its state; the details follow.
Where something needs attention, at most two hints point on:

```console
hint: 1 change waits for your vote: juist approve
hint: 3 warnings: juist health
```
{{< /step >}}

On a device in several networks, the second hint names the network, as in
`juist health work`. `juist status` itself says only what stops the network:
a fork or rollback alarm, or a schema this version of juist cannot read.

The state on the first line is one of these:

| State | Meaning |
|---|---|
| `connected` | everything works |
| `no network` | this device is in no network yet; `juist health` says how to join or create one |
| `not connected` | juistd holds the network but has no tunnels up, or the network runs on this host already; `juist health` says why |
| `waiting for peers` | there are other devices, but none of them has been heard from yet |
| `no tunnel up` | other devices are known, but no tunnel to them carries traffic |
| `limited` | this device's view may be out of date, so it keeps tunnels only to vouchers (see `Freshness` below) |
| `disabled` | the network was ended with a break-glass secret; start over with `juist reset` |
| `removed` | this device is no longer in the network |
| `refused` | the other devices refuse this one; most likely it was removed |
| `behind` | this device was away so long that the others no longer keep the part of the log it needs; join again with a new invite link ([Troubleshooting]({{< relref "docs/troubleshooting" >}}#warning-this-devices-log-is-older-than-what-the-networks-devices-keep)) |
| `disconnected` | the log has split or gone back, and every tunnel stays down until an admin resolves it ([Troubleshooting]({{< relref "docs/troubleshooting" >}}#warning-log-rollback-alarm-the-chain-went-back-from-epoch-4-to-3-)) |
| `joining a network` | this device is joining a network |
| `not running` | the daemon is not running, as in `juist0 · not running`, or `juistd not running` where no juist package is installed; `juist health` says how to start it (see [Troubleshooting]({{< relref "docs/troubleshooting" >}}#not-running)) |

## What each line means

- `This device`: its name and its addresses in the network, IPv4 first, then IPv6.
- `Devices`: how many other devices there are, and how many had no tunnel
  carrying traffic at the last check; `juist devices` says why.
- `Relays`: how many devices may [relay]({{< relref "docs/relays" >}}), and
  which one this device uses.
- `HTTPS`: on a device that sends only HTTPS, the relays on port 443 it uses, and its proxy. See [HTTPS only]({{< relref "docs/https-only" >}}).
- `Relay name`: the public name this device's relay serves on port 443. Root and the operator also see whether it serves it yet.
- `Exit node`: which device carries this device's internet traffic, if any. See [Exit nodes]({{< relref "docs/exit-nodes" >}}).
- `Names`: this device's own names, such as `laptop.home.juist`; `juist names` lists the network's, and `juist health` says why where they are not resolved. See [Names]({{< relref "docs/names" >}}).
- `Freshness`: when a [voucher]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)
  last confirmed this device's view, and how long that stays valid. After 48
  hours without one, it reads `expired; vouchers only`, and `juist health`
  warns a day before. Without vouchers, it reads `unchecked: no voucher`.
- `Published`: the published names this device serves, or why it does not
  serve them. See [Publishing services]({{< relref "docs/publishing" >}}).
- `Ingress`: on an ingress, whether it runs, the names it serves, the ports
  it passes on by TCP, and any ports another program holds.
- `Sharing`: how many shares this device has (`juist share` lists them), or
  why nobody can reach them.
- `Ports`: the ports juistd listens on. `udp/41643` is the one for the tunnels.
- `Schema`: the version of the record format the network's log is at. Where
  this version of juist implements a newer one, it follows in yellow, as in
  `19 (20)`; on a device with an admin key, `juist health` then says how to
  upgrade (see [Updating juist]({{< relref "docs/updating" >}})).
- `Updated`: when juistd last applied the network's state.

Lines such as `Subnets`, `Published` or `Renumbering` appear only while those
features are in use.

## What needs attention

`juist health` says what needs attention on this device, each warning with a
`hint:` that fixes it, and which devices it does not reach:

```console
$ juist health
warning: log sync to vps fails in the tunnel: tcp/41644 does not answer there
hint: where it runs Linux: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone
no answer from phone: offline, or udp/41643 blocked
```

A plain line such as `no answer from phone` needs nothing done while that
device is off. Below the warnings follow the changes that wait for your
vote (see [Admins]({{< relref "docs/admins" >}})) and, on a device with an
admin key, how to upgrade the network's schema. Where nothing needs
attention it says so:

```console
$ juist health
nothing needs attention
```

On a device in several networks, `juist health` prints each network's under
its name.

## Listing the devices

`juist devices` lists every device in a table:

```console
$ juist devices
NAME                  IPV4         REACHED  SCHEMA  ROLES
laptop (this device)  198.18.36.1  -        20      -
nas                   198.18.36.2  direct   20      voucher, names, publishes
vps                   198.18.36.3  direct   20      voucher, relay
phone                 198.18.36.4  relayed  20      -
```

`ROLES` lists, for each device:

- the roles the network gives it, such as `voucher`, `relay` or `exit`;
- its subnets;
- `names` if public names point at it ([`juist names`]({{< relref "docs/names" >}}) lists them);
- `publishes` if it publishes names ([`juist publish`]({{< relref "docs/publishing" >}}) lists them);
- `-` if none of these apply.

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

`SCHEMA` is the newest schema each device's juist implements, as the device
announces it. It is yellow where older than this device's, and `-` where
this device has heard no announcement of it yet. Where juistd does not run
or has heard none, the column is left out.

With an [access policy]({{< relref "docs/access" >}}), `juist devices`
lists only this device and the members it has a tunnel with, and ends with
`hint: 2 more devices the access policy keeps apart from this one: juist devices --all`.

`juist devices -6` adds each device's IPv6 address. `juist devices --keys`
adds its identity key, which [`juist remove`]({{< relref "docs/remove" >}})
also accepts.

`juist status -d` (`--devices`) prints the status and, after an empty line,
the device table, as `juist status` and `juist devices` one after the other.

`juist status -v` (`--verbose`) adds a line under `Relays` for each device
the last check reached through a relay, naming the device whose relay
carries the traffic to it:

```console
  Relays        1 available, via vps
                phone via vps
```

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

Each entry is one change, followed by the
[admins]({{< relref "docs/admins" >}}) whose keys approved it.

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

This shows what juistd itself reports; on FreeBSD it is `/var/log/juistd.log`.
A second network on the same device has its own daemon, `juistd@juist1`, with
its own log, on FreeBSD `/var/log/juistd.juist1.log`.

## Troubleshooting

`juist health` lists warnings, each followed by a `hint:` line.
[Troubleshooting]({{< relref "docs/troubleshooting" >}}) explains the common
ones and what to do about them.
