---
title: Renaming and renumbering
linkTitle: Renaming and renumbering
description: Give the network or a device another name, or move its devices' IPv4 addresses, on every device at once.
lead: You can rename a network or a device, and move its IPv4 addresses to another range, without setting anything up again. Old addresses keep working for a week, so a device that is offline meanwhile is not cut off.
---

## What it is

A network's name is a label. It shows in `juist status` and is how you name
the network in commands. Renaming it changes nothing else. A device's name is
one too, with its name in DNS: `laptop.home.juist`.

Each device has an address in the network: an IPv4 address and an IPv6
address. Renumbering moves the IPv4 addresses, of every device or of one. You
need it when the network's range clashes with a LAN you use, or with
[another network on the same device]({{< relref "docs/networks" >}}). IPv6
addresses never change.

Both are changes to the membership log, the signed list of every change that
every device checks ([How juist works]({{< relref "docs/how-it-works" >}})).
An admin makes them, and every device follows. Where the quorum needs more
than one admin, the change waits for the others
([Several admins]({{< relref "docs/admins" >}})).

## Renaming the network

{{< step on="an admin's device" >}}
```sh
juist network rename office
```

It prints `renamed "home" to "office"`, and every device takes the new name.
{{< /step >}}

## Renaming a device

{{< step on="an admin's device" >}}
```sh
juist rename phone tablet
```

It prints `renamed phone to tablet`. Every device then reaches it as
`tablet.home.juist`, and `phone.home.juist` no longer resolves. Its keys,
addresses, roles and published names stay as they were.
{{< /step >}}

The device is named as in `juist remove`: by name, address or key. A name
another device has already, in any case, is refused. A device that
[shares files]({{< relref "docs/publishing" >}}) shares under its new name,
`tablet.pub.example.org`, so a name another device publishes is refused too,
as is one the device publishes or points at itself, and one that gives no
DNS label. A running `juist share` prints its new link.

## Moving every device's address

{{< step on="an admin's device" >}}
Move the whole network into a new range:

```console
$ juist network renumber 10.7.0.0/22
move "home" from 198.18.36.0/22 to 10.7.0.0/22, old addresses until Fri 9 Oct 14:00? [y/N] y
moving to 10.7.0.0/22; old addresses until Fri 9 Oct 14:00
```

Each device keeps its place in the range where that is free: `198.18.36.2`
becomes `10.7.0.2`.
{{< /step >}}

{{< step on="any device" >}}
Watch the move:

```console
$ juist network
home
  IPv4          10.7.0.0/22, 198.18.36.0/22 until Fri 9 Oct 14:00
  IPv6          fd77:9359:d9fb::/48

MOVING  FROM         TO        OLD UNTIL
laptop  198.18.36.1  10.7.0.1  Fri 9 Oct 14:00
nas     198.18.36.2  10.7.0.2  Fri 9 Oct 14:00
```

`juist devices` shows each device's new address, and the old one after it,
as `10.7.0.2 (was 198.18.36.2)`.
{{< /step >}}

Until the deadline, devices answer at both addresses. After it, only the new
ones work.

## Moving one device's address

```sh
juist network renumber phone 10.7.0.9
```

This moves `phone` to `10.7.0.9`, in the network's own range. Its old address
keeps working until the deadline, as above.

## Retiring old addresses now

When every device has heard of the move, you need not wait for the deadline:

| To … | run |
|---|---|
| move one device and retire its old address at once | `juist network renumber phone 10.7.0.9 --finish` |
| retire every old address now | `juist network renumber --finish` |

`--finish` warns first: devices not told of the move yet lose the old
address.

## Good to know

- Old IPv4 addresses keep working for 7 days by default. `--for 12h` or
  `--for 14d` sets another time; make it long enough for every device to come
  online once.
- The deadline is fixed when the change is proposed. Where other admins
  approve it later, they see how much of it is left.
- A device keeps one old address. Moving it again before the deadline drops
  the earlier old address at once, and juist warns about it.
- Retired addresses stay held, so that no other device takes them, until a
  plain `juist network renumber --finish`.
- The new range must have room for every device. juist warns when it
  overlaps a LAN of this host, or another network the device is in.
- Configuration outside juist that names old addresses is not moved: update
  firewall rules, `/etc/hosts` entries and the like yourself.
- With [several networks]({{< relref "docs/networks" >}}) on the device, name
  the network first: `juist network renumber work 10.7.0.0/24`,
  `juist network rename work office`.
- A device name with `.` or `_` is no DNS name: juist warns, and the device
  is then reached by its address alone. A device with the role `publish`
  cannot take such a name, since it shares under its name.
- An admin key keeps the device name it was filed under; `juist admins`
  shows it.

## If something goes wrong

| You see | What to do |
|---|---|
| `juist status`: `no IPv4 on this host: …` | two networks here overlap; renumber one of them, as the hint says |
| `juist: 10.7.0.9 is taken by nas` | pick a free address |
| `juist: 10.7.0.9 is outside the network's range …` | pick one in the range `juist network` shows |
| `juist: the network predates renumbering` | once every device runs this version: `juist log upgrade` |
| `juist: the network predates renaming a device` | the same |
| `juist: another device is named "tablet" already` | pick another name, or rename that device first |
