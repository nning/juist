---
title: Renaming and renumbering
linkTitle: Renaming and renumbering
description: Give the network or a device another name, move the devices' IPv4 addresses, or end the network, on all devices at the same time.
lead: You can rename a network or a device, and move its IPv4 addresses to another range, without setting anything up again. Old addresses keep working for a week, so a device that is offline in the meantime is not cut off.
---

## Names and addresses

A network's name is only a label. It shows in `juist status`, and you use it
to refer to the network in commands. Renaming the network changes nothing
else. The same goes for a device's name, which also gives the device its DNS
name: `laptop.home.juist`.

Each device has an IPv4 address and an IPv6 address in the network.
Renumbering moves the IPv4 addresses, either of all devices or of a single
one. You need it when the network's range clashes with a LAN you use, or with
[another network on the same device]({{< relref "docs/networks" >}}). IPv6
addresses never change.

Both are changes to the membership log, the signed list of every change that
every device checks ([How juist works]({{< relref "docs/how-it-works" >}})).
An admin makes them, and every device follows. If the quorum needs more than
one admin, the change waits for the others
([Several admins]({{< relref "docs/admins" >}})).

## Renaming the network

{{< step on="an admin's device" >}}
```sh
juist network rename office
```

It prints `renamed "home" to "office"`, and every device adopts the new name.
{{< /step >}}

## Renaming a device

{{< step on="an admin's device" >}}
```sh
juist rename phone tablet
```

It prints `renamed phone to tablet`. Every device then reaches it as
`tablet.home.juist`, and `phone.home.juist` no longer resolves. Its keys,
addresses, roles and published names stay the same.
{{< /step >}}

You specify the device as for `juist remove`: by name, address or key. juist
refuses a name that another device already has, regardless of upper or lower
case.

A device that [shares files]({{< relref "docs/publishing" >}}) shares them
under its new name, such as `tablet.pub.example.org`. For such a device, juist
also refuses a name that another device publishes, a name the device itself
already publishes or points at itself, and a name that is not a valid DNS
label. A running `juist share` prints its new link.

## Moving every device's address

{{< step on="an admin's device" >}}
Move the whole network into a new range:

```console
$ juist network renumber 10.7.0.0/22
move "home" from 198.18.36.0/22 to 10.7.0.0/22, old addresses until Fri 9 Oct 14:00? [y/N] y
moving to 10.7.0.0/22; old addresses until Fri 9 Oct 14:00
```

Each device keeps its position in the range if that position is free:
`198.18.36.2` becomes `10.7.0.2`.
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

`juist devices` shows each device's new address followed by the old one, as
`10.7.0.2 (was 198.18.36.2)`.
{{< /step >}}

Until the deadline, devices answer at both addresses. After that, only the
new ones work. Connections keep running through the move, except those to or
from an old address, which end when that address does.

## Moving one device's address

```sh
juist network renumber phone 10.7.0.9
```

This moves `phone` to `10.7.0.9`, which must be in the network's range. As
above, its old address keeps working until the deadline.

## Retiring old addresses early

Once every device has heard of the move, you don't have to wait for the
deadline:

| To | Run |
|---|---|
| move one device and retire its old address immediately | `juist network renumber phone 10.7.0.9 --finish` |
| retire all old addresses now | `juist network renumber --finish` |

`--finish` warns first that devices that have not yet heard of the move lose
the old address.

## Ending the network

`juist create` shows the network's break-glass secret once, as the line
`Break-glass   juist-break-glass-1.…`, and does not store it anywhere. The
secret ends the network for good, without any admin. It is the way out when
too few admin keys are left to change the network, because they were lost or
stolen.

{{< step on="a device of the network" >}}
```console {device="laptop"}
$ pass show juist/break-glass-home | juist network disable --yes
disabled "home"; every device stops as the record reaches it
```
{{< /step >}}

Without a pipe, `juist network disable` prompts for the line, without echoing
it, and then asks whether to end the network. `--secrets FILE` reads the line
from a file.

Each device passes the record on and drops its tunnels as soon as it receives
it, and its `juist status` then says `disabled`. To carry on, run
`juist reset` on each device and join them to a new network created with
`juist create`.

Store the line separately from the admin keys: whoever gets a vault holding
both can both govern the network and end it.

## Notes

- Old IPv4 addresses keep working for 7 days by default. `--for 12h` or
  `--for 14d` sets a different period. Make it long enough for every device to
  come online at least once.
- The deadline is fixed when the change is proposed. Admins who approve it
  later see how much time is left.
- A device has at most one old address. Moving it again before the deadline
  drops the earlier old address immediately, and juist warns about this.
- Retired addresses stay reserved, so that no other device gets them, until
  you run `juist network renumber --finish` without further arguments.
- The new range must have room for every device. juist warns when it
  overlaps a LAN of this host, or another network the device is in.
- Configuration outside juist that names old addresses is not moved: update
  firewall rules, `/etc/hosts` entries and the like yourself.
- With [several networks]({{< relref "docs/networks" >}}) on the device, name
  the network first: `juist network renumber work 10.7.0.0/24`,
  `juist network rename work office`.
- A device name containing `.` or `_` is not a valid DNS name. juist warns,
  and the device can then only be reached by its address. A device with the
  `publish` role cannot take such a name, since it shares under its name.
- An admin key keeps the device name it was filed under; `juist admins`
  shows it.
- Anyone holding the break-glass line can end the network. A device running a
  juist version older than `juist network disable` does not stop until it is
  updated. A device that is offline at the time finds no other device to reach
  when it comes back.
- Networks created before juist showed the line keep their secrets in the
  keystore, as `break-glass-NETWORK.secrets`. `juist network disable` reads
  that file from there; move it offline.

## Troubleshooting

| What you see | What to do |
|---|---|
| `juist status`: `no IPv4 on this host: …` | Two networks on this device overlap. Renumber one of them, as the hint says. |
| `juist: 10.7.0.9 is taken by nas` | Pick a free address. |
| `juist: 10.7.0.9 is outside the network's range …` | Pick one in the range that `juist network` shows. |
| `juist: the network predates renumbering` | Once every device runs this version, run `juist log upgrade`. |
| `juist: the network predates renaming a device` | The same. |
| `juist: another device is named "tablet" already` | Pick another name, or rename that device first. |
| `juist: no line on stdin` | Pipe the break-glass line in, or give its file with `--secrets FILE`. |
| `juist: no break-glass secret of "home" there` | The line belongs to another network. |
| `juist: "home" is disabled; nothing changes it any more` | The network has ended. Run `juist reset`, then `juist create`. |

