---
title: Keys, rotating and resetting
linkTitle: Keys
description: Give a device new keys, start a device over, deal with a lost device, back up admin keys, and know what cannot be undone.
lead: Each device has keys of its own, and the network shares one secret. You can replace them, take a device out and start it over, and cut off a device you have lost.
---

## What it is

Each device holds its own keys. Its WireGuard and sealing keys protect its
tunnels and the messages sealed to it. Its identity key names it in the
membership log, the signed list of every change that every device checks
([How juist works]({{< relref "docs/how-it-works" >}})).

The network also has a group secret, which every member shares and uses to
find the others. Admin keys are different again: they belong to people and
approve changes ([Several admins]({{< relref "docs/admins" >}})).

Replacing keys is called rotating them. A new key is a change to the log, so
the admins approve it like any other change.

## Rotating keys

| To replace … | run | note |
|---|---|---|
| this device's WireGuard and sealing keys | `juist rotate` | its name and addresses stay |
| this device's identity key | `juist rotate identity` | its IPv6 address changes |
| the network's group secret | `juist rotate group-secret` | after a leak |

Use `juist rotate` when you want new keys on a device you still trust. Where
an admin key of the network is on the device and the quorum needs one vote,
it applies at once:

```console {device="laptop"}
$ juist rotate
new keys cfe695661243
new keys live
rotated this device's keys
```

Where the change needs another admin, it waits for them, and the new keys
stay staged until the log names them. `juist rotate abandon` drops a rotation
that still waits for approval.

Connections keep running when the device takes its new keys: each peer's
tunnel waits a moment for a handshake under them. A device that runs a relay
restarts its tunnels instead, and `juist rotate identity`, which moves the
device's IPv6 address, ends what ran over the old one.

## Starting a device over

`juist reset` makes a device leave the network, as on a fresh install. It
forgets the network, and this device's keys, log, peers and operator for it.
Admin keys are kept. Here `phone` was removed from the network already:

```console {device="phone"}
$ juist reset
forget "home" and reset this device, with new keys? [y/N] y
reset; new keys, no network
```

Where your keystore holds admin keys, it adds the line
`admin keys kept in ~/.config/juist/admins`, with the full path.

A device the network still lists needs `--force`. Remove it first where you
can, from an admin's device, so that the others stop trusting it too.

On a device in [several networks]({{< relref "docs/networks" >}}), only the
network you name is forgotten, with its own juistd unless that is the first
one: `juist reset work --force`. The other networks keep their keys.

## When a device is lost

{{< step on="an admin's device" >}}
Remove the lost device:

```sh
juist remove phone
```

This also rotates the group secret. Every device drops phone's tunnel as soon
as it hears of the removal. A device cut off from the rest drops it at the
latest when its freshness expires, after 48 hours without a voucher.
{{< /step >}}

{{< step on="an admin's device" >}}
If the lost device held an admin key, take that key's vote away too. The
column `ON` of `juist admins` shows which key was on it:

```sh
juist admins remove nid:…
```

This is refused if the remaining keys cannot reach the quorum.
{{< /step >}}

A replacement device joins with a new invite, as any new device does
([Invites]({{< relref "docs/invites" >}})). If you find the old device again,
its `juist status` says `removed`. Join it again with a new invite, or run
`juist reset` there.

## Backing up admin keys

An admin key exists only in the keystore of the machine it was made on. To
keep a copy in a password manager, print it as one line and pipe it there.
`juist admins` lists the keys on this machine under `KEY HERE`:

{{< step on="an admin's machine" >}}
```sh
juist admins export alice@home | pass insert -m juist/alice
```
{{< /step >}}

To have it back, on any machine, pipe the line in again:

```console {device="laptop"}
$ pass show juist/alice | juist admins import alice@home
imported admin key "alice@home"
it casts 1 vote in "home"
```

The line goes through a pipe, never onto the command line. It carries a
checksum, so a line cut short is refused. An import never replaces a key,
and warns `"home" gives it no vote` where the key was removed since the
backup.

The break-glass line `juist create` showed is kept the same way, apart from
the admin keys
([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).

A device's own keys are not exported: a copy on another machine would be a
second device under the first one's name. A lost device is removed, and a new
one invited.

## Good to know

- Rotating, resetting and removing are for root and the device's
  [operator]({{< relref "docs/operator" >}}). Approving takes an admin key.
- `juist reset` warns when this device is the only one in the network: the
  network ends with it.
- `juist log` shows every rotation and who approved it.

{{< note danger >}}
Losing a quorum of admin keys is final. With fewer admin keys left than a
change needs, no change can be signed again: no device can be added or
removed. The break-glass secret `juist create` shows does not give the
network new admins: it ends it for good
([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).
What helps is a backup of each admin key, more admins than the quorum needs,
each on devices of their own, and for `juist admins require`, one key more
than it requires.
{{< /note >}}

Why juist accepts this is under
[trade-offs]({{< home "trade-offs" >}}).

## If something goes wrong

| You see | What to do |
|---|---|
| `juist: still a member of "home"` | `juist remove phone` on an admin's device first, or add `--force` |
| `juist status`: `removed` | this device is out of the network: join again with a new invite, or `juist reset` |
| `hint: the new keys stay staged until the log names them or: juist rotate abandon` | wait for the approval, or drop the rotation with `juist rotate abandon` |
| `juist: no admin key of this network in …` | run it where an admin's key is |
