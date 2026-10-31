---
title: Keys, rotating and resetting
linkTitle: Keys
description: Give a device new keys, start a device over, deal with a lost device, back up admin keys, and know what cannot be undone.
lead: Each device has its own keys, and all devices in a network share one secret. You can replace both, take a device out and start it over, and cut off a device you have lost.
---

## Which keys there are

Each device has its own keys. Its WireGuard and sealing keys protect its
tunnels and the messages sealed to it. Its identity key identifies it in the
[membership log]({{< relref "docs/how-it-works" >}}#the-membership-log).

The network also has a group secret, which all members share and use to find
each other. Admin keys belong to people and approve changes
([Several admins]({{< relref "docs/admins" >}})).

Replacing keys is called rotating them. A new key is a change to the log, so
the admins approve it like any other.

## Rotating keys

| To replace | Run | Note |
|---|---|---|
| this device's WireGuard and sealing keys | `juist rotate` | its name and addresses stay |
| this device's identity key | `juist rotate identity` | its IPv6 address changes |
| the network's group secret | `juist rotate group-secret` | after a leak |

Use `juist rotate` to give new keys to a device you still trust. If the device
holds an admin key of the network and the quorum needs only one vote, the
change takes effect immediately:

```console {device="laptop"}
$ juist rotate
new keys cfe695661243
new keys live
rotated this device's keys
```

If the change needs another admin, it waits for their approval, and the new
keys stay staged until the log contains them. `juist rotate abandon` drops a
rotation that is still waiting for approval.

Connections keep running while the device switches to its new keys. A
device that runs a relay restarts its tunnels instead.

`juist rotate identity` changes the device's IPv6 address, which ends the
connections that used the old one. It needs the network at schema 19; below
it, it stops with `juist: the network predates rotating an identity key`
until an admin runs `juist log upgrade`
([Updating juist]({{< relref "docs/updating" >}})).

## Starting a device over

`juist reset` takes a device out of the network and leaves it as if freshly
installed. It forgets the network along with everything it kept for it: its
keys, log, peers and operator. Admin keys are kept. In this example, `phone`
had already been removed from the network:

```console {device="phone"}
$ juist reset
forget "home" and reset this device, with new keys? [y/N] y
reset; new keys, no network
```

If your keystore holds admin keys, it adds the line
`admin keys kept in ~/.config/juist/admins`, with the full path.

If the network still lists the device, `juist reset` needs `--force`. Where
you can, remove the device from an admin's device first, so that the other
devices stop trusting it too.

On a device in [several networks]({{< relref "docs/networks" >}}), only the
network you name is forgotten: `juist reset work --force`. Its juistd is
removed too, unless it is the first network's. The other networks keep their
keys.

## When a device is lost

{{< step on="an admin's device" >}}
Remove the lost device:

```sh
juist remove phone
```

This also rotates the group secret. Every device drops its tunnel to phone
once it hears of the removal; a cut-off device does so within 48 hours if the
network has [vouchers]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).
{{< /step >}}

{{< step on="an admin's device" >}}
If the lost device held an admin key, remove that key's vote too. The `ON`
column of `juist admins` shows which key was on it:

```sh
juist admins remove nid:…
```

juist refuses this if the remaining keys cannot reach the quorum.
{{< /step >}}

A replacement device joins with a new invite, like any new device
([Invites]({{< relref "docs/invites" >}})). If the old device turns up again,
its `juist status` says `removed`. Join it again with a new invite, or run
`juist reset` on it.

## Backing up admin keys

An admin key exists only in the keystore of the machine it was created on. To
keep a copy in a password manager, print it as a single line and pipe it
there. `juist admins` lists the keys on this machine under `KEY HERE`:

{{< step on="an admin's machine" >}}
```sh
juist admins export alice@home | pass insert -m juist/alice
```
{{< /step >}}

To restore it on any machine, pipe the line back in:

```console {device="laptop"}
$ pass show juist/alice | juist admins import alice@home
imported admin key "alice@home"
it casts 1 vote in "home"
```

The line always goes through a pipe, never onto the command line. Its
checksum refuses a truncated line. It also covers the key's quantum-safe
signing key, which derives from it. An import never replaces an existing key.
If the key was removed from the network since the backup, the import warns
`"home" gives it no vote`.

Keep the break-glass line that `juist create` showed the same way, but
separately from the admin keys
([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).

A device's own keys cannot be exported: a copy on another machine would be a
second device under the first one's name. Instead, remove a lost device and
invite a new one.

## Good to know

- Only root and the device's [operator]({{< relref "docs/operator" >}}) can
  rotate, reset and remove. Approving takes an admin key.
- `juist reset` warns when this device is the only one in the network, since
  the network ends with it.
- `juist log` shows every rotation and who approved it.

{{< note danger >}}
Losing a quorum of admin keys is final. With fewer admin keys left than a
change needs, no device can ever be added or removed again. The break-glass
secret that `juist create` shows only ends the network
([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).
Back up every admin key, have more admins than the quorum needs, each on
their own devices, and with `juist admins require`, hold one key more than
it requires.
{{< /note >}}

Why juist accepts this is explained under
[trade-offs]({{< home "trade-offs" >}}).

## Troubleshooting

| What you see | What to do |
|---|---|
| `juist: still a member of "home"` | Run `juist remove phone` on an admin's device first, or add `--force`. |
| `juist status`: `removed` | This device is no longer in the network. Join again with a new invite, or run `juist reset`. |
| `hint: the new keys stay staged until the log names them or: juist rotate abandon` | Wait for the approval, or drop the rotation with `juist rotate abandon`. |
| `juist: no admin key of this network in …` | Run the command where an admin's key is. |

