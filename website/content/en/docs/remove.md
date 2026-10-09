---
title: Removing a device
linkTitle: Removing a device
description: Take a device out of the network on every device, and know how soon each one drops it.
lead: juist remove takes a device out of the network, such as a phone you lost. Every device drops its tunnel as soon as it hears of the removal, and a device cut off from the others drops it at the latest when its freshness expires.
---

## What it is

Removing a device is a change to the network's log, the signed list of who
belongs (see [How juist works]({{< relref "docs/how-it-works" >}})). Like any
change, it needs the approval of your admins, the people whose keys approve
changes.

Once the removal is in the log, every device that receives it drops the
removed device's tunnel. The network also gets a new group secret, a key all
members share, so the removed device can no longer find the others.

## Removing a device

{{< step on="an admin's device" >}}
Remove the device by its name, its address, or its key (`juist devices --keys`,
with `--all` where an access policy keeps it apart from this device):

```sh
juist remove phone
```

```console
$ juist remove phone
remove phone (198.18.36.4  fd4c:8a21:e3f:e83:5a7d:f12c:9b46:d371) from "home"? [y/N] y
removed phone
```

Where a change needs more than one admin, it prints `pending …` instead and
waits for the others to run `juist approve`
([approving changes]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist log` now lists `device removal: phone`, with the admins who approved
it.

## What the removed device sees

If it can be reached when the removal is applied, it is told:

```console {device="phone"}
$ juist status
home · removed
hint: rejoin with a new invite, or start over: juist reset
```

To use it again, [invite]({{< relref "docs/invites" >}}) it anew, or run
`juist reset` to leave it in no network, as on a fresh install.

A device that was offline then is not told. It may report itself connected,
although no member accepts it any more, or say
`the network's devices refuse this one: most likely it was removed`.

## Why it is not instant everywhere

There is no server that tells every device at once. Devices pass changes on to
each other, so a device that is offline, or cut off from the others, hears of
the removal only when it is back in touch. Until then, it could keep a tunnel
to the removed device.

Freshness puts a limit on that. A **voucher** is a device that confirms every
hour that the network's state is current. A new network has none, so there is
no limit until you make one. A device that no voucher has
confirmed for 48 hours keeps tunnels only to vouchers, so it cannot carry a
removed device along. Its `juist status` then shows the state `limited` and
`Freshness  expired; vouchers only`.

This holds only while the vouchers are not cut off together with the device:
a voucher keeps every device it still reaches current.

{{< step on="an admin's device" >}}
Make an always-on device, such as a VPS, a voucher:

```sh
juist grant vps voucher
```

The role is not an admin key. It lets the device confirm the network's state,
and change nothing.
{{< /step >}}

By default, one voucher is enough. A voucher that lies could then keep the
devices it reaches on an old view. To guard against that, require several:

```sh
juist admins vouchers 2
```

Now a device trusts its view only when two vouchers have confirmed it within
48 hours. One dishonest voucher is not enough, but two vouchers must be online,
so give the role to a third as a spare. `juist grant` and `juist admins
vouchers` warn where there is none, and where the one voucher needed also
relays.

## Good to know

- `juist remove` refuses to remove one of the vouchers that `juist admins vouchers` requires, and says how to lower the number first.
- Removing the last voucher warns that freshness then goes unchecked.
- If the removed device held an admin key, as a lost laptop might, take that key's vote away too: `juist admins remove`. See [Admins]({{< relref "docs/admins" >}}).
- `juist remove` on the device itself warns that it leaves the network for good.
- `juist reset` on a device the network still lists needs `--force`. Remove it first where you can.

## If something goes wrong

`Freshness  expired; vouchers only` means too few vouchers have been
reachable for 48 hours. `juist status` warns a day before, with `freshness
ends in …`. Bring a voucher back online; the device is current again once the
voucher's confirmation arrives. See
[Troubleshooting]({{< relref "docs/troubleshooting" >}}).
