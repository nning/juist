---
title: Removing a device
linkTitle: Removing a device
description: Take a device out of the network on every device, and know how soon each one drops it.
lead: juist remove takes a device out of the network, such as a phone you lost. Every device drops its tunnel as soon as it hears of the removal, and a device cut off from the others drops it at the latest when its freshness expires.
---

## How removal works

Removing a device is a change to the network's log, the signed list of who
belongs (see [How juist works]({{< relref "docs/how-it-works" >}})). Like any
change, it needs the approval of your admins, the people whose keys approve
changes.

Once the removal is in the log, every device that receives it drops the
removed device's tunnel. The network also gets a new group secret, a key all
members share, so the removed device can no longer find the others.

## Removing a device

{{< step on="an admin's device" >}}
Remove the device by its name, address, or key. `juist devices --keys` shows
the keys; add `--all` if an access policy separates that device from this one:

```sh
juist remove phone
```

```console
$ juist remove phone
remove phone (198.18.36.4  fd4c:8a21:e3f:e83:5a7d:f12c:9b46:d371) from "home"? [y/N] y
removed phone
```

If the change needs more than one admin, it prints `pending …` instead and
waits for the others to run `juist approve`
([approving changes]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist log` now lists `device removal: phone`, with the admins who approved
it.

## What the removed device sees

If the removed device is reachable when the removal takes effect, it is told:

```console {device="phone"}
$ juist status
home · removed

hint: 1 warning: juist health
$ juist health
warning: this device was removed from the network
hint: rejoin with a new invite, or start over: juist reset
```

To use it again, [invite]({{< relref "docs/invites" >}}) it again, or run
`juist reset`, which leaves it in no network, as after a fresh install.

A device that was offline at that moment is not told. It may report itself connected,
although no member accepts it any more, or say
`the network's devices refuse this one: most likely it was removed`.

## Why removal is not instant

There is no server that tells all devices at the same time. Devices pass changes on to
each other, so a device that is offline, or cut off from the others, hears of
the removal only when it is back in touch. Until then, it could keep a tunnel
to the removed device.

Freshness puts a limit on that. A **voucher** is a device that confirms every
hour that the network's state is current. A new network has none, so there is
no limit until you make a device a voucher. If no voucher has confirmed a
device's view for 48 hours, it keeps tunnels only to vouchers, so it can no
longer stay connected to a removed device. Its `juist status` then shows the state `limited` and
`Freshness  expired; vouchers only`.

This holds only while the vouchers are not cut off together with the device:
a voucher keeps every device it still reaches current.

{{< step on="an admin's device" >}}
Make an always-on device, such as a VPS, a voucher:

```sh
juist grant vps voucher
```

The role does not give the device an admin key. The device can confirm the
network's state, but not change anything.
{{< /step >}}

By default, one voucher is enough. A voucher that lies could then keep the
devices it reaches on an old view. To guard against that, require several:

```sh
juist admins vouchers 2
```

Now a device trusts its view only when two vouchers have confirmed it within
48 hours. One dishonest voucher is then not enough, but two vouchers must be
online, so give the role to a third device as a spare. `juist grant` and
`juist admins vouchers` warn if there is no spare, and if only one voucher is
needed and a voucher also relays.

## Notes

- `juist remove` refuses to remove one of the vouchers that `juist admins vouchers` requires, and says how to lower the number first.
- Removing the last voucher warns that freshness then goes unchecked.
- If the removed device held an admin key, as a lost laptop might, take that key's vote away too: `juist admins remove`. See [Admins]({{< relref "docs/admins" >}}).
- Running `juist remove` on the device itself warns that the device leaves the network for good.
- `juist reset` on a device the network still lists needs `--force`. Remove it first where you can.

## Troubleshooting

`Freshness  expired; vouchers only` means too few vouchers have been
reachable for 48 hours. `juist health` warns a day before, with `freshness
ends in …`. Bring a voucher back online; the device is current again once the
voucher's confirmation arrives. See
[Troubleshooting]({{< relref "docs/troubleshooting" >}}).
