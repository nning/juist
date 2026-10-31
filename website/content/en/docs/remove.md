---
title: Removing a device
linkTitle: Removing a device
description: Take a device out of the network on every device, and know how soon each one drops it.
lead: juist remove takes a device out of the network, such as a phone you lost. Every device drops its tunnel as soon as it hears of the removal, and a device cut off from the others drops it at the latest when its freshness expires.
---

## How removal works

Removing a device is a change to the
[membership log]({{< relref "docs/how-it-works" >}}#the-membership-log) and
needs your admins' approval. Every device that receives it drops the removed
device's tunnel. The network also gets a new group secret, the key all
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

A device that was offline then is not told. It may report itself connected,
although no member accepts it, or say
`the network's devices refuse this one: most likely it was removed`.

## Why removal is not instant

Devices pass changes on to each other. A device that is offline or cut off
hears of the removal only when it is back in touch, and until then could keep
a tunnel to the removed device. [Freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)
limits that to 48 hours, but only once the network has a voucher:

{{< step on="an admin's device" >}}
Make an always-on device, such as a VPS, a voucher:

```sh
juist grant vps voucher
```

The role gives the device no admin key. It confirms the network's state but
cannot change anything.
{{< /step >}}

One lying voucher could keep the devices it reaches on an old view. To guard
against that, require two:

```sh
juist admins vouchers 2
```

Two vouchers must then be online, so give the role to a third device as a
spare. `juist grant` and `juist admins vouchers` warn if there is no spare.

## Good to know

- `juist remove` refuses to remove a voucher that `juist admins vouchers`
  requires, and says how to lower the number first. Removing the last voucher
  warns that freshness then goes unchecked.
- If the removed device held an admin key, as a lost laptop might, take that
  key's vote away too: `juist admins remove` ([Admins]({{< relref "docs/admins" >}})).
- `juist reset` on a device the network still lists needs `--force`. Remove
  it first if you can.

## Troubleshooting

`Freshness  expired; vouchers only` means too few vouchers have been
reachable for 48 hours. `juist health` warns a day before, with `freshness
ends in …`. Bring a voucher back online; the device is current again once the
voucher's confirmation arrives. See
[Troubleshooting]({{< relref "docs/troubleshooting" >}}).
