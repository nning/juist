---
title: A network of phones alone
linkTitle: Phones alone
description: Found a network on an Android phone and invite the others, with no computer and no server; they meet through Tailscale's public DERP servers until a device of your own relays.
lead: A few phones, no computer, no server. One phone founds the network and invites the others, and they reach each other on Wi-Fi and on mobile data, through Tailscale's public DERP servers where they cannot directly.
---

## What you get

Each phone reaches the others at their addresses in the network, at home, on
the road and between carriers. One phone holds the admin key and admits or
removes the others behind its fingerprint. A phone that is removed learns
of it as soon as it meets one that knows.

## What you need

- Android 12 or newer on each phone, with the [app]({{< relref "docs/android" >}}).
- A screen lock on the phone that founds the network: it guards the admin key.

## Setting it up

{{< step on="the first phone" >}}
Tap **Create a network**, name the network and the phone, and confirm with
your fingerprint or screen lock.

The app then shows the network's break-glass line, once: keep it somewhere
safe, apart from the phone, in case the network ever has to be ended. It
offers a backup of the admin key too, which you may skip, as described in
[Android]({{< relref "docs/android" >}}).
{{< /step >}}

{{< step on="the first phone" >}}
Under the devices, tap **Invite a device**. The app shows a QR code.
{{< /step >}}

{{< step on="each other phone" >}}
Scan the QR code with the app. Both phones show four words; once they match,
tap **Same words** on the first phone and confirm with your fingerprint.
{{< /step >}}

## Watch out for

- **Tailscale's servers see who talks to whom.** Phones on mobile data can
  rarely reach each other directly, and no phone can relay for the others,
  so the network uses Tailscale's public DERP servers from the start. They
  carry encrypted WireGuard traffic alone, but see every phone's public
  address and which phones exchange packets with which, when and how much
  ([Relays]({{< relref "docs/relays" >}}#public-derp)). You need no
  Tailscale account.
- **The admin key is on one phone.** Lost, without a backup, the network can
  no longer be changed: no device admitted, none removed. The break-glass
  line ends it only from a computer that is a member already, which no
  phone is: join a laptop early, or keep the key's backup.
- **Freshness is unchecked**, since no phone vouches for the others: a
  removed phone keeps working with those that have not learned of its
  removal.

## Without Tailscale's servers

Once a device of yours with a public address relays, the network no longer
needs Tailscale's servers. A laptop is where you turn them off, since the app
has no switch for it.

{{< step on="the first phone" >}}
Invite the laptop: **Invite a device**, then share the link.
{{< /step >}}

{{< step on="laptop" >}}
[Install juist]({{< relref "docs/install" >}}) and join with the link:

```sh
sudo juist join 'juist:…'
```

Then compare the four words with the phone's and admit it there.
{{< /step >}}

{{< step on="the first phone" >}}
In the status screen's menu, tap **Back up the admin key** and copy the line
into a password manager, or save it as a file sealed by a password.
{{< /step >}}

{{< step on="laptop" >}}
Import the admin key from the line or the file, under a name of your choice:

```sh
pass show juist/home | juist admins import alice@home
```

or `juist admins import alice@home < juist-admin-home.txt`, the file the app
saved, which asks for its password. The laptop now holds a copy of the phone's key
([Admin keys]({{< relref "docs/keys" >}})).
{{< /step >}}

{{< step on="vps" as="the relay" >}}
Set up a device with a public address as a relay, such as a small VPS, as
[Relays]({{< relref "docs/relays" >}}#setting-up-a-relay) describes: join,
open the ports, and `juist grant vps relay` on the laptop. Give it a public
name on 443 too ([A relay on 443]({{< relref "docs/relays" >}}#a-relay-on-443)):
until now Tailscale's servers served phones on Wi-Fi that lets nothing but
HTTPS out, and without them only that name does.
{{< /step >}}

{{< step on="laptop" >}}
Turn Tailscale's servers off:

```sh
juist network derp off
```

`juist status` then counts the VPS on its `Relays` line and no longer names
Tailscale's servers.
{{< /step >}}

A laptop behind NAT, as at home, relays for no one: turned off before a
device with a public address relays, Tailscale's servers leave phones on
mobile data that cannot reach each other directly without a way to meet.
`juist network derp on` turns them back on.

Vouchers bound to 48 hours how long a removed phone keeps working with the
others. They want devices that are always on, best two in different places
([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)). A
laptop or phone that is often off makes a poor one, and a relay as a
voucher, while one voucher is enough, could keep a device it cuts off
fresh, which `juist grant` warns of.

## Read more

- [Android]({{< relref "docs/android" >}}): the app, the admin key and its
  backup
- [Without a relay of your own]({{< relref "docs/relays" >}}#public-derp):
  what Tailscale's servers see
- [Admin keys]({{< relref "docs/keys" >}}): the break-glass line, and keys on
  several devices
