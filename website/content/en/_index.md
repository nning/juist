---
title: juist
description: A peer-to-peer mesh VPN with no coordination server. WireGuard carries the traffic; a log signed by your admins says who belongs to the network.
headline: A mesh VPN with no coordination server
lead: WireGuard carries the traffic. Who belongs to the network is a log signed by your admins, and every device checks that log for itself.
links:
  - {label: Features, anchor: features}
  - {label: Trade-offs, anchor: trade-offs}
  - {page: docs/architecture}
  - {page: docs/compare}
  - {page: docs}
---

{{< rules >}}
No server in the middle
: Devices find each other on the LAN, through each other, or through the public BitTorrent DHT. They punch through NAT, and fall back to a relay that one of your own devices runs.

Changes need your admins
: Admitting or removing a device takes a quorum of admins, each with a key on their own devices. The keys stay in the keystore; the daemon never holds them.

Fail-closed
: Once a network has vouchers, a device that too few of them vouched for in 48 hours keeps tunnels only to vouchers. It cannot keep a removed device connected.
{{< /rules >}}

## Your first network

On the first device, `juist create` makes a network and `juist invite` prints
a code for the LAN and a link for anywhere else. The new device joins with
either. Both then show four words, and the invite admits the device only once
you have compared them.

```console {device="laptop"}
$ juist create home
created network "home"
$ juist invite
invite to "home", expires in 1h; on the new device:

  juist join 'juist:Kx7q…@192.168.1.20:41642'

  juist join 42-drumbeat-tolerance-glucose  # same LAN

nas wants to join; compare with the words it shows:
  atlas-amulet-banjo-asteroid
same? [y/N] y
admitting nas (nid:fcRW83T_…)
admitted nas at 198.18.36.2
nas joined
```

## Features {#features}

Made for networks of up to about 100 devices with a few admins. A network holds at most 512 devices.

{{< features >}}

## Publishing services {#publishing}

A member's service, such as a NAS at home, can be reached from the internet by
name. A device with a public address, the ingress, reads the name the client
asks for and passes the connection through the tunnel. TLS ends at the member,
so the ingress never sees the content.

{{< flow publish >}}

How to set it up is in the [handbook]({{< relref "docs/publishing" >}}).

## Trade-offs {#trade-offs}

Without a server in the middle, some things are weaker than with one. Each
entry says what can happen, why juist accepts it, and what you can change.
All of them are in [02-threat-model.md](https://github.com/nning/juist/blob/main/docs/02-threat-model.md).

### Membership

{{< trade title="Revocation is eventually consistent" knob="juist admins vouchers M" >}}
What happens
: A device cut off from the network keeps tunnels to a removed device until it hears of the removal.

Why accepted
: There is no server that every device could ask. The freshness lease bounds it: a device no voucher has vouched for in 48 h keeps tunnels only to vouchers.

What you can do
: Make always-on devices vouchers, and require M of them, so that the bound holds against M − 1 dishonest ones. A new network has no vouchers, and so no bound.
{{< /trade >}}

{{< trade title="Losing a quorum of admin keys is final" knob="more admins than the quorum needs" >}}
What happens
: With fewer than k admin keys left, no change can be signed again, ever.

Why accepted
: A way around the quorum would be one for an attacker too.

What you can do
: Give the network more admins than the quorum needs, each with their own devices.
{{< /trade >}}

### Reachability

{{< trade title="Symmetric NAT everywhere needs a relay" knob="juist grant vps relay" >}}
What happens
: Where every device sits behind symmetric NAT, no direct tunnel forms.

Why accepted
: The relay is one of your own members and sees only WireGuard ciphertext.

What you can do
: Grant `relay` to a device with a public address.
{{< /trade >}}

{{< trade title="Public helpers see addresses" knob="--no-dht --no-stun" >}}
What happens
: The public BitTorrent DHT and STUN servers see the addresses that use them.

Why accepted
: Nothing they return is trusted. A compromised helper can delay connections, but cannot change who belongs to the network.

What you can do
: Run juistd without them, and give devices addresses at which they can reach each other.
{{< /trade >}}

### Cryptography

{{< trade title="A tunnel starts on the group's key" knob="no setting" >}}
What happens
: Two devices get their own key one log sync after their tunnel comes up. Until then, their traffic is protected by a key any member could derive.

Why accepted
: Against everyone outside the network it is quantum-safe from the start. Only a member, or a device removed since, with a quantum computer could read those first seconds.

What you can do
: Nothing; it lasts until the next log sync between the two.
{{< /trade >}}
