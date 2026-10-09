---
title: Security in short
linkTitle: Security
description: Whom juist trusts and whom it does not, where the keys live, and what it accepts on purpose.
lead: What juist protects, what it relies on, and where its limits are, for readers who are not security experts. juist has not had a security audit.
---

## What it is

juist has no server in the middle that decides who belongs to the network.
Your admins decide, by signing changes, and every device checks those changes
itself. This page says what follows from that: whom you have to trust, where
the keys are, and what juist cannot do.

The full analysis, with every weakness that remains, is in the
[threat model](https://github.com/nning/juist/blob/main/docs/02-threat-model.md).

## Whom you trust

- Your admins, as a group. A change, such as admitting or removing a device,
  needs the quorum: as many admin votes as the network requires. An admin
  with fewer votes than that can change nothing alone, and the log records who
  signed each change.
- The network's start. Every device checks each change in the
  [membership log]({{< relref "docs/how-it-works" >}}#the-membership-log) back
  to the first one, made when the network was created.
- Every member, as far as the [access policy]({{< relref "docs/access" >}})
  lets it in. Without one, an admitted device reaches every port of every
  other member through the tunnel. With one, each device refuses what no
  rule passes, whatever the sender does.
- An exit node, for what it carries. The internet traffic you send through an
  [exit node]({{< relref "docs/exit-nodes" >}}) is readable there, as it would
  be at any VPN provider.

## Whom you do not trust

- The paths in between. Every change is signed and checked by every device,
  however it arrived. Traffic between members is encrypted by WireGuard.
- The public helpers. The public BitTorrent DHT and the STUN servers help
  devices find each other. They can delay a connection, but cannot change who
  belongs to the network or read traffic. They see the addresses that use them.
- The relay. A [relay]({{< relref "docs/relays" >}}) is one of your own
  members. Only members can use it, and it sees only encrypted WireGuard
  traffic.
- The daemon, for signing. juistd never holds an admin key, so a compromised
  juistd cannot sign changes.

## Where the keys live

- Admin keys are in your keystore, `~/.config/juist`, on each machine you
  approve from. Never copy a key: an admin with two laptops makes a key on
  each. Each network gets a key of its own, so a lost or stolen key costs one
  network.
- The device's own keys are held by juistd; on Linux the package keeps
  them in `/var/lib/juist`. juistd runs as its own user, with `CAP_NET_ADMIN`
  only. On a phone, the [Android app]({{< relref "docs/android" >}}) seals
  them by a key that Android Keystore holds. The `juist` command signs only what it has rebuilt from its own
  verified log, whatever juistd asks.
- The break-glass secret `juist create` shows once, and keeps nowhere, ends
  the network for good with no admin needed. Keep it offline, apart from the
  admin keys: one vault holding both governs the network and ends it.

## What invites protect against

An [invite]({{< relref "docs/invites" >}}) lets one device join. It protects
against three things:

- Guessing. A code allows exactly one guess, and only from the LAN. A link
  holds a 128-bit secret, far too long to guess.
- A device in between. Before anything is signed, the admin compares four
  words with the new device. They are made so that nobody in between can
  search for a match.
- A compromised daemon on the inviting device. The link binds the new
  device to the inviting admin's signature, so that daemon cannot enroll it
  into a network of its own.

## Removing a device, and its limit

`juist remove phone` takes a device out of the network. It replaces the
network's group secret, which members use to find each other, and every member drops its tunnel to the device on
hearing of the removal. See [Removing a device]({{< relref "docs/remove" >}}).

The limit: a member that is cut off from the rest hears of it late, and until
then keeps its tunnel to the removed device. Freshness bounds that to 48
hours: a member that no voucher has vouched for in 48 hours keeps tunnels only
to vouchers. A **voucher** is a device that confirms every hour that the
network's state is current. With `juist admins vouchers M`, that bound holds
even if M − 1 vouchers lie. See
[freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).

A lost or stolen device is a member until you remove it. Remove it as soon as
you notice.

## What juist accepts

Some things are weaker without a server in the middle. The
[trade-offs]({{< home "trade-offs" >}}) say for each what can happen, why
it is accepted, and what you can change. In short:

- Losing the admin keys of a quorum makes the network unrecoverable. Give it
  more admins than the quorum needs.
- A network where every device sits behind symmetric NAT needs a relay member.
- The public DHT and STUN servers see the addresses that use them, and nothing
  more. With a relay of your own, juistd can run without them.

## Post-quantum

A future quantum computer could break today's common encryption. juist
protects the network's group secrets against that: they use X25519 together
with ML-KEM-768. WireGuard traffic is not protected that way. Signatures are
Ed25519.

So traffic recorded today could one day be decrypted. Do not rely on juist for
traffic that must stay secret for decades.

## Good to know

- juist has not had a security audit.
- On Linux, juist drops what reaches a device's juist addresses other than
  through the tunnel, and what claims to come from a member but arrives from
  the LAN. So a container on the device no longer reaches the device's own
  juist address. On FreeBSD a service that listens only on a device's juist
  address can still be reached from that device's LAN. Either way, have
  services check who connects.
- Every change to the network, and who approved it, is in `juist log`.

## Reporting a vulnerability

Report it privately, through **Report a vulnerability** on the
[repository's Security tab](https://github.com/nning/juist/security), not in
a public issue. You get an answer within a week, and a fix is released before
the details are published.
