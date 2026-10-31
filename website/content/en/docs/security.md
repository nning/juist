---
title: Security in short
linkTitle: Security
description: What juist trusts and what it does not, where the keys live, and which weaknesses it accepts on purpose.
lead: What juist protects, what it relies on, and where its limits are, for readers who are not security experts. juist has not had a security audit.
---

## Who decides

juist has no server in the middle that decides who belongs to the network.
Your admins decide, by signing changes, and every device checks those changes
itself. This page explains what follows from that: what you have to trust,
where the keys are, and what juist cannot do.

The full analysis, with every remaining weakness, is in the
[threat model](https://github.com/nning/juist/blob/main/docs/02-threat-model.md).

## What you have to trust

- Your admins, as a group. A change, such as admitting or removing a device,
  needs the quorum: as many admin votes as the network requires. An admin
  with fewer votes than that cannot change anything alone, and the log
  records who signed each change.
- The start of the network. Every device checks each change in the
  [membership log]({{< relref "docs/how-it-works" >}}#the-membership-log) all
  the way back to the first one, made when the network was created, or to a
  checkpoint the admins signed.
- Every member, as far as the [access policy]({{< relref "docs/access" >}})
  lets it in. Without a policy, an admitted device reaches every port of every
  other member through the tunnel. With one, each device refuses whatever no
  rule allows, no matter what the sender does.
- An exit node, for the traffic it carries. The internet traffic you send
  through an [exit node]({{< relref "docs/exit-nodes" >}}) can be read there,
  just as at any VPN provider.

## What you don't have to trust

- The paths in between. Every change is signed and checked by every device,
  however it arrived. Traffic between members is encrypted by WireGuard.
- The public helpers. The public BitTorrent DHT and the STUN servers help
  devices find each other. They can delay a connection, but they cannot change
  who belongs to the network or read traffic. They do see the addresses of the
  devices that use them, and the DHT sees which of them look each other up.
  Devices ask the network's relays first, and of the devices that reach one
  another only one asks the DHT.
- The relay. A [relay]({{< relref "docs/relays" >}}) is one of your own
  members. Only members can use it, and it sees only encrypted WireGuard
  traffic.
- The daemon, for signing. juistd never holds an admin key, so a compromised
  juistd cannot sign changes.

## Where the keys live

- Admin keys are in your keystore, `~/.config/juist`, on each machine you
  approve from. Never copy a key: an admin with two laptops creates a key on
  each. Each network gets its own key, so a lost or stolen key affects only
  one network.
- The device's own keys are held by juistd. On Linux the package keeps them in
  `/var/lib/juist`, and juistd runs as its own user, with only
  `CAP_NET_ADMIN`. On a phone, the [Android app]({{< relref "docs/android" >}})
  seals them with a key held by the Android Keystore.
- The `juist` command signs only what it has rebuilt from its own verified
  copy of the log, whatever juistd asks it to sign.
- The break-glass secret, which `juist create` shows once and stores nowhere,
  ends the network for good without any admin. Keep it offline and apart from
  the admin keys: whoever holds a vault with both can run the network and end
  it.

## What invites protect against

An [invite]({{< relref "docs/invites" >}}) lets one device join. It protects
against three things:

- Guessing. A code allows exactly one guess, and only from the LAN. A link
  holds a 128-bit secret, far too long to guess.
- Someone in the middle. Before anything is signed, the admin compares four
  words with the new device. The words cover every key of the new device, and
  are chosen so that an attacker in the middle cannot search for a matching
  set. Both devices need the same version of juist for the words to match.
- A compromised daemon on the inviting device. The link binds the new device
  to the inviting admin's signature, so that daemon cannot enroll it into a
  network the daemon controls. A code has no such anchor: the new device
  trusts the network its daemon shows the first time.

## Removing a device

`juist remove phone` takes a device out of the network. It replaces the
network's group secret, which members use to find each other. Every member
drops its tunnel to the device as soon as it learns of the removal. See
[Removing a device]({{< relref "docs/remove" >}}).

The limit: a member that is cut off from the rest learns of the removal late,
and until then keeps its tunnel to the removed device. Freshness limits that
to 48 hours: a member that no voucher has vouched for in 48 hours keeps
tunnels only to vouchers. With `juist admins vouchers M`, that
limit holds even if M − 1 vouchers lie. See
[freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).

A lost or stolen device stays a member until you remove it. Remove it as soon
as you notice.

## Accepted trade-offs

Some things are weaker without a server in the middle. The
[trade-offs]({{< home "trade-offs" >}}) explain for each one what can happen,
why it is accepted, and what you can change. In short:

- If the admin keys of a quorum are lost, the network cannot be recovered.
  Give it more admins than the quorum needs.
- A network where every device sits behind symmetric NAT needs a relay member.
- The public DHT and STUN servers see the addresses of the devices that use
  them. If a device has lost track of another and no relay knows where it is,
  it looks it up in the DHT. The DHT then sees that two addresses belong to
  one network, but not to which, nor whose they are. With a relay of your
  own, juistd can run without them.

## Quantum-safe

A future quantum computer could break today's common encryption and forge
today's common signatures, and traffic recorded now could be decrypted then.
juist protects against both:

- Every WireGuard handshake mixes in a preshared key. Two devices first use a
  key derived from the network's group secret. Once they have synced their
  logs, they switch to a key that only the two of them hold: each encapsulates
  a secret to the other's ML-KEM-768 key. This key is renewed with every
  change to the members.
- Group secrets are sealed with X25519 combined with ML-KEM-768.
- Every change to the network, and every message devices sign for one
  another, is signed with ML-DSA-44; Ed25519 alone is refused. The only
  exception are copies of a device's announcement from the DHT, a relay or
  the LAN, which say no more than where to reach the device.
- Each device's and admin's ML-DSA key derives from the key it already has,
  so its backup covers it.
- Joining agrees a key with ML-KEM-768 after the code or link is checked, so
  someone who records a join and later has a quantum computer learns
  nothing from it.
- Relays and juist's other ends accept TLS 1.3 with X25519 and ML-KEM-768
  alone, and devices that reach only HTTPS require it. Connections
  through the ingress agree their key that way wherever the other end offers
  it, as current browsers do.

Every tunnel between devices on the current version is quantum-safe. A device
on an older version gets none of your traffic until it is updated:
`juist health` warns that it runs an older juist, and `juist devices` shows
it as `outdated`.

The limit: whoever steals a device and later has a quantum computer reads what
that device could read, its own tunnels' traffic recorded today included. Remove
a lost device at once.

juist reads networks whose log is at schema 18 or later, where every change
is signed this way. A network created with an older version is read no
more: its admins create it again, and its devices join the new one.

What stays classical: a relay proves itself with a classical certificate,
since it is trusted only to pass traffic, and a proxy that ends TLS without
ML-KEM cannot carry a device that reaches only HTTPS.

## Good to know

- On Linux, juist drops traffic that reaches a device's juist addresses
  without coming through the tunnel, and traffic that claims to come from a
  member but arrives from the LAN. As a result, a container on the device can
  no longer reach the device's own juist address.
- On FreeBSD, a service that listens only on a device's juist address can
  still be reached from that device's LAN. On either system, have services
  check who connects.
- Every change to the network, and who approved it, is in `juist log`.

## Reporting a vulnerability

Report it privately, through **Report a vulnerability** on the
[repository's Security tab](https://github.com/nning/juist/security), not in
a public issue. You get an answer within a week, and a fix is released before
the details are published.
