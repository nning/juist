---
title: Architecture
linkTitle: Architecture
description: How juist is built, layer by layer, in what sense it is zero trust, and what it takes from WireGuard and Tailscale.
lead: juist is a mesh VPN without a coordination server. This page explains how it is built, what it takes from WireGuard and Tailscale, and in what sense it is zero trust.
---

## In short {#overview}

Most mesh VPNs have a coordination server. It knows every device and its
keys, tells each device which others it may talk to, and is where an admin
adds or removes devices. Whoever runs that server, or breaks into it, decides
who belongs to the network.

juist has no such server. In its place is the
[membership log]({{< relref "docs/how-it-works" >}}#the-membership-log),
which your admins sign and every device checks for itself. Everything else
(finding devices, getting through NAT, carrying traffic) can go through paths
and helpers that juist does not trust.

The terms used here are explained in
[How juist works]({{< relref "docs/how-it-works" >}}); how juist differs from
other mesh VPNs is on [juist compared]({{< relref "docs/compare" >}}).

## Zero trust {#zero-trust}

Zero trust is a security model in which nothing is trusted because of where
it sits in the network. Inside the LAN or outside it, every access is
authenticated first. NIST describes the model in
[SP 800-207](https://doi.org/10.6028/NIST.SP.800-207); Google's
[BeyondCorp](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/)
is a well-known example of it.

juist follows it in these points:

- No address is trusted. A packet counts only if it arrives through a
  WireGuard tunnel from a key the membership log admits. A device on the same
  LAN, or one that claims a member's address, gets nothing through.
- No server and no path is trusted. Every device checks every change to the
  network against the admins' signatures, however it arrived.
- No single key decides. With a quorum of two or more, a stolen admin key
  cannot change anything on its own, and juistd never holds an admin key.
- Trust expires. A removed device loses its tunnels as soon as the members
  hear of it. For members that are cut off,
  [freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)
  limits this to 48 hours.

Where juist falls short of the model:

- Without an [access policy]({{< relref "docs/access" >}}), an admitted
  device reaches every port of every other member. The policy names devices,
  not users, so services on members should still check who connects.
- juist knows devices, not users. It does not check who sits at a device or
  whether the device is up to date.

## The layers {#layers}

juist is built in four layers. A layer relies on the ones below it to deliver
packets, but never to decide who belongs to the network.

| Layer | What it does | Trusted for | Built from |
|---|---|---|---|
| Trust | The membership log, the quorum, the group secret, freshness and invites | Who belongs to the network | juist |
| Sync | Carries log entries and addresses: from member to member, on the LAN and through the DHT | Nothing; every entry is signed | juist, BitTorrent DHT |
| Connectivity | Finds a path between two devices, through NAT or over a relay | Nothing; it can delay a connection, never admit one | Tailscale: magicsock, DERP |
| Data plane | Encrypts and authenticates every packet between two devices | Keeping traffic secret and unaltered | Tailscale: wireguard-go |

The layers below the trust layer can delay or prevent a connection. They
cannot change who is a member, and they cannot read or alter traffic.
WireGuard enforces that at the bottom: juistd configures its peers from the
membership log and from nothing else.

juistd turns the state of the log into everything the operating system sees:
the WireGuard peers, the packet filter, the routes and the names. It does this
again whenever a new change arrives.

## WireGuard {#wireguard}

[WireGuard](https://www.wireguard.com/) is a VPN protocol by Jason A.
Donenfeld, described in his paper
[WireGuard: Next Generation Kernel Network Tunnel](https://www.wireguard.com/papers/wireguard.pdf)
(NDSS 2017). Its handshake is built on the
[Noise protocol framework](https://noiseprotocol.org/noise.html), with
Curve25519, ChaCha20-Poly1305 and BLAKE2s; the
[protocol page](https://www.wireguard.com/protocol/) has the details.

juist relies on what WireGuard calls cryptokey routing. Each peer is a public
key together with the addresses it may use. A packet from a peer is accepted
only if its source address belongs to that key, and a packet to an address
goes only to the key that owns it. juist fills that table only from the
membership log, so:

- a key the log does not admit cannot complete a handshake;
- a member cannot send from another member's address;
- an address in the network is bound to a key, not to anything a router or a
  relay says.

On top of that, juist's packet filter drops every incoming packet it was not
told to accept.

juist runs WireGuard in user space on every platform, in
[the version Tailscale maintains](https://github.com/tailscale/wireguard-go)
of [wireguard-go](https://git.zx2c4.com/wireguard-go/), because Tailscale's
NAT traversal (see below) requires it. Kernel WireGuard would be faster on
Linux and FreeBSD.

Every WireGuard handshake mixes in a preshared key that a future quantum
computer cannot recover, so traffic recorded today stays secret. Two devices
start with a key derived from the [group secret](#log). When they sync the
log, each encapsulates a secret to the other's ML-KEM-768 key, and they switch
to a key that only the two of them hold. That key is renewed with every change
to the members.

## What juist takes from Tailscale {#tailscale}

[Tailscale](https://tailscale.com/blog/how-tailscale-works) is a mesh VPN
on WireGuard, with a coordination server run by Tailscale Inc. Its client is
[open source](https://github.com/tailscale/tailscale) under the BSD-3-Clause
licence. juist includes parts of that client, pinned to version 1.104.0:

- **magicsock and disco** find a direct path between two devices and get
  through NAT. Tailscale explains how in
  [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works).
- **DERP** passes traffic where no direct path forms; see
  [DERP servers](https://tailscale.com/kb/1232/derp-servers). Tailscale runs
  DERP servers for all its users. In juist, DERP runs on a member granted
  `relay` and serves only members of the log.
- **wgengine** connects WireGuard to the operating system: the network
  device, the packet filter, routes and DNS.
- **STUN** lets a device learn its public address.

juist leaves out the part that talks to a coordination server. Tailscale's
client gets its peers and their keys from that server; juist gives the same
code peers built from the membership log instead. You need no
Tailscale account, and no traffic goes to Tailscale.

A bug in the reused connectivity code can break connections or expose
addresses, but it cannot admit a device: WireGuard, below it, checks every
packet against keys from the log.

### Tailnet Lock {#tailnet-lock}

[Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) is Tailscale's
own answer to a coordination server that should not be trusted with keys:
trusted devices sign which keys may join. The membership log borrows its
design, a chain of signed records, but is juist's own code. It differs in
three ways:

- the log holds the members themselves, not only the keys that sign them;
- every change needs the quorum, not one trusted signature;
- the devices order and spread the changes among themselves, where Tailnet
  Lock relies on the coordination server for that.

## The membership log {#log}

Each change, such as "admit nas", is a record. It contains the hash of the
record before it, and it counts only once enough admins have signed it with
their [ML-DSA-44](https://doi.org/10.6028/NIST.FIPS.204) keys, which a
quantum computer cannot forge either. Every device checks each signature
itself, from the network's first record or from a checkpoint that a quorum
of admins signed.

Changes made at the same time on different devices are put into one order,
and every device works out the same order. Changes that contradict each other
are never resolved silently, with one exception: a change that takes
authority away, such as a removal, wins. A real fork,
where two histories disagree about who is a member, raises an alarm that an
admin has to resolve.

Every change to the members replaces the network's group secret. The new
secret is sealed to each member with
[HPKE](https://www.rfc-editor.org/rfc/rfc9180), using X25519 together with
[ML-KEM-768](https://doi.org/10.6028/NIST.FIPS.203), so a removed device
cannot read anything protected with it.

## Finding devices without a server {#discovery}

To find each other, devices publish their addresses. The group secret
protects what they publish:

- On the LAN, devices answer multicast DNS queries for a name derived from the
  group secret, and the answer is encrypted. Others on the LAN learn that
  juist is in use, and nothing more.
- In the public BitTorrent DHT, each member publishes its signed address as a
  mutable item ([BEP 44](https://www.bittorrent.org/beps/bep_0044.html)).
  Only members can compute the key it is stored under, and only members can
  decrypt it.
- Members pass on to each other where they last reached a device.

An invite works before the new device holds any secret. Both sides run
[SPAKE2](https://www.rfc-editor.org/rfc/rfc9382), a key exchange based on a
short password, and then agree a key with ML-KEM-768. The code or link
cannot be guessed offline, and a device that places itself in between is
revealed by the four words both sides compare.

## Sources {#sources}

Zero trust

- Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly:
  [Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207),
  NIST SP 800-207, 2020
- Rory Ward, Betsy Beyer:
  [BeyondCorp: A New Approach to Enterprise Security](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/),
  ;login:, 2014

WireGuard

- Jason A. Donenfeld:
  [WireGuard: Next Generation Kernel Network Tunnel](https://www.wireguard.com/papers/wireguard.pdf),
  NDSS 2017
- [WireGuard, protocol and cryptography](https://www.wireguard.com/protocol/)
- Trevor Perrin: [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [wireguard-go](https://git.zx2c4.com/wireguard-go/), and
  [Tailscale's fork](https://github.com/tailscale/wireguard-go) that juist
  uses

Tailscale

- [How Tailscale works](https://tailscale.com/blog/how-tailscale-works)
- [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
- [DERP servers](https://tailscale.com/kb/1232/derp-servers)
- [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
- [The Tailscale client's source](https://github.com/tailscale/tailscale)

Other standards

- [RFC 9180, HPKE](https://www.rfc-editor.org/rfc/rfc9180)
- [FIPS 203, ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [RFC 9382, SPAKE2](https://www.rfc-editor.org/rfc/rfc9382)
- [FIPS 204, ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [BEP 44, storing data in the BitTorrent DHT](https://www.bittorrent.org/beps/bep_0044.html)

The design in full, with the reasons for each decision, is in the
repository's
[architecture document](https://github.com/nning/juist/blob/main/docs/04-architecture.md)
and [threat model](https://github.com/nning/juist/blob/main/docs/02-threat-model.md).
