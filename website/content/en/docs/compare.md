---
title: juist compared
linkTitle: Compared with others
description: How juist differs from other mesh VPNs, with a central server and without one, and when one of them fits better.
lead: How juist differs from other mesh VPNs, and when one of them fits you better.
---

## What sets them apart {#question}

Most mesh VPNs carry traffic in a similar way: encrypted tunnels between
devices, direct where NAT allows, over a relay where it does not. They
differ in who decides which devices belong to the network, and in how a device
is removed again.

In juist, your admins decide, by signing changes in the
[membership log]({{< relref "docs/how-it-works" >}}#the-membership-log), and
every device checks those changes itself. No server is needed for that, and
none has to be trusted. How that is built is on the
[Architecture]({{< relref "docs/architecture" >}}) page.

Four things set juist apart from every other mesh here:

- **No central infrastructure, and still WireGuard.** The other meshes
  without a server use their own protocols, and EasyTier offers WireGuard only
  as one option among several. WireGuard alone does not get through NAT.
- **An admin quorum.** You can require several admins for each change, so
  that no single person can add a device.
- **Routing and names without a server.** Among the meshes without a server,
  only juist publishes services to the internet and points public names at
  members. In the others, routes and names are set by hand in each device's
  configuration, or are not available at all.
- **Quantum-safe throughout.** Every tunnel mixes in a key a quantum
  computer cannot recover, and every change to the network is signed with
  ML-DSA. None of the others signs its members that way, and of the others
  only NetBird offers post-quantum tunnels, as an experimental option.

## At a glance {#overview}

EasyTier stands in for the shared-secret meshes.

{{< matrix >}}

## Tailscale {#tailscale}

[Tailscale](https://tailscale.com/blog/how-tailscale-works) is the most
polished mesh VPN, with clients for Linux, Windows, macOS, iOS and Android,
sign-in through an identity provider, and
[access rules](https://tailscale.com/kb/1018/acls). juist builds in parts of
its client, see [Architecture]({{< relref "docs/architecture" >}}#tailscale).

The coordination server is run by Tailscale Inc. and is not open source. It
knows every device and hands out the keys, so whoever controls it could add a
device of their own. [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
closes that gap: devices accept a new key only if a key you hold has signed
it. Removing a device and spreading the change still go through the server.
Its tunnels are not post-quantum: it sets no preshared key and lets you set
none.

Choose Tailscale if you want clients for every platform and user accounts
with access rules by user, and can accept a company's server at the centre.

## Headscale {#headscale}

[Headscale](https://github.com/juanfont/headscale) is an open source
coordination server for the Tailscale clients, which you run yourself. You then
have to trust your server instead of Tailscale's. It does not support Tailnet
Lock ([feature request](https://github.com/juanfont/headscale/issues/1307)),
so the devices take what the server tells them without checking it.

Choose Headscale if you want Tailscale's clients without Tailscale's server,
and can run and protect a server of your own.

## NetBird {#netbird}

[NetBird](https://docs.netbird.io/about-netbird/how-netbird-works) connects
devices through WireGuard, coordinated by a management server that holds the
devices, their keys and the access rules. You can use the one NetBird runs,
or run it yourself together with its signal and relay servers. The client is
BSD-3-Clause, the servers are AGPL-3.0. With
[Rosenpass](https://docs.netbird.io/client/post-quantum-cryptography), an
experimental option not available on phones, its tunnels become
post-quantum.

Choose NetBird if you want a self-hosted server with a dashboard, sign-in
through your identity provider and access rules by user.

## Netmaker {#netmaker}

[Netmaker](https://docs.netmaker.io/) builds its mesh from WireGuard too, in
the kernel on Linux and FreeBSD, around a server you run yourself or rent
from Netmaker. As with NetBird, that server knows the devices and hands out
their keys. The core is Apache-2.0; sign-in through an identity provider and
failover relays come with the paid edition.

Choose Netmaker if you want WireGuard in the kernel and a server of your own.

## ZeroTier {#zerotier}

[ZeroTier](https://docs.zerotier.com/protocol) has a protocol of its own, not
WireGuard, and emulates an Ethernet network between devices. Who belongs is
decided by a [network controller](https://docs.zerotier.com/controller),
ZeroTier's or your own. Its core is MPL-2.0. The controller's source is
available, but under ZeroTier's own licence, which restricts commercial use.
ZeroTier One, the open source client, is not post-quantum; ZeroTier Quantum,
a separate commercial platform launched in 2026, promises to be.

Choose ZeroTier if you need a layer 2 network, such as for broadcast or
protocols other than IP.

## Nebula {#nebula}

[Nebula](https://nebula.defined.net/docs/), from Slack, has no server either.
Each device carries a certificate signed by your own CA, which names its
address and groups, and members with a public address help the others find
each other. It is MIT licensed and has run at large scale.

What it lacks is a way to remove a device. Each device has to receive a
[blocklist](https://nebula.defined.net/docs/config/pki/) by some other means,
such as configuration management. A device that has not received it accepts
the removed device until its certificate expires. In juist, a removal is a signed
change that the devices pass on among themselves, so no separate channel is
needed.

Choose Nebula if your devices are managed centrally anyway and you want
access rules by group.

## Tinc {#tinc}

[Tinc](https://www.tinc-vpn.org/) is the oldest mesh here without a server.
Each device holds a host file with the public key of each member it connects
to, and the members pass on what they know of the rest. A member with a
public address helps the others through NAT and forwards their traffic where
needed. To remove a device, its file has to go from every device that holds
it. Version 1.0.37 is likely the last 1.0 release, and 1.1 has been a
pre-release since 2021.

Choose Tinc for a few devices you configure by hand, with software that has
run for decades.

## rayfish {#rayfish}

[rayfish](https://github.com/rayfish/rayfish) is the newest mesh here and
the closest to juist: no account and no server to trust. A network is a key
pair. Its coordinator admits devices by invite or by approval and publishes
the list of members, signed with the network's key, and a removal reaches
the others the same way. It tunnels over the QUIC of
[iroh](https://www.iroh.computer/), not WireGuard, and by default uses the
relays and the pkarr server of n0, the company behind iroh; both can be
replaced.

Where juist differs: rayfish's co-coordinators hold one and the same network
key, so anyone with a copy can change anything on their own. In juist every admin
has a key of their own, and a change takes k of them. rayfish calls itself
experimental, before 1.0 and without a security audit.

Two other projects from the same year take a similar approach:
[nostr-vpn](https://github.com/mmalmi/nostr-vpn), whose devices accept a
list of members only if one of its admins signed it, and the direct mode of
[Tunnet](https://github.com/tunnetio/Tunnet), with signed members and
revocations in a document the devices replicate. In both, one admin or
coordinator can make any change.

Choose rayfish to try a mesh without a server on platforms juist lacks, such
as Windows or macOS.

## Shared-secret meshes {#shared-secret}

Projects such as [EasyTier](https://github.com/EasyTier/EasyTier) admit
anyone who knows the network's name and secret. That is simple to set up, but
devices are not admitted individually, and nobody records who admitted them.
To remove one, the secret has to be changed on every device that stays.

## WireGuard alone {#wireguard}

[WireGuard](https://www.wireguard.com/quickstart/) itself only connects
devices whose keys and addresses you have written into each other's
configuration. There is nothing in between to trust, and in the kernel it is
faster than juist, which runs WireGuard in user space. But every new device
means editing every other device, it cannot connect two devices that are both
behind NAT, and it has no relay. A preshared key, set by hand or rotated by
Rosenpass, makes its tunnels post-quantum.

Choose WireGuard alone for a few devices with fixed public addresses.

## Not compared here {#elsewhere}

Some projects often named alongside these solve a different problem. Pangolin,
Firezone, Twingate and Defguard connect devices to gateways and services
rather than to each other, and Cloudflare Mesh carries all traffic through
Cloudflare's network. Yggdrasil, cjdns and Mycelium are one open network
that anyone can join. Hamachi and Radmin VPN are made for games on a LAN.
EdgeVPN, hyprspace and wgmesh admit whoever knows a shared secret or is on
a hand-written list, like the shared-secret meshes above. innernet is, like
juist, a command-line tool for Linux, but around a server that decides who
belongs.

## Where juist is weaker {#weaker}

- juist has not had a security audit.
- It runs on Linux and FreeBSD, and on Android as a member without names,
  roles or subnets that cannot be an exit node; there is nothing for
  Windows, macOS or iOS.
- It knows devices, not users: its access rules name devices, and there is
  no sign-in through an identity provider.
- A removed device is taken out as soon as the other devices hear of it, but
  a device that is cut off may hear of it only after up to 48 hours. A
  central server tells every device it reaches right away.
- It is made for networks of 25 to 100 devices with a few admins.

## Sources {#sources}

- [How Tailscale works](https://tailscale.com/blog/how-tailscale-works),
  [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock),
  [Tailscale's open source](https://tailscale.com/opensource)
- [Headscale](https://github.com/juanfont/headscale), and its
  [request for Tailnet Lock](https://github.com/juanfont/headscale/issues/1307)
- [How NetBird works](https://docs.netbird.io/about-netbird/how-netbird-works),
  [NetBird's licence](https://github.com/netbirdio/netbird/blob/main/LICENSE)
- [ZeroTier's protocol](https://docs.zerotier.com/protocol),
  [network controller](https://docs.zerotier.com/controller),
  [licence](https://github.com/zerotier/ZeroTierOne/blob/dev/LICENSE.txt)
- [Nebula's documentation](https://nebula.defined.net/docs/), its
  [PKI and blocklist](https://nebula.defined.net/docs/config/pki/),
  [Introducing Nebula](https://slack.engineering/introducing-nebula-the-open-source-global-overlay-network-from-slack/)
- [WireGuard quick start](https://www.wireguard.com/quickstart/)
- [Netmaker's NAT traversal](https://docs.netmaker.io/docs/how-to-guides/nat-traversal),
  [its sign-in through OAuth](https://docs.netmaker.io/docs/server-installation/integrating-oauth),
  [its clients](https://docs.netmaker.io/docs/client-installation)
- [Tinc](https://www.tinc-vpn.org/)
- [rayfish](https://github.com/rayfish/rayfish) and its
  [security model](https://github.com/rayfish/rayfish/blob/main/SECURITY.md),
  [nostr-vpn's protocol](https://github.com/mmalmi/nostr-vpn/blob/main/docs/protocol.md),
  [Tunnet](https://github.com/tunnetio/Tunnet)
- [Headscale and OIDC](https://headscale.net/stable/ref/oidc/),
  [NetBird's kernel and user-space WireGuard](https://docs.netbird.io/help/troubleshooting-client),
  [ZeroTier's SSO](https://docs.zerotier.com/sso/),
  [Mobile Nebula](https://github.com/DefinedNet/mobile_nebula),
  [EasyTier's access rules](https://easytier.rs/en/guide/config/acl.html)
- [EasyTier](https://github.com/EasyTier/EasyTier)
- Routing and names:
  [Tailscale's exit nodes](https://tailscale.com/kb/1103/exit-nodes),
  [DNS](https://tailscale.com/kb/1054/dns),
  [Funnel](https://tailscale.com/kb/1223/funnel) and
  [one tailnet at a time](https://tailscale.com/kb/1225/fast-user-switching);
  [Headscale's features](https://headscale.net/stable/about/features/);
  [NetBird's custom zones](https://docs.netbird.io/manage/dns/custom-zones),
  [reverse proxy](https://docs.netbird.io/manage/reverse-proxy) and
  [profiles](https://docs.netbird.io/client/profiles);
  [Netmaker's DNS](https://docs.netmaker.io/docs/features/dns);
  [ZeroTier's exit node](https://docs.zerotier.com/exitnode) and
  [DNS](https://docs.zerotier.com/dns/);
  [Nebula's unsafe routes](https://nebula.defined.net/docs/guides/unsafe_routes/)
  and [lighthouse DNS](https://nebula.defined.net/docs/config/lighthouse/);
  [Tinc as a gateway](https://www.tinc-vpn.org/examples/redirect-gateway/);
  [rayfish's exit nodes](https://rayfish.xyz/docs/11-exit-nodes);
  [EasyTier's magic DNS](https://easytier.rs/en/guide/network/magic-dns.html)
- Against a quantum computer:
  [Tailscale](https://tailscale.com/docs/concepts/post-quantum-cryptography),
  [NetBird with Rosenpass](https://docs.netbird.io/client/post-quantum-cryptography),
  [ZeroTier Quantum](https://www.zerotier.com/news/rsac-2026-zerotier-launches-zerotier-quantum-the-worlds-first-end-to-end-quantum-secure-networking-platform/),
  [Nebula's request](https://github.com/slackhq/nebula/issues/1446),
  [iroh's handshakes](https://iroh.computer/blog/iroh-post-quantum-handshakes),
  [WireGuard's known limitations](https://www.wireguard.com/known-limitations/)
- HTTPS only and layer 2:
  [Tailscale's DERP servers](https://tailscale.com/kb/1232/derp-servers),
  [NetBird's relays](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity),
  [Netmaker 1.7](https://github.com/gravitl/netmaker/releases/tag/v1.7.0),
  [ZeroTier's TCP relay](https://docs.zerotier.com/relay/),
  [Tinc's configuration](https://www.tinc-vpn.org/documentation-1.1/Main-configuration-variables.html),
  [iroh's relays](https://docs.iroh.computer/configuring-networks),
  [Nebula on layer 2](https://github.com/slackhq/nebula/issues/1452),
  [EasyTier on layer 2](https://github.com/EasyTier/EasyTier/issues/184)

The survey behind this page, with about 25 projects, is in the repository:
[control-plane options](https://github.com/nning/juist/blob/main/docs/03-control-plane-options.md)
and the
[project survey](https://github.com/nning/juist/blob/main/docs/research/project-survey.md).
