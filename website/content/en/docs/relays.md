---
title: Relays, ports and firewalls
linkTitle: Relays and ports
description: Give the network a relay for devices that cannot reach each other, open the right ports, and run without public helpers.
lead: When two devices cannot reach each other directly, a member of your own network passes their traffic on. This page also lists the ports juist uses and what to open where.
---

## What it is

Most devices sit behind a router that does NAT: they share one public address
and cannot be reached from outside. juist usually gets a direct tunnel through
anyway. It fails only where both devices sit behind symmetric NAT, a stricter
kind that some routers do. Then the two need a relay.

A relay is a member of your network, a device with a public address such as a
VPS, that passes traffic between devices that cannot reach each other
([How juist works]({{< relref "docs/how-it-works" >}})). No third party ever
relays your traffic. Only members can use the relay, and it sees only encrypted WireGuard
traffic.

A relay also carries invites. When you run `juist invite` on a laptop behind
NAT, the invite waits at the relay too, and the link names it, so a new device
joins from anywhere ([Invites]({{< relref "docs/invites" >}})). The invite's
secret never reaches the relay.

## Setting up a relay

{{< step on="vps" as="the relay" >}}
Join the network, then open the ports with ufw:

```sh
sudo juist join 'juist:…'
sudo ufw allow juist && sudo ufw allow juist-relay
```

Or, with firewalld:

```sh
sudo firewall-cmd --permanent --add-service=juist --add-service=juist-relay && sudo firewall-cmd --reload
```
{{< /step >}}

{{< step on="an admin's device" >}}
Give the VPS the role `relay`. A role is a permission the network records for
one device.

```sh
juist grant vps relay
```

The line `Relays` in `juist status` then counts it as available.
{{< /step >}}

`juist revoke vps relay` takes the role back. A relay works best on two or more
devices with public addresses. In a network of more than two devices,
`juist status` warns while none may relay.

## A relay on 443

A relay can also serve a public name on port 443, as any HTTPS server does.
A device on a network that lets nothing else out reaches it there, by itself
or with [HTTPS alone]({{< relref "docs/https-only" >}}).

{{< step on="your DNS" >}}
Point a name at the relay, with an A record, and an AAAA record where it has
IPv6: `relay.example.org`.
{{< /step >}}

{{< step on="vps" as="the relay" >}}
Have the relay serve the name:

```sh
sudo juist set --relay-name relay.example.org
```

juistd takes 443/tcp at the relay's addresses, ufw or firewalld let it in, and
Let's Encrypt issues a certificate for the name. `juist status` then says:

```console
  Relay name    relay.example.org, on 443
```
{{< /step >}}

- Every device learns the name from the relay's announcement once the
  network's log is at schema 12. Before, `juist status` says
  `members are not told of relay.example.org`, and `juist log upgrade` raises
  it.
- Binding 443 takes a privilege juistd otherwise lacks, which root grants:
  `sudo juist set` gives it `CAP_NET_BIND_SERVICE` for this alone, by a
  systemd drop-in, and `sudo juist set --relay-name ""` takes it back along
  with the name. On FreeBSD, juistd's helper binds 443 while root's grant is
  in place, where no other program answers on 443, and pf, where it runs,
  must let it in. Should the grant outlive the name, `juist status` warns,
  and `juist reset` takes it back.
- Members use the name once the server at it says it is this relay: a name
  that leads elsewhere is not taken.
- On the network's [ingress]({{< relref "docs/publishing" >}}), which holds
  443 already, the ingress hands the name's connections to the relay.
- A CAA record for the name must allow Let's Encrypt.
- Only the default network's juistd serves a name on 443, on a device in
  several networks.

## Ports

| Port | For | Open it where |
|---|---|---|
| 41643/udp | WireGuard and path discovery | a device with a public address |
| 41645/tcp, 41645/udp | the relay, and the STUN answers members measure it by | a device granted `relay` |
| 443/tcp | the relay under its public name | a relay given a name; `juist set --relay-name` opens it |
| 41642/tcp | an invite taken as a code on the LAN | the inviting device, while `juist invite` runs |
| 443/tcp, 443/udp, 80/tcp | the names devices publish, by TLS and QUIC | a device granted `ingress`; `juist ingress serve` opens them |
| the ports names are published on by TCP | those names | every ingress; it opens and closes them as they come and go |

Behind NAT, nothing needs opening. A link invite needs no port either: where it
cannot reach the inviting device directly, it meets it through a relay at once,
or through the public DHT in about a minute.

A device in [several networks]({{< relref "docs/networks" >}}) runs one juistd
for each. The n-th one's ports are these plus 10·n: 41653/udp for
`juistd@juist1`.

## Firewalls

The packages install ufw and firewalld profiles named `juist`, `juist-relay`,
`juist-relay-443`, `juist-invite` and `juist-ingress`. The profiles name the first network's
ports; `juist status` gives the others' by number.

Log sync, how devices pass on changes to the membership log (the signed
record of who belongs to the network), runs inside
the tunnel: TCP 41644 on `juist0` (41654 on `juist1`, and so on). Traffic there
has already passed WireGuard and juist's own filter, and the packages let it in
where ufw or firewalld runs. A firewall you configured by hand must let it in
too. Otherwise the device keeps its tunnels but misses changes to the network,
removals included; `juist status` says so. An
[exit node]({{< relref "docs/exit-nodes" >}}) also answers its members' DNS
there, on UDP and TCP 41646, which such a firewall must let in as well.

{{< note >}}
Upgrading from a build whose `juist` profile opened every port: ufw keeps the
old ports until `sudo ufw app update juist`, and firewalld narrows `juist` to
41643/udp at once. In either case a relay needs `juist-relay` added.
{{< /note >}}

## Running without public helpers

By default juistd asks public STUN servers (Google, Cloudflare) for its own
public address. It also uses the public BitTorrent DHT, a shared directory on
the internet, to find members it has lost track of. Both see addresses, never
contents.

Once you have a relay of your own, the network can run without either. Put
this on every device:

```sh
sudo systemctl edit juistd
```

and enter:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/juistd --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0 --no-dht --no-stun
```

Devices then find each other on the LAN and through members they already know.
The relay tells each device its public address, and invite links meet through
it. `man juistd` lists every option.

## If something goes wrong

| `juist status` says | What to do |
|---|---|
| `no tunnel traffic from …` | open 41643/udp on a device with a public address, or grant one `relay` |
| `no device reaches this relay` | open 41645/tcp and udp on the relay, in any firewall in front of it too |
| `no device may relay` | `juist grant DEVICE relay`, on a device with a public address |
| `no certificate for relay.example.org yet` | point the name at the relay, and let 443/tcp reach it |
| `the relay cannot take 443` | another program holds 443 there, or juistd lacks the capability `juist set` grants |
| `members are not told of …` | `juist log upgrade`, on an admin's device |
| `log sync … fails in the tunnel` | let `juist0` in through the host firewall, as the hint says |
| `no answer from …` | the device is offline, or its 41643/udp is closed |
