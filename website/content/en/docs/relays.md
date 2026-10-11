---
title: Relays, ports and firewalls
linkTitle: Relays and ports
description: Give the network a relay for devices that cannot reach each other, open the right ports, and run without public helpers.
lead: When two devices cannot reach each other directly, a member of your own network passes their traffic on. This page also lists the ports juist uses and what to open where.
---

## What a relay does

Most devices sit behind a router that does NAT: they share one public address
and cannot be reached from outside. juist usually gets a direct tunnel through
anyway. It fails only where both devices sit behind symmetric NAT, a stricter
kind that some routers use. Then the two need a relay.

A relay is a member of your network with a public address, such as a VPS, that
passes traffic between devices that cannot reach each other
([How juist works]({{< relref "docs/how-it-works" >}})). No third party ever
relays your traffic. Only members can use the relay, and it sees only
encrypted WireGuard traffic.

A relay also helps with invites. When you run `juist invite` on a laptop
behind NAT, the invite also waits at the relay, and the link names the relay,
so a new device can join from anywhere
([Invites]({{< relref "docs/invites" >}})). The invite's secret never reaches
the relay.

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

The `Relays` line in `juist status` then counts it as available.
{{< /step >}}

`juist revoke vps relay` takes the role away. It is best to give the role to
two or more devices with public addresses. In a network of more than two
devices, `juist status` warns as long as no device may relay.

## A relay on 443

A relay can also serve a public name on port 443, like any HTTPS server.
A device on a network that lets nothing else out reaches the relay there,
either by itself or in [HTTPS-only mode]({{< relref "docs/https-only" >}}).

{{< step on="your DNS" >}}
Point a name such as `relay.example.org` at the relay, with an A record, and
an AAAA record if the relay has IPv6.
{{< /step >}}

{{< step on="vps" as="the relay" >}}
Have the relay serve the name:

```sh
sudo juist set --relay-name relay.example.org
```

juistd listens on 443/tcp at the relay's addresses, ufw or firewalld let it
in, and Let's Encrypt issues a certificate for the name. `juist status` then
says:

```console
  Relay name    relay.example.org, on 443
```
{{< /step >}}

- Every device learns the name from the relay's announcement once the
  network's log is at schema 12. Until then, `juist status` says
  `members are not told of relay.example.org`, and `juist log upgrade` raises
  the schema.
- Listening on port 443 needs a privilege that juistd otherwise lacks and that
  only root can grant. `sudo juist set` grants it `CAP_NET_BIND_SERVICE` for
  this purpose only, through a systemd drop-in, and
  `sudo juist set --relay-name ""` takes it away together with the name.
- On FreeBSD, juistd's helper binds 443 only while root's grant is in place and
  no other program listens on 443. If pf runs, it must let the traffic in.
- If the grant outlives the name, `juist status` warns, and `juist reset` takes
  it away.
- Members use the name only once the server at that name confirms it is this
  relay. A name that points elsewhere is not used.
- If the relay is also the network's
  [ingress]({{< relref "docs/publishing" >}}), which already holds 443, the
  ingress passes the name's connections on to the relay.
- A CAA record for the name must allow Let's Encrypt.
- On a device in several networks, only the default network's juistd serves a
  name on 443.

## Ports

| Port | For | Open it where |
|---|---|---|
| 41643/udp | WireGuard and path discovery | a device with a public address |
| 41645/tcp, 41645/udp | the relay, and the STUN replies members use to measure it | a device granted `relay` |
| 443/tcp | the relay under its public name | a relay with a name; `juist set --relay-name` opens it |
| 41642/tcp | accepting an invite by code on the LAN | the inviting device, while `juist invite` runs |
| 443/tcp, 443/udp, 80/tcp | the names devices publish, over TLS and QUIC | a device granted `ingress`; `juist ingress serve` opens them |
| the TCP ports names are published on | those names | every ingress; it opens and closes them as names are added and removed |

Devices behind NAT need no open ports. Link invites need none either: if the
new device cannot reach the inviting device directly, the two meet through a
relay right away, or through the public DHT within about a minute.

A device in [several networks]({{< relref "docs/networks" >}}) runs one juistd
per network. The n-th one uses these ports plus 10·n, for example 41653/udp
for `juistd@juist1`.

## Firewalls

The packages install ufw and firewalld profiles named `juist`, `juist-relay`,
`juist-relay-443`, `juist-invite` and `juist-ingress`. The profiles cover the
first network's ports; `juist status` gives the port numbers for the others.

Log sync runs inside the tunnel, on TCP 41644 on `juist0` (41654 on `juist1`,
and so on). It is how devices pass on changes to the membership log, the
signed record of who belongs to the network. Traffic there has already passed
WireGuard and juist's own filter, and the packages let it in where ufw or
firewalld runs. A firewall you configured by hand must let it in too.
Otherwise the device keeps its tunnels but misses changes to the network,
including removals; `juist status` reports this. An
[exit node]({{< relref "docs/exit-nodes" >}}) also answers its members' DNS
queries there, on UDP and TCP 41646, which such a firewall must let in as well.

{{< note >}}
Upgrading from a build whose `juist` profile opened every port: ufw keeps the
old ports until `sudo ufw app update juist`, while firewalld narrows `juist`
to 41643/udp right away. In both cases, a relay needs `juist-relay` added.
{{< /note >}}

## Running without public helpers

By default, juistd asks public STUN servers (Google, Cloudflare) for its own
public address. It also uses the public BitTorrent DHT, a shared directory on
the internet, to find members it has lost track of. Both see addresses, never
contents.

Once you have a relay of your own, the network can run without either. On
every device, run:

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

## Troubleshooting

| `juist status` says | What to do |
|---|---|
| `no tunnel traffic from …` | open 41643/udp on a device with a public address, or grant one `relay` |
| `no device reaches this relay` | open 41645/tcp and udp on the relay, and in any firewall in front of it |
| `no device may relay` | run `juist grant DEVICE relay` for a device with a public address |
| `no certificate for relay.example.org yet` | point the name at the relay, and let 443/tcp reach it |
| `the relay cannot take 443` | another program holds 443 there, or juistd lacks the capability `juist set` grants |
| `members are not told of …` | run `juist log upgrade` on an admin's device |
| `log sync … fails in the tunnel` | let `juist0` through the host firewall, as the hint says |
| `no answer from …` | the device is offline, or its 41643/udp is closed |
