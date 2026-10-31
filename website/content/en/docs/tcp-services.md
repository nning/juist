---
title: TCP services
linkTitle: TCP services
description: Publish a game server or another service without TLS on its own port of every ingress.
lead: A service that does not speak TLS, such as a Minecraft server, gets its own port on every ingress. The ingress passes each connection straight to the device without reading it.
status: [Linux, FreeBSD]
---

## Setting it up

You need a domain and an ingress, as
[Publishing services]({{< relref "docs/publishing" >}}#setting-it-up) sets them
up.

{{< step on="an admin's device" >}}
```sh
juist publish add nas mc 25565 --tcp
```

This publishes port 25565 of nas on port 25565 of every ingress, as
`mc.example.org`, and prints `nas: publishes mc.example.org:25565/tcp`.
`--tcp=PORT` picks another public port:
`juist publish add nas ssh 22 --tcp=2222` prints
`ssh.example.org:2222/tcp to 22`.
{{< /step >}}

{{< step on="nas" as="the target" >}}
If the service listens on all addresses, its operator agrees with
`juist publish serve`. If it listens only on loopback, publish it on the
device:

```sh
juist publish add mc 127.0.0.1:25565 --tcp
```

It prints `passing mc.example.org to 127.0.0.1:25565`.
{{< /step >}}

Players connect to `mc.example.org:25565`. Every ingress listens on the port
while a name is published on it. On Linux, the ingress opens the port in
firewalld or ufw and closes it when the name goes. `juist status` on the
ingress lists these ports, and any that another program holds.

{{< note caution >}}
The ingress sees everything a protocol carries if the protocol does not
encrypt itself, and a CAA record does not help there. Publish this way only
what encrypts itself, as SSH does, or what anyone may see.
{{< /note >}}

## Good to know

- Only admins can publish a TCP port. The `publish` role shares only on 443.
- Each public port belongs to one name. Ports 80, 443 and juist's own ports,
  41640 to 41739, are refused, as is a port an ingress uses for a name of its
  own.
- Members reach the name directly at its device if the public port equals the
  device's port and there is no `--proxy`. Otherwise they go through the
  ingress.
- `--proxy` first sends the client's address in a PROXY protocol v2 header,
  which the service must expect. Paper and Velocity do if configured to;
  vanilla Minecraft does not.
- juist prints no SRV record. Clients that look one up, as Minecraft does for
  a name without a port, need it at your DNS provider:
  `_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.`
- UDP is not passed on, so Minecraft Bedrock's 19132/udp is not either.

## Troubleshooting

| You see | What to do |
|---|---|
| `another program holds port 25565 on …, where juist would pass NAME by TCP` | The service listens on all addresses, including the overlay addresses. Publish its port instead, as the hint says, and agree with `juist publish serve`. |
| on vps, `juist status`: `Ingress` says `…; another program holds port 22` | A program on the ingress, often sshd, holds a published port. juist leaves the port to it. Publish the name on another port with `--tcp=PORT`. |
