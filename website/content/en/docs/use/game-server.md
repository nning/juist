---
title: A game server for friends
linkTitle: A game server for friends
description: Run a game server at home and let friends play on it under a name of yours, without opening a port on your router, through an ingress or straight through the tunnel.
lead: Your Minecraft server runs on the NAS at home, behind a router that opens no port. Friends connect to mc.example.org:25565 anyway, through your ingress, and friends in your network go straight through the tunnel.
---

## What you get

A server that does not speak TLS, such as Minecraft Java Edition, gets its
own port on every [ingress]({{< relref "docs/publishing" >}}), the member
with a public address that passes connections on. Friends without juist
connect to `mc.example.org:25565`, and the ingress passes each connection
through the tunnel to the NAS without reading it. Your router opens no port,
and your address at home appears in no public record.

Friends who are members of your network reach the server directly at the
NAS, as long as the public port is the NAS's own and the name has no
`--proxy`.

## What you need

- A network with a domain and an ingress, set up once as in steps 1 to 3 of
  [Publishing services]({{< relref "docs/publishing" >}}#setting-it-up).
- The game server on a member, here `nas`.

## Setting it up

{{< step on="an admin's device" >}}
Publish port 25565 of nas on every ingress:

```sh
juist publish add nas mc 25565 --tcp
```

It prints `nas: publishes mc.example.org:25565/tcp`. `--tcp=PORT` picks a
different public port.
{{< /step >}}

{{< step on="nas" as="the game server" >}}
If the server listens on all addresses, agree to serve it:

```sh
juist publish serve
```

If it listens only on loopback, juist passes the bytes on to it unchanged:

```sh
juist publish add mc 127.0.0.1:25565 --tcp
```

It prints `passing mc.example.org to 127.0.0.1:25565`.
{{< /step >}}

{{< step on="your DNS provider's website" >}}
Optionally, for clients that look up an SRV record, as Minecraft does for a
name without a port:

```text
_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.
```
{{< /step >}}

## Watch out for

- **TCP only.** The ingress passes no UDP, so Minecraft Bedrock's 19132/udp
  is not reachable from the internet. Friends in your network reach the NAS
  through the tunnel, where UDP gets through too.
- **The ingress sees what the protocol does not encrypt.** Publish this way
  only what encrypts itself or what anyone may see.
- **The server is on the internet.** Anyone who finds the name can connect,
  so use the game's own allowlist. A server you do not trust with access to
  your network belongs on a member of its own
  ([keeping the server away]({{< relref "docs/service-member" >}})).
- **Friends in the network reach every port of every device** unless an
  [access policy]({{< relref "docs/access" >}}) says otherwise, for example
  `pass from <friends> to nas proto tcp port 25565`.
- **Client addresses.** The server sees connections from the ingress.
  `--proxy` on `juist publish add` sends the client's address in a PROXY
  protocol v2 header, which Paper and Velocity accept when configured to and
  vanilla Minecraft does not.
- Ports 80, 443 and juist's own, 41640 to 41739, cannot be published this way.

## Read more

- [Game servers and other TCP services]({{< relref "docs/tcp-services" >}})
- [Invites]({{< relref "docs/invites" >}}), to bring friends into the network
