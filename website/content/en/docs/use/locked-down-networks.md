---
title: From locked-down networks
linkTitle: From locked-down networks
description: Reach your network from a hotel, company or school network that lets nothing out but HTTPS, through a relay on port 443 and, where there is one, the company's proxy.
lead: The hotel Wi-Fi lets nothing out but HTTPS, and the company network only its proxy. A relay of yours on port 443 gets your laptop through anyway, looking like any other HTTPS client.
---

## What you get

Your laptop reaches every member from a network where WireGuard, path
discovery and the relay's usual port are blocked. Its traffic goes over TLS
to a relay of yours on port 443, under a public name such as
`relay.example.org`. Most of the time the laptop needs no setting for this:
where it cannot reach the relay's usual port, it switches to the name by
itself.

A network that inspects traffic, or lets it out only through a proxy, takes
one more setting on the laptop.

## What you need

- A [relay]({{< relref "docs/relays" >}}) with a public address, such as a
  small VPS, and a name you can point at it.
- If the network has an [ingress]({{< relref "docs/publishing" >}}) that is
  also a relay, you already have one: its relay serves `relay.` plus the
  network's domain on 443.

## Setting it up

{{< step on="your DNS" >}}
Point a name such as `relay.example.org` at the relay, with an A record, and
an AAAA record if the relay has IPv6.
{{< /step >}}

{{< step on="vps" as="the relay" >}}
Have the relay serve the name on 443:

```sh
sudo juist set --relay-name relay.example.org
```

Let's Encrypt issues a certificate for it, and every device learns the name.
`juist status` says `Relay name    relay.example.org, on 443`.
{{< /step >}}

{{< step on="laptop" as="the device in the hotel" >}}
Nothing to do where the network only blocks ports. Where it inspects traffic
too, send only HTTPS:

```sh
sudo juist set --https-only
```

It prints `https only`. Where traffic leaves only through the company's
proxy, give juist the proxy as well, and type its URL when asked:

```sh
sudo juist set --https-only --proxy -
```

Back on an open network, `sudo juist set --https-only=false` lets tunnels go
direct again.
{{< /step >}}

## Watch out for

- **Everything goes through the relay**, so the relay limits the speed, and
  the tunnel's TCP runs inside TCP, which recovers slowly from packet loss. A
  second relay on 443 in another place keeps the laptop reachable if one goes
  down.
- **Joining from such a network** takes `--https-only` before `juist join`,
  and the invite link. A code does not work: it needs the LAN, which
  HTTPS-only mode does not search.
- **It does not hide juist** from a censor that probes servers or
  fingerprints TLS.
- **A CAA record for the relay's name** must allow Let's Encrypt.
- **The Android app** has no setting for HTTPS-only mode, but switches to a
  relay's name on 443 by itself where UDP and the relay's port are blocked.

## Read more

- [Networks that only allow HTTPS]({{< relref "docs/https-only" >}}): the
  proxy, and what `juist health` says
- [A relay on 443]({{< relref "docs/relays" >}}#a-relay-on-443)
