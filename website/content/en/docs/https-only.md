---
title: Networks that pass HTTPS alone
linkTitle: HTTPS alone
description: Reach your network from a hotel's, a company's or a school's network that lets nothing out but HTTPS, through your relays on 443, and through a proxy where there is one.
lead: Some networks let nothing out but HTTPS, and some sort what passes by how it looks. A device on one reaches the others through your relays on port 443, as one HTTPS client among others.
---

## What it is

On a hotel's, a company's or a school's network often only TCP to port 443
gets out. WireGuard, path discovery and the relay's own port 41645 do not.

A [relay]({{< relref "docs/relays" >}}) that serves a public name on 443 is
the way out. Every device learns the name, and one that cannot reach the
relay's own port falls back to the name by itself. Nothing needs setting up
on the device for that.

A network that looks closer, and blocks or reports what is not HTTPS, needs
more: with `juist set --https-only` a device sends nothing but TLS to the
relays' names on 443, and DNS queries for those names. No WireGuard over UDP,
no path discovery, no search of the LAN, no public DHT and no STUN server.
Every packet then goes through a relay.

## Setting it up

{{< step on="the relay" >}}
Give a relay a public name on 443, as [Relays]({{< relref "docs/relays" >}})
describes:

```sh
sudo juist set --relay-name relay.example.org
```
{{< /step >}}

{{< step on="laptop" as="the device in the hotel" >}}
Send nothing but HTTPS from now on:

```sh
sudo juist set --https-only
```

It prints `https only`. `juist status` then says which relays it goes
through:

```console
  HTTPS         only, by relay.example.org
```
{{< /step >}}

To join a network from such a place, set it before `juist join`, and use the
invite's link: it names the relays on 443, as `r=relay.example.org`. A code
typed in is found on the LAN, which a device on HTTPS alone does not search.

```sh
sudo juist set --https-only
sudo juist join 'juist:…'
```

Back on an open network, `sudo juist set --https-only=false` lets tunnels go
direct again.

## Through a proxy

A company network may let nothing out but through its HTTP proxy. Name the
proxy, with a user and password where it asks for one:

```sh
sudo juist set --https-only --proxy http://user:password@proxy.example.com:3128
```

The proxy is asked for `CONNECT relay.example.org:443` alone, and resolves
the name itself, so the device needs no DNS of its own then. Without
`--proxy`, juistd takes the `HTTPS_PROXY` of its environment, and
`--proxy ""` goes back to that. `juist status` shows the proxy without its
password.

## Good to know

- Every packet goes through a relay, at the relay's speed, and TCP carries
  the tunnel's TCP, which recovers slowly from loss. Two relays in different
  places keep a device reachable when one goes.
- The relay's certificate is checked against the certificate authorities the
  system trusts, as a browser does. A company that intercepts TLS sees no
  more than the relay does: WireGuard encrypts end to end, so it sees which
  devices talk to each other, not what they say.
- It does not hide juist from a censor that probes servers or fingerprints
  TLS: a probe of the relay's name finds a relay, and the TLS handshake is that
  of a Go program, not a browser.
- The Android app has no switch for it yet. It falls back to a relay's name on
  443 by itself where UDP and the relay's port are blocked.

## If something goes wrong

| `juist status` says | What to do |
|---|---|
| `HTTPS  only, and no relay on 443` | give a relay a public name: `sudo juist set --relay-name NAME` on it |
| `warning: no relay on 443/tcp` | the same |
| `no answer from …: offline, or at no relay on 443` | the device is offline, or reaches no relay with a name |
| `no tunnel traffic from … through the relays on 443` | check the relays' names in DNS, and that 443 reaches them |

A join that says `the invite link names no relay on 443` needs a new link,
made once a relay serves a name on 443.
