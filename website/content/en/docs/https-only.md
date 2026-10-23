---
title: Networks that only allow HTTPS
linkTitle: HTTPS only
description: Reach your network from a hotel, company or school network that lets nothing out but HTTPS, through your relays on port 443, and through a proxy if there is one.
lead: Some networks let nothing out but HTTPS, and some inspect traffic to check that it looks like HTTPS. A device on such a network reaches the others through your relays on port 443, looking like any other HTTPS client.
---

## How it works

On hotel, company or school networks, often only TCP to port 443 gets out.
WireGuard, path discovery and the relay's usual port 41645 are blocked.

The way out is a [relay]({{< relref "docs/relays" >}}) that serves a public
name on port 443. Every device learns that name, and a device that cannot
reach the relay's usual port switches to the name by itself. Nothing needs to
be set up on the device for this.

One relay on 443 is enough. A device that reaches only some relays sends
everything through its own one, and the other devices keep a connection to
that relay while it is there, so it reaches devices that use a relay without
a name too. Phones that save battery keep no such connection: the device
reaches them once they next send something, as they do when they sync. If
the network has an [ingress]({{< relref "docs/publishing" >}}) that is also
a relay, its relay serves `relay.` plus the network's domain on 443 by
itself.

A network that inspects traffic, and blocks or reports anything that is not
HTTPS, needs more. With `juist set --https-only`, a device sends only TLS to
the relays' names on port 443, plus DNS queries for those names. It sends no
WireGuard over UDP, does no path discovery and no LAN search, and uses neither
the public DHT nor STUN servers. Every packet then goes through a relay.

## Setting it up

{{< step on="the relay" >}}
Unless the ingress's relay serves one already, give a relay a public name on
port 443, as described in [Relays]({{< relref "docs/relays" >}}):

```sh
sudo juist set --relay-name relay.example.org
```
{{< /step >}}

{{< step on="laptop" as="the device in the hotel" >}}
Send only HTTPS from now on:

```sh
sudo juist set --https-only
```

It prints `https only`. `juist status` then shows which relays it goes
through:

```console
  HTTPS         only, by relay.example.org
```
{{< /step >}}

To join a network from such a place, set this before `juist join`, and use the
invite link, not the code. The link names the relays on 443, for example
`r=relay.example.org`. A typed code is looked up on the LAN, which a device in
HTTPS-only mode does not search.

```sh
sudo juist set --https-only
sudo juist join 'juist:…'
```

Back on an open network, `sudo juist set --https-only=false` lets tunnels go
direct again.

## Through a proxy

Some company networks let traffic out only through their HTTP proxy. Give
juist the proxy, with a user name and password if it requires them:

```sh
sudo juist set --https-only --proxy -
```

juist then asks for the URL, such as
`http://user:password@proxy.example.com:3128`, and does not show it as you
type. On the command line, every user of the device could read the password.
For a proxy without a password, `--proxy http://proxy.example.com:3128` is
enough.

juist asks the proxy only for `CONNECT relay.example.org:443`, and the proxy
resolves the name itself, so the device does not need DNS of its own. Without
`--proxy`, juistd uses the `HTTPS_PROXY` from its environment, and
`--proxy ""` goes back to that. `juist status` shows the proxy without its
password.

## Notes

- Every packet goes through a relay, so the relay limits the speed. The
  tunnel's TCP connections then run inside TCP, which recovers slowly from
  packet loss. Two relays in different places keep a device reachable if one
  goes down.
- The relay's certificate is checked against the certificate authorities the
  system trusts, as a browser does. A device uses a relay's name only once the
  server at that name confirms it is that relay. A company that intercepts TLS
  sees no more than the relay does: WireGuard encrypts end to end, so it sees
  which devices talk to each other, but not what they say.
- HTTPS-only mode does not hide juist from a censor that probes servers or
  fingerprints TLS. Probing the relay's name reveals a relay, and the TLS
  handshake is that of a Go program, not a browser.
- The Android app has no setting for HTTPS-only mode. It does switch to a
  relay's name on 443 by itself where UDP and the relay's port are blocked.

## Troubleshooting

| What you see | What to do |
|---|---|
| `juist status`: `HTTPS  only, and no relay on 443` | give a relay a public name: run `sudo juist set --relay-name NAME` on it |
| `juist health`: `warning: no relay on 443/tcp` | the same |
| `juist health`: `no answer from …: offline, or at no relay on 443` | the device is offline, or cannot reach any relay that has a name |
| `juist health`: `no tunnel traffic from … through the relays on 443` | check the relays' names in DNS, and that port 443 reaches them |
| `juist health`: `warning: … not at the relay on …, the one this device reaches it at` | the device runs, but keeps no connection there: it saves battery and is reached once it sends, or it runs an older juist |
| `juist health`: `no answer from …: not at the relay on …` | the device is offline, or keeps no connection there; once it is known to be offline, the line goes |

If joining says `the invite link names no relay on 443`, you need a new invite
link, made after a relay serves a name on 443.
