---
title: Names
linkTitle: Names
description: Reach devices by name instead of address, and have public names lead to a member through the tunnel.
lead: Every device in your network has a name, such as nas.home.juist, or just nas. You can also point a public name, such as mail.example.org, at a device, so that members reach it through the tunnel.
---

## How names work

Every member has a DNS name: `DEVICE.NETWORK.juist`. In the network `home`,
the device `nas` is `nas.home.juist`, and plain `nas` works too. Nothing needs
turning on for this.

You can also point a **public name** at a member. Say your NAS runs a mail
server known as `mail.example.org`. On devices that turned public names on,
that name then leads to the NAS through the tunnel. The certificate still
matches, and the rest of the internet still gets the public record.

Both work on Linux and FreeBSD, where juist sets up the device's DNS itself
([how](#resolver)). The [Android app]({{< relref "docs/android" >}}#names)
resolves the members' names and the names published under the network's
domain, not public names.

## Reaching a device by name

```sh {device="laptop"}
ssh nas.home.juist
ssh nas
```

Both lead to the NAS, at its addresses in the network.

## Pointing a public name at a device

{{< step on="an admin's device" >}}
Point the name at the device:

```sh
juist names add nas mail.example.org
```

It prints `nas: names mail.example.org`. Like any change, it needs the
admins' approval ([approving changes]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="each device that should use it" >}}
Turn public names on for this device:

```sh
juist names on
```

It prints `public names on: mail.example.org at nas`.
{{< /step >}}

`juist names` lists the network's names and how this device resolves each.
`juist names off` makes this device resolve them publicly again.
`juist names remove nas mail.example.org` takes the name from the device.

## Why each device opts in

A public name in the network overrides what the internet says. The admins
could point any public name at any member. A connection that checks the
certificate would fail, but plain HTTP, mail without certificate checks and
much internal tooling would not notice.

So each device decides for itself. A device without `juist names on` resolves
every public name as without juist. Member names such as `nas.home.juist`
override nothing outside the network and need no consent.

The exception is the network's domain for
[publishing]({{< relref "docs/publishing" >}}). Once the admins set it, every
member resolves that domain through juistd, with DNSSEC off for it. A name
published there on port 443 leads straight to its device; other names in the
domain resolve as before. Only set a domain you control: juist cannot check
that you do.

## Leaving this device's DNS alone

```sh
sudo juist set --dns=false
```

It prints `dns off`. juistd then leaves this device's DNS alone: no network
names, and no DNS through an exit node. The `Names` line in `juist status`
ends in `(DNS off)`. `sudo juist set --dns` turns it on again, without a
restart.

## Good to know

- A public name has at least two labels, such as `example.org`, and is not
  under `.juist`, `.local`, `.localhost`, `.arpa`, `.invalid` or `.onion`.
- Each public name points at one device. A device can have up to 32.
- While its device cannot be reached, or this device's view is out of date, a
  public name resolves publicly again.
- A device whose name is not a valid DNS label has no name under `.juist`.
- Under an [access policy]({{< relref "docs/access" >}}), a device has names
  only for the members it keeps a tunnel with.
- If juistd answers all of a device's DNS, it also answers reverse lookups of
  the network's addresses.

## How the device resolves names {#resolver}

- With systemd-resolved, it sends queries for the network's names to juistd.
  Names juistd passes on go where systemd-resolved would send them. juistd
  refuses names systemd-resolved would ask over DNS over TLS, rather than send
  them in plain text, and names only Tailscale's resolver would answer.
  `juist health` says so.
- On Linux without systemd-resolved, juistd answers all of the device's DNS
  while it runs, other names through the resolvers the device used before.
  The package points `/etc/resolv.conf` at juistd's file, and back when juistd
  stops.
- On FreeBSD, juistd hands its resolver to resolvconf.
- On Android, see [the app's names]({{< relref "docs/android" >}}#names).
- If Tailscale wrote `/etc/resolv.conf`, juist leaves it alone, and the
  network's names do not resolve on that device.

## Troubleshooting

`juist names` lists every name of the network and how this device resolves
each. If names are not resolved, or a public name is off,
[`juist health`]({{< relref "docs/status" >}}) says why:

| `juist health` says | Meaning |
|---|---|
| `1 public name, off on this device` | there is a public name, but this device has not turned names on |
| `mail.example.org resolved publicly: nas is not reachable` | the public name leads to its public address for now |
| `warning: home.juist not resolved here: systemd-resolved refused juistd` | systemd-resolved did not let juistd set up DNS |
| `warning: home.juist not resolved here: systemd-resolved refused juistd: polkit is not installed` | the same, on a host without polkit, which runs the package's rule |
| `warning: home.juist not resolved here: /etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub` | programs here bypass systemd-resolved |
| `warning: home.juist not resolved here: systemd-resolved does not run on this host` | juistd runs without the package's service, which hands it `/etc/resolv.conf` |
| `warning: home.juist not resolved here: tailscaled writes /etc/resolv.conf` | Tailscale answers this device's DNS; `sudo tailscale set --accept-dns=false` and `sudo systemctl restart juistd` hand it to juistd, without the tailnet's names |
| `warning: home.juist not resolved here: /etc/resolv.conf is no longer juistd's` | another program, such as a DHCP client, wrote `/etc/resolv.conf`; `sudo systemctl restart juistd` hands it back |
| `warning: home.juist not resolved here: /etc/resolv.conf asks …, not juistd` | on FreeBSD, resolvconf leaves alone a `resolv.conf` it did not write |
| `warning: names juistd forwards are refused: the host asks tailscaled alone, whose answers members cannot reach` | an exit node refuses members the names the host sends to Tailscale alone; `sudo tailscale set --accept-dns=false` on it leaves the tailnet's names to its other resolvers |
| `warning: names juistd forwards are refused: systemd-resolved asks over DNS over TLS, which juistd does not speak` | juistd refuses this device names systemd-resolved would ask over TLS rather than send them in plain text; `juist exit use DEVICE` sends them through the tunnel |
| `warning: names juistd forwards are refused: systemd-resolved knows no DNS server` | systemd-resolved has no server to ask; `resolvectl status` shows the servers it knows |
| `warning: names the host's DNS routing sends elsewhere are refused, as it cannot be read: …` | juistd cannot ask systemd-resolved where a name goes, and refuses such names until it can; `systemctl status systemd-resolved` shows how it is |

Where systemd-resolved refused juistd, `juist health` adds:

```console
hint: the package's polkit rule allows juistd that: /usr/share/polkit-1/rules.d/60-juist.rules
```

Install juist from the package ([Install]({{< relref "docs/install" >}})),
which brings that rule. If polkit is missing, as after `dpkg -i`, the hint
installs it:

```console
hint: sudo apt install polkitd, or sudo dnf install polkit
```

juistd tries again within a minute, without a restart. In uplink mode, the
hint points `/etc/resolv.conf` at the stub:

```sh
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
