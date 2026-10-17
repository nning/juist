---
title: Names
linkTitle: Names
description: Reach devices by name instead of address, and have public names lead to a member through the tunnel.
lead: Every device in your network has a name, such as nas.home.juist, or just nas. You can also point a public name, such as mail.example.org, at a device, so that members reach it through the tunnel.
---

## How names work

Each device in the network is a **member**, and each member has a name. juist
turns that name into a DNS name: `DEVICE.NETWORK.juist`. In the network `home`,
the device `nas` is `nas.home.juist`, and plain `nas` works too. You don't
need to turn anything on for this.

You can also point a **public name** at a member. Say your NAS runs a mail
server that the internet knows as `mail.example.org`. On devices that have
turned public names on, `mail.example.org` then leads to the NAS through the
tunnel, not over the internet. The name stays the same, so the server's
certificate still matches. The rest of the internet still gets the public
record.

Both work on Linux and FreeBSD. Where systemd-resolved runs, it sends these
names to juistd. Elsewhere juistd answers the device's DNS
itself while it runs: the network's names, and every other name from the
resolvers the device had before. On Linux the package's service points
`/etc/resolv.conf` at a file juistd writes, and back when juistd stops; on
FreeBSD juistd gives its resolver to resolvconf. A `/etc/resolv.conf` that
Tailscale wrote stays Tailscale's, and the network's names are not resolved
on that device.

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

It prints `nas: names mail.example.org`. This is a change to the network, so
like any other change it needs the admins' approval
([approving changes]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="each device that should use it" >}}
Turn public names on for this device:

```sh
juist names on
```

It prints `public names on: mail.example.org at nas`.
{{< /step >}}

`juist names` lists the network's names, the public ones among them, and how
this device resolves each one.
`juist names off` makes this device resolve them publicly again, and
`juist names remove nas mail.example.org` takes the name away from the device.

## Why each device opts in

A public name in the network overrides what the internet says. The admins who
approve such a change could point any public name at any member they choose.
A connection that checks a certificate would then fail, since the member has
no certificate for that name. But plain HTTP, mail without a verified
certificate, and a lot of internal tooling would not notice.

So each device decides for itself. A device that has not run `juist names on`
resolves every public name as it would without juist. Member names such as
`nas.home.juist` override nothing outside the network, so they need no
consent.

The exception is the network's own domain for
[publishing]({{< relref "docs/publishing" >}}). Once the admins set it, every
member resolves that domain through juistd, whether public names are on or
not, and DNSSEC is off for it on members. A name published there on port 443
leads straight to its device; every other name in the domain resolves as
before. `juist network domain` warns about this, and admins see it when they
approve the change. Only set it to a domain you control: juist cannot check that
you do.

## Leaving this device's DNS alone

```sh
sudo juist set --dns=false
```

It prints `dns off`. juistd then leaves this device's DNS as it found it: no
names of the network, and no DNS through an exit node, which then goes to the
device's own resolvers outside the tunnel. The `Names` line in `juist status`
then ends in `(DNS off)`, and `juist health` says what that means. `sudo juist
set --dns` turns it on again. Neither needs a restart.

## Notes

- A public name has at least two labels, such as `example.org`, and is not under `.juist`.
- Each public name points at one device. A device can have up to 32.
- A public name is resolved publicly again while its device cannot be reached, or while this device's view of the network is out of date. The connection then goes to the public address, as it would without juist.
- A device whose name is not a valid DNS label has no name under `.juist`.
- Under an [access policy]({{< relref "docs/access" >}}), a device has names only for the members it keeps a tunnel with. The public names of the other members resolve publicly on that device.
- In `juist devices`, a device that public names point at shows `names` under `ROLES`. `juist names` lists the names.

## Troubleshooting

The `Names` line in [`juist status`]({{< relref "docs/status" >}}) lists this
device's own names, such as `nas.home.juist, mail.example.org`, and ends in
`(DNS off)` where DNS is off. `juist names` lists every name of the network,
its domains among them, and how this device resolves each. Where they are not
resolved, or a public name is off, [`juist health`]({{< relref "docs/status" >}})
says why:

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

Where systemd-resolved refused juistd, `juist health` adds:

```console
hint: the package's polkit rule allows juistd that: /usr/share/polkit-1/rules.d/60-juist.rules
```

Install juist from the package (see [Install]({{< relref "docs/install" >}})),
which brings that rule. Where polkit is missing, as after `dpkg -i`, which
skips the packages juist recommends, the hint installs it:

```console
hint: sudo apt install polkitd, or sudo dnf install polkit
```

juistd tries again within a minute, without a restart. In uplink mode,
the hint gives the command that points `/etc/resolv.conf` at the stub:

```sh
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
