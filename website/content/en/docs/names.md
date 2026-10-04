---
title: Names
linkTitle: Names
description: Reach devices by name instead of address, and have public names lead to a member through the tunnel.
lead: Every device in your network has a name, such as nas.home.juist, or just nas. You can also point a public name, such as mail.example.org, at a device, so that members reach it through the tunnel.
---

## What it is

Each device in the network is a **member**, and each member has a name. juist
turns that name into a DNS name: `DEVICE.NETWORK.juist`. In the network `home`,
the device `nas` is `nas.home.juist`, and `nas` alone works too. Nothing needs
to be turned on for this.

You can also point a **public name** at a member. Say your NAS runs a mail
server that the internet knows as `mail.example.org`. On devices that turned
public names on, `mail.example.org` then leads to the NAS through the tunnel,
not over the internet. The name stays the same, so the server's certificate
still matches. The rest of the internet still resolves the public record.

Both work on Linux, on devices where systemd-resolved runs. FreeBSD's
resolver cannot route these names, so they do not work there, and
`juist status` says so.

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
it needs the admins' approval, as any other
([approving changes]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="each device that is to use it" >}}
Turn public names on, on this device:

```sh
juist names on
```

It prints `public names on: mail.example.org at nas`.
{{< /step >}}

`juist names` lists the public names and how this device resolves each.
`juist names off` resolves them publicly again, and
`juist names remove nas mail.example.org` takes the name away from the device.

## Why each device turns them on

A public name in the network overrides what the internet says. The admins who
approve such a change could point any public name at a member of their
choosing. A connection that checks a certificate then fails, since the member
has no certificate for that name. Plain HTTP, mail without a verified
certificate, and much internal tooling would not notice.

So each device decides for itself. A device that has not run `juist names on`
resolves every public name as it would without juist. Names of members, such
as `nas.home.juist`, claim nothing outside the network and need no consent.

The network's own domain for publishing is the exception: setting it, the
admins have every member resolve it through juistd, whose answers lead to the
devices that publish its names, and turn DNSSEC off for it on members.
`juist network domain` and its approval say so. Set it only to a domain you
control: juist cannot tell whether you do.

## Good to know

- A public name has at least two labels, such as `example.org`, and is not under `.juist`.
- Each public name points at one device. A device may have up to 32.
- A public name is resolved publicly again while its device cannot be reached, or while this device's view of the network is out of date. The connection then goes to the public address, as without juist.
- A device whose name is not a valid DNS label has no name under `.juist`.
- The network's own domain for [publishing]({{< relref "docs/publishing" >}}) goes to juistd whole on every member, names on or not: a name published there on port 443 leads straight to its device, and every other name of the domain resolves as before. DNSSEC is off for that domain on members.
- `juist devices` shows a device's public names under `ROLES`, as `names mail.example.org`.

## If something goes wrong

The `Names` line in [`juist status`]({{< relref "docs/status" >}}) says how
this device resolves the network's names:

| `Names` says | Meaning |
|---|---|
| `home.juist` | members' names work |
| `home.juist; mail.example.org at nas` | members' names and the public names work |
| `home.juist; 1 public name, off on this device` | there is a public name, but this device has not turned names on |
| `home.juist not resolved: systemd-resolved refused juistd` | systemd-resolved did not let juistd set up DNS |
| `home.juist not resolved: /etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub` | programs here bypass systemd-resolved |

Where systemd-resolved refused juistd, `juist status` adds:

```console
hint: the package's polkit rule allows juistd that, where polkit runs: /usr/share/polkit-1/rules.d/60-juist.rules
```

Install juist as the package (see [Install]({{< relref "docs/install" >}})),
which brings that rule, and polkit where the host lacks it. For the uplink mode, the hint gives the command that
points `/etc/resolv.conf` at the stub:

```sh
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
