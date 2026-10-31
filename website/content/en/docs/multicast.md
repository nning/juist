---
title: Finding devices across the network
linkTitle: Multicast
description: Programs that find each other by multicast on a LAN, such as printers, media servers and LAN games, find the members of your network the same way.
lead: Many programs find each other by multicast. AirPlay and printers use mDNS, media servers SSDP, Windows WS-Discovery, and LAN games their own groups. juist carries this multicast between the members, as if they shared one LAN.
---

## How it works

A program that sends multicast on `juist0` reaches the programs on the
other members that listen on their `juist0`. juist carries UDP to multicast
groups, over IPv4 and IPv6. The datagram arrives with the sender's address
in the network, so an answer goes straight back to it.

It carries pings to IPv6 groups too, so that `ping -I juist0 ff02::1`
shows the members that answer, each by its link-local address.

Multicast is on by default. Every member can then answer discovery queries
on the others, as a device on your LAN can. It can announce a printer or a
media server, and the answer carries its address in the network.

juist does not carry:

- multicast from other devices on your LAN. Only what a member sends itself
  crosses.
- broadcast, such as to `255.255.255.255`.
- IPv6 groups other than those of link scope (`ff02::`) and site scope
  (`ff05::`).
- ICMP to a group other than an IPv6 ping, such as router advertisements,
  neighbour discovery or MLD.
- DHCPv6, so that no member hands the others addresses or DNS servers.
- multicast under an [access policy]({{< relref "docs/access" >}}), unless a
  `pass multicast` rule passes it.

A member sends at most 100 datagrams a second, in bursts of up to 200. The
others drop what goes past that.

## Under an access policy

With an [access policy]({{< relref "docs/access" >}}), multicast passes only
where a rule passes it, from device to device:

```text
pass multicast from <family> to <family>
pass multicast from <gamers> to <gamers> port 4445
```

The first rule, without a port, passes pings too. The second passes only
UDP port 4445, a game's own group. Each rule
also passes the answers a device sends straight back. Such rules need the
network's schema 22; see [Updating]({{< relref "docs/updating" >}}).

## Programs that use the default interface

Many programs listen and send on every interface, `juist0` among them. Some
use only the host's default interface, usually the LAN's. For those, route
their group into the network.

{{< step on="laptop" >}}
Route SSDP's group into the network:

```sh
sudo juist set --groups 239.255.255.250
```

It prints `groups 239.255.255.250`, and `juist status` shows:

```console
  Multicast     on, routed: 239.255.255.250
```
{{< /step >}}

{{< step on="nas" as="the other members" >}}
Do the same on every member that runs such a program, so that it receives
the group on its default interface too.
{{< /step >}}

A routed group goes to the members and no longer to the LAN, from this
device. Several groups are separated by commas. `sudo juist set --groups ""`
routes none again. You can route only IPv4 groups, and only on Linux.
Changing the groups restarts the device's tunnels, which takes a few
seconds.

## Avahi

On Linux and FreeBSD, avahi asks and answers mDNS for many programs. It leaves out a
device like `juist0` unless its configuration allows it. `juist health`
warns of this:

```console
warning: avahi leaves juist0 out, a point-to-point device: members are not found by mDNS
hint: set allow-point-to-point=yes under [server] in /etc/avahi/avahi-daemon.conf, then restart avahi-daemon
```

Add the line under `[server]` in `/etc/avahi/avahi-daemon.conf`, on FreeBSD
in `/usr/local/etc/avahi/avahi-daemon.conf`:

```ini
[server]
allow-point-to-point=yes
```

Then restart avahi, on FreeBSD with `service avahi-daemon restart`:

```sh
sudo systemctl restart avahi-daemon
```

## Turning it off

```sh
sudo juist set --multicast=false
```

It prints `multicast off`, and `juist status` shows `Multicast off`.
`sudo juist set --multicast` turns it on again. Both restart the device's
tunnels, which takes a few seconds.

The Android app carries no multicast.

## If something goes wrong

- **A program finds no member.** Run `juist health` and look for the avahi
  warning. Check that the program listens on `juist0`, or route its group as
  above.
- **`juist status` shows no `Multicast` line.** The device has no `juist0`,
  as a [service member]({{< relref "docs/service-member" >}}) does not.
