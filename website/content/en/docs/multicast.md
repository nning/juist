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

Without an access policy, multicast and discovery copying are on by default.
With a policy they are off until a matching `pass multicast` rule permits
them, by device, direction and port. `sudo juist set --multicast=false`
disables both even if policy permits them. Every permitted member can answer discovery queries
on the others, as a device on your LAN can. It can announce a printer or a
media server, and the answer carries its address in the network.

juist does not carry:

- multicast from other devices on your LAN. Only what a member sends itself
  crosses.
- DHCP broadcasts (UDP source or destination ports 67 and 68), or fragmented broadcasts.
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

On Linux, juist automatically copies this host's IPv4 UDP multicast into
the network alongside the LAN. Programs that use only the default interface,
such as Minecraft Java, need no group configuration. `juist status` shows:

```console
  Multicast     on, copied: auto
```

Copying follows those permissions on every participating Linux member. Existing
explicit group lists remain in force. To restore the automatic default:

```sh
sudo juist set --groups auto
```

To copy only selected groups, give a comma-separated list, for example
`sudo juist set --groups 239.255.255.250` for SSDP. `sudo juist set --groups ""`
stops copying groups and prints `groups off`; broadcast remains on.

The original still goes to the LAN. Copying works only for IPv4 on Linux,
for unfragmented UDP packets up to 1280 bytes including the IP header
(1252 bytes of payload). Changing the groups restarts the device's tunnels,
which takes a few seconds. IPv6 programs must send and listen on `juist0`.

### Minecraft Java Edition

No group configuration is needed on Linux with the automatic default.
Under a policy, the discovery and game permissions below are still required.

Java Edition announces an open LAN world on UDP port 4445. The copy carries
the host's address in juist, so the client connects through juist; players
on the original LAN still receive the announcement too. Under an access
policy, allow multicast port 4445 and the game's TCP port separately. The
TCP port is the one chosen when opening the world to LAN.

Java's multicast socket joins only the default interface's group. With
automatic copying or a matching explicit group list, juist also delivers a
local unicast UDP copy with the sender's address preserved. Under an access policy, this copy additionally
needs ordinary UDP access to port 4445. For example, with TCP port 25565
chosen in the LAN dialog:

```text
pass multicast from <gamers> to <gamers> port 4445
pass from <gamers> to <gamers> proto udp port 4445
pass from <gamers> to <gamers> proto tcp port 25565
```

The original multicast still reaches listeners on `juist0`; an application
that accepts both deliveries can see two copies. The packet's payload and
source are unchanged. A socket bound to a LAN interface, LAN address or group address may still
need explicit support for `juist0`.

## What other members learn

Automatic copying includes discovery from every program on this host,
not only games you deliberately use through juist. It can reveal device
names, service identifiers and other information normally sent on the LAN.
Without a policy every member can receive it. Use an access policy to limit
who receives it, or `sudo juist set --multicast=false` to turn it off here.

## UDP broadcast

On Linux, juist automatically copies this host's IPv4 UDP broadcasts into
its network, with multicast on. It copies both `255.255.255.255` and subnet
broadcasts; the latter arrive as `255.255.255.255`. The originals still go
to the LAN. There is no list of ports to configure. The packet must fit
1280 bytes including the IP header and must not be fragmented. DHCP
broadcasts are excluded. NetBIOS on UDP ports 137 and 138 follows this same
broadcast path, without protocol-specific address or name handling.

Broadcast uses the same `pass multicast` rules and rate limit as multicast.
An answer is permitted for ten seconds on the source UDP port. A program
bound to its LAN address or LAN interface alone may not receive packets
arriving on `juist0`. Addresses written inside a discovery message are
not translated.

Automatic copying works only on Linux. On FreeBSD, multicast programs
must send and listen on `juist0` themselves. The Android app carries
neither multicast nor broadcast.

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

This turns off multicast and broadcast even where policy permits them. It prints `multicast off`, and `juist status` shows `Multicast off`.
`sudo juist set --multicast` allows discovery again where policy permits it. Both restart the device's
tunnels, which takes a few seconds.

The Android app carries no multicast.

## If something goes wrong

- **A program finds no member.** Run `juist health` and look for the avahi
  warning. On Linux, check that `juist status` says `copied: auto` or lists
  the program's group. Elsewhere the program must listen on `juist0`.
- **`juist status` shows no `Multicast` line.** The device has no `juist0`,
  as a [service member]({{< relref "docs/service-member" >}}) does not.
