---
title: Troubleshooting
linkTitle: Troubleshooting
description: What juist status says when something is wrong, what it means, and the command that fixes it.
lead: When something does not work, run juist status first. It says what needs attention and prints a hint with the fix. This page lists the common cases.
---

## Where to look

Run this on the device that has the problem:

```sh
juist status
```

Warnings start with `warning:` and come below the device table. Each is
followed by a `hint:` line with the command to run. Any local user may run
`juist status`; see [Status and devices]({{< relref "docs/status" >}}) for what
each line means.

For more detail, read the daemon's own log:

```sh
journalctl -u juistd
```

A second network on the same device has its own daemon and log:
`journalctl -u juistd@juist1`.

## Common problems

### `juistd not running`

The daemon, the program that keeps the tunnels up, is not running. Start it:

```sh
sudo systemctl enable --now juistd
```

For a second network on the device, the daemon is `juistd@juist1`. On
FreeBSD, `service juistd start`. See [Install]({{< relref "docs/install" >}}).

### `read-only; to manage this device …`

You are not root and not the device's operator, the local user who may manage
it without sudo. You can see the status, and nothing more. Make yourself the
operator, once:

```sh
sudo juist set --operator=$USER
```

See [Managing without sudo]({{< relref "docs/operator" >}}).

### `no answer from nas: offline, or udp/41643 blocked`

The device `nas` did not answer. Either it is switched off or offline, or a
firewall in front of it closes port 41643/udp. Check that it is running. If it
has a public address, open 41643/udp there. See
[Relays]({{< relref "docs/relays" >}}).

### `no tunnel traffic from nas`

`nas` is known, but no traffic arrives from it. Port 41643/udp is blocked, or
both devices sit behind NAT and there is no relay, a member that passes traffic
between devices that cannot reach each other. Open 41643/udp on a device with a
public address, as the hint says:

```console
hint: on a device with a public address: sudo ufw allow juist, or firewall-cmd --add-service=juist
```

Or make such a device a relay with `juist grant vps relay`. See
[Relays]({{< relref "docs/relays" >}}).

### `no device reaches this relay`

This device is a relay, but no other device gets through to it. Port 41645 is
likely closed, for TCP or UDP. Open both on the relay, and in any firewall in
front of it, such as your hosting provider's:

```sh {device="vps"}
sudo ufw allow juist-relay
```

With firewalld: `sudo firewall-cmd --permanent --add-service=juist-relay && sudo firewall-cmd --reload`.
See [Relays]({{< relref "docs/relays" >}}).

### `log sync to nas fails in the tunnel`

The tunnel works, but a firewall on this host drops the log sync inside it,
TCP 41644 on `juist0`. The device then misses changes to the network,
removals included. Let `juist0` in, on both devices, as the hint says:

```console
hint: on both devices: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone
```

Where firewalld is the cause, `juist status` says `firewalld blocks juist0`
and gives the command for it. See [Relays]({{< relref "docs/relays" >}}).

### `no device may relay`

In a network of more than two devices, no device is allowed to relay. Devices
behind strict NATs need one. On an admin's device, give the role to a device
with a public address:

```sh
juist grant vps relay
```

See [Relays]({{< relref "docs/relays" >}}).

### `warning: no relay on 443/tcp`

This device sends nothing but HTTPS, and no relay serves a public name on
443, the one way it reaches the others. Give a relay a name, on the relay:

```sh
sudo juist set --relay-name relay.example.org
```

Or, on a network that lets more out, `sudo juist set --https-only=false`. See
[HTTPS alone]({{< relref "docs/https-only" >}}). Where a relay has a name and
the warning stays, the server at the name does not say it is that relay:
check the name's DNS.

### `warning: juistd may bind any port below 1024, which no relay on 443 here needs`

The right to bind 443, granted for a relay's public name, outlived the name,
as when giving it back found no root. Take it back as the hint says:

```sh
sudo /usr/lib/juist/relay.sh off
```

`juist reset` takes it back too. See [Relays]({{< relref "docs/relays" >}}).

### `Freshness  expired; vouchers only`

Too few vouchers have been reachable for 48 hours. A voucher is a device that
confirms every hour that the network's state is current. Until enough do
again, this device keeps tunnels only to vouchers, and its state reads
`limited`. Bring a voucher back online. To keep it from happening again, make
vouchers only of devices that are always on, with a spare. See
[Removing a device]({{< relref "docs/remove" >}}).

### `warning: freshness ends in 20h unless 2 vouchers vouch again`

Fewer vouchers than needed have vouched for a day. In the time shown, this
device becomes `limited` as above. Bring a voucher back online before then.

### `removed`

This device is no longer in the network. To use it again, join with a new
invite, or start over:

```sh
juist reset
```

See [Removing a device]({{< relref "docs/remove" >}}) and
[Invites]({{< relref "docs/invites" >}}).

### `no IPv4 on this host`

This device is in two networks whose IPv4 ranges overlap. The second one then
works over IPv6 only. Move one of them to another range, for example:

```sh
juist network renumber work 10.7.0.0/24
```

See [Several networks]({{< relref "docs/networks" >}}).

### `Exit node  vps, internet refused: …`

This device sends its internet traffic through the exit node `vps`, but cannot
use it right now, for example because `vps` cannot be reached. juist then
refuses the traffic rather than send it directly. Bring `vps` back, or go
direct again:

```sh
juist exit off
```

See [Exit nodes]({{< relref "docs/exit-nodes" >}}).

### `this device does not serve: IP forwarding is off …`

This device is meant to be an exit node, but the host does not forward
traffic. Run this again on it; it sets the host up with sudo:

```sh
juist exit serve
```

See [Exit nodes]({{< relref "docs/exit-nodes" >}}).

### `DNS goes to …, outside the tunnel: systemd-resolved refused juistd …`

While you use an exit node, systemd-resolved did not let juistd send DNS
through the tunnel, so lookups go out directly. The juist package brings a polkit rule that allows juistd to
do this, where polkit runs. Install juist as the package, and polkit where the
host lacks it. See
[Install]({{< relref "docs/install" >}}) and [Names]({{< relref "docs/names" >}}).
