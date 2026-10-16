---
title: Troubleshooting
linkTitle: Troubleshooting
description: What juist health says when something is wrong, what it means, and the command that fixes it.
lead: When something does not work, run juist health first. It says what needs attention and prints a hint with the fix. This page lists the common cases.
---

## Where to look

Run this on the device that has the problem:

```sh
juist health
```

Warnings start with `warning:`, and each one is followed by a `hint:` line
with the command to run. Plain lines name the devices this one does not
reach. Where nothing is wrong, it says `nothing needs attention`.
`juist status` shows the network's state and details. Any local user may run
both. [Status and devices]({{< relref "docs/status" >}}) explains what each
line means.

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
FreeBSD, run `service juistd start`. See [Install]({{< relref "docs/install" >}}).

### `read-only; to manage this device …`

You are neither root nor the device's operator, the local user who may manage
it without sudo. You can see the status, but nothing more. To make yourself
the operator, run this once:

```sh
sudo juist set --operator=$USER
```

See [Managing without sudo]({{< relref "docs/operator" >}}).

### `no answer from nas: offline, or udp/41643 blocked`

The device `nas` did not answer. Either it is switched off or offline, or a
firewall in front of it blocks port 41643/udp. Check that it is running. If it
has a public address, open 41643/udp there. See
[Relays]({{< relref "docs/relays" >}}).

### `no tunnel traffic from nas`

`nas` is known, but no traffic arrives from it. Either port 41643/udp is
blocked, or both devices are behind NAT and there is no relay. A relay is a
member that passes traffic between devices that cannot reach each other. Open
41643/udp on a device with a public address, as the hint says:

```console
hint: on a device with a public address: sudo ufw allow juist, or firewall-cmd --add-service=juist
```

Or make such a device a relay with `juist grant vps relay`. See
[Relays]({{< relref "docs/relays" >}}).

Where a relay is available, the warning reads
`no tunnel traffic from nas, though it announces itself`, without a hint:
nas runs and says where to reach it, yet neither a direct path nor a relay
carries its traffic.

### `no device reaches this relay`

This device is a relay, but no other device gets through to it. Port 41645 is
probably closed for TCP or UDP. Open it for both on the relay, and in any
firewall in front of it, such as your hosting provider's:

```sh {device="vps"}
sudo ufw allow juist-relay
```

With firewalld: `sudo firewall-cmd --permanent --add-service=juist-relay && sudo firewall-cmd --reload`.
See [Relays]({{< relref "docs/relays" >}}).

### `log sync to nas fails in the tunnel`

The tunnel works, but the log sync that runs inside it (TCP 41644 on
`juist0`) gets no answer from nas, most often because a firewall there drops
it. The devices then miss changes to the network, including removals. Where
nas runs Linux, allow incoming traffic on `juist0` there, as the hint says:

```console
hint: where it runs Linux: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone
```

If firewalld on this device is the cause, `juist health` says
`firewalld blocks juist0` and gives the command to fix it. See
[Relays]({{< relref "docs/relays" >}}).

### `warning: log sync fails: nas runs a newer juist`

nas runs a newer version of juist, whose changes this one cannot read. This
device misses changes to the network until you update juist on it.

### `warning: log sync to nas fails`

The tunnel works and the log sync reaches nas, but fails. juistd's log says
why.

### `no device may relay`

The network has more than two devices, but none of them is allowed to relay.
Devices behind strict NATs need a relay. On an admin's device, give the role
to a device with a public address:

```sh
juist grant vps relay
```

See [Relays]({{< relref "docs/relays" >}}).

### `warning: no relay on 443/tcp`

This device sends only HTTPS, so it can reach the others only through a relay
that serves a public name on port 443, and there is none. Give a relay a
public name by running this on the relay:

```sh
sudo juist set --relay-name relay.example.org
```

Or, if the network lets more than HTTPS out, run
`sudo juist set --https-only=false`. See
[HTTPS only]({{< relref "docs/https-only" >}}). If a relay has a name and the
warning remains, the server reached under that name does not identify itself
as that relay. Check the name's DNS.

### `warning: juistd may bind any port below 1024, which no relay on 443 here needs`

juistd was allowed to bind port 443 so that a relay could serve its public
name. The name is gone, but the permission remains, for example because the
name was removed without root, so the permission could not be revoked. Revoke
it as the hint says:

```sh
sudo /usr/lib/juist/relay.sh off
```

`juist reset` revokes it too. See [Relays]({{< relref "docs/relays" >}}).

### `Freshness  expired; vouchers only`

Too few vouchers have been reachable for 48 hours. A voucher is a device that
confirms every hour that the network's state is current. Until enough of them
vouch again, this device keeps tunnels only to vouchers, and its state reads
`limited`. Bring a voucher back online. To prevent this, choose only devices
that are always on as vouchers, and have one more than you need. See
[Removing a device]({{< relref "docs/remove" >}}).

### `warning: freshness ends in 20h unless 2 vouchers vouch again`

For a day, fewer vouchers than needed have vouched. When the time shown runs
out, this device becomes `limited`, as described above. Bring a voucher back
online before then.

### `warning: nas runs an older juist, unreachable until updated`

The network was upgraded, and nas still runs a version of juist from before
the upgrade. Until you update juist on nas, none of your traffic reaches it,
and none of its traffic reaches you. Its tunnel carries only the network's
changes, so that nas can tell you the same. `juist devices` shows it as
`outdated`. Where nas has no tunnel to this device at all, since its version
knows no device that joined after the upgrade, it shows `no answer`.

### `warning: nas runs an older juist, which applies no changes until updated`

The network was upgraded, and nas still runs a version of juist from before
the upgrade. nas stays reachable, but it applies no change to the network
until you update juist on it, a removal included. `juist status` on nas
says the same.

### `warning: this change builds on juistd's view of the log, …`

You are removing a device or an admin key, or taking authority away, while
juistd's view of the network is stale: no voucher has vouched for it lately.
A change that withdraws authority wins over changes made meanwhile that this
device has not seen, and undoes them. Where the change can wait, bring the
device back in touch with a voucher first. Where it cannot, as for a stolen
device, go ahead, and redo what it undoes.

### `warning: nas fell too far behind to reach this device`

nas was offline for more changes than this device keeps keys for. nas can
catch up from a device that still has those keys, usually one that was
offline for as long. Otherwise, join it to the network again with a new
invite. Only a device that runs is said to have fallen behind: of one that is
offline, this device may hold only an announcement from before it joined.

### `alarm: log: rollback alarm: the chain went back from epoch 4 to 3, …`

Two admins changed the network at the same time, and the changes this device
applied first lost to the others. Taking the winning changes would move the
network's group secret back to an older one, which this device never does,
since a removed device may hold it. So every tunnel stays down, though the
device keeps receiving changes, removals included. An admin redoes the lost
changes, or runs `juist rotate group-secret`. Once that change reaches this
device, it connects again.

### `warning: this device's log is older than what the network's devices keep`

The device was offline while the network changed and the other devices
dropped the part of the log it still needed, which they do once they have seen
every device past it. Invite it again: an admin runs `juist invite`, and the
device joins with the link it prints, keeping its keys and name. A typed code
cannot replace the device's log. If the join says the chain does not continue
this log, nothing it missed moved the group secret, so it cannot tell the
invite's log is newer: run `juist reset`, then join.

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
blocks the traffic rather than sending it directly. Make `vps` reachable
again, or send traffic directly again:

```sh
juist exit off
```

See [Exit nodes]({{< relref "docs/exit-nodes" >}}).

### `this device does not serve: IP forwarding is off …`

This device is meant to be an exit node, but the host does not forward
traffic. Run this command on it again. It sets up the host using sudo:

```sh
juist exit serve
```

See [Exit nodes]({{< relref "docs/exit-nodes" >}}).

### `DNS goes to …, outside the tunnel: systemd-resolved refused juistd …`

You are using an exit node, but systemd-resolved did not allow juistd to send
DNS through the tunnel, so lookups go out directly. The juist package includes
a polkit rule that allows this, wherever polkit runs. Install juist from the
package, and install polkit where the line ends in `polkit is not installed`,
as the hint says. See
[Install]({{< relref "docs/install" >}}) and [Names]({{< relref "docs/names" >}}).
