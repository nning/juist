---
title: Your first network
linkTitle: Your first network
description: Create a network on one device, invite a second one, and check that the two reach each other.
lead: Two devices, one network, a few minutes. You create the network on one device, invite the other, compare four words, and ping it.
---

## What you will set up

Say you have a laptop and a NAS at home, both with juist
[installed]({{< relref "docs/install" >}}). You make the laptop the first
device of a network called `home`, and then invite the NAS.

A **network** is the group of devices that reach each other through juist,
and each of them is a **member**. Whoever creates the network is its first
**admin**: the person whose key signs changes, such as admitting a device. See
[How juist works]({{< relref "docs/how-it-works" >}}).

## Creating the network and inviting a device

{{< step on="laptop" as="the first device" >}}
Create the network as your own user, without sudo. Your admin key belongs in
your own keystore, the directory `~/.config/juist` in your home directory.

```console
$ juist create home
not the operator; run sudo juist set --operator=alice? [Y/n] y
operator alice
created network "home"
  This device   laptop  198.18.36.1  fd84:7a1f:97ee:5630:7c56:12b6:971f:2222
  IPv4 range    198.18.36.0/22
  Quorum        1 of 1 vote
  Admin         alice
  Break-glass   juist-break-glass-1.qL0x…dW8.u3Rk6g
  Operator      alice
warning: the break-glass secret is shown only now and kept nowhere: keep it safe, apart from the admin keys
hint: with it, juist network disable ends the network once too few admin keys are left to change it
```

juist asks for sudo once, to make you the device's **operator**: the local
user who manages it without sudo from then on. Without a name, `juist create`
names the network with two random words.
{{< /step >}}
{{< step on="laptop" >}}
Invite the new device:

```console
$ juist invite
invite to "home", expires in 1h; on the new device:

  juist join 'juist:Kx7…@192.168.1.20:41642'

  juist join 42-drumbeat-tolerance-glucose  # same LAN
```

It prints a link that works for a device anywhere, with the same link as a QR
code above it (left out here). Last comes a code for a device on the same LAN.
Then it waits.
{{< /step >}}
{{< step on="nas" as="the new device" >}}
Join with the code, or with the link if the NAS is somewhere else:

```console
$ sudo juist join 42-drumbeat-tolerance-glucose
looking for the inviting device on the LAN
connected to 192.168.1.20:41642
tell the inviting admin these words:
  atlas-amulet-banjo-asteroid
```

Because the command runs under sudo, the user who ran sudo becomes the NAS's
operator.
{{< /step >}}
{{< step on="laptop" >}}
The invite shows four words too. Answer `y` only if they are the same as on
the NAS:

```console
nas wants to join; compare with the words it shows:
  atlas-amulet-banjo-asteroid
same? [y/N] y
admitting nas (nid:fcRW83T_…)
admitted nas at 198.18.36.2
nas joined
```

On the NAS, `juist join` ends with the device's addresses:

```console {device="nas"}
joined "home" as nas
  Addresses     198.18.36.2  fd84:7a1f:97ee:21a8:2ab0:e8e:caa0:b306
  Devices       2
  Operator      alice
```
{{< /step >}}
{{< step on="either device" >}}
Check that the two reach each other:

```console
$ juist status
home · connected
  This device   laptop  198.18.36.1  fd84:7a1f:97ee:5630:7c56:12b6:971f:2222
  Devices       1 other
  Names         laptop.home.juist
  Freshness     unchecked: no voucher
  Ports         udp/41643
  Schema        20
  Updated       just now
$ juist devices
NAME                  IPV4         REACHED  SCHEMA  ROLES
laptop (this device)  198.18.36.1  -        20      -
nas                   198.18.36.2  direct   20      -
$ ping 198.18.36.2
```

`juist devices` lists the devices, and `ping nas.home.juist` works too.
{{< /step >}}

## Behind NAT, or with a public address

The link also works when the two devices sit behind NAT in different places,
for example the laptop at home and the NAS at a friend's. They meet
through the public BitTorrent DHT, which takes about a minute. This fails only
if both NATs are symmetric. In that case, join from an internet connection that
can reach the inviting device, or give the network a [relay]({{< relref "docs/relays" >}})
first. [Inviting devices]({{< relref "docs/invites" >}}) has the details.

Behind NAT, you do not need to open anything in a firewall. A device with a
public address, such as a VPS, needs port 41643/udp open.

## Notes

- `juist create home` names the network `home`. The device is named after its
  host unless you pass `--device`.
- The IPv4 range is a random `/22` in `198.18.0.0/15`, such as
  `198.18.36.0/22`. `--ipv4` sets a specific one.
- The code works only on the same LAN, and a single wrong guess invalidates
  it. The link keeps working.
- An invite admits one device and lasts an hour. Run `juist invite` again for
  the next one.
- The `Break-glass` line is shown only this once and kept nowhere. Put it in
  a password manager or on paper, apart from the admin keys. With it, you can
  end the network if too few admin keys are left to change it
  ([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).
- The network has no **voucher** yet. A voucher is a device that confirms
  every hour that the network's state is current. This limits how long a
  device that is cut off from the others can keep talking to one you removed. Give the role only to devices that are
  always on (`juist grant DEVICE voucher`); `juist create --voucher` makes the
  first device one. See
  [freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).

## Troubleshooting

| What you see | What to do |
|---|---|
| `juist: run as alice, without sudo: the admin key belongs in your keystore` | Run `juist create` without sudo. |
| `juist0 · not running` in `juist status` | `sudo systemctl enable --now juistd` |
| `read-only; to manage this device …` | `sudo juist set --operator=$USER`, once |
| `warning: code voided: wrong guess from …` | Join with the link, which still works. If that was not your device, someone else knows the invite. |
| `juist: words not confirmed; nothing signed` | If the words differed, the device asking is not the one you invited. Start a new invite. |
| `no answer from a device` in `juist health` | It is offline, or its port 41643/udp is closed. |
| `no tunnel traffic from a device` | Open 41643/udp on a device with a public address, or grant one `relay`. |

More cases are on the [Troubleshooting]({{< relref "docs/troubleshooting" >}})
page.
