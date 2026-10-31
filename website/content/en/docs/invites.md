---
title: Inviting devices
linkTitle: Inviting devices
description: Add a device to the network with a code or a link, compare the four words, and give it a role as it joins.
lead: An invite lets exactly one new device join the network. You run it on an admin's device, and the new device joins with the code or the link it prints.
---

## How an invite works

An **invite** is a short-lived secret that one new device uses to join.
`juist invite` prints it as a code and as a link, and waits. The new device
runs `sudo juist join` with either.

Only an [admin's]({{< relref "docs/how-it-works" >}}#admins) device can
invite, because admitting a device is a signed change. Before anything is
signed, both devices show four words for you to compare. They prove that the
device asking to join is the one you invited.

## Code or link

| | Code | Link |
|---|---|---|
| Looks like | `42-drumbeat-tolerance-glucose` | `'juist:Kx7…@192.168.1.20:41642'` |
| Works from | the same LAN only | anywhere |
| A wrong guess | voids the code | voids nothing |

The **code** is a number and three words, short enough to read aloud. The
number tells invites apart; the three words are the secret. The new device
finds the inviting device on the LAN and connects to it on TCP port 41642. If
a firewall might block that port, `juist invite` prints the command that opens
it, such as `hint: the firewall may block the device: sudo ufw allow 41642/tcp`.

The code allows exactly one guess. After a wrong one, the inviting device
says `warning: code voided: wrong guess from …` and refuses the right code
too. The link still works.

The **link** holds a 128-bit secret, the inviting device's addresses and the
inviting admin's key. Copy it whole, including the quotes, so that the shell
does not change it.

In a terminal, `juist invite` also shows the link as a QR code. A phone joins
by scanning it with the [Android app]({{< relref "docs/android" >}}), or by
typing the code. If the window is too narrow for the QR code, juist says so.

Code and link stop working when a device joins or the invite expires. An
invite lasts an hour; `--expires 2h` changes that, up to `7d`.

## Inviting a device

{{< step on="an admin's device" >}}
Start the invite. To give the new device a different name, add it here:

```sh
juist invite nas
```

Without a name, the device keeps its host name. If another member already
uses the name, juist adds a number.
{{< /step >}}
{{< step on="nas" as="the new device" >}}
Join with the code on the same LAN, or with the link from anywhere:

```sh
sudo juist join 42-drumbeat-tolerance-glucose
```

The new device shows four words: `tell the inviting admin these words:`.
{{< /step >}}
{{< step on="an admin's device" >}}
Compare them with the words the invite shows, and answer:

```console
nas wants to join; compare with the words it shows:
  atlas-amulet-banjo-asteroid
same? [y/N] y
admitting nas (nid:fcRW83T_…)
admitted nas at 198.18.36.2
nas joined
```
{{< /step >}}

## The four words

The words cover the new device's identity and all its keys. If another
device has put itself between the two, the words differ. A device in between
cannot search for matching words, because each side commits to its part
before it learns the other's.

If the words differ, answer `n`. The invite signs nothing:
`juist: words not confirmed; nothing signed`. Start a new invite, and find out
which device tried to join.

`juist invite --yes` skips the comparison. Use it only where you cannot
compare anyway, such as in a script.

## Inviting with a role

An invite can give the new device a [role]({{< relref "docs/how-it-works" >}}#roles)
as it joins:

| Option | The new device becomes |
|---|---|
| `--relay` | a relay, which passes traffic for devices that cannot reach each other ([Relays]({{< relref "docs/relays" >}})) |
| `--voucher` | a voucher, which confirms every hour that the network's state is current ([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)) |
| `--ingress` | an ingress, which takes connections from the internet for published names ([Publishing services]({{< relref "docs/publishing" >}})) |
| `--service NAME` | a service member that publishes `NAME` and cannot open connections to other devices ([Service members]({{< relref "docs/service-member" >}})) |

To invite a VPS as the network's ingress:

```console
$ juist invite vps --ingress
invite to "home" as ingress, expires in 1h; on the new device:
```

`--ingress` and `--voucher` do not combine, and `--service` combines with
none of the others. Other roles, such as `exit`, are granted after joining
with `juist grant`.

## Across NAT

The link works even when both devices are behind NAT in different places.
The new device first tries the addresses in the link. If it cannot reach
them, the two meet through the public BitTorrent DHT, and the new device says
`no direct answer; meeting through the DHT (up to a minute)`.

If the network has a relay and the inviting device is behind NAT, the invite
also waits at the relay: `juist invite` says
`meets through relay 203.0.113.7:41645 where this device is unreachable`. The
relay never sees the invite's secret.

This fails only if both NATs are symmetric, that is, they pick a new port for
every destination. Then join from an internet connection that can reach the
inviting device, or give the network a [relay]({{< relref "docs/relays" >}})
first.

## Good to know

- One invite admits one device. Run `juist invite` again for the next.
- `--no-lan` prints only the link. `--no-dht` keeps the invite off the public
  DHT. `--port` picks another TCP port than 41642.
- `sudo juist join` makes the sudo user the device's
  [operator]({{< relref "docs/operator" >}}). `--operator` names another user,
  `--name` the device's name.
- If a change needs more than one admin's vote, the invite waits for the
  others, and the new device shows `waiting for approval (1 of 2 votes)`. The
  wait counts against the invite's lifetime.
- On a device in several networks, name the network: `juist invite work`.
- With an [access policy]({{< relref "docs/access" >}}), the new device gets
  no traffic until a rule names it. `juist invite` says so in a `hint:` line.

## Troubleshooting

| What you see | What to do |
|---|---|
| `juist: no admin key of this network here` | Invite from an admin's device. |
| `warning: code not announced on the LAN (…); use the link` | Join with the link. |
| `warning: code voided: …` | Join with the link. If that was not your device, someone else knows this invite. |
| `juist: invite expired` | Start a new invite, with a longer `--expires` if the wait was for other admins. |
| `juist: cannot reach the inviting device, …` | Check that the invite still runs. If both devices are behind NAT, join from an internet connection that can reach the inviting device, or add a relay first. |
| `juist: comparing the device's words needs a terminal; pass --yes to skip` | Run `juist invite` in a terminal, or pass `--yes` where you cannot compare. |
| `juist: … the inviting device runs an incompatible version of juist` | Update juist on both devices, then invite again. |
| `juist: the invite link is from an older juist; ask for a new one` | Update juist on the inviting device and start a new invite. |
