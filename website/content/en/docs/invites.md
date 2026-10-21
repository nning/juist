---
title: Inviting devices
linkTitle: Inviting devices
description: Add a device to the network with a code or a link, compare the four words, and give it a role as it joins.
lead: An invite lets exactly one new device join the network. You run it on an admin's device, and the new device joins with the code or the link it prints.
---

## How an invite works

An **invite** is a short-lived secret that one new device uses to join the
network. `juist invite` prints it in two forms, a code and a link, and waits.
The new device runs `sudo juist join` with either.

Only an admin's device can invite, because admitting a device is a change to
the network that an admin has to sign. An **admin** is a person with a key
that signs changes; see [How juist works]({{< relref "docs/how-it-works" >}}).

Before anything is signed, both devices show four words for you to compare.
That is how you know that the device asking to join is the one you invited.

## Code or link

| | Code | Link |
|---|---|---|
| Looks like | `42-drumbeat-tolerance-glucose` | `'juist:Kx7…@192.168.1.20:41642'` |
| Works from | the same LAN only | anywhere |
| A wrong guess | voids the code | voids nothing |

The **code** is a number and three words, short enough to read aloud or type.
The number tells invites apart and is not secret; the three words are. The new
device finds the inviting device by asking on the LAN, then connects to it on
TCP port 41642. If a firewall on the inviting device might block that port,
`juist invite` prints the command that opens it, such as
`hint: the firewall may block the device: sudo ufw allow 41642/tcp`.

The code allows exactly one guess. After a wrong one, the inviting device
says `warning: code voided: wrong guess from …` and refuses the right code
too. The link still works.

The **link** holds a 128-bit secret, the inviting device's addresses, and the
inviting admin's key, which binds the new device to that admin's signature.
Copy it whole, including the quotes: it contains characters that a shell would
otherwise change.

In a terminal, `juist invite` also draws the link as a QR code, above the
`juist join` line for the link. A camera reads the QR code as the link
itself, without the command. The LAN code is printed last, so that it stays
visible even in a window shorter than the QR code. There is no QR code when
the output is not a terminal, or when the window is too narrow for it, in
which case juist says so, for example
`no qr code: the terminal is narrower than 59 columns`.

A phone joins by scanning the QR code with the
[Android app]({{< relref "docs/android" >}}), or by typing the code into it.

The code and the link both stop working when a device joins or the invite
expires. An invite lasts an hour unless you give `--expires`, such as
`--expires 2h`. The maximum is `7d`.

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

The words cover the new device's identity and all of its keys. If another
device has put itself between the two, the words differ. Each side commits to
its part of the words before it learns the other's, so a device in between
cannot search for a match.

If the words differ, answer `n`. The invite then signs nothing:
`juist: words not confirmed; nothing signed`. Start a new invite, and find out
which device tried to join.

`juist invite --yes` admits the device without comparing. Since that skips
the check, use it only where you could not compare anyway, such as in a
script.

## Inviting with a role

A **role** gives a device an extra job in the network. An invite can give the
new device a role as it joins:

| Option | The new device becomes |
|---|---|
| `--relay` | a relay, which passes traffic for devices that cannot reach each other ([Relays]({{< relref "docs/relays" >}})) |
| `--voucher` | a voucher, which confirms every hour that the network's state is current ([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)) |
| `--ingress` | an ingress, which takes connections from the internet for published names ([Publishing services]({{< relref "docs/publishing" >}})) |
| `--service NAME` | a service member that publishes `NAME` under the network's domain and cannot open connections to other devices ([Publishing services]({{< relref "docs/publishing" >}}#keeping-the-server-away-from-your-network)) |

To invite a VPS as the network's ingress:

```console
$ juist invite vps --ingress
invite to "home" as ingress, expires in 1h; on the new device:
```

An ingress cannot be a voucher, so `--ingress` and `--voucher` cannot be
combined. A service member has no other role, so `--service` cannot be
combined with any of the others. Other roles, such as `exit`, are granted
after joining with `juist grant`.

## Across NAT

The link works even when both devices are behind NAT in different places. The
new device first tries the addresses in the link. If it cannot reach them, the
two devices find each other through the public BitTorrent DHT, and the new
device says `no direct answer; meeting through the DHT (up to a minute)`.
Most of that minute is spent joining the DHT.

If the network has a relay and the inviting device is behind NAT, the invite
also waits at the relay, and the link includes the relay's address.
`juist invite` then says
`meets through relay 203.0.113.7:41645 where this device is unreachable`. The
relay never sees the invite's secret.

This fails only if both NATs are symmetric, that is, they pick a new port for
every destination. In that case, do one of these:

- join from an internet connection that can reach the inviting device;
- give the network a [relay]({{< relref "docs/relays" >}}) first, then invite
  again.

## Notes

- One invite admits one device. Run `juist invite` again for the next.
- `--no-lan` prints only the link, no code. `--no-dht` keeps the invite off
  the public DHT. `--port` picks a TCP port other than 41642.
- `sudo juist join` makes the user who ran sudo the device's
  [operator]({{< relref "docs/operator" >}}), the local user who manages it
  without sudo. `--operator` names a different user. `--name` sets the name
  the device joins under.
- If the network needs more than one admin's vote, the invite waits for the
  other admins, and the new device shows
  `waiting for approval (1 of 2 votes)`. The wait counts against the invite's
  lifetime.
- On a device in several networks, say which one: `juist invite work`.
- If the network has an [access policy]({{< relref "docs/access" >}}), it
  passes no traffic to or from the new device until a rule names it.
  `juist invite` points this out in a `hint:` line.

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
