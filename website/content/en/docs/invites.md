---
title: Inviting devices
linkTitle: Inviting devices
description: Add a device to the network with a code or a link, compare the four words, and give it a role as it joins.
lead: An invite lets exactly one new device join the network. You run it on an admin's device, and the new device joins with the code or the link it prints.
---

## What it is

An **invite** is a short-lived secret that one new device uses to join the
network. `juist invite` prints it in two forms, a code and a link, and waits.
The new device runs `sudo juist join` with either.

Only an admin's device can invite, since admitting a device is a change to the
network that an admin signs. An **admin** is a person with a key that signs
changes; see [How juist works]({{< relref "docs/how-it-works" >}}).

Before anything is signed, both devices show four words, and you compare them.
That is how you know the device that asks is the one you invited.

## Code or link

| | Code | Link |
|---|---|---|
| Looks like | `42-drumbeat-tolerance-glucose` | `'juist:Kx7…@192.168.1.20:41642'` |
| Works from | the same LAN only | anywhere |
| A wrong guess | voids the code | voids nothing |

The **code** is a number and three words, short enough to read aloud or type.
The number tells invites apart and is not secret; the three words are. The new
device finds the inviting one by asking the LAN. The inviting device takes it
on TCP port 41642, which a firewall on it may have to let in; `juist invite`
then prints the command that opens it, such as
`hint: the firewall may block the device: sudo ufw allow 41642/tcp`.

The code allows exactly one guess. After a wrong one, the inviting device
says `warning: code voided: wrong guess from …` and refuses the right code
too. The link still works then.

The **link** holds a 128-bit secret, the inviting device's addresses, and the
inviting admin's key, which binds the new device to that admin's signature.
Copy it whole, with its quotes, since it contains characters a shell would
otherwise change.

In a terminal, `juist invite` also draws the link as a QR code, above the
`juist join` line; a camera reads it as the link's text, without the
command. The code is left out where the output is not a terminal, and in a
window too narrow for it, which says so:
`no qr code: the terminal is narrower than 59 columns`.

A phone joins by scanning the QR code with the
[Android app]({{< relref "docs/android" >}}), or by typing the code into it.

Both end when a device joins or the invite expires. An invite lasts an hour
unless you give `--expires`, such as `--expires 2h`; the longest is `7d`.

## Inviting a device

{{< step on="an admin's device" >}}
Start the invite. Name the new device here if it should not keep its own name:

```sh
juist invite nas
```

Without a name, the device keeps its host name. A name another member already
uses gets a number added.
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

The words cover the new device's identity and every one of its keys. If
another device has put itself between the two, it shows other words. Each
side fixes its part of the words before it learns the other's, so a device in
between cannot search for a match.

If the words differ, answer `n`. The invite then signs nothing:
`juist: words not confirmed; nothing signed`. Start a new invite, and find out
which device asked.

`juist invite --yes` admits without comparing. Use it only where you could not
compare anyway, such as in a script, since it gives up that check.

## Inviting with a role

A **role** gives a device one more job in the network. An invite can admit the
new device with one at once:

| Option | The new device becomes |
|---|---|
| `--relay` | a relay, which passes traffic for devices that cannot reach each other ([Relays]({{< relref "docs/relays" >}})) |
| `--voucher` | a voucher, which confirms every hour that the network's state is current ([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)) |
| `--ingress` | an ingress, which takes connections from the internet for published names ([Publishing services]({{< relref "docs/publishing" >}})) |
| `--service NAME` | a service member publishing `NAME` under the network's domain, which every device keeps from opening connections ([Publishing services]({{< relref "docs/publishing" >}}#keeping-the-server-away-from-your-network)) |

For a VPS that is to be the network's ingress:

```console
$ juist invite vps --ingress
invite to "home" as ingress, expires in 1h; on the new device:
```

An ingress cannot be a voucher, so `--ingress` and `--voucher` do not go
together, and a service member holds no other role: `--service` goes with
none of the others. Other roles, such as `exit`, are given after joining with
`juist grant`.

## Across NAT

The link works when both devices sit behind NAT in different places. The new
device first tries the link's addresses. Where it cannot reach them, the two
meet through the public BitTorrent DHT, and the new device says
`no direct answer; meeting through the DHT (up to a minute)`. That minute is
mostly spent joining the DHT.

Where the network has a relay, an invite on a device behind NAT also waits at
the relay, and the link names it. `juist invite` then says
`meets through relay 203.0.113.7:41645 where this device is unreachable`. The
invite's secret never reaches the relay.

Meeting fails where both NATs are symmetric, which means they pick a new port
for every destination. Then do one of these:

- join from an internet connection that can reach the inviting device;
- give the network a [relay]({{< relref "docs/relays" >}}) first, then invite
  again.

## Good to know

- One invite admits one device. Run `juist invite` again for the next.
- `--no-lan` prints no code, only the link. `--no-dht` keeps the invite off
  the public DHT. `--port` picks another TCP port than 41642.
- `sudo juist join` makes the user who ran sudo the device's
  [operator]({{< relref "docs/operator" >}}), the local user who manages it
  without sudo, unless `--operator` names another. `--name` gives the name to
  join as.
- Where the network needs more than one admin's vote, the invite waits for
  the other admins, and the new device shows
  `waiting for approval (1 of 2 votes)`. The wait counts against the invite's
  lifetime.
- On a device in several networks, say which one: `juist invite work`.
- Under an [access policy]({{< relref "docs/access" >}}), the new device is
  passed nothing until a rule names it, and `juist invite` says so in a
  `hint:` line.

## If something goes wrong

| What you see | What to do |
|---|---|
| `juist: no admin key of this network here` | Invite from an admin's device. |
| `warning: code not announced on the LAN (…); use the link` | Join with the link. |
| `warning: code voided: …` | Join with the link. If that was not your device, someone else knows this invite. |
| `juist: invite expired` | Start a new invite, with a longer `--expires` if the wait was for other admins. |
| `juist: cannot reach the inviting device, …` | Check that the invite still runs. If both devices are behind NAT, join from an internet connection that can reach the inviting device, or add a relay first. |
| `juist: comparing the device's words needs a terminal; pass --yes to skip` | Run `juist invite` in a terminal, or pass `--yes` where you cannot compare. |
