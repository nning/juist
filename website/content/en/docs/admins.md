---
title: Several admins
linkTitle: Several admins
description: Add admins and admin keys, set how many must approve a change, and approve the changes that wait for you.
lead: An admin is a person whose key approves changes to the network. With several admins, you decide how many of them must agree before a device joins, leaves or gets a role.
---

## Admins, keys and the quorum

Every change to the network, such as admitting a device, removing one or
giving it a role, is a record in the membership log. The log is the signed
list of every change, and every device checks it for itself
([How juist works]({{< relref "docs/how-it-works" >}})). A change takes
effect once enough admins have signed it.

An **admin** is a person. An **admin key** is the key that person signs with.
It lives in their keystore, `~/.config/juist`, as a file such as
`admins/alice@home.key`. An admin has one key on each device they approve
from. Never copy a key to another device; create a new one there instead.

The **quorum** is the number of votes a change needs. Each admin key has a
vote, but all of one person's keys together count as that person's votes
only once, whichever of them signs. Say alice, bob and carol are admins with
one vote each, and the quorum is 2. Then any two of them can approve a
change, so one of them can be on holiday, and none of them can change
anything on their own.

An admin is not the same as a voucher. A voucher is a device with the role
`voucher` that confirms every hour that the network's state is current. A
voucher holds no admin key.

## Approving from two laptops

Your admin name is what `juist create` printed on the `Admin` line, and what
`juist admins` lists. It is your login name, unless you gave `--admin-name`.
Use that name for the second laptop's key; under any other name, the key
becomes a second admin.

{{< step on="laptop2" as="your second laptop" >}}
Create a key under your admin name:

```sh
juist admins new alice
```

It prints the command that adds the key, with the key itself in it. The key
is long, since it carries its quantum-safe signing key too: copy the command
whole.
{{< /step >}}

{{< step on="laptop" as="your first laptop" >}}
Run that command exactly as printed:

```sh
juist admins add alice nid:… --on laptop2
```

It prints `added a key of alice's; 2 keys, 1 signing`.
{{< /step >}}

`juist admins` then lists which machine each key is on. A change waiting for
approval says where the keys that can approve it are.

## One key per network

Each network gets its own admin key, such as `admins/alice@home.key`. A lost
or stolen key then affects only one network, and no two networks' logs share
a key.

- A key from `juist admins new` is filed under the first network whose log
  names it. `juist admins new alice --network home` names the network right
  away.
- To govern a new network with a key you already have, say so:
  `juist create lab --admin-key alice@home`.
- `juist admins` lists the keys on this machine and the networks each one
  governs.
- On a machine in no network, `juist approve --key alice@home FILE` says which
  key signs.

## Two admins who must both agree

Say alice and bob each have two devices, and every change should need both
of them.

{{< step on="an admin's device" >}}
Add each of bob's keys, one per device. Bob creates them with
`juist admins new bob`, which prints the line to run:

```sh
juist admins add bob nid:…
```

Bob now has two keys, which share one vote.
{{< /step >}}

{{< step on="an admin's device" >}}
Make three always-on devices vouchers, require two of them to confirm that
the network's state is current, and require both admins for every change:

```sh
juist grant nas voucher
juist grant vps voucher
juist grant pi voucher
juist admins vouchers 2
juist admins quorum 2
```

`juist admins` now shows `Quorum  2 of 2 votes`.
{{< /step >}}

With `juist admins vouchers 2`, a voucher that lies about the network's
state cannot fool a device on its own; it would need an accomplice. In
return, two vouchers must be online. The third keeps that true while one is
down.

## One admin, two devices per change

Even as the only admin, you can require every change to be approved from
two of your devices:

```sh
juist admins require alice 2
```

Keep three keys for this. With exactly two, losing one device may lock the
network.

## When a change needs another admin

A change that needs someone else's vote waits for them on the network's
voucher devices. You see this when you make the change:

```console {device="laptop"}
$ juist remove phone
remove phone (198.18.36.4  fd77:9359:d9fb:bcb6:5fc:cc5c:f45d:c475) from "home"? [y/N] y
pending remove-phone.rec: needs 1 more vote, from bob on nas; another admin runs, on an admin device or with the file:
  juist approve
  juist approve remove-phone.rec
```

On bob's device, `juist status` hints
`1 change waits for your vote: juist approve`, and `juist health` names the
change. Bob approves it there:

```console {device="nas"}
$ juist approve
device removal, proposed by alice's key on laptop:
  removes the device phone (nid:A7Bu6lgr…)
approve? [y/N] y
signed as bob's key on nas
applied
```

`juist approve` asks about each change waiting for your vote. It works out
what the change does from the record and the log, never from the file name.
Once the change has enough votes, it takes effect on every device.

For waiting changes to reach an admin's devices, each admin runs
`juist admins receive` once. Whoever creates a network has already done so.
`juist admins receive` is itself a change, approved like any other.

## Change files

Each change is also saved as a file, such as `remove-phone.rec`, in the
directory you ran the command in. You can send it to another admin, who runs
this on a device in the network:

```sh
juist approve remove-phone.rec
```

It shows what the change does, asks for confirmation, signs the file in
place, and applies the change once it has enough votes. `juist apply` does
the same.

On a machine in no network, an admin can approve the admission of a device,
but nothing that may change who approves or vouches: a removal, a role, an
admin key, or the quorum. Only the log shows who such a change affects.

## Notes

- `juist admins` lists every admin with their votes and the machines their
  keys are on, as well as the quorum and the number of vouchers needed.
- `juist admins add NAME KEY --votes N` gives a key more than one vote.
  `juist create --admin-votes N` does the same for the key `juist create`
  makes.
- `juist admins remove NAME|KEY` takes a key's vote away. It is refused if
  the remaining keys cannot reach the quorum.
- `juist admins quorum` warns when every change needs every admin, since
  losing one admin's keys would then lock the network. If you set a quorum
  above 1 in a network without a voucher, it points out that changes waiting
  for votes travel through vouchers. `juist create --quorum` does the same.
- Admin keys leave their machine only as a backup line
  ([Keys]({{< relref "docs/keys" >}}#backing-up-admin-keys)). The machine
  holding them does not have to be in a network:
  `juist create --no-device` creates a network from a machine that only
  signs.
- Run admin commands as yourself, without sudo: the keys are in your
  keystore.
- `juist log` shows every change and who approved it, and `juist log show 3`
  what change 3 did.
- The [access policy]({{< relref "docs/access" >}}) is changed the same way.
  `juist approve policy.rec` shows the change as a diff against the current
  policy.
- When an update of juist adds to the network's log, the `Schema` line of
  `juist status` shows the network's schema and, in parentheses, this
  version's, as in `18 (19)`. On your device, `juist health` then hints
  `once every device runs this version: juist log upgrade`. `juist devices`
  shows which schema each device's juist implements. Once every device runs
  the new version, run `juist log upgrade`. From the upgrade on, devices on
  older versions apply no changes until they are updated: `juist health` on
  every other device names them, and `juist status` on them says so. Where
  one has no tunnel to a device, `juist devices` there shows it as
  `outdated`.
- juist reads networks whose log is at schema 18 or later, where every
  change is signed quantum-safe
  ([Security]({{< relref "docs/security" >}}#quantum-safe)). A network
  created with an older juist is read no more: its admins create it again,
  and its devices join the new one.

{{< note danger >}}
If so many admin keys are lost that no change can get the votes it needs,
the network is locked for good. The break-glass secret that `juist create`
shows can then only end it
([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).
Back up each admin key, and give the network more admins than the quorum
needs, each with their own devices ([Keys]({{< relref "docs/keys" >}}#backing-up-admin-keys)).
{{< /note >}}

## Troubleshooting

| You see | What to do |
|---|---|
| `hint: for changes waiting for your vote to reach you: juist admins receive` | run `juist admins receive` once |
| `juist health`: `hint: once every device runs this version: juist log upgrade` | update juist on every device, then run `juist log upgrade` |
| `juist: the network predates rotating an identity key` | update juist on every device, then run `juist log upgrade` |
| `--admin "bob": a key with no signing key, from an older juist` | bob runs `juist admins new bob` again with this version and sends the new line |
| `juist: the key names no signing key, which the network needs; it is from an older juist` | bob runs `juist admins new bob` with this version and sends the command it prints, whole |
| `hint: bob cannot read it on an admin device yet; send them the file` | send bob the `.rec` file; he runs `juist approve FILE` |
| `juist: no admin key of this network in …` | run the command where an admin's key is |
| `juist: run as alice, without sudo: …` | run it again without sudo |
| `….rec: outdated by a later change` | whoever started the change makes it again |
