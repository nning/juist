---
title: Several admins
linkTitle: Several admins
description: Add admins and admin keys, set how many must approve a change, and approve the changes that wait for you.
lead: An admin is a person whose key approves changes to the network. With several admins, you decide how many of them must agree before a device joins, leaves or gets a role.
---

## What it is

Every change to the network, such as admitting a device, removing one or
giving it a role, is a record in the membership log. The log is the signed
list of every change, and every device checks it for itself
([How juist works]({{< relref "docs/how-it-works" >}})). A change counts once
enough admins have signed it.

An **admin** is a person. An **admin key** is the key that person signs with.
It lives in their keystore, `~/.config/juist`, as a file such as
`admins/alice@home.key`. An admin holds one key on each device they approve
from. Never copy a key to another device; create a new one there instead.

The **quorum** is how many votes a change needs. Each admin key has a vote,
and a person's keys cast that person's votes once, whichever of them signs.
Say alice, bob and carol are admins with one vote each, and the quorum is 2.
Then any two of them can approve a change, and one of them can be on holiday.
One of them alone can change nothing.

An admin is not the same as a voucher. A voucher is a device with the role
`voucher` that confirms every hour that the network's state is current. A
voucher holds no admin key.

## Approving from both of your laptops

Your admin name is what `juist create` printed on the line `Admin`, and what
`juist admins` lists. It is your login name, unless you gave `--admin-name`.
Use that name for the second laptop's key; under any other name the key
becomes a second admin.

{{< step on="laptop2" as="your second laptop" >}}
Create a key under your admin name:

```sh
juist admins new alice
```

It prints the command that adds the key, with the key itself in it.
{{< /step >}}

{{< step on="laptop" as="your first laptop" >}}
Run the command as printed:

```sh
juist admins add alice nid:… --on laptop2
```

It prints `added a key of alice's; 2 keys, 1 signing`.
{{< /step >}}

`juist admins` then lists which machine each key is on. A change that waits
for approval says where the keys are that can give it.

## One key per network

Each network gets an admin key of its own, such as `admins/alice@home.key`.
A lost or stolen key then costs one network, and two networks' logs share no
key.

- A key from `juist admins new` is filed under the first network whose log
  names it. `juist admins new alice --network home` names the network at once.
- To govern a new network with a key you already have, say so:
  `juist create lab --admin-key alice@home`.
- `juist admins` lists the keys on this machine and the networks each one
  governs.
- On a machine in no network, `juist approve --key alice@home FILE` says which
  key signs.

## Two admins, and neither decides alone

Say alice and bob each have two devices, and every change should need both of
them.

{{< step on="an admin's device" >}}
Add each of bob's keys, once for each device of his. Bob creates them with
`juist admins new bob`, which prints the line to run:

```sh
juist admins add bob nid:…
```

Bob now holds two keys, which cast one vote between them.
{{< /step >}}

{{< step on="an admin's device" >}}
Make three devices that are always on vouchers, require two of them to
confirm that the network's state is current, and both admins for every
change:

```sh
juist grant nas voucher
juist grant vps voucher
juist grant pi voucher
juist admins vouchers 2
juist admins quorum 2
```

`juist admins` now shows `Quorum  2 of 2 votes`.
{{< /step >}}

With `juist admins vouchers 2`, one voucher that lies about the network's
state cannot fool a device alone. It needs one accomplice. Two vouchers must
then be online, which the third keeps true while one is down.

## Alone, with two devices for every change

You can also be the only admin and still want every change to need two of
your devices:

```sh
juist admins require alice 2
```

Hold three keys for that. With exactly two, losing one device may lock the
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

On bob's device, `juist status` says
`1 change waits for your vote: …`. Bob approves it there:

```console {device="nas"}
$ juist approve
device removal, proposed by alice's key on laptop:
  removes the device phone (nid:A7Bu6lgr…)
approve? [y/N] y
signed as bob's key on nas
applied
```

`juist approve` asks about each change waiting for your vote. It shows what
the change does from the record and the log, never from the file's name.
Once the change has its votes, it applies on every device.

For a waiting change to reach an admin's devices, each admin runs
`juist admins receive` once. The founder of a new network already has. It is
a change like any other.

## Change files

The change is saved as a file too, such as `remove-phone.rec`, in the
directory you ran the command in. You can send it to an admin, who runs on a
device in the network:

```sh
juist approve remove-phone.rec
```

It shows what the change does, asks, signs the file in place, and applies the
change once it is complete. `juist apply` does the same.

On a machine in no network, an admin can approve the admission of a device.
They cannot approve anything that may change who approves or vouches: a
removal, a role, an admin key, or the quorum. Only the log says whom such a
change touches.

## Good to know

- `juist admins` lists every admin, their votes, the machines their keys are
  on, the quorum and the vouchers needed.
- `juist admins add NAME KEY --votes N` gives a key more than one vote.
  `juist create --admin-votes N` does the same for the key `juist create`
  makes.
- `juist admins remove NAME|KEY` takes a key's vote away. It is refused if
  the rest cannot reach the quorum.
- `juist admins quorum` warns when every change needs every admin, since then
  losing one admin's keys locks the network. Above 1 in a network with no
  voucher, it says that changes waiting for votes travel through vouchers, as
  `juist create --quorum` does.
- Admin keys leave their machine only as a backup line
  ([Keys]({{< relref "docs/keys" >}}#backing-up-admin-keys)), and that machine
  needs no network of its own. `juist create --no-device` makes a network from a machine that
  only signs.
- Run admin commands as yourself, without sudo: the keys are in your
  keystore.
- `juist log` shows every change and who approved it.
- After juist is updated, `juist status` on your device says
  `the network is at schema 9, this version at schema 10` when this version
  adds to the network's log. Once every device runs it, run
  `juist log upgrade`. Devices on older versions stop applying changes at
  the upgrade until they are updated.

{{< note danger >}}
Losing every key of the admins a change needs locks the network for good.
The break-glass secret `juist create` shows only ends it
([Ending the network]({{< relref "docs/network-changes" >}}#ending-the-network)).
Back each admin key up, and give the network more admins than the quorum
needs, each on devices of their own ([Keys]({{< relref "docs/keys" >}}#backing-up-admin-keys)).
{{< /note >}}

## If something goes wrong

| You see | What to do |
|---|---|
| `hint: for changes waiting for your vote to reach you: juist admins receive` | run `juist admins receive` once |
| `hint: once every device runs this version: juist log upgrade` | update juist on every device, then run `juist log upgrade` |
| `hint: bob cannot read it on an admin device yet; send them the file` | send bob the `.rec` file; he runs `juist approve FILE` |
| `juist: no admin key of this network in …` | run the command where an admin's key is |
| `juist: run as alice, without sudo: …` | run it again without sudo |
| `….rec: outdated by a later change` | whoever started the change makes it again |
