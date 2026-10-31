---
title: Updating juist
linkTitle: Updating juist
description: Install a new release on every device, and move the network to a new schema once all of them run it.
lead: To update juist, install the new release's package on each device. Some releases also bring a new format for the network's log; the network switches to it only when an admin runs juist log upgrade, after every device has the new release.
---

## Installing a new release

Install the new package the same way as the first one
([Install]({{< relref "docs/install" >}})). The device keeps its keys, its
networks and its settings.

{{< step on="a Debian or Ubuntu device" >}}
```sh
curl -LO https://github.com/nning/juist/releases/latest/download/juist_amd64.deb
sudo apt install ./juist_amd64.deb
```

The package restarts juistd, and `juist-ingress` and `juist-serve` where they
run. Fedora's `sudo dnf install` of the new RPM does the same.
{{< /step >}}
{{< step on="a FreeBSD device" >}}
As root, install the package, then restart the daemon yourself, since pkg
cannot:

```sh
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd15-amd64.pkg
service juistd restart
```

This restarts the daemons of every network on the device. Where they run,
restart `juist_ingress` and `juist_serve` too. Until then, the old daemons
keep running.
{{< /step >}}

Devices on different releases keep working together while the network stays
on its schema, so you can update them one at a time. On a phone, install the
new APK over the old one
([Android]({{< relref "docs/android" >}}#installing-the-app)).

## The schema

Every device checks every change in the network's log, so all of them have to
understand the format the changes are written in. That format is the
**schema**, and it has a number, such as 20 or 21. Each release of juist
implements one schema and reads the older ones down to 18.

A new release does not change the network's schema by itself. The network
stays on its schema until an admin raises it, so a device that has not been
updated yet keeps working.

When this device's release implements a newer schema than the network uses:

- the `Schema` line of `juist status` shows the network's schema and, in
  parentheses, this release's, as in `20 (21)`;
- on a device with an admin key, once every device's juist implements it,
  `juist health` adds `hint: every device implements schema 21: juist log upgrade`.

## Raising the schema

{{< step on="any device" >}}
Check that every device runs the new release. The `SCHEMA` column of
`juist devices` shows the newest schema each device's juist implements, in
yellow where it is older than this device's:

```console
$ juist devices
NAME                  IPV4         REACHED  SCHEMA  ROLES
laptop (this device)  198.18.36.1  -        21      -
nas                   198.18.36.2  direct   21      voucher
phone                 198.18.36.4  relayed  20      -
```

Here the phone still needs the new app. A `-` in place of a number means
juistd has heard nothing of that device yet: it has been off since it
joined, or its membership has expired.
{{< /step >}}
{{< step on="an admin's device" >}}
Raise the network's schema:

```console
$ juist log upgrade
warning: raising schema 20 to schema 21, which cannot be undone
continue? [y/N] y
upgraded to schema 21
```

As long as a device's juist does not implement the new schema, or juistd has
heard nothing of it, `juist log upgrade` changes nothing and names it:

```console
$ juist log upgrade
juist: not every device implements schema 21: phone (20)
hint: update them, or raise it anyway: juist log upgrade --force
```

`--force` raises the schema all the same, and the devices it names stop until
they are updated. juist learns each device's schema from juistd, so run the
command on a device of the network whose juistd is running.

Like any change, it needs the quorum's votes; with a quorum above one, it
waits for the other admins ([Several admins]({{< relref "docs/admins" >}})).
{{< /step >}}

## Raising it by itself

`juist log upgrade --when-ready` raises the schema without asking once every
device implements it, and until then does nothing and prints nothing;
`juist log upgrade` says which devices it waits for.

{{< step on="an admin's device" >}}
Run it from a timer as the user whose keystore holds the admin key, such as
daily from that user's crontab (`crontab -e`):

```
0 3 * * * juist log upgrade --when-ready
```

With a quorum above one, your vote alone does not raise the schema:
`--when-ready` then proposes nothing and fails, and you run
`juist log upgrade` yourself.
{{< /step >}}

## A device that missed the update

A device whose juist does not know the network's new schema stops applying
changes, a removal included, until it is updated. The other devices warn
about it in `juist health`:

```console
warning: nas runs an older juist, which applies no changes until updated
```

A device on an older release can also be cut off from traffic altogether:
the others send it nothing but the network's changes. `juist devices` shows
it as `outdated`, and `juist health` says
`nas runs an older juist, unreachable until updated`.

In both cases, install the new release on that device. It catches up with
the log by itself. The Android app stops following the network the same way
until it is updated.

## Good to know

- juist reads networks whose log is at schema 18 or later, where every change
  is signed quantum-safe ([Security]({{< relref "docs/security" >}}#quantum-safe)).
  A network created with an older juist cannot be read any more: its admins
  create it again, and its devices join the new one.
- `juist log` lists the upgrade as `schema upgrade`, with the admins who
  approved it. It cannot be undone.
- An invite between two devices on releases that do not understand each other
  fails with `the inviting device runs an incompatible version of juist`.
  Update both, then invite again.
- `juist version` prints the release this device runs, as `v0.23.0`; a build
  from between two releases prints the next one and its commit, as
  `v0.23.1-0.20261024075157-M23`. The app's About shows the same,
  without the `v`.
