---
title: Managing without sudo
linkTitle: Managing without sudo
description: Name the local user who manages a device, so that juist commands run without sudo.
lead: Each device can have one operator, a local user who may run every juist command on it without sudo. You set the operator once, as root.
---

## Who may do what

On each device, the daemon `juistd` does the work, and the `juist` command
sends it requests. The daemon decides who may ask for what:

| Who | May |
|---|---|
| root | everything, including choosing the operator |
| the operator | everything else: list devices, invite, approve, use an exit node, and so on |
| any other local user | only `juist status` |

The **operator** is the local user chosen for this device, usually you, the
person who uses it. Once there is an operator, you no longer type `sudo`
before each command.

Changes to the network itself, such as admitting or removing a device, also
need an admin key. An admin is a person whose key approves changes. Admin keys
live in your own keystore, `~/.config/juist`, so you run those commands as
yourself, not with sudo (see [Admins]({{< relref "docs/admins" >}})).

## Setting the operator

Usually there is nothing to do:

- `juist create`, run as yourself, asks once to run `sudo juist set` and makes you the operator.
- `sudo juist join …` makes the user who ran sudo the operator, unless `--operator` names another.

If the device has no operator yet, or you want to change it, set it by hand.

{{< step on="laptop" >}}
Make your user the operator:

```sh
sudo juist set --operator=$USER
```

It prints `operator alice`. From now on, every juist command works on this
device without sudo.
{{< /step >}}

To remove the operator:

```sh
sudo juist set --operator=""
```

It prints `operator cleared`.

## Notes

- Each device has one operator per network. Only root can choose it with
  `juist set --operator`. The operator may change the other `juist set`
  options, such as those for [networks that only pass HTTPS]({{< relref "docs/https-only" >}}).
- In a terminal, a command that needs the operator asks
  `not the operator; run sudo juist set --operator=alice? [Y/n]` and, if you
  agree, runs it.
- A few commands change the host itself and still ask for sudo once:
  `juist exit serve`, `juist subnet serve`, and creating or joining a
  [second network]({{< relref "docs/networks" >}}) on the same device.
- On a device in several networks, name the network:
  `sudo juist set work --operator=$USER`.
- `juist reset` forgets the operator along with the network.

## Troubleshooting

`juist status`, run by a user who is not the operator, ends with:

```console
$ juist status
…
hint: read-only; to manage this device: sudo juist set --operator=alice
```

Run that command once. If a command cannot ask, as in a script, it fails
with `juist: operator only` and the same hint.

See also [Status and devices]({{< relref "docs/status" >}}) and
[Troubleshooting]({{< relref "docs/troubleshooting" >}}).
