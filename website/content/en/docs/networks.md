---
title: Several networks
linkTitle: Several networks
description: Put one device in several networks at the same time, and tell juist which one a command is for.
lead: A device can be in more than one network at the same time, such as a home network and a work network. Each network runs alongside the others, with its own daemon, address and keys.
---

## One juistd per network

Your laptop may belong to your home network and to your team's network, with
different admins, devices and rules. juist keeps them apart by giving each
network its own juistd.

The first network runs in `juistd.service`, each further one in a numbered
instance: `juistd@juist1`, `juistd@juist2`, and so on. Each instance has its
own network device (`juist0`, `juist1`, …), state directory and ports, and
runs as its own user (`juist`, `juist1`, …), so that one network's juistd
cannot read another's keys.

## Joining or creating a second network

{{< step on="laptop" as="a device already in home" >}}
Join the other network with the link from its invite, as for the first one:

```sh
sudo juist join 'juist:…'
```

The new network, say `work`, runs alongside `home`. To create a network of
your own instead, `juist create work` works the same way. Run without sudo,
`juist` asks for sudo once to start the new juistd.
{{< /step >}}

{{< step on="laptop" >}}
Check both:

```sh
juist status
juist devices
```

`juist status` shows both networks one after the other, each under a heading
with its juistd. `juist devices` lists the devices of all networks.
{{< /step >}}

## Choosing the network

A command that applies to one network takes it as its first argument, either
by the network's name or by the name of its juistd:

```sh
juist devices work                      # by name
juist devices juist1                    # by juistd
juist invite work                       # with several networks, say which
juist network renumber work 10.7.0.0/24
```

If the device is in only one network, you can leave the name out.

`--network NAME` does the same for any command. So does the environment
variable `$JUIST_NETWORK`, except for `juist create`, `juist join` and
`juist admins new`.

Commands that list things show every network when you don't name one:
`status`, `health`, `devices`, `network`, `admins`, `names`, `exit`,
`subnet` and `publish`. Any other command does not ask which network you
mean; it stops and lists them:

```console
$ juist invite
juist: this device is in 2 networks: home (juist0), work (juist1)
hint: name one first: juist invite home [NAME]
```

If a command has an optional argument of its own, the network's name comes
before it. To invite a device named `home` into the network `home`, run
`juist invite home home`.

## Overlapping address ranges

Two networks may use overlapping IPv4 ranges. Both still work on the same
device, but the one with the higher-numbered juistd runs over IPv6 only.
`juist health` says so, and suggests which one to renumber:

```console
$ juist health
home
nothing needs attention

work
warning: no IPv4 on this host: "home" (juist0) holds 198.18.36.2, which "work" claims too (198.18.36.0/22)
hint: renumber one of the two networks: juist network renumber juist1 PREFIX, or the other
```

Once one of them is [renumbered]({{< relref "docs/network-changes" >}}), IPv4
comes back by itself.

## One admin key per network

Each network gets its own admin key, such as `admins/alice@home.key` and
`admins/alice@work.key`, so a lost key affects only one network. To manage a
new network with a key you already have, name it:
`juist create lab --admin-key alice@home`
([Several admins]({{< relref "docs/admins" >}})).

## Leaving one network

```sh
juist reset work --force
```

This leaves `work` and removes its juistd. `home` stays as it is, with its
keys. `--force` is needed while `work` still lists this device. Where you can,
remove the device from `work` first ([Removing a device]({{< relref "docs/remove" >}})).

## Good to know

- One host runs at most ten juistds: `juistd.service` and `juistd@juist1` to
  `juistd@juist9`.
- The n-th juistd's ports are the first one's plus 10·n: 41653/udp for
  `juistd@juist1`, and log sync on TCP 41654 on `juist1`. The packages'
  firewall profiles cover only the first network's ports; `juist status` shows
  the others ([Relays, ports and firewalls]({{< relref "docs/relays" >}})).
- If the second network's juistd is not running, start it with
  `sudo systemctl enable --now juistd@juist1`. `journalctl -u juistd@juist1`
  shows its log. On FreeBSD, the rc.conf variable `juistd_instances` lists the
  instances, and `service juistd start juist1` starts one.
- A device can be in a network only once. An invite does not say which
  network it is for, so a second join to the same network is admitted first.
  The new juistd then refuses the network and names the admission an admin
  should remove.
- A device in several networks sends its internet traffic through the
  [exit node]({{< relref "docs/exit-nodes" >}}) of only one of them.
- Members of one network may learn this host's addresses in its other
  networks, and so which address ranges those use.

