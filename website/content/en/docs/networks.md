---
title: Several networks
linkTitle: Several networks
description: Put one device in several networks at once, and tell juist which one a command is about.
lead: A device can be in more than one network at the same time, such as a home network and a work one. Each network runs beside the others, with its own daemon, address and keys.
---

## What it is

Your laptop may belong to your home network and to your team's network. The
two have different admins, different devices and different rules. juist keeps
them apart on the laptop: each network has a juistd of its own. juistd is the
daemon, the background service that keeps the tunnels
([How juist works]({{< relref "docs/how-it-works" >}})).

The first network runs in `juistd.service`. Each further one runs in a
numbered instance beside it: `juistd@juist1`, `juistd@juist2`, and so on.
Each has its own network device (`juist0`, `juist1`, …), its own state
directory and its own ports.

## Joining or creating a second network

{{< step on="laptop" as="a device already in home" >}}
Join the other network with the link from its invite, as for the first one:

```sh
sudo juist join 'juist:…'
```

The new network, say `work`, runs beside `home`. `juist create work` works
the same way for a network of your own. Without sudo, `juist` asks for sudo
once, to start the new juistd.
{{< /step >}}

{{< step on="laptop" >}}
Check both:

```sh
juist status
juist devices
```

`juist status` shows both networks, one after the other, each headed by its
juistd. `juist devices` lists every network's devices.
{{< /step >}}

## Telling juist which network you mean

A command about one network takes it as its first argument, by name or by
its juistd's name:

```sh
juist devices work                      # by name
juist devices juist1                    # by juistd
juist invite work                       # with several networks, say which
juist network renumber work 10.7.0.0/24
```

Where the device is in one network only, you can leave the name out.

`--network NAME` does the same for any command, and so does the environment
variable `$JUIST_NETWORK`.

The listings `status`, `devices`, `network` and `admins` show every network
when you name none. Any other command stops, rather than ask which network you
mean, and names them:

```console
$ juist invite
juist: this device is in 2 networks: home (juist0), work (juist1)
hint: name one first: juist invite home [NAME]
```

Where a command's own argument is optional, the network's name comes first.
To invite a device named `home` into the network `home`, run
`juist invite home home`.

## Overlapping address ranges

Two networks may use IPv4 ranges that overlap. Both still work on one device:
the one in the higher-numbered juistd runs over IPv6 only. `juist status`
says so, and which one to renumber:

```console
$ juist status
…
warning: no IPv4 on this host: "home" (juist0) holds 198.18.36.2, which "work" claims too (198.18.36.0/22)
hint: renumber one of the two networks: juist network renumber juist1 PREFIX, or the other
```

Once one of them is [renumbered]({{< relref "docs/network-changes" >}}), IPv4
comes back by itself.

## Each network has its own admin key

An admin key is the key an admin signs changes with. Each network gets one of
its own, such as `admins/alice@home.key` and `admins/alice@work.key`. A lost
or stolen key then costs one network only. To govern a new network with a key
you already have, say so: `juist create lab --admin-key alice@home`. More is
in [Several admins]({{< relref "docs/admins" >}}).

## Leaving one network

```sh
juist reset work --force
```

This leaves `work` and removes its juistd. `home` stays as it is, with its
keys. `--force` is needed while `work` still lists this device; where you can,
remove the device there first ([Keys]({{< relref "docs/keys" >}})).

## Good to know

- One host runs at most ten juistds: `juistd.service` and `juistd@juist1` to
  `juistd@juist9`.
- The n-th juistd's ports are the first one's plus 10·n: 41653/udp for
  `juistd@juist1`, and log sync on TCP 41654 on `juist1`. The firewall
  profiles the packages install name the first network's ports; `juist status`
  gives the others' ([Relays, ports and firewalls]({{< relref "docs/relays" >}})).
- When the second network's juistd is not running, start it with
  `sudo systemctl enable --now juistd@juist1`; `journalctl -u juistd@juist1` shows
  its log.
- On FreeBSD, the other networks' instances are listed in the rc.conf variable
  `juistd_instances`, and `service juistd start juist1` starts one.
- A device can be in the same network only once. An invite does not say
  which network it is for, so joining one again is admitted first. The new
  juistd then refuses the network, and says which admission an admin should
  remove.
- A device in several networks sends its internet traffic through
  [an exit node]({{< relref "docs/exit-nodes" >}}) of one network only.
- Every juistd runs as the same user, `juist`. One that is taken over holds
  the device keys of every network on the host.
- A network's members may learn this host's addresses in its other networks,
  and with them which ranges it is in.
