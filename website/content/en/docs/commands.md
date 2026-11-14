---
title: Commands
linkTitle: Commands
description: Every juist command with its arguments and options, as its own help gives them.
lead: Every juist command with its options. On the device, juist COMMAND --help and man juist say the same.
---

This page is generated from juist's help as it reads on Linux. On FreeBSD,
juistd sets up the host for exit nodes and subnet routes itself, with its own
pf rules. Options go before or after a command's arguments. If the device is
in several networks, a command about one network takes the network's name
first ([Several networks]({{< relref "docs/networks" >}})).

## Getting started

### `juist create [NETWORK]`

Create a network with this device as its first member. NETWORK defaults to two random words. A device already in a network runs the new one in its own juistd.

Use \-\-voucher only on a device that is always on: if it is off for 48 hours, the other devices reach only vouchers.

Your admin key (new, or \-\-admin-key), the \-\-admin keys and \-\-quorum decide who may change the network. Losing the admin keys loses the network.

- `-a, --admin NAME=KEY[:VOTES]`: another admin, as NAME=KEY\[:VOTES]; repeatable
- `-K, --admin-key NAME`: use the existing admin key NAME (see juist admins)
- `-u, --admin-name NAME`: your admin NAME (default: user name or \-\-admin-key)
- `-v, --admin-votes N`: votes of your admin key (default 1)
- `-n, --device NAME`: this device's NAME (default: hostname)
- `-4, --ipv4 PREFIX`: IPv4 PREFIX, such as 10.111.0.0/24 (default: a free /22 in 198.18.0.0/15)
- `-N, --no-device`: create without this device, for a signing-only machine
- `-o, --operator USER`: local USER who manages this device without sudo
- `-q, --quorum N`: votes a change needs (default 1)
- `-r, --relay`: make this device a relay
- `-V, --voucher`: make this device a voucher
- `-y, --yes`: do not ask

### `juist invite [NETWORK] [NAME]`

Invite one device and wait until it joins. Prints a code for the same LAN, and a link and QR code for anywhere; behind NAT the devices meet through the public BitTorrent DHT. Both end when a device joins or the invite expires. A wrong guess voids the code; the link still works.

NAME is the device's name in the network (default: its own). Where more admins must approve, the invite waits for them.

- `-e, --expires DURATION`: invite lifetime DURATION, like 30m, 2h or 7d (default 1h)
- `-i, --ingress`: make the device an ingress
- `-d, --no-dht`: do not meet through the public DHT
- `-l, --no-lan`: no code on the LAN; link only
- `-p, --port N`: TCP port to listen on (default 41642)
- `-r, --relay`: make the device a relay
- `-S, --service NAME`: make the device a service member publishing NAME
- `-V, --voucher`: make the device a voucher
- `-y, --yes`: admit without comparing words

### `juist join CODE`

Join a network with the code or link juist invite printed, such as 42-drumbeat-tolerance-glucose. Under sudo, on a device without an operator, the sudo user becomes its operator, unless \-\-operator names another. A device already in a network runs the new one in its own juistd.

- `-n, --name NAME`: NAME to join as (default: hostname)
- `-o, --operator USER`: local USER who manages this device without sudo

## Devices

### `juist status [NETWORK]`

Show this device's network and how many devices it reaches, for every network if the device is in several. Any local user may run it. juist health says what needs attention.

- `-d, --devices`: list the devices too
- `-v, --verbose`: name the relay of each relayed device

### `juist health [NETWORK]`

Say what needs attention on this device, and which devices it does not reach, for every network if the device is in several.

### `juist devices [NETWORK]`

List the network's devices and how juistd last reached each. SCHEMA is the newest schema a device's juist implements, yellow if older than this one's. On a device in several networks, it lists each network unless NETWORK names one.

- `-a, --all`: list the devices the access policy keeps apart too
- `-6, --ipv6`: show IPv6 addresses
- `-k, --keys`: show identity keys

### `juist remove [NETWORK] DEVICE`

Remove a device, by name, address or key (juist devices \-\-keys), and rotate the group secret. Devices drop its tunnel once they hear of it, at the latest when their freshness expires.

- `-y, --yes`: do not ask

### `juist rename [NETWORK] DEVICE NAME`

Rename a device, by name, address or key. DEVICE.NETWORK.juist and its share name change with it. Keys, addresses, roles and public names stay.

### `juist rotate [NETWORK] [identity|group-secret|abandon]`

Replace keys.

```
  juist rotate                 this device's WireGuard and sealing keys;
                               name and addresses stay
  juist rotate identity        this device's identity key; its IPv6 moves
  juist rotate group-secret    the network's group secret, after a leak
  juist rotate abandon         drop a rotation awaiting approval
```

### `juist exit`

Send this device's internet traffic through another device, or serve as one.

```
  juist exit                the exit nodes, and the one in use
  juist exit use DEVICE     send internet traffic through DEVICE
  juist exit off            send it directly again
  juist exit serve          carry the network's internet traffic;
                            sets the host up with sudo where needed
  juist exit serve --stop   stop, and undo that
```

An admin makes a device an exit node: juist grant DEVICE exit. It carries traffic to public addresses and DNS (but not the LAN's domain where systemd-resolved runs); the LAN stays direct. If the exit node cannot be used, traffic is refused, not sent directly.

### `juist exit use [NETWORK] DEVICE`

Send this device's internet traffic and DNS through DEVICE. The LAN, the network, and answers to connections from the internet (such as ssh) stay direct; \-\-isolate sends those through DEVICE too, unless that would end the ssh session it runs in. If DEVICE cannot carry the traffic, it is refused, not sent directly. \-\-force uses a DEVICE that does not serve yet, or ends the session anyway.

- `-f, --force`: use it even if it does not serve, or ends this ssh session
- `-i, --isolate`: send answers to connections from the internet through it too

### `juist exit off [NETWORK]`

Send this device's internet traffic directly again.

### `juist exit serve [NETWORK]`

Carry the network's internet traffic, if an admin made this device an exit node. Sets up forwarding and the firewall with sudo where needed. \-\-stop stops and undoes it.

- `-S, --stop`: stop serving

### `juist subnet`

Reach networks behind a device, or route this device's for the others.

```
  juist subnet                           the subnets, and which this device uses
  juist subnet add DEVICE PREFIX...      have DEVICE route PREFIX for every member
  juist subnet remove DEVICE PREFIX...   take PREFIX from DEVICE
  juist subnet serve                     route what the network grants this device;
                                         sets the host up with sudo where needed
  juist subnet serve --stop              stop, and undo that
  juist subnet off                       reach none of them through the network
  juist subnet on                        reach them again
```

An admin adds a subnet, such as 192.168.1.0/24, to a device, and its operator agrees to route it: juist subnet serve. Members then reach the subnet through that device, unless they have their own route to it, as on its LAN.

### `juist subnet add [NETWORK] DEVICE PREFIX...`

Have a device route subnets, such as 192.168.1.0/24, for every member, once its operator agrees: juist subnet serve.

### `juist subnet remove [NETWORK] DEVICE PREFIX...`

Take subnets from a device.

### `juist subnet serve [NETWORK]`

Route the subnets the network grants this device, for the other members. Sets up forwarding and the firewall with sudo where needed. \-\-stop stops and undoes it.

- `-S, --stop`: stop routing

### `juist subnet off [NETWORK]`

Stop reaching the subnets through the network; the host's own routes apply. juist subnet on undoes it.

### `juist subnet on [NETWORK]`

Reach the subnets through the network again.

### `juist names`

Point public names at devices, for members to reach through the tunnel.

```
  juist names                         list the names and how this device resolves them
  juist names add DEVICE NAME...      point NAME at DEVICE
  juist names remove DEVICE NAME...   take NAME from DEVICE
  juist names on                      resolve public names to their devices here
  juist names off                     resolve them publicly again
```

On Linux, FreeBSD and macOS, every device is DEVICE.NETWORK.juist to the others. A public name such as mail.example.org resolves to its device where names are on, and publicly elsewhere or while its device is out of reach.

### `juist names add [NETWORK] DEVICE NAME...`

Point public names such as mail.example.org at a device. Devices with juist names on resolve them to it.

### `juist names remove [NETWORK] DEVICE NAME...`

Take public names from a device.

### `juist names on [NETWORK]`

Resolve the network's public names to their devices, through the tunnel, on this device. juist names off undoes it.

### `juist names off [NETWORK]`

Resolve the network's public names publicly again, as without juist.

### `juist publish [NETWORK] [NAME] [PORT|HOST:PORT|status-page]`

Publish services on the internet through an ingress, or list them.

```
  juist publish                           list the published names
  juist publish NAME PORT|HOST:PORT       publish NAME here; juist ends TLS
  juist publish NAME status-page          publish the network's status page
  juist publish NAME [PORT] --on DEVICE   publish NAME on DEVICE, whose
                                          service on PORT (443) ends TLS
  juist publish NAME                      serve what is published here
  juist publish PORT                      publish PORT under this device's name
  juist publish --stop [NAME|PORT]        stop publishing; alone, stop serving
```

NAME is a name under the network's domain, such as docs, the domain itself, or a full name whose DNS points at the ingresses, such as photos.example.org. Publishing a name takes an admin key; without one, juist prints the admin's command. PORT needs the publish role and lasts until Ctrl-C, \-\-for or \-\-stop.

- `-b, --background`: publish PORT in the background
- `-t, --for DURATION`: publish PORT for DURATION, like 2h or 7d
- `-2, --http2`: offer HTTP/2; the service speaks it without TLS (h2c)
- `-3, --http3`: offer HTTP/3 too
- `-m, --members`: for members only, not the internet; =false makes it public
- `-o, --on DEVICE`: publish on DEVICE, whose service ends TLS
- `-P, --proxy`: send the client address in a PROXY protocol v2 header
- `-W, --public WHAT`: WHAT non-members see of the status page: none, services, network or all (default services)
- `-S, --stop`: stop publishing NAME or PORT; alone, stop serving
- `-T, --tcp[=PORT]`: publish by TCP on PORT of every ingress, default the device's port

### `juist share [NETWORK] [FILE|DIR] | --stop [FILE|DIR|PORT|URL]`

Share FILE or DIR read-only on the internet, under this device's name and a random path, until Ctrl-C, \-\-for or juist share \-\-stop. A directory is listed and downloads as a ZIP. Without FILE or DIR, list the shares, juist publish PORT included. Needs the publish role.

- `-b, --background`: share in the background
- `-t, --for DURATION`: share for DURATION, like 2h or 7d
- `-S, --stop`: stop the named share, or the only one

### `juist ingress`

Take connections from the internet for published names.

```
  juist ingress                  what this ingress serves
  juist ingress serve [--stop]   serve as the network's ingress
```

An ingress is a device with a public address and the ingress role (juist grant DEVICE ingress). It passes each connection, by name or TCP port, through the tunnel to the device that publishes it, without ending TLS.

### `juist ingress serve [NETWORK]`

Serve as the network's ingress: run the juist-ingress service on 443, 443/udp (HTTP/3), 80 and the published TCP ports, and open them in firewalld or ufw. \-\-stop undoes it.

- `-S, --stop`: stop serving

### `juist reset [NETWORK]`

Forget the network on this device: keys, log, peers and operator, as on a fresh install. Admin keys stay. If the network still lists the device, remove it first, or use \-\-force. With several networks, only the named one is forgotten, with its juistd unless that is the default.

- `-f, --force`: reset even if the network still lists this device
- `-y, --yes`: do not ask

## Administration

### `juist grant [NETWORK] DEVICE ROLE...`

Give a device roles. Roles:

```
  exit     carries others' internet traffic once its operator agrees:
           juist exit serve
  ingress  takes connections from the internet for published names; for a
           device with a public address and no other role
  service  a service member (juistd --serve beside a service); no device
           may open a connection to it
  publish  shares and publishes under its own name without a vote each time
  relay    relays between devices that cannot reach each other; best on
           two or more devices with public addresses
  voucher  confirms hourly that the network state is current; if too few do
           for 48 hours, devices reach only vouchers. For devices that are
           always on. Not an admin key.
```

A phone can only be a voucher, once the network runs schema 20 or later and this device has heard from it.

### `juist revoke [NETWORK] DEVICE ROLE...`

Take roles from a device: exit, ingress, service, publish, relay or voucher. juist grant \-\-help says what each does.

- `-y, --yes`: do not ask

### `juist policy`

Set which device may open what on which other. Without a policy, every device may open anything on every other.

```
  juist policy                                the network's policy
  juist policy edit                           change it in $EDITOR
  juist policy set FILE                       make FILE the policy, - for standard input
  juist policy diff FILE                      how FILE differs from the policy
  juist policy check FILE                     check FILE against the network and run its tests
  juist policy test from DEVICE to DEST ...   whether the policy passes it, and by which rule
  juist policy fmt [FILE...]                  print FILE in canonical form
  juist policy off                            withdraw it
```

A policy lists what devices may open, in pf's syntax; everything else is refused:

```
  table <staff> { laptop, phone }
  pass from <staff> to nas proto tcp port 445
  pass from laptop to internet via vps
```

Relays and vouchers reach every device for juist's own traffic.

### `juist policy edit [NETWORK]`

Edit the access policy in $VISUAL or $EDITOR (default vi). It is set once it parses and passes its tests.

- `-y, --yes`: do not ask

### `juist policy set [NETWORK] FILE`

Make FILE, - for standard input, the access policy, once it parses and passes its tests.

- `-y, --yes`: do not ask

### `juist policy diff [NETWORK] FILE`

Show how FILE differs from the access policy, both in canonical form: - marks a line only the policy has, + a line only FILE has. Exits 1 if they differ.

### `juist policy check [NETWORK] FILE`

Parse FILE against the network, as juist policy set would, and run its tests. Sets nothing.

### `juist policy test [NETWORK] from DEVICE to DEST [proto P [port N]]`

Say whether the access policy lets DEVICE open DEST, and by which rule. DEST is a device, internet via DEVICE, an address, name NAME, or a published name. Exits 1 if no rule allows it.

### `juist policy fmt [FILE...]`

Print each FILE (default: standard input) in canonical form, as juist policy prints the policy. -w rewrites the files instead; -l lists those not in canonical form, and fails if there are any.

- `-l, --list`: list files not in canonical form
- `-w, --write`: rewrite FILE in place

### `juist policy off [NETWORK]`

Withdraw the access policy: every device may then open anything on every other again.

- `-y, --yes`: do not ask

### `juist approve [NETWORK] [FILE...]`

Sign change files with your admin keys and apply each once it has enough votes. Without FILE, ask about each change waiting for your vote. Alias: juist apply.

What a change does is shown from the record and the log, never from the file name or comments. Changes to who may approve need the log on this device. Changes that do not fit it are refused: a signature cannot be taken back.

- `-k, --key NAME`: sign only with the admin key NAME (see juist admins)
- `-n, --no-apply`: sign, do not apply
- `-y, --yes`: do not ask

### `juist admins`

Manage the admin keys that approve changes, and how many votes a change needs.

```
  juist admins                   list admin keys and thresholds
  juist admins new NAME          create an admin key on this machine
  juist admins add NAME KEY      add KEY as an admin key of NAME
  juist admins remove NAME|KEY   remove an admin key
  juist admins quorum K          require K votes for every change
  juist admins require NAME N    count NAME's votes only when N of their keys sign
  juist admins vouchers M        require M vouchers to confirm the network state
  juist admins receive           let changes waiting for your vote reach your keys here
  juist admins export NAME       print an admin key as one line, for a password manager
  juist admins import NAME       read that line from stdin as key NAME
```

An admin key leaves its machine only as the line export prints.

### `juist admins new [NETWORK] NAME`

Create an admin key on this machine and print the command that adds it. NETWORK need not be one this machine is in; without it, the key belongs to the first network that adds it.

- `-o, --on MACHINE`: MACHINE holding the key (default: this device)

### `juist admins add [NETWORK] NAME KEY`

Give KEY, as juist admins new printed it, a vote held by NAME. Keys under one name cast that person's votes once. \-\-on is not checked.

- `-o, --on MACHINE`: MACHINE holding the key (default: this one, if it does)
- `-v, --votes N`: votes the key carries (default 1)

### `juist admins remove [NETWORK] NAME|KEY`

Take an admin key's vote away. Refused if the remaining votes cannot reach the quorum.

### `juist admins quorum [NETWORK] K`

Require K admin votes for every later change.

- `-y, --yes`: do not ask

### `juist admins require [NETWORK] NAME N`

Count NAME's votes only when N of their keys sign. Hold N+1 keys: with exactly N, losing one device can lock the network.

- `-y, --yes`: do not ask

### `juist admins vouchers [NETWORK] M`

Require M vouchers to have confirmed the network state recently before a device trusts it. A lying voucher then needs M-1 others, and M vouchers must be online.

### `juist admins receive [NETWORK]`

Have changes waiting for your vote reach the admin keys here. This is a change like any other, signed by each key.

### `juist admins export NAME`

Print the admin key NAME, as juist admins lists it under KEY HERE, as one line for a password manager. The line is the key: keep it secret.

```
  juist admins export alice@home | bx create --name "juist alice" --password-stdin
```

juist admins import reads it back.

### `juist admins import NAME`

Read a line juist admins export printed from stdin and keep its key here as NAME, such as alice@home. For a line the Android app sealed, the password is asked for at the terminal if stdin is a file, else read from the next line of stdin, or asked for if there is none. An existing key is never replaced.

### `juist set [NETWORK]`

Change this device's settings. \-\-operator, run as root, sets the local user who may manage the device without sudo; \-\-operator="" clears it. \-\-https-only reaches relays only by TLS on 443, through \-\-proxy if given. \-\-relay-name serves this device's relay on 443 under a public name (default: relay.DOMAIN on the ingress). \-\-dns=false leaves the host's DNS alone: no network names, no DNS through an exit node. \-\-multicast=false carries no multicast or broadcast; under a policy, a pass multicast rule allows it. On Linux, \-\-groups limits which IPv4 groups are copied. \-\-port-mapping=false asks the router for no port.

- `-D, --dns`: manage this host's DNS for network names and exit nodes (default true)
- `-G, --groups GROUPS`: IPv4 multicast GROUPS to copy: auto, a list, or "" for none (default auto)
- `-O, --https-only`: reach relays only by TLS on 443
- `-M, --multicast`: carry multicast and broadcast where the policy allows (default true)
- `-o, --operator USER`: local USER who manages this device
- `-U, --port-mapping`: ask the router for a port by UPnP, NAT-PMP or PCP (default true)
- `-P, --proxy URL`: HTTP proxy URL for relays; - reads it from stdin, "" uses HTTPS\_PROXY
- `-R, --relay-name NAME`: public NAME of this device's relay on 443

### `juist network`

Show, rename and renumber the network, set its domain and public DERP servers, or end it.

```
  juist network [NETWORK]                        show name and address ranges,
                                                 for every network without NETWORK
  juist network rename [NETWORK] NAME            rename the network
  juist network domain [NETWORK] DOMAIN          set the public domain for juist publish
  juist network domain [NETWORK] off             remove it
  juist network derp [NETWORK] on                use Tailscale's public DERP servers
                                                 where no member relays
  juist network derp [NETWORK] off               use none
  juist network renumber [NETWORK] PREFIX        move every device into PREFIX,
                                                 such as 10.7.0.0/22
  juist network renumber [NETWORK] DEVICE ADDR   move one device to ADDR
  juist network renumber [NETWORK] --finish      retire the old addresses now
  juist network disable [NETWORK]                end the network for good with the
                                                 break-glass secret; every device stops
```

NETWORK is a network of this device, or its juistd (juist1); it can be left out if there is only one. Old IPv4 addresses work until the deadline; IPv6 addresses never move.

### `juist network rename [NETWORK] NAME`

Rename the network on every device. Nothing else changes.

### `juist network domain [NETWORK] DOMAIN|off`

Set the public domain for published names, such as pub.example.org. Its DNS points \*.DOMAIN at the ingresses. off removes it. Members resolve DOMAIN through juistd, without DNSSEC.

### `juist network derp [NETWORK] on|off`

Use Tailscale's public DERP servers where no member relays, or none. They see only encrypted traffic, but also the public address of every device and who talks to whom, when and how much. Member relays come first.

### `juist network renumber [NETWORK] PREFIX | DEVICE ADDR | --finish`

Move every device into PREFIX, at the same offset where free, or one device to ADDR. Old addresses keep working for the time \-\-for gives; make that long enough for every device to come online once. \-\-finish alone retires them now. Configuration outside juist is not changed.

- `-f, --finish`: retire old addresses now; with DEVICE ADDR, only its old one
- `-t, --for DURATION`: keep old addresses for DURATION, like 12h or 7d (default 7d)
- `-y, --yes`: do not ask

### `juist network disable [NETWORK]`

End the network for good: a record with its break-glass secret, the line juist create showed, stops every device it reaches. Nothing undoes it; each device starts over with juist reset.

- `-g, --secrets FILE`: FILE with the break-glass secret, - for stdin (default: the keystore's file, else stdin)
- `-y, --yes`: do not ask

### `juist log`

Inspect the membership log: the signed chain of every change, which each device holds and verifies.

```
  juist log                 list the changes
  juist log show N|HASH     what one change did, and who signed it; -1 is the last
  juist log verify [FILE]   re-verify the log, or check a change file
  juist log checkpoint      record the whole current state as one change
  juist log upgrade         raise the network to this build's record schema
```

### `juist log verify [NETWORK] [FILE...]`

Verify the stored log from its start, and that this device can open the group secret. With FILEs, say what each change needs and whether it applies.

### `juist log checkpoint [NETWORK]`

Record the whole current state as one change. Every device checks it against its own history. juist records one by itself every 256 changes.

### `juist log upgrade [NETWORK]`

Raise the network to this build's record schema once every device supports it (see juist devices). \-\-force raises it anyway; devices on older builds stop until updated. \-\-when-ready, for timers, raises it without asking once every device is ready, and does nothing before.

- `-f, --force`: raise it even if devices are not ready
- `-w, --when-ready`: raise it without asking if every device is ready
- `-y, --yes`: do not ask
