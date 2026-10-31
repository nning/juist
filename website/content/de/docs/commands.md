---
title: Befehle
linkTitle: Befehle
description: Jeder juist-Befehl mit seinen Argumenten und Optionen, so wie seine eigene Hilfe sie nennt.
lead: Alle juist-Befehle mit ihren Optionen. Auf dem Gerät sagen juist BEFEHL --help und man juist dasselbe.
---

Diese Seite entsteht aus der eingebauten Hilfe von juist, so wie sie unter
Linux lautet, und ist deshalb englisch. Unter FreeBSD richtet juistd den Host
für Exit-Nodes und Subnetz-Routen selbst ein, mit eigenen pf-Regeln. Optionen
stehen vor oder nach den Argumenten. Ist das Gerät in mehreren Netzen, nimmt
ein Befehl zu einem Netz zuerst dessen Namen
([Mehrere Netze]({{< relref "docs/networks" >}})).

## Getting started

### `juist create [NETWORK]`

Create a network with this device as its first member. NETWORK defaults to two random words. If the device is already in a network, the new network gets its own juistd.

\-\-voucher makes this device a voucher too. If it is then off for 48 hours, the other devices reach only vouchers, so use it on a device that is always on.

The admin keys (this keystore's and \-\-admin) and \-\-quorum decide who may change the network. Changing them later takes a quorum too. This keystore's admin key is new, unless \-\-admin-key reuses one from another network. Losing the admin keys loses the network: there is no recovery.

- `-a, --admin NAME=KEY[:VOTES]`: another admin, as NAME=KEY\[:VOTES]; repeatable
- `-K, --admin-key NAME`: govern it with the admin key NAME here too, as "juist admins" lists it
- `-u, --admin-name NAME`: your NAME as admin (default: your user name, or \-\-admin-key's)
- `-v, --admin-votes N`: votes of the admin key created here (default 1)
- `-n, --device NAME`: this device's NAME (default: the hostname)
- `-4, --ipv4 PREFIX`: IPv4 PREFIX, such as 10.111.0.0/24 (default: a free /22 in 198.18.0.0/15)
- `-N, --no-device`: do not make this device a member; for a signing-only machine
- `-o, --operator USER`: local USER who manages this device without sudo
- `-q, --quorum N`: votes a change needs (default 1)
- `-r, --relay`: make this device a relay
- `-V, --voucher`: make this device a voucher
- `-y, --yes`: do not ask

### `juist invite [NETWORK] [NAME]`

Invite one device and wait for it to join. Prints a code for the same LAN and a link for anywhere. Behind NAT, the two devices meet through the public BitTorrent DHT. Both end when a device joins or the invite expires. A wrong guess voids the code; the link still works. A terminal also shows the link as a QR code.

NAME is the device's name in the network (default: its own). If more than one admin must approve, the invite waits for them.

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

Join a network with the code or link that juist invite printed, such as 42-drumbeat-tolerance-glucose. The device verifies the network's log itself. Under sudo, on a device with no operator, the sudo user becomes its operator, unless \-\-operator names another. If the device is already in a network, the new network gets its own juistd.

- `-n, --name NAME`: NAME to join as (default: the hostname)
- `-o, --operator USER`: local USER who manages this device without sudo

## Devices

### `juist status [NETWORK]`

Show this device's network and how many devices it reaches, for every network if the device is in several. Any local user may run it. juist health says what needs attention; juist devices lists the devices.

- `-d, --devices`: list the devices too, as juist devices does
- `-v, --verbose`: name the relay that carries the traffic to each relayed device

### `juist health [NETWORK]`

Say what needs attention on this device, each with a hint, and which devices it does not reach, for every network if the device is in several. juist status shows the state.

### `juist devices [NETWORK]`

List the network's devices and how juistd last reached each: directly, through a relay, or not. outdated means the device runs an older juist and stays unreachable until updated. SCHEMA is the newest schema each device's juist implements, yellow if older than this one's. juistd checks every 30s. On a device in several networks, it lists each network unless NETWORK names one.

- `-a, --all`: list the devices the access policy keeps apart from this one too
- `-6, --ipv6`: show IPv6 addresses
- `-k, --keys`: show identity keys

### `juist remove [NETWORK] DEVICE`

Remove a device, by name, address or key (juist devices \-\-keys). This rotates the group secret. Every device drops the removed one's tunnel once it hears of the removal; a device cut off from the rest does so when its freshness expires, at the latest.

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

An admin makes a device an exit node: juist grant DEVICE exit. It carries only traffic to public addresses, so the LAN stays direct. It carries DNS too, except for the LAN's own domain if systemd-resolved runs. If the exit node cannot be used, traffic is refused, not sent directly.

### `juist exit use [NETWORK] DEVICE`

Send this device's internet traffic and DNS through DEVICE. The LAN and the network's devices stay direct. So do answers to connections from the internet, such as ssh. \-\-isolate sends those through DEVICE too; it refuses if that would end the ssh session it runs in. If DEVICE cannot carry the traffic, it is refused, not sent directly. \-\-force chooses a DEVICE that does not serve yet, or ends the session anyway.

- `-f, --force`: choose it though it does not serve, or would end this ssh session
- `-i, --isolate`: send answers to connections from the internet through it too

### `juist exit off [NETWORK]`

Send this device's internet traffic directly again.

### `juist exit serve [NETWORK]`

Carry the network's internet traffic, if an admin made this device an exit node. If the host does not forward yet, sudo sets that up and opens the firewall for it. \-\-stop stops and undoes it.

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

An admin adds a subnet, such as 192.168.1.0/24, to a device, and its operator agrees to route it: juist subnet serve. Every member then reaches the subnet through that device, unless the member reaches those addresses by its own route, as on its LAN.

### `juist subnet add [NETWORK] DEVICE PREFIX...`

Have a device route subnets, such as 192.168.1.0/24, for every member, once its operator agrees: juist subnet serve.

### `juist subnet remove [NETWORK] DEVICE PREFIX...`

Take subnets from a device.

### `juist subnet serve [NETWORK]`

Route the subnets the network grants this device, for the other members. If the host does not forward yet, sudo sets that up and opens the firewall for it. \-\-stop stops and undoes it.

- `-S, --stop`: stop routing

### `juist subnet off [NETWORK]`

Stop reaching the network's subnets through it; the host routes them itself, as before. juist subnet on undoes it.

### `juist subnet on [NETWORK]`

Reach the network's subnets through it again.

### `juist names`

Point public names at devices, so that members reach them through the tunnel.

```
  juist names                         the network's names, public ones too, and how this device resolves each
  juist names add DEVICE NAME...      point NAME at DEVICE
  juist names remove DEVICE NAME...   take NAME from DEVICE
  juist names on                      resolve them to their devices on this device
  juist names off                     resolve them publicly again
```

On Linux and FreeBSD, every device is DEVICE.NETWORK.juist to the others. A public name, such as mail.example.org, resolves to its device on each device that turned names on. Elsewhere, and while its device is out of reach, it resolves publicly.

### `juist names add [NETWORK] DEVICE NAME...`

Point public names, such as mail.example.org, at a device. Each device that turned names on (juist names on) resolves them to it.

### `juist names remove [NETWORK] DEVICE NAME...`

Take public names from a device.

### `juist names on [NETWORK]`

On this device, resolve the network's public names to their devices, through the tunnel. juist names off undoes it.

### `juist names off [NETWORK]`

Resolve the network's public names publicly again, as without juist.

### `juist publish`

Publish devices' services on the internet, through an ingress.

```
  juist publish                                    the published names, and where
                                                   this device sends them on
  juist publish add NAME HOST:PORT                 publish NAME.DOMAIN on this device,
                                                   ending TLS and sending it on to HOST:PORT
  juist publish add DEVICE NAME [PORT]             publish NAME.DOMAIN on DEVICE's PORT
  juist publish add DEVICE NAME PORT --tcp         publish DEVICE's PORT on PORT of every
                                                   ingress, by TCP
  juist publish status-page NAME [--public WHAT]   serve the network's status page as
                                                   NAME.DOMAIN on this device
  juist publish remove [DEVICE] NAME               stop publishing NAME
  juist publish serve [--stop]                     serve what is published on this
                                                   device to the ingresses
```

A name is one label under the network's domain (juist network domain), or the domain itself, spelled out. Its DNS points at the ingresses (juist grant DEVICE ingress). An ingress reads the name a client asks for and passes the connection to the device. There, juist ends TLS (juist publish add NAME HOST:PORT), or the service does. A name published by TCP (\-\-tcp) gets its own port on every ingress instead. juist publish PORT publishes this host's PORT under the device's own name at once, if the device has the publish role.

### `juist publish add [NETWORK] NAME HOST:PORT | DEVICE NAME [PORT]`

Publish NAME.DOMAIN, or DOMAIN itself. With HOST:PORT, such as 127.0.0.1:2283, the name is published on this device: juist ends TLS with its own certificate and sends the connection on to HOST:PORT. With DEVICE, the name goes to DEVICE's PORT (default 443), where the service ends TLS, once DEVICE's operator agrees. With \-\-tcp, every ingress passes TCP to the device on a separate port, for a service without TLS. With \-\-members, the internet cannot reach the name; members reach it at the device, as the access policy allows.

- `-2, --http2`: offer clients HTTP/2; the service at HOST:PORT takes it without TLS (h2c)
- `-3, --http3`: offer clients HTTP/3 too; juist proxies the HTTP of the service at HOST:PORT
- `-m, --members`: for members alone, whom the access policy names: not for the internet; =false makes it public
- `-P, --proxy`: send the client's address in a PROXY protocol v2 header
- `-T, --tcp[=PORT]`: publish by TCP on PORT of every ingress, the device's port unless given, not by TLS on 443

### `juist publish status-page [NETWORK] NAME`

Serve the network's status page as NAME.DOMAIN on this device, where juist ends TLS. It shows the devices, how this device reaches them, the published names and the log's changes. Members see all of it. \-\-public sets what others see: none, services, network (all but the changes) or all.

- `-W, --public WHAT`: WHAT non-members see: none, services, network or all (default services)

### `juist publish remove [NETWORK] [DEVICE] NAME`

Stop publishing NAME on DEVICE (default: this device). On this device, juist also stops ending TLS for NAME.

### `juist publish serve [NETWORK]`

Serve the names the network publishes on this device. The ingresses then pass their connections to this device's ports. The service ends TLS there, or juist does if told to by juist publish add NAME HOST:PORT. \-\-stop undoes it and keeps where the names go.

- `-S, --stop`: stop serving

### `juist share [NETWORK] [FILE|DIR] | --stop [FILE|DIR|PORT|URL]`

Share FILE or DIR read-only on the internet, under this device's own name and a random path, until Ctrl-C or \-\-for. With \-\-background, until juist share \-\-stop. A directory is listed and downloads as a ZIP. Without FILE or DIR, list this device's shares, including those of juist publish PORT. The device needs the publish role.

- `-b, --background`: share in the background
- `-t, --for DURATION`: share for DURATION, like 2h or 7d
- `-S, --stop`: stop a share, the only one where none is named

### `juist ingress`

Take connections from the internet for the names devices publish.

```
  juist ingress                  what this ingress serves
  juist ingress serve [--stop]   serve as the network's ingress, on 443
                                 and 80, and the ports names are published
                                 on by TCP
```

An ingress is a device with a public address and the ingress role (juist grant DEVICE ingress). It reads the name a client asks for, or the port a name is published on by TCP, and passes the connection through the tunnel to the device. It ends no TLS.

### `juist ingress serve [NETWORK]`

Serve as the network's ingress: the juist-ingress service, on 443, 443/udp for HTTP/3, 80 and the ports names are published on by TCP, let through firewalld or ufw where one runs. \-\-stop undoes it.

- `-S, --stop`: stop serving

### `juist reset [NETWORK]`

Forget the network on this device: its keys, log, peers and operator, as on a fresh install. Admin keys are kept. If the network still lists the device, this needs \-\-force; remove the device first if you can. On a device in several networks, only the named one is forgotten, with its juistd unless that is the default. The others keep their keys.

- `-f, --force`: reset even if the network still lists this device
- `-y, --yes`: do not ask

## Administration

### `juist grant [NETWORK] DEVICE ROLE...`

Give a device roles. Roles:

```
  exit     carries other devices' internet traffic, once its operator
           agrees: juist exit serve
  ingress  takes connections from the internet for published names; on a
           device with a public address and no other role
  service  a service member: juistd --serve next to a service; no device
           may open a connection to it
  publish  shares under its own name without a vote each time:
           juist share FILE, juist publish PORT
  relay    relays for devices that cannot reach each other; best on two or
           more devices with public addresses
  voucher  confirms hourly that the network state is current. If too few
           vouch for 48 hours, devices reach only vouchers, so give it to
           devices that are always on. Not an admin key.
```

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
  juist policy check FILE                     read FILE against the network, run its tests
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

Edit the network's access policy in $VISUAL or $EDITOR (default vi). It is set once it parses and passes its tests.

- `-y, --yes`: do not ask

### `juist policy set [NETWORK] FILE`

Make FILE the network's access policy, once it parses against the network and passes its tests. - reads standard input. If the change needs other admins' votes, it goes to them like any change.

- `-y, --yes`: do not ask

### `juist policy diff [NETWORK] FILE`

Show how FILE differs from the network's access policy, both in canonical form: - marks a line only the policy has, + a line only FILE has. Exits 1 if they differ.

### `juist policy check [NETWORK] FILE`

Parse FILE against the network, as juist policy set would, and run its tests. Sets nothing.

### `juist policy test [NETWORK] from DEVICE to DEST [proto P [port N]]`

Say whether the network's access policy lets DEVICE open DEST, and which rule allows it. DEST is a device, internet via DEVICE, an address, name NAME, or a published name, as in a test line of a policy. Exits 1 if no rule allows it.

### `juist policy fmt [FILE...]`

Print each FILE (default: standard input) in canonical form, as juist policy prints the policy. Reads no log. -w rewrites the files instead; -l lists the files not in canonical form and fails if there are any.

- `-l, --list`: list files not in the policy's own form
- `-w, --write`: rewrite FILE in place

### `juist policy off [NETWORK]`

Withdraw the network's access policy. Every device may then open anything on every other again.

- `-y, --yes`: do not ask

### `juist approve [NETWORK] [FILE...]`

Sign change files with this keystore's admin keys, in place, and apply each once it has enough votes. Without files, ask about each change waiting for your vote on this admin device. Alias: juist apply.

The effect of each change is shown from the record and the log, never from the file's name or comments. Changes to who may approve need the log on this device. Records that do not fit this device's log are refused, because a signature cannot be taken back.

- `-k, --key NAME`: sign with the admin key NAME only, as "juist admins" lists it
- `-n, --no-apply`: sign only
- `-y, --yes`: do not ask

### `juist admins`

Manage the admin keys that approve changes, and how many votes a change needs.

```
  juist admins                   list admin keys and thresholds
  juist admins new NAME          create an admin key on this machine
  juist admins add NAME KEY      give another admin's key a vote
  juist admins remove NAME|KEY   take an admin key's vote away
  juist admins quorum K          require K votes for every change
  juist admins require NAME N    count NAME's votes only when N of their keys sign
  juist admins vouchers M        require M vouchers to confirm a device's view
  juist admins receive           let changes waiting for your vote reach your keys here
  juist admins export NAME       print an admin key here as one line, for a password manager
  juist admins import NAME       read that line from stdin into the key NAME
```

Admin keys leave their machine only as the line export prints, which needs no network.

### `juist admins new NAME`

Create an admin key on this machine and print the command that adds it. \-\-network names the network it is for. Without it, the key goes to the first network whose log names it, once juist admins or a change signed with it reads that log.

- `-o, --on MACHINE`: MACHINE the key is kept on (default: this device's name, or the hostname)

### `juist admins add [NETWORK] NAME KEY`

Give KEY, as juist admins new printed it, a vote held by the person NAME. Several keys under one name together cast that person's votes once. \-\-on is an unverified label.

- `-o, --on MACHINE`: MACHINE the key is kept on (default: this one, if it holds the key)
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

Require M vouchers to have vouched within the freshness TTL before a device trusts its view. A lying voucher then needs M-1 accomplices, and M vouchers must be online.

### `juist admins receive [NETWORK]`

Give this keystore's admin keys the encryption keys that pending changes are sealed to, so that the changes reach you on your admin devices. This is a change like any other; each key signs it itself.

### `juist admins export NAME`

Print the admin key NAME (as juist admins lists it under KEY HERE) as one line on stdout, for a password manager:

```
  juist admins export alice@home | bx create --name "juist alice" --password-stdin
```

juist admins import reads it back.

### `juist admins import NAME`

Read a line printed by juist admins export from stdin and keep its key here as NAME, such as alice@home. An existing key of that name is never replaced. Says whether the network still gives the key a vote.

### `juist set [NETWORK]`

Change this device's settings. \-\-operator sets the local user who may manage the device without sudo; run it as root. \-\-operator="" clears it. \-\-https-only sends only TLS to relays on 443, through \-\-proxy if given. \-\-relay-name serves this device's relay on 443 under a public name (default: relay.DOMAIN on the network's ingress). \-\-dns=false leaves this host's DNS alone: no network names, and no DNS through an exit node.

- `-D, --dns`: take this host's DNS for the network's names and the exit node; =false leaves it alone (default true)
- `-O, --https-only`: reach relays by TLS on 443 alone; =false undoes it
- `-o, --operator USER`: local USER who manages this device
- `-P, --proxy URL`: HTTP proxy URL to reach them by, - to read it from stdin; "" for HTTPS\_PROXY
- `-R, --relay-name NAME`: public NAME of this device's relay on 443

### `juist network`

Show, rename and renumber the network, set its domain, or end it.

```
  juist network [NETWORK]                        name and address ranges; every
                                                 network's, without NETWORK
  juist network rename [NETWORK] NAME            rename the network
  juist network domain [NETWORK] DOMAIN          the public domain names are
                                                 published under (juist publish)
  juist network domain [NETWORK] off             withdraw it
  juist network renumber [NETWORK] PREFIX        move every device into PREFIX,
                                                 such as 10.7.0.0/22
  juist network renumber [NETWORK] DEVICE ADDR   move one device to ADDR; with
                                                 --finish, retiring its old one now
  juist network renumber [NETWORK] --finish      retire the old addresses now
  juist network disable [NETWORK]                end the network for good with the
                                                 break-glass secret: every device stops
```

NETWORK names one of this device's networks, or its juistd (juist1). It can be left out if the device is in only one. Old IPv4 addresses keep working until the deadline. IPv6 addresses never move.

### `juist network rename [NETWORK] NAME`

Rename the network on every device. Nothing else changes.

### `juist network domain [NETWORK] DOMAIN|off`

Set the public domain that names are published under, such as pub.example.org; its DNS points \*.DOMAIN at the ingresses. off withdraws it. Every member then resolves DOMAIN through juistd, with DNSSEC off for it.

### `juist network renumber [NETWORK] PREFIX | DEVICE ADDR | --finish`

Move IPv4 addresses.

```
  juist network renumber [NETWORK] PREFIX        every device into PREFIX,
                                                 at the same offset if free
  juist network renumber [NETWORK] DEVICE ADDR   one device to ADDR; with
                                                 --finish, retiring its old
                                                 one now
  juist network renumber [NETWORK] --finish      retire the old addresses now
```

Old addresses keep working until \-\-for from now; make that long enough for every device to come online once. Retired addresses stay reserved until a plain \-\-finish, so that no other device takes them. Configuration outside juist that names old addresses is not changed.

- `-f, --finish`: retire old addresses now; with DEVICE ADDR, only that device's
- `-t, --for DURATION`: keep old addresses for DURATION, like 12h or 7d (default 7d)
- `-y, --yes`: do not ask

### `juist network disable [NETWORK]`

End the network for good. This reveals its break-glass secret, the line juist create showed, in a record that stops every device it reaches. Nothing undoes it; each device starts over with juist reset. The line is read from stdin, or from FILE with \-\-secrets.

- `-g, --secrets FILE`: FILE holding the break-glass secret, - for stdin (default: an older network's file in the keystore, else stdin)
- `-y, --yes`: do not ask

### `juist log`

Inspect the membership log: the signed, hash-chained record of every change, which each device holds and verifies.

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

Raise the network to this build's record schema once every device's juist implements it, as juist devices shows. \-\-force raises it anyway, and devices on older builds stop until updated. \-\-when-ready, for a timer, raises it without asking once they do, and else does nothing.

- `-f, --force`: raise it although devices lag
- `-w, --when-ready`: raise it without asking once every device is ready
- `-y, --yes`: do not ask
