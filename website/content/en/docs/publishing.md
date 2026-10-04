---
title: Publishing services
linkTitle: Publishing services
description: Make a service on one of your devices, such as a NAS at home, reachable from the internet by name.
lead: A service on a member, such as a NAS at home, can be reached from the internet by name. A device with a public address passes the connections on; the encryption ends at the member.
status: [Linux, FreeBSD]
---

## What it is

You run a service at home, say a document server on your NAS, and want to open
it from any browser as `docs.example.org`. Your router at home opens no port
for this, and its address is in no public record.

A few words first:

- A domain is a name you own on the internet, such as `example.org`.
- A DNS record is an entry at your DNS provider that says which address a
  name points to.
- TLS is the encryption a browser uses for `https://` addresses.
- A certificate proves to the browser that the server really is
  `docs.example.org`. juist gets one from Let's Encrypt.
- An ingress is a device of your network with a public address, a small
  VPS for example, that an admin gave the role `ingress`. It takes connections
  on port 443, reads the name the browser asks for, and passes the connection
  through the tunnel to the member that publishes the name.

{{< flow publish >}}

The ingress ends no TLS, so it never sees the content. TLS ends at the NAS, and
the NAS passes the plain connection on to the service. One ingress serves
every name of the network.

## Setting it up

{{< step on="an admin's device" >}}
Set the network's domain and give the VPS the role:

```sh
juist network domain example.org
juist grant vps ingress
```
{{< /step >}}

{{< step on="your DNS provider's website" >}}
Point `*.example.org` at the VPS's public address, for every name at once, or
`docs.example.org` alone.
{{< /step >}}

{{< step on="vps" as="the ingress" >}}
```sh
juist ingress serve
```

It asks once for sudo, starts the `juist-ingress` service, and opens ports 443
and 80 in firewalld or ufw; on FreeBSD, pf is left to the host's own rules.
Port 80 only redirects to https.
{{< /step >}}

{{< step on="nas" as="the target" >}}
Its [operator]({{< relref "docs/operator" >}}), the local user who manages the
device, publishes the name and says where the plain connection goes:

```sh
juist publish add docs 127.0.0.1:8080
```

`docs` goes to port 443 on the NAS. juist gets a certificate through the
ingress and ends TLS here. It prints `nas: publishes docs.example.org:443`,
`serving docs.example.org` and
`ending TLS for docs.example.org to 127.0.0.1:8080`, then the CAA record that
keeps other accounts from certificates for the name (see below), and the
first time
`warning: a server published from this device reaches the network and its LAN once compromised`.

Publishing is an admin's change. Where the NAS holds no admin key, it prints
`docs.example.org goes to 127.0.0.1:8080 once published on this device` and
the command an admin runs, `juist publish add nas docs.example.org`. Where a change needs
more than one admin, it waits for the others
([how changes are approved]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist grant` and `juist publish add` name the next step and the device it
runs on. Run there by that device's operator, they take that step too.
`juist invite vps --ingress` admits a new device as the ingress at once.

## Keeping the server away from your network

{{< note danger >}}
A server published from a full member reaches the network and the member's
LAN once someone breaks into it. Publish from one only what you would put on
the internet anyway.
{{< /note >}}

A **service member** keeps the server away from them: a juistd
of its own beside the service, with no privilege, which every device keeps
from opening any connection to it. Only its replies pass.

{{< step on="an admin's device" >}}
```sh
juist invite immich --service immich
```

It admits the new device, named `immich`, as a service member that
publishes `immich.example.org`, and prints the link to join with.
{{< /step >}}

{{< step on="the server" as="the service member" >}}
In Docker, the service goes on an internal network with the service member
alone, and the service member's image (`make image` in the source tree, then
`docker load`) on that network and one with a way out:

```sh
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated immich-only
docker network connect immich-only immich-server     # and disconnect it from every other network
docker run -d --name immich-juist -v immich-juist:/var/lib/juist -e JUIST_JOIN='juist:…' \
    juist:VERSION --serve immich=immich-server:2283
docker network connect immich-only immich-juist
```

It joins by the link once started, and ignores it once in the network;
`docker logs immich-juist` says how the join went, with the words to compare
where the invite asks for them.

The same as one Compose file, with a web service to try it on, for Docker
and Podman: [examples/service-member](https://github.com/nning/juist/tree/main/examples/service-member) in the
repository.

Outside Docker, `juistd --serve immich=127.0.0.1:2283` runs it as any user.
`--serve @=web:80` serves the domain itself.
{{< /step >}}

It ends TLS itself, with a certificate from Let's Encrypt, and answers nothing
but what it publishes and log sync. The service has no way out, so one that
downloads things at its first start needs that done beforehand. The isolated
gateway mode, Docker 29's, keeps the host from the service too; without it,
the service reaches whatever on the host listens on every address, at the
network's gateway.

## Sharing at once

A device an admin gave the role `publish` (`juist grant laptop publish`)
publishes under its own name, `laptop.example.org`, without asking an admin
each time:

```sh
juist share ~/photos/2026          # at https://laptop.example.org/RANDOM/, until Ctrl-C
juist publish 8000 --for 2h        # this device's web server on port 8000, for two hours
juist share -b --for 7d ~/talk.pdf # in the background, for a week
juist share --stop                 # ends this device's share, whichever command holds it
```

A share is read under its random path alone; anywhere else on the name answers
404, and entries such as `.git` stay hidden. A directory is listed, sortable
by name, size or date, and downloads whole, or any folder in it, as a ZIP; a
folder holding an `index.html` shows that page instead. It ends with the command or at
`--for`, seven days at most, and where the device goes away, ten minutes
later at most. With `--background` (`-b`), the command returns once the share
is up, and the share goes on, under the same link even across a restart of
juistd, until `juist share --stop` or `--for`; `juist status` shows it as
`Sharing`. One certificate for the device's name covers every share, so
their paths reach no certificate log. A device shares one thing at a time.
[Renamed]({{< relref "docs/network-changes" >}}), it shares under its new
name, and `juist share` prints the new link.

## A status page

A device serves the network's status page under a published name, in this
website's look, light or dark as the browser asks:

```sh
juist publish status-page status                # at https://status.example.org/
juist publish status-page status --public all   # anyone sees all of it
```

Members see all of it: every device with its addresses and roles, how the
serving device reaches it (direct, through a relay, sought or absent) and
when it last heard from it, the published names and shares and whether each
is up, what needs attention, and the log's newest changes. Anyone else sees
what `--public` says:

| `--public` | Anyone but a member sees |
|---|---|
| `none` | nothing: the page answers 404 |
| `services`, the default | the published names and shares, and whether each is up |
| `network` | all but the changes |
| `all` | all of it |

The page knows a member by the overlay address its connection comes from;
whoever comes through the ingress is the public, whatever the ingress says.
It refreshes itself every 15 seconds while it is open, which makes it a
status screen for a phone, too. Opened once with `https://`, the browser
keeps to https for it.

Devices, published names and changes are the network's, the same on every
member. Reach and what needs attention are the serving device's own, and the
page says whose: serve it from a device that is always on and reaches the
others well. An ingress cannot, holding port 443 itself.

{{< note caution >}}
With `--public network` or `all`, anyone who has the address sees your
devices' names, overlay addresses and roles, and with `all` who approved which
change. Only members see that otherwise.
{{< /note >}}

`juist publish status-page status --public none` says anew what the public
sees, and `juist publish remove status` takes the page down. It is a name
whose TLS juist ends, as with `juist publish add NAME HOST:PORT`; a service
member serves it with `--serve status=status-page:all`, and its reach is
then that of a device every other keeps from opening connections.

## Good to know

- A published name is one label under the domain, `docs.example.org`, or the
  domain itself, `example.org`, spelled out: `juist publish add nas
  example.org`. A device publishes 16 names at most. One device at most
  publishes the domain itself, and it needs
  A and AAAA records of its own at your DNS provider, the ingress's, which
  `*.example.org` does not cover. A CAA record there holds for every name
  under it that has none of its own: give each device's names their own.
- A service can end TLS itself and hold its own certificate, as it would
  facing the internet. An admin then publishes it with
  `juist publish add nas docs`, on port 443 unless you give another port after
  the name, and nas's operator agrees with `juist publish serve`.
- `--proxy` on `juist publish add` hands the service the client's address in a
  PROXY protocol v2 header. Members then reach the name through the ingress
  too.
- An ingress passes 16384 connections at once, 256 from one address and
  1024 from one /24 or /48; juist ending TLS on a device takes 8192.
  `--max-conns N` and, for the ingress, `--max-per-source N` change that:
  on Linux in a drop-in for `juist-ingress` or `juist-serve`, on FreeBSD in
  `juist_ingress_args` or `juist_serve_args`.
- `--http2` on `juist publish add NAME HOST:PORT` offers clients HTTP/2, for
  a service that takes it without TLS (h2c) besides HTTP/1.1. A browser then
  opens one connection instead of up to six. A service that takes
  HTTP/1.1 alone fails with it.
- Every member on Linux with systemd-resolved sends the whole domain to
  juistd, which answers a name published on 443, or shared, with its
  device's address while that device is reachable, so that members
  reach it directly through the tunnel, with the same certificate, and passes
  every other name of the domain on as before. DNSSEC is off for the domain on
  members ([Names]({{< relref "docs/names" >}})). `http://` to such a name
  goes to the device's port 80, where juist redirects it to https, unless
  another program listens there on every address: that program then answers,
  which `juist status` warns of.
- `juist publish` lists the published names, and where this device sends its
  own. `juist publish remove docs` stops publishing one on this device,
  `juist publish remove nas docs` on another. `juist publish serve --stop`
  stops serving and keeps where names go. `juist ingress serve --stop` stops
  the ingress.
- An ingress and juist's own TLS run on Linux and FreeBSD, for the device's
  default network. On FreeBSD, pf, where the host runs it, lets 443 and 80 in by
  the host's own rules.
- `juist network domain off` is refused while a device publishes names under
  the domain, with the `juist publish remove` that comes first.
- An ingress is never a voucher or an exit node, publishes nothing under its
  own name or on 80 and 443, which it holds itself, and routes no subnet; a
  service member holds no other role. `juist grant` names the role that is in
  the way. Every
  member takes from it only connections to the ports it publishes and serves,
  and log sync, replies to what it opened itself, pings included, and ICMP
  errors on its own connections. Everything else from it is dropped.
- An ingress holds 1024 connections at once: 64 from one address, or one
  IPv6 /64, and 256 from one IPv4 /24 or IPv6 /48, on 443 and on 80 each. A
  client that does not answer its service's TLS hello within a minute is let
  go, one quiet both ways after 5 minutes.
- A client gets 10 seconds to send its TLS hello to the ingress.
- The ingress logs a line for each connection: the client's address and
  port, the name it asked for, what came of it (`spliced`, `not served`,
  `no hello`, `target unreachable`, `refused`), the bytes each way and how
  long it lasted; on port 80 the method, path, status and User-Agent too.
  Past port 80 it sees neither path nor User-Agent, TLS ending at the
  device. `journalctl -u juist-ingress` shows them, on FreeBSD
  `/var/log/juist-ingress.log`, kept as long as the journal or newsyslog keeps them.
- The ingress runs as its own user, `juist-ingress`, holds no key of the
  network, and may ask juistd one thing: what is published.
- An ingress whose view of the network is stale serves nothing. If its juistd
  stops answering, the names go down within fifteen seconds.
- `juist revoke vps ingress`, or `service`, makes the device a member like
  any other again, which juist warns of:
  `warning: vps is confined no more, now a member like any other`. One that
  may be compromised goes by `juist remove`. Without the ingress role, run
  `juist ingress serve --stop` on it.

{{< note caution >}}
Whoever controls the ingress can get a certificate for your names and intercept
public clients, and members that reach a name through it: those on another
port than 443, behind `--proxy`, or without systemd-resolved. Members that resolve a name on 443
to its device connect to it directly. A CAA
record, a DNS record that says who may issue certificates for a name, bound to
the target's ACME account closes that gap: `juist publish add NAME HOST:PORT`
prints it, and the terminator's log names it for a service member.
{{< /note >}}

## If something goes wrong

| You see | What to do |
|---|---|
| `the network has no domain to publish under` | `juist network domain example.org` first |
| on nas, `juist status`: `Published` says `not served here: not agreed to on this device (juist publish serve)` | run `juist publish serve` on nas |
| on vps, `juist status`: `Ingress` says `not running on this device (juist ingress serve)` | run `juist ingress serve` on vps |
| `juist ingress` on vps: `nothing to serve` | no name is published and served yet; a hint says when the view is stale |
| `the ingress does not answer on 443: …` | `journalctl -u juist-ingress` shows why; on FreeBSD, `/var/log/juist-ingress.log` |
| `the terminator does not answer on …` | `journalctl -u juist-serve` shows why; on FreeBSD, `/var/log/juist-serve.log` |
| `this device holds no publish role` | an admin runs `juist grant DEVICE publish` |
| `juist status`: `Sharing` says `reached by nobody: the terminator does not run` | `juist share` starts it; `journalctl -u juist-serve` shows why it stopped |
| `juist status`: `Published` says `…, but ends TLS for none: the terminator does not run (juist publish serve)` | run `juist publish serve`; `journalctl -u juist-serve` shows why it stopped |
| `the terminator does not say it listens on …` | it did not start in time; `journalctl -u juist-serve` shows why |
| `juist status`: `warning: another program holds port 80 on …` | members opening `http://NAME` reach that program instead of a redirect to https; have it listen on the addresses it serves alone, and open the name with `https://` meanwhile |
| `juist status`: `warning: no certificate for NAME: …` | the CA issued none, for the reason given; most often it cannot reach NAME, whose public DNS must point at a running ingress. Until then a client's TLS fails |
| `another program holds port 443 on …, where juist would end TLS` | stop that program, or publish on another port |
| `this device shares already` | stop the other `juist share` or `juist publish PORT` first, in the background too: `juist share --stop` |
| `this device is no ingress` | an admin runs `juist grant DEVICE ingress` |
| `warning: the network has no ingress, so nothing reaches it from the internet` | grant a device with a public address the role `ingress` |
| `warning: nothing answers on 127.0.0.1:8000 yet` | start the web server that `juist publish 8000` points at |
| `warning: firewalld blocks tcp/443 on juist0, …` | `juist0` is not in firewalld's `trusted` zone, which the package sets at its first install alone; run the `firewall-cmd` the hint gives |
