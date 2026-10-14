---
title: Publishing services
linkTitle: Publishing services
description: Make a service on one of your devices, such as a NAS at home, reachable from the internet by name.
lead: A service on a member, such as a NAS at home, can be reached from the internet by name. A device with a public address passes the connections on, and the encryption ends at the member.
status: [Linux, FreeBSD]
---

## How it works

You run a service at home, say a document server on your NAS, and want to open
it from any browser as `docs.example.org`. Your router at home does not need to
open a port for this, and its address does not appear in any public record.

A few terms first:

- A domain is a name you own on the internet, such as `example.org`.
- A DNS record is an entry at your DNS provider that says which address a
  name points to.
- TLS is the encryption a browser uses for `https://` addresses.
- A certificate proves to the browser that the server really is
  `docs.example.org`. juist gets one from Let's Encrypt.
- An ingress is a device in your network with a public address, a small VPS
  for example, that an admin has given the role `ingress`. It accepts
  connections on port 443, reads the name the browser asks for, and passes the
  connection through the tunnel to the member that publishes the name.

{{< flow publish >}}

The ingress does not decrypt TLS, so it never sees the content. TLS ends on
the NAS, which passes the decrypted connection on to the service. One ingress
serves every name in the network.

## Setting it up

{{< step on="an admin's device" >}}
Set the network's domain and give the VPS the role:

```sh
juist network domain example.org
juist grant vps ingress
```
{{< /step >}}

{{< step on="your DNS provider's website" >}}
Point `*.example.org` at the VPS's public address to cover every name, or point
only `docs.example.org` at it.
{{< /step >}}

{{< step on="vps" as="the ingress" >}}
```sh
juist ingress serve
```

It asks for sudo once and starts the `juist-ingress` service. It opens ports
443 (TCP and UDP, for HTTP/3) and 80 in firewalld or ufw, and opens and closes
the ports of names published by TCP as those names come and go
([below](#a-game-server-or-another-tcp-service)). On FreeBSD, pf is left to the
host's own rules. Port 80 only redirects to https.
{{< /step >}}

{{< step on="nas" as="the target" >}}
Its [operator]({{< relref "docs/operator" >}}), the local user who manages the
device, publishes the name and says where the decrypted connection goes:

```sh
juist publish add docs 127.0.0.1:8080
```

`docs` goes to port 443 on the NAS. juist gets a certificate through the
ingress and ends TLS here. The command prints
`nas: publishes docs.example.org:443`, `serving docs.example.org` and
`ending TLS for docs.example.org to 127.0.0.1:8080`. Then it prints the CAA
record that stops other ACME accounts from getting certificates for the name
(see below), and, the first time,
`warning: a server published from this device reaches the network and its LAN once compromised`.

Publishing is a change only admins can make. If the NAS holds no admin key, it
prints `docs.example.org goes to 127.0.0.1:8080 once published on this device`
and the command an admin needs to run, `juist publish add nas docs.example.org`.
If a change needs more than one admin, it waits for the others
([how changes are approved]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist grant` and `juist publish add` print the next step and the device it
runs on. If that device's operator runs them on that device, they carry out
that step as well. `juist invite vps --ingress` admits a new device directly as
the ingress.

## Keeping the server away from your network

{{< note danger >}}
If someone breaks into a server published from a full member, they can reach
the network and the member's LAN from it. From a full member, publish only what
you would put on the internet anyway.
{{< /note >}}

A **service member** keeps the server away from your network. It is a separate,
unprivileged juistd that runs beside the service. No device accepts connections
it opens; only its replies get through.

{{< step on="an admin's device" >}}
```sh
juist invite immich --service immich
```

This admits a new device named `immich` as a service member that publishes
`immich.example.org`, and prints the link to join with.
{{< /step >}}

{{< step on="the server" as="the service member" >}}
In Docker, put the service on an internal network that it shares only with the
service member. Attach the service member's container to that network and to
one with internet access. Its image comes from `make image` in the source
tree, followed by `docker load`:

```sh
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated immich-only
docker network connect immich-only immich-server     # and disconnect it from every other network
docker run -d --name immich-juist -v immich-juist:/var/lib/juist -e JUIST_JOIN='juist:…' \
    juist:VERSION --serve immich=immich-server:2283
docker network connect immich-only immich-juist
```

Once started, it joins with the link, and once it is in the network it ignores
the link. `docker logs immich-juist` shows how the join went, including the
words to compare if the invite asks for them.

The same setup as a single Compose file, with a web service to try it on, for
Docker and Podman: [examples/service-member](https://github.com/nning/juist/tree/main/examples/service-member) in the
repository.

Outside Docker, `juistd --serve immich=127.0.0.1:2283` runs it as any user.
`--serve @=web:80` serves the domain itself.
{{< /step >}}

The service member ends TLS itself, with a certificate from Let's Encrypt, and
answers only for the names it publishes and for log sync. The service has no
internet access, so if it downloads things on its first start, do that
beforehand. Docker 29's isolated gateway mode also cuts the service off from
the host. Without it, the service can reach anything on the host that listens
on all addresses, through the network's gateway.

## HTTP/3

For a name whose service speaks HTTP and whose TLS juist ends, browsers can use
HTTP/3, which is QUIC on 443/udp. It connects in one round trip less, and on a
slow link it loses no time over a lost packet:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

The command prints `ending TLS for docs.example.org to 127.0.0.1:8080, with HTTP/3`
and a DNS record to add at your DNS provider,
`docs.example.org. HTTPS 1 . alpn="h3,h2"`. With that record, browsers try
HTTP/3 from their first request. Without it, they use it from their second
request, once the `Alt-Svc` header juist adds to its responses has told them
about it. If 443/udp is blocked anywhere along the way, browsers stay on HTTP/2
over TCP.

- With `--http3`, juist also proxies the service's HTTP over TCP and offers
  clients HTTP/2. The service still gets every request with its original Host,
  and no `X-Forwarded-For` or any other proxy header. With `--http2` as well,
  juist talks to the service over h2c.
- The status page always offers HTTP/3. A service member offers it for its
  names with `juistd --serve NAME=ADDR --http3`.
- WebSockets stay on HTTP/1.1 over TCP, and juist passes them on unchanged.
- `--proxy` tells the service the client's address on each of its
  connections, as it does over TCP.
- A client whose address changes, such as a phone moving from Wi-Fi to LTE,
  has to connect again.
- Shares are served over TCP only.
- A client that connects from one UDP socket to names on two different
  devices, as Go's HTTP/3 client does, reaches only the first device over
  QUIC.

## Members-only names {#names-for-members-alone}

A name can have a certificate from the CA like any other and still be reachable
only by members of the network, for example the family's photos at
`photos.example.org`:

{{< step on="an admin's device" >}}
```sh
juist publish add nas photos --members
```

It prints `nas: publishes photos.example.org:443 (members)`, and `juist publish`
lists the name with `(members)`.
{{< /step >}}

{{< step on="nas" as="the target" >}}
```sh
juist publish add photos 127.0.0.1:2342
```

juist gets the certificate through the ingress and ends TLS here, as for any
name.

If you add `--members` here too, the service itself is marked as members-only:
juist never sends the name to it while the log lists the name as public.
`juist status` warns about that, and `juist publish` shows the service with
`(members)`. Later commands keep the mark until `--members=false`. A service
member marks its services the same way with `juistd --serve NAME=ADDR --members`.
{{< /step >}}

Without an [access policy]({{< relref "docs/access" >}}), every member can open
the name. With one, only the members a rule names it for can, as
`pass from <family> to name photos` does; a rule to the device, or to `any`,
does not open the name.

- The ingress passes the name to nobody except the CA, which connects to it by
  TLS on 443 to check the name when it issues or renews the certificate.
  Everyone else gets nothing, and the ingress logs `members only`. The name's
  public DNS record still points at the ingress, so that the CA can reach it.
- The device that ends TLS accepts the name only from the members it is meant
  for, recognized by the network address their connection comes from. From the
  ingress it accepts only the CA's check, so a compromised ingress gets no
  further.
- On Linux with systemd-resolved, members reach the name directly at its
  device, like any name on 443. Devices that resolve the network's names
  through public DNS cannot reach it at all: FreeBSD, Linux without
  systemd-resolved (where `juist status` warns about each such name), and the
  Android app.
- The name needs a service of its own. juist does not serve a members-only name
  if another name or a share on the same device reaches the same service with
  its bytes passed through unchanged, because a client of the other name could
  ask the service for the members-only name in its Host header. `juist status`
  reports this. Names whose HTTP juist proxies (`--http3`) are held to their
  own Host and do not count. Let the service listen only on 127.0.0.1, and do
  not forward another device's names to it.
- The device itself cannot reach the name through juist. Otherwise every
  program on it would get in, including one that a client of a public service
  on the same device could make send requests. On that device, reach the
  service at its own address.
- A members-only name is always on 443, by TLS, without `--proxy`. Running
  `juist publish add nas photos` again without `--members` keeps it
  members-only; `--members=false` makes it public.
- Like every certificate, its name appears in the CA's public certificate
  logs. What the name is called is not secret, only what it serves.

## Game servers and other TCP services {#a-game-server-or-another-tcp-service}

A service that does not speak TLS, such as a Minecraft server, gets its own
port on every ingress. The ingress passes each connection on that port straight
to the device without reading any of it.

{{< step on="an admin's device" >}}
```sh
juist publish add nas mc 25565 --tcp
```

This publishes port 25565 of nas on port 25565 of every ingress, as
`mc.example.org`, and prints `nas: publishes mc.example.org:25565/tcp`.
`--tcp=PORT` picks a different public port: `juist publish add nas ssh 22 --tcp=2222`
prints `ssh.example.org:2222/tcp to 22`.
{{< /step >}}

{{< step on="nas" as="the target" >}}
If the service listens on all addresses, its operator agrees with
`juist publish serve`. If it listens only on loopback, juist passes the bytes
on to it unchanged:

```sh
juist publish add mc 127.0.0.1:25565 --tcp
```

It prints `passing mc.example.org to 127.0.0.1:25565`.
{{< /step >}}

Players then connect to `mc.example.org:25565`. Every ingress listens on such a
port as long as a name is published on it, and answers nothing while the device
does not serve it. On Linux, the ingress opens the port in firewalld or ufw
while it runs, and closes it again when the name is removed or the ingress
stops. `juist status` on the ingress lists these ports, and any that another
program holds.

- Only admins can publish a TCP port, as a change to the network. The
  `publish` role shares only on 443.
- Each public port belongs to one name in the network. Ports 80, 443 and
  juist's own ports, 41640 to 41739, are refused, as is a port on which an
  ingress serves a name of its own.
- Members reach the name directly at its device if its public port is the same
  as the device's port and it has no `--proxy`. Otherwise they go through the
  ingress.
- `--proxy` first sends the client's address in a PROXY protocol v2 header,
  which the service must expect. Paper and Velocity do if configured to;
  vanilla Minecraft does not.
- juist does not print an SRV record. Clients that look one up, as Minecraft
  does for a name without a port, find it once you add it at your DNS provider:
  `_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.`
- UDP is not passed on, so Minecraft Bedrock's 19132/udp is not either.

{{< note caution >}}
The ingress sees everything a protocol carries if the protocol does not encrypt
itself, and a CAA record does not help there. Publish this way only what
encrypts itself, as SSH does, or what anyone may see.
{{< /note >}}

## Quick sharing

A device that an admin has given the role `publish` (`juist grant laptop publish`)
can publish under its own name, `laptop.example.org`, without asking an admin
each time:

```sh
juist share ~/photos/2026          # at https://laptop.example.org/RANDOM/, until Ctrl-C
juist publish 8000 --for 2h        # this device's web server on port 8000, for two hours
juist share -b --for 7d ~/talk.pdf # in the background, for a week
juist share                        # lists this device's shares, with their links
juist share --stop ~/talk.pdf      # ends one, by its file, port or link, whichever command holds it
```

A share is reachable only under its random path. Every other path on the name
answers 404, unless a `juist publish PORT` serves it. Entries such as `.git`
stay hidden. A directory is shown as a list, sortable by name, size or date,
and can be downloaded as a ZIP, whole or folder by folder. A folder that holds
an `index.html` shows that page instead.

A share ends when its command ends or when `--for` runs out, after seven days
at most. If the device goes away, the share ends at most ten minutes later.
With `--background` (`-b`), the command returns once the share is up. The share
then keeps running until `juist share --stop` or `--for` ends it, under the same
link even across a restart of juistd. `juist share` lists it with its link, and
`juist status` counts it under `Sharing`.

One certificate for the device's name covers every share, so their paths never
appear in a certificate log. A device holds up to 16 shares at a time, each
under its own path, plus one `juist publish PORT`, which answers every path no
share has. `juist share --stop` without an argument ends the only share; if
several are running, it says to name one. If the device is
[renamed]({{< relref "docs/network-changes" >}}), it shares under its new name,
and `juist share` prints the new link.

## Status page

A device can serve the network's status page under a published name, in this
website's look, light or dark as the browser prefers:

```sh
juist publish status-page status                # at https://status.example.org/
juist publish status-page status --public all   # anyone sees all of it
```

Members see all of it:

- every device with its addresses and roles;
- how the serving device reaches each one (direct, through a relay, sought,
  absent, or outdated where it runs an older juist), and when it last heard
  from it;
- the published names and shares, whether each is up, and `members only` on
  those for members alone;
- what needs attention;
- the log's newest changes.

Everyone else sees what `--public` allows, and never a members-only name:

| `--public` | What non-members see |
|---|---|
| `none` | nothing: the page answers 404 |
| `services`, the default | the published names and shares, and whether each is up |
| `network` | everything but the changes |
| `all` | all of it |

The page recognizes a member by the overlay address its connection comes from.
Anyone who comes through the ingress counts as the public, whatever the ingress
claims. While open, the page refreshes every 15 seconds, so it also works as a
status screen on a phone. Once it has been opened with `https://`, the browser
keeps using https for it.

Devices, published names and changes belong to the network and are the same on
every member. Reach and what needs attention are seen from the serving device,
and the page says which device that is. So serve it from a device that is
always on and reaches the others well. An ingress cannot serve it, because it
holds port 443 itself.

{{< note caution >}}
With `--public network` or `all`, anyone who has the address sees your
devices' names, overlay addresses and roles, and with `all` also who approved
which change. Otherwise only members see that.
{{< /note >}}

Running `juist publish status-page status --public none` again changes what
the public sees, and `juist publish remove status` takes the page down. The
page is a name whose TLS juist ends, as with `juist publish add NAME HOST:PORT`.
A service member serves it with `--serve status=status-page:all`. The reach it
shows is then that of a device the others accept no connections from.

## Names and DNS records

- A published name is either one label under the domain, such as
  `docs.example.org`, or the domain itself, `example.org`, written out in
  full: `juist publish add nas example.org`. A device publishes at most 16 names.
- Only one device can publish the domain itself. The domain needs its own A
  and AAAA records at your DNS provider, pointing at the ingress, because
  `*.example.org` does not cover it. A CAA record on the domain applies to
  every name under it that has no CAA record of its own, so give each device's
  names their own.
- A name with a record of its own, such as the CAA or HTTPS record juist
  prints, no longer gets an address from `*.example.org`. Give it its own A and
  AAAA records too, pointing at the ingress.
- Every member on Linux with systemd-resolved sends queries for the whole
  domain to juistd. juistd answers a name published on 443, or a shared one,
  with its device's address while that device is reachable, so that members
  reach it directly through the tunnel, with the same certificate. All other
  names in the domain are passed on as before, and their answers are cached
  for 30 seconds at most, so that a newly published name is soon reached
  directly. DNSSEC is off for the domain on members
  ([Names]({{< relref "docs/names" >}})).
- `http://` to such a name goes to the device's port 80, where juist redirects
  it to https. If another program listens there on all addresses, that program
  answers instead, and `juist health` warns about it.

## More options

- A service can end TLS itself and hold its own certificate, as it would facing
  the internet. An admin then publishes it with `juist publish add nas docs`,
  on port 443 unless you give another port after the name, and nas's operator
  agrees with `juist publish serve`.
- `--proxy` on `juist publish add` hands the service the client's address in a
  PROXY protocol v2 header. Members then reach the name through the ingress
  too.
- `--http2` on `juist publish add NAME HOST:PORT` offers clients HTTP/2, for a
  service that accepts it without TLS (h2c) as well as HTTP/1.1. A browser then
  opens one connection instead of up to six. A service that only speaks
  HTTP/1.1 fails with it.

## Limits

- An ingress passes up to 16384 connections at a time, 256 from one address
  and 1024 from one /24 or /48. A device where juist ends TLS accepts 8192.
  `--max-conns N`, and for the ingress `--max-per-source N`, change these
  limits: on Linux in a drop-in for `juist-ingress` or `juist-serve`, on
  FreeBSD in `juist_ingress_args` or `juist_serve_args`.
- A client gets 10 seconds to send its TLS hello to the ingress.
- A client that does not answer its service's TLS hello within a minute is
  disconnected, and so is any connection that has been idle in both directions
  for 5 minutes.

## Managing published names

- `juist publish` lists the published names, and where this device sends its
  own. `juist publish remove docs` stops publishing a name on this device,
  `juist publish remove nas docs` on another device.
- `juist publish serve --stop` stops serving but keeps where the names go.
  `juist ingress serve --stop` stops the ingress.
- `juist network domain off` is refused while any device publishes names under
  the domain, and the error names the `juist publish remove` to run first.
- An ingress and juist's own TLS run on Linux and FreeBSD, for the device's
  default network. On FreeBSD, juist leaves pf alone: if the host runs it, the
  host's own rules decide whether 443 (TCP and UDP), 80 and the ports of names
  published by TCP get in.

## The ingress

- An ingress is never a voucher or an exit node, and routes no subnet. It
  cannot share under its own name, and it publishes nothing on 80, 443 or a
  port a name is published on by TCP, because it holds those ports itself. A
  service member holds no other role. `juist grant` names the role that is in
  the way.
- Every member accepts only these from an ingress: connections to the ports
  the member publishes and serves, log sync, replies to connections the member
  opened itself (pings included), and ICMP errors for its own connections.
  Everything else from the ingress is dropped.
- The ingress logs one line for each connection: the client's address and
  port, the name it asked for, the outcome (`spliced`, `not served`,
  `no hello`, `target unreachable`, `refused`), the bytes in each direction and
  how long it lasted. On port 80 it adds the method, path, status and
  User-Agent, and on a port published by TCP the port and the name it goes to.
  Beyond port 80 it sees neither path nor User-Agent, because TLS ends at the
  device.
- A QUIC flow is logged when it ends, as `access: quic`. It is marked
  `not proven` if its client never completed a handshake, which a client with
  a spoofed address cannot do. Lines for such flows, and for refused QUIC
  flows, are limited to one a second, with a count of the lines left out.
- `journalctl -u juist-ingress` shows the log, on FreeBSD
  `/var/log/juist-ingress.log`. It is kept as long as the journal or newsyslog
  keeps it.
- The ingress runs as its own user, `juist-ingress`, holds no key of the
  network, and can ask juistd only one thing: what is published.
- An ingress whose view of the network is stale serves nothing. If its juistd
  stops answering, the names go down within fifteen seconds.
- `juist revoke vps ingress` (or `service`) makes the device an ordinary member
  again, and juist warns about it:
  `warning: vps is confined no more, now a member like any other`. Remove a
  device that may be compromised with `juist remove` instead. Once the ingress
  role is gone, run `juist ingress serve --stop` on the device.

{{< note caution >}}
Whoever controls the ingress can get a certificate for your names and intercept
public clients, as well as members that reach a name through the ingress:
those on a port other than 443, behind `--proxy`, or without systemd-resolved.
Members that resolve a name on 443 to its device connect to it directly. A CAA
record closes this gap. It is a DNS record that says who may issue
certificates for a name, here bound to the target's ACME account.
`juist publish add NAME HOST:PORT` prints it; for a service member, the
terminator's log shows it.
{{< /note >}}

## Troubleshooting

| You see | What to do |
|---|---|
| `the network has no domain to publish under` | run `juist network domain example.org` first |
| on nas, `juist status`: `Published` says `not served here: not agreed to on this device (juist publish serve)` | run `juist publish serve` on nas |
| on vps, `juist status`: `Ingress` says `not running on this device (juist ingress serve)` | run `juist ingress serve` on vps |
| `juist ingress` on vps: `nothing to serve` | no name is published and served yet; if the view is stale, a hint says so |
| `the ingress does not answer on 443: …` | `journalctl -u juist-ingress` shows why; on FreeBSD, `/var/log/juist-ingress.log` |
| `the terminator does not answer on …` | `journalctl -u juist-serve` shows why; on FreeBSD, `/var/log/juist-serve.log` |
| `this device holds no publish role` | an admin runs `juist grant DEVICE publish` |
| `juist status`: `Sharing` says `reached by nobody: the terminator does not run` | `juist share` starts it; `journalctl -u juist-serve` shows why it stopped |
| `juist status`: `Published` says `…, but ends TLS for none: the terminator does not run (juist publish serve)` | run `juist publish serve`; `journalctl -u juist-serve` shows why it stopped |
| `the terminator does not say it listens on …` | it did not start in time; `journalctl -u juist-serve` shows why |
| `juist health`: `warning: another program holds port 80 on …` | members opening `http://NAME` reach that program instead of a redirect to https. Make it listen only on the addresses it serves, and open the name with `https://` until then |
| `juist health`: `warning: no certificate for NAME: …` | the CA issued none, for the reason given. Most often it cannot reach NAME, whose public DNS must point at a running ingress. Until then, clients' TLS fails |
| `juist status`: `warning: not serving NAME, which is for members alone: OTHER reaches its service as it is, …` | OTHER goes to the same service by TCP, or without being proxied, so its clients could ask the service for NAME. Give NAME a service of its own |
| `juist status`: `warning: not serving NAME, its service meant for members alone: the log has the name public` | to publish it for members, an admin runs `juist publish add DEVICE NAME --members`; to make it public, run `juist publish add NAME HOST:PORT --members=false` on the device |
| `juist status`: `warning: NAME, for members alone, is not reached from here, …` | this device resolves the network's names through public DNS, so NAME leads to the ingress, which refuses it. On Linux, use systemd-resolved |
| `another program holds port 443 on …, where juist would end TLS` | stop that program, or publish on another port |
| on vps, `juist status`: `Ingress` says `…; another program holds port 443/udp` | another program, often a web server's own HTTP/3, holds 443/udp on the ingress. Browsers stay on TCP until it lets go; then the ingress takes the port |
| `access: quic … refused: another name's flow from its address` | a client connected from one UDP socket to names on two devices, and the ingress passes that socket on to only one of them. Browsers use a separate socket for each |
| HTTP/3 slower than HTTP/2 under load | the host's UDP buffers are small: `sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000` on the device ending TLS |
| `another program holds port 25565 on …, where juist would pass NAME by TCP` | the service listens on all addresses, including the device's overlay addresses. Publish its port instead, as the hint says, and agree with `juist publish serve` |
| on vps, `juist status`: `Ingress` says `…; another program holds port 22` | a program on the ingress, often its sshd, holds a port a name is published on by TCP. juist then leaves that port to the program and to the firewall's rules. Publish the name on another port with `--tcp=PORT` |
| `this device publishes a port already` | another `juist publish PORT` is running, perhaps in the background: `juist share` lists it, `juist share --stop PORT` ends it |
| `this device holds 16 shares already` | `juist share` lists them; end one with `juist share --stop` |
| `this device is no ingress` | an admin runs `juist grant DEVICE ingress` |
| `warning: the network has no ingress, so nothing reaches it from the internet` | give a device with a public address the role `ingress` |
| `warning: nothing answers on 127.0.0.1:8000 yet` | start the web server that `juist publish 8000` points at |
| `warning: firewalld blocks tcp/443 on juist0, …` | `juist0` is not in firewalld's `trusted` zone, which the package sets up only on its first install. Run the `firewall-cmd` command the hint gives |
