---
title: Publishing services
linkTitle: Publishing services
description: Make a service on one of your devices, such as a NAS at home, reachable from the internet by name.
lead: A service on a member, such as a NAS at home, becomes reachable from the internet by name. A device with a public address passes the connections on, and TLS ends at the member.
status: [Linux, FreeBSD]
---

## How it works

Say you run a document server on your NAS and want to open it as
`docs.example.org` from any browser. Your router opens no port, and its
address appears in no public record.

An **ingress** is a member with a public address, such as a small VPS, that an
admin gave the role `ingress`. It accepts connections on port 443, reads the
name the client asks for, and passes the connection through the tunnel to the
member that publishes the name.

{{< flow publish >}}

The ingress does not decrypt TLS. TLS ends on the NAS, with a certificate from
Let's Encrypt, and the NAS passes the connection on to the service. One ingress
serves every name in the network.

Every way of publishing needs a domain and an ingress. Steps 1 to 3 below set
them up once.

| To publish | See |
|---|---|
| a web service on a member | [Setting it up](#setting-it-up) |
| a server you do not trust inside your network | [Service members]({{< relref "docs/service-member" >}}) |
| a name only members can open | [Members-only names]({{< relref "docs/members-only" >}}) |
| a game server or another service without TLS | [TCP services]({{< relref "docs/tcp-services" >}}) |
| a file, a directory or a local web server, right away | [Sharing]({{< relref "docs/sharing" >}}) |
| an overview of the network's devices | [Status page](#status-page) |

## Setting it up

{{< step on="an admin's device" >}}
Set the network's domain and give the VPS the role:

```sh
juist network domain example.org
juist grant vps ingress
```

`juist invite vps --ingress` admits a new device as the ingress right away.
{{< /step >}}

{{< step on="your DNS provider's website" >}}
Point `*.example.org` at the VPS's public address, or only `docs.example.org`.
{{< /step >}}

{{< step on="vps" as="the ingress" >}}
```sh
juist ingress serve
```

It asks for sudo once and starts the `juist-ingress` service. On Linux, it
opens 443 (TCP and UDP) and 80 in firewalld or ufw. On FreeBSD, the host's pf
rules decide. Port 80 only redirects to https.
{{< /step >}}

{{< step on="nas" as="the target" >}}
The NAS's [operator]({{< relref "docs/operator" >}}) publishes the name and
says where the connection goes:

```sh
juist publish add docs 127.0.0.1:8080
```

juist gets a certificate through the ingress and ends TLS on the NAS. The
command prints `nas: publishes docs.example.org:443`, `serving docs.example.org`
and `ending TLS for docs.example.org to 127.0.0.1:8080`. Then it prints the
name's [CAA record](#protecting-the-certificate). The first time, it also warns:
`warning: a server published from this device reaches the network and its LAN once compromised`.

Publishing is a change only admins can make. If the NAS holds no admin key, it
prints `docs.example.org goes to 127.0.0.1:8080 once published on this device`
and the command for an admin: `juist publish add nas docs.example.org`. If a
change needs more than one admin, it waits for the others
([how changes are approved]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist grant` and `juist publish add` print the next step and the device it
runs on. If you run them as that device's operator, on that device, they do
that step too.

{{< note danger >}}
If someone breaks into a server published from a full member, they can reach
the network and the member's LAN. From a full member, publish only what you
would put on the internet anyway. For anything else, use a
[service member]({{< relref "docs/service-member" >}}).
{{< /note >}}

## Protecting the certificate

Whoever controls the ingress can get a certificate for your names and
intercept public clients. This also affects members that reach a name through
the ingress: on a port other than 443, behind `--proxy`, or on devices that do
not resolve the network's names. Members that resolve a name on 443 to its
device connect to it directly.

A **CAA record** closes this gap. It is a DNS record that allows only the
target's ACME account to get certificates for the name. Add it at your DNS
provider:

- `juist publish add NAME HOST:PORT` prints it.
- `juist publish serve`, run by the device's operator, prints it again.
- The terminator's log has it too: `journalctl -u juist-serve`, on FreeBSD
  `/var/log/juist-serve.log`. A service member prints it in its own log.

A CAA record on the domain applies to every name under it that has none of its
own, so give each device's names their own record.

## Names and DNS records

- A name is one label under the domain, such as `docs.example.org`, or the
  domain itself, written out: `juist publish add nas example.org`. A device
  publishes at most 16 names.
- Only one device can publish the domain itself. The domain needs its own A
  and AAAA records pointing at the ingress, because `*.example.org` does not
  cover it.
- A name with a record of its own, such as the CAA or HTTPS record juist
  prints, no longer gets an address from `*.example.org`. Give it its own A
  and AAAA records too.
- Members on Linux and FreeBSD resolve the domain through juistd. A name on
  443, or a shared one, resolves to its device while that device is
  reachable, so members reach it directly through the tunnel. DNSSEC is off
  for the domain on members ([Names]({{< relref "docs/names" >}})).
- `http://NAME` reaches port 80 on the device, where juist redirects to
  https. If another program listens there on all addresses, it answers
  instead, and `juist health` warns about it.

## HTTP/3

For a name whose TLS juist ends and whose service speaks HTTP, browsers can
use HTTP/3, which is QUIC on 443/udp:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

The command prints a DNS record to add: `docs.example.org. HTTPS 1 . alpn="h3,h2"`.
With it, browsers use HTTP/3 from the first request. Without it, they use it
from the second, once juist's `Alt-Svc` header has told them. If 443/udp is
blocked on the way, browsers stay on HTTP/2 over TCP.

- With `--http3`, juist proxies the service's HTTP and also offers HTTP/2. The
  service sees each request's original Host and no proxy headers. With
  `--http2` as well, juist talks h2c to the service.
- WebSockets stay on HTTP/1.1 over TCP.
- A client whose address changes, such as a phone moving from Wi-Fi to LTE,
  connects again.
- A service member offers HTTP/3 with `juistd --serve NAME=ADDR --http3`. The
  status page always offers it. Shares use TCP only.

## More options

- A service can end TLS itself, with its own certificate. An admin publishes
  it with `juist publish add nas docs`, on port 443 unless you give another
  port, and the NAS's operator agrees with `juist publish serve`.
- `--proxy` sends the client's address to the service in a PROXY protocol v2
  header, over HTTP/3 too. Members then reach the name through the ingress.
- `--http2` offers clients HTTP/2, for a service that accepts it without TLS
  (h2c). A service that only speaks HTTP/1.1 fails with it.

## Status page

A device can serve the network's status page under a published name:

```sh
juist publish status-page status                # at https://status.example.org/
juist publish status-page status --public all   # anyone sees all of it
```

Members see all of it: the devices with their addresses, roles and schema, how
the serving device reaches each one, the published names and shares, what
needs attention, and the log's newest changes. Everyone else sees what
`--public` allows, and never a members-only name:

| `--public` | What non-members see |
|---|---|
| `none` | nothing: the page answers 404 |
| `services`, the default | the published names and shares, and whether each is up |
| `network` | everything but the changes |
| `all` | all of it |

- The page recognizes a member by the overlay address its connection comes
  from. Anyone who comes through the ingress counts as the public.
- Reach and warnings are seen from the serving device, so serve the page from a
  device that is always on. An ingress cannot serve it.
- Run the command again with another `--public` to change it.
  `juist publish remove status` takes the page down.
- A service member serves it with `--serve status=status-page:all`.

{{< note caution >}}
With `--public network` or `all`, anyone who has the address sees your
devices' names, overlay addresses and roles. With `all`, they also see who
approved which change.
{{< /note >}}

## Managing published names

- `juist publish` lists the published names, and where this device sends its
  own.
- `juist publish remove docs` stops publishing a name on this device,
  `juist publish remove nas docs` on another device.
- `juist publish serve --stop` stops serving but keeps where the names go.
  `juist ingress serve --stop` stops the ingress.
- `juist network domain off` is refused while devices publish names under the
  domain. The error names the `juist publish remove` to run first.
- An ingress and juist's TLS run on Linux and FreeBSD, for the device's
  default network.

## The ingress

- An ingress has no other role: it is no voucher or exit node and routes no
  subnet. It cannot share, and publishes nothing on 80, 443 or a port that a
  name is published on by TCP, because it holds those ports itself.
  `juist grant` names the role in the way.
- Members accept only this from an ingress: connections to the ports they
  publish and serve, log sync, and replies to their own connections. They drop
  everything else.
- It runs as its own user, `juist-ingress`, holds no key of the network, and
  can ask juistd only what is published.
- An ingress whose view of the network is stale serves nothing. If its juistd
  stops answering, the names go down within 15 seconds.
- It logs one line per connection: the client's address, the name, the
  outcome, the bytes and the duration. See `journalctl -u juist-ingress`, on
  FreeBSD `/var/log/juist-ingress.log`.
- `juist revoke vps ingress` makes the device an ordinary member again, with a
  warning. Remove a device that may be compromised with `juist remove`
  instead. Then run `juist ingress serve --stop` on it.

## Limits

- An ingress passes up to 16384 connections at a time: 256 from one IPv4
  address or IPv6 /64, and 1024 from one IPv4 /24 or IPv6 /48. A device where
  juist ends TLS accepts 8192.
- `--max-conns N`, and on the ingress `--max-per-source N`, change these
  limits: on Linux in a drop-in for `juist-ingress` or `juist-serve`, on
  FreeBSD in `juist_ingress_args` or `juist_serve_args`.
- A client gets 10 seconds to send its TLS hello to the ingress, and a minute
  to answer its service's. A connection idle in both directions for 5 minutes
  is closed.

## Troubleshooting

| You see | What to do |
|---|---|
| `the network has no domain to publish under` | Run `juist network domain example.org` first. |
| `this device is no ingress` | An admin runs `juist grant DEVICE ingress`. |
| `warning: the network has no ingress, so nothing reaches it from the internet` | Give a device with a public address the role `ingress`. |
| on vps, `juist status`: `Ingress` says `not running on this device (juist ingress serve)` | Run `juist ingress serve` on vps. |
| `juist ingress` on vps: `nothing to serve` | No name is published and served yet. If the view is stale, a hint says so. |
| on nas, `juist status`: `Published` says `none (ready to serve)` | No name is published on nas yet. An admin runs `juist publish add nas immich`. |
| on nas, `juist status`: `Published` says `immich.example.org (not served)` | Run `juist publish serve` on nas. |
| `juist status`: `Published` says `…, but ends TLS for none: the terminator does not run (juist publish serve)` | Run `juist publish serve`. `journalctl -u juist-serve` shows why it stopped. |
| `the ingress does not answer on 443: …` | `journalctl -u juist-ingress` shows why, on FreeBSD `/var/log/juist-ingress.log`. |
| `the terminator does not answer on …` or `does not say it listens on …` | `journalctl -u juist-serve` shows why, on FreeBSD `/var/log/juist-serve.log`. |
| `another program holds port 443 on …, where juist would end TLS` | Stop that program, or publish on another port. |
| `juist health`: `warning: another program holds port 80 on …` | Members opening `http://NAME` reach that program instead of a redirect. Make it listen only on the addresses it serves. |
| `juist health`: `warning: no certificate for NAME: …` | The CA issued none, for the reason given. Most often it cannot reach NAME: its public DNS must point at a running ingress. |
| `warning: firewalld blocks tcp/443 on juist0, …` | `juist0` is not in firewalld's `trusted` zone. Run the `firewall-cmd` command from the hint. |
| on vps, `juist status`: `Ingress` says `…; another program holds port 443/udp` | Another program, often a web server's own HTTP/3, holds 443/udp. Browsers stay on TCP until it lets go. |
| `access: quic … refused: another name's flow from its address` | A client used one UDP socket for names on two devices. The ingress passes such a socket on to one device only. Browsers use one socket per name. |
| HTTP/3 slower than HTTP/2 under load | The host's UDP buffers are small: `sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000` on the device ending TLS. |
