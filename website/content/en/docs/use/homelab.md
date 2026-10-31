---
title: A homelab on the internet
linkTitle: A homelab on the internet
description: Make a service on your NAS or home server reachable from the internet by name, behind CGNAT or DS-Lite, without forwarding a port on your router.
lead: Your provider gives you no public IPv4 address, or you would rather not open a port at home. A small VPS in your network takes the connections for docs.example.org and passes them through the tunnel to your NAS, where TLS ends.
---

## What you get

`docs.example.org` opens in any browser, served by the NAS at home. The
NAS connects out to the VPS, so your router opens no port and its address
appears in no public DNS record. The VPS, the **ingress**, reads only the
name a browser asks for and passes the connection on. TLS ends on the NAS,
with a certificate from Let's Encrypt, so the ingress never sees the content.

Members of the network skip the ingress and reach the name directly at the
NAS, through the tunnel.

## What you need

- A domain, `example.org` here, and access to its DNS records.
- A VPS with a public address, running Linux or FreeBSD, in the network.
  Open 41643/udp on it, `sudo ufw allow juist`, so that the NAS connects to
  it directly ([ports]({{< relref "docs/relays" >}}#ports)).
- The NAS running Linux or FreeBSD, with the service on a local port,
  `127.0.0.1:8080` here.

## Setting it up

{{< step on="an admin's device" >}}
Set the network's domain and make the VPS the ingress:

```sh
juist network domain example.org
juist grant vps ingress
```
{{< /step >}}

{{< step on="your DNS provider's website" >}}
Point `*.example.org` at the VPS's public address, or only
`docs.example.org`.
{{< /step >}}

{{< step on="vps" as="the ingress" >}}
```sh
juist ingress serve
```

It asks for sudo once, starts the ingress and opens 443 and 80 in firewalld
or ufw.
{{< /step >}}

{{< step on="nas" as="the target" >}}
Publish the name, with HTTP/3 for browsers that can use it:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

It prints `ending TLS for docs.example.org to 127.0.0.1:8080, with HTTP/3`,
then two DNS records to add at your DNS provider. The HTTPS record lets
browsers start with HTTP/3. The CAA record binds the name's certificates to
this device's ACME account.
{{< /step >}}

## Watch out for

- **Add the CAA record.** Without it, whoever controls the ingress could get
  a certificate for your name and read the traffic of visitors from the
  internet.
- **A published server reaches your network once compromised.** The NAS is a
  full member. Publish from it only what you would put on the internet
  anyway, and run anything else as a
  [service member]({{< relref "docs/service-member" >}}),
  which no device accepts connections from.
- **The ingress sees the name, the client's address, sizes and timing**, and
  logs one line per connection.
- **Publishing is an admin's change.** If the NAS holds no admin key, the
  command prints the one an admin runs.

## Read more

- [Publishing services]({{< relref "docs/publishing" >}}): every option, the
  ingress, limits
- [HTTP/3]({{< relref "docs/publishing" >}}#http3)
- [Game servers and other TCP services]({{< relref "docs/tcp-services" >}})
