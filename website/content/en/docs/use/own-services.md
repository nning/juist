---
title: Your own services, through the tunnel
linkTitle: Your own services, through the tunnel
description: Reach your mail server, Nextcloud or Git server under its usual name through the tunnel, while the rest of the internet keeps reaching it as before.
lead: Your mail server is mail.example.org, for you and for everyone else. With juist on the server and on your laptop, the laptop reaches the same name through the tunnel. The certificate still matches, and nobody else notices a thing.
---

## What you get

Your mail clients keep `mail.example.org` as their server. On a laptop that
has [public names]({{< relref "docs/names" >}}) turned on, the name leads to
the server's address in the network, so IMAP and submission go through the
tunnel. Where the server cannot be reached through the network, the laptop
falls back to its public address, as it would without juist.

The example uses a mail server called `mail`. A Nextcloud, a Git server or
any other service under its own name works the same way.

## What you need

- A network with the laptop in it ([your first network]({{< relref "docs/first-network" >}})).
- The server running Linux or FreeBSD. With a public address, open
  41643/udp there, `sudo ufw allow juist` or
  `sudo firewall-cmd --permanent --add-service=juist && sudo firewall-cmd --reload`,
  so that devices connect to it directly ([ports]({{< relref "docs/relays" >}})).
- Laptops on Linux or FreeBSD. The Android app does not resolve public names.

## Setting it up

{{< step on="mail" as="the server" >}}
[Install juist]({{< relref "docs/install" >}}) and join the network with an
[invite]({{< relref "docs/invites" >}}). Then leave the server's own DNS as it
was, since the server only has to be reached:

```sh
sudo juist set --dns=false
```

It prints `dns off`. Without this, on a host without systemd-resolved,
juistd answers all of the host's DNS, and the mail server's blocklist, SPF
and DANE lookups would go through it.
{{< /step >}}

{{< step on="an admin's device" >}}
Point the name at the server:

```sh
juist names add mail mail.example.org
```

Add more names the same way, such as `imap.example.org`, up to 32 per
device. Each one is a change to the network that the admins approve.
{{< /step >}}

{{< step on="each laptop" >}}
Turn public names on:

```sh
juist names on
```

It prints `public names on: mail.example.org at mail`. `juist names` shows
how this laptop resolves each name.
{{< /step >}}

## Watch out for

- **Every member reaches every port of the server.** The package lets the
  traffic on `juist0` through ufw and firewalld. Without an
  [access policy]({{< relref "docs/access" >}}), an admin panel, a spam
  filter's web interface or a database that listens on every address is
  then open to every member. A policy limits that, for example:

  ```text
  table <laptops> { laptop, laptop2 }

  pass from <laptops> to mail proto tcp port { 993, 465, 587 }
  ```

  It holds for the whole network: whatever no rule passes is refused
  between all devices.
- **The service has to listen on the server's address in the network.**
  Postfix and Dovecot listen on every address by default. A service bound
  to the public address alone does not answer through the tunnel.
- **Clients now come from the network's addresses**, such as `198.18.36.4`.
  Do not add them to Postfix's `mynetworks` or any other list of trusted
  networks: every member could then send mail without logging in. Rate
  limits and fail2ban see these addresses too.
- **No exit node on the server.** With `juist exit use` there, outgoing mail
  would leave from the exit node's address, and SPF and the reverse DNS
  would no longer match.

## Read more

- [Names]({{< relref "docs/names" >}}): why each device opts in, and how a
  device resolves names
- [Access policy]({{< relref "docs/access" >}})
- [What the package installs]({{< relref "docs/install" >}})
