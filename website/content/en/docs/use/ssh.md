---
title: Servers without open SSH
linkTitle: Servers without open SSH
description: Close port 22 to the internet and reach your servers by ssh through the tunnel, by name, from the devices you allow.
lead: Port 22 on a server with a public address draws login attempts all day. With juist on the server and on your laptop, ssh goes through the tunnel, and the port can close to the internet.
---

## What you get

Your laptop reaches the server as `ssh server`, or `ssh server.home.juist` in
the network `home`, through the tunnel. To the internet, port 22 is closed:
nobody outside the network can even try a password or a key. With an
[access policy]({{< relref "docs/access" >}}), only the devices you choose
reach port 22 through the tunnel too.

The example uses a server called `server` in the network `home`.

## What you need

- A network with the laptop in it ([your first network]({{< relref "docs/first-network" >}})).
- The server on Linux or FreeBSD. Open 41643/udp there, `sudo ufw allow juist`
  or `sudo firewall-cmd --permanent --add-service=juist && sudo firewall-cmd --reload`,
  so that devices connect to it directly ([ports]({{< relref "docs/relays" >}})).
- A way in that does not need ssh, such as your provider's web console or
  rescue system, in case juist stops on the server.

## Setting it up

{{< step on="server" >}}
[Install juist]({{< relref "docs/install" >}}) and join the network with an
[invite]({{< relref "docs/invites" >}}).
{{< /step >}}

{{< step on="laptop" >}}
Check that ssh works through the tunnel, before you close anything:

```sh
ssh server
```
{{< /step >}}

{{< step on="server" >}}
Close port 22 to the internet: remove the rule that opens it, such as
`sudo ufw delete allow OpenSSH`, or
`sudo firewall-cmd --permanent --remove-service=ssh && sudo firewall-cmd --reload`,
and in your provider's firewall, if it has one. The package lets the traffic
on `juist0` through ufw and firewalld, so ssh through the tunnel keeps
working. Leave sshd listening on every address.
{{< /step >}}

## Watch out for

- **juist is now your way in.** If juistd stops on the server, or the
  network removes it, only the provider's console gets you in. `juist health`
  on the server says what needs attention before it comes to that.
- **A stale server keeps tunnels only to vouchers.** In a network with
  vouchers, a server that has heard from none for 48 hours drops the tunnel
  to your laptop. `juist health` warns a day ahead
  ([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)).
- **Every member reaches port 22.** Without an access policy, any device in
  the network can try to log in. A rule such as
  `pass from laptop to server proto tcp port 22` limits that to the laptop.
  The policy holds for the whole network, and it refuses whatever no rule
  passes.
- **A hand-made firewall must let 22 through on `juist0`**, and the log's
  sync on TCP 41644 there ([firewalls]({{< relref "docs/relays" >}}#firewalls)).

## Read more

- [Names]({{< relref "docs/names" >}}): how devices resolve `server` and
  `server.home.juist`
- [Access policy]({{< relref "docs/access" >}})
- [Status and devices]({{< relref "docs/status" >}}): `juist status` and
  `juist health`
