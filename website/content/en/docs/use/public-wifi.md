---
title: Safe on public Wi-Fi
linkTitle: Safe on public Wi-Fi
description: In a café, a hotel or on a train, send your internet traffic and DNS through your own VPS or your connection at home, so the Wi-Fi sees only encrypted traffic.
lead: The café's Wi-Fi does not need to see where you go. Your laptop or phone sends its internet traffic through the tunnel to your own VPS or your connection at home, and goes online from there.
---

## What you get

On the café's Wi-Fi, your laptop sends its internet traffic and its DNS to a
member of your network, the [exit node]({{< relref "docs/exit-nodes" >}}),
which sends it on. The Wi-Fi sees only encrypted traffic to the exit node.
Websites see the exit node's address: your VPS's, or your own at home.

The example uses a VPS called `vps`. A NAS or a small server at home works
the same way.

## What you need

- A network with the laptop or phone in it ([your first network]({{< relref "docs/first-network" >}})).
- A member that stays on, on Linux or on FreeBSD with pf, to be the exit node.
- On the device you travel with: Linux, FreeBSD or the
  [Android app]({{< relref "docs/android" >}}).

## Setting it up

{{< step on="an admin's device" >}}
Give the VPS the role:

```sh
juist grant vps exit
```

This is a change to the network that the admins approve.
{{< /step >}}

{{< step on="vps" as="the exit node" >}}
Agree to carry the network's internet traffic:

```sh
juist exit serve
```

The first time, it asks to run a setup script with sudo. Then it prints
`serving as an exit node`.
{{< /step >}}

{{< step on="laptop" >}}
On the café's Wi-Fi:

```sh
juist exit use vps
```

It prints `internet via vps`, and the `Exit node` line in `juist status` says
`vps, DNS too`. Back home, `juist exit off` goes direct again and prints
`internet direct`. On a phone, choose `vps` under **Internet** on the app's
status screen.
{{< /step >}}

## Watch out for

- **Log in to the Wi-Fi's portal first.** While the exit node cannot be
  reached, the laptop's internet traffic is blocked, not sent directly.
- **When the exit node is down, so is your internet.** That is on purpose:
  nothing leaves past it. `juist exit off` sends the traffic directly again.
- **The exit node sees what you send through it**, as any VPN provider would.
  Choose a device you trust.
- **Your LAN and the network's devices stay direct**, and so do replies to
  connections from the internet, such as an ssh session to the laptop.
  `juist exit use vps --isolate` sends those replies through the exit node as
  well.

## Read more

- [Exit nodes]({{< relref "docs/exit-nodes" >}}): what goes through the exit
  node, and every reason it cannot be used
- [Android]({{< relref "docs/android" >}}#through-an-exit-node): an exit node
  on the phone
- [Access policy]({{< relref "docs/access" >}}): which devices may use which
  exit node
