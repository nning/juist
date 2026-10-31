---
title: Your home LAN from anywhere
linkTitle: Your home LAN from anywhere
description: Reach the printer, the router's web interface or the cameras at home from anywhere, although they run no juist, through one member at home.
lead: The printer, the router and the cameras at home will never run juist. One member at home, such as the NAS, passes the network's traffic on to them, and your laptop reaches them from anywhere at their usual addresses.
---

## What you get

Your laptop opens `192.168.1.1` for the router's web interface, prints to
`192.168.1.20` and watches a camera's stream as if it were at home. The NAS
is a [subnet router]({{< relref "docs/subnets" >}}): it takes that traffic
out of the tunnel and passes it on to its LAN. The devices on the LAN see
connections from the NAS and need no configuration.

The example uses the LAN `192.168.1.0/24` and a NAS called `nas`.

## What you need

- A network with the laptop in it ([your first network]({{< relref "docs/first-network" >}})).
- A member at home on Linux, or on FreeBSD with pf, that stays on: a NAS, a
  small server or a Raspberry Pi.
- Laptops on Linux or FreeBSD. The Android app cannot use a subnet router.

## Setting it up

{{< step on="nas" as="the member at home" >}}
[Install juist]({{< relref "docs/install" >}}) and join the network with an
[invite]({{< relref "docs/invites" >}}).
{{< /step >}}

{{< step on="an admin's device" >}}
Have nas route its LAN for the network:

```sh
juist subnet add nas 192.168.1.0/24
```

This is a change to the network that the admins approve.
{{< /step >}}

{{< step on="nas" >}}
Agree to route it:

```sh
juist subnet serve
```

The first time, it asks to run a setup script with sudo. Then it prints
`routing 192.168.1.0/24`.
{{< /step >}}

{{< step on="laptop" >}}
Nothing to set up. `juist subnet` shows the subnet as `in use`.
{{< /step >}}

## Watch out for

- **A LAN with the same addresses wins.** In a hotel whose network is also
  `192.168.1.0/24`, the laptop reaches the hotel's devices, not yours. A less
  common range at home, such as `192.168.73.0/24`, avoids that.
- **Every member reaches the whole LAN.** Without an
  [access policy]({{< relref "docs/access" >}}), that includes the router's
  web interface and every camera. A rule such as
  `pass from laptop to 192.168.1.20` lets a device reach only what it needs.
- **Docker drops routed traffic to its containers.** `juist subnet serve`
  warns when the subnet contains a Docker network.

## Read more

- [Subnet routers]({{< relref "docs/subnets" >}}): every state and reason
  `juist subnet` shows
- [Access policy]({{< relref "docs/access" >}})
- [Exit nodes]({{< relref "docs/exit-nodes" >}}), for the whole internet
  instead of one LAN
