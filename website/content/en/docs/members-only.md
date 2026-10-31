---
title: Members-only names
linkTitle: Members-only names
description: A published name with a real certificate that only members of the network can open.
lead: A name such as photos.example.org can have a certificate from the CA like any published name and still be reachable only by members of your network.
status: [Linux, FreeBSD]
---

## How it works

The ingress passes a members-only name to nobody except the CA, which checks
the name by TLS on 443 when it issues or renews the certificate. Everyone else
gets nothing, and the ingress logs `members only`. The public DNS record still
points at the ingress, so that the CA can reach it.

The device that ends TLS accepts the name only from the members it is meant
for, recognized by the overlay address their connection comes from. From the
ingress it accepts only the CA's check, so a compromised ingress gets no
further.

You need a domain and an ingress, as
[Publishing services]({{< relref "docs/publishing" >}}#setting-it-up) sets them
up.

## Setting it up

{{< step on="an admin's device" >}}
```sh
juist publish add nas photos --members
```

It prints `nas: publishes photos.example.org:443 (members)`, and
`juist publish` lists the name with `(members)`.
{{< /step >}}

{{< step on="nas" as="the target" >}}
```sh
juist publish add photos 127.0.0.1:2342 --members
```

juist gets the certificate through the ingress and ends TLS here.
`--members` marks the service itself as members-only: juist never sends the
name to it while the log lists the name as public. Later commands keep the
mark until `--members=false`. A service member marks its services with
`juistd --serve NAME=ADDR --members`.
{{< /step >}}

## Who can open it

Without an [access policy]({{< relref "docs/access" >}}), every member can.
With one, only the members a rule names it for, such as
`pass from <family> to name photos`. A rule to the device, or to `any`, does
not open the name.

Members on Linux, FreeBSD and Android reach the name directly at its device.
Devices that resolve the network's names through public DNS cannot reach it.
`juist health` warns about each such name there, and so does the Android app.

## Good to know

- The name needs its own service. juist does not serve a members-only name if
  another name or share on the same device reaches the same service unproxied,
  because that name's clients could ask the service for the members-only name
  in the Host header. Names proxied with `--http3` do not count. Let the
  service listen only on 127.0.0.1.
- The device itself cannot reach the name through juist. Otherwise every
  program on it would get in. On that device, use the service's own address.
- A members-only name is always on 443, by TLS, without `--proxy`. Running
  `juist publish add nas photos` again without `--members` keeps it
  members-only; `--members=false` makes it public.
- The name appears in the CA's public certificate logs, like every
  certificate. The name is not secret, only what it serves.

## Troubleshooting

| You see | What to do |
|---|---|
| `juist health`: `warning: not serving NAME, which is for members alone: OTHER reaches its service as it is, …` | OTHER reaches the same service by TCP or unproxied. Give NAME its own service. |
| `juist health`: `warning: not serving NAME, its service meant for members alone: the log has the name public` | To publish it for members, an admin runs `juist publish add DEVICE NAME --members`. To make it public, run `juist publish add NAME HOST:PORT --members=false` on the device. |
| `juist health`: `warning: NAME, for members alone, is not reached from here, …` | This device resolves the network's names through public DNS, so NAME leads to the ingress, which refuses it. The rest of `juist health` says why. |
