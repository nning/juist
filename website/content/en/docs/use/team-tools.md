---
title: Tools for members alone
linkTitle: Tools for members alone
description: Run a wiki, a dashboard or another internal tool under a real name with a real certificate that only members of your network can open.
lead: The team's wiki is wiki.example.org, with a certificate every browser trusts, on laptops and phones alike. The internet gets nothing from it, and the access policy says which members may open it.
---

## What you get

A **members-only name** has a certificate from Let's Encrypt like any
published name, so browsers open it without a warning and the link is the
same everywhere. Only members reach it. They connect through the tunnel
directly to the device that runs the tool, and that device accepts the name
only from the members it is meant for. The ingress passes the name to
nobody but the CA, which checks it when it issues the certificate.

## What you need

- A network with a domain and an ingress.
  [Publishing services]({{< relref "docs/publishing" >}}#setting-it-up) sets
  both up once, in its first three steps.
- The tool on a device running Linux or FreeBSD, `tools` here, listening
  only on `127.0.0.1:3000`.
- Members on Linux, FreeBSD or Android.

## Setting it up

{{< step on="an admin's device" >}}
Publish the name for members alone:

```sh
juist publish add tools wiki --members
```

It prints `tools: publishes wiki.example.org:443 (members)`.
{{< /step >}}

{{< step on="tools" as="the target" >}}
Say where the decrypted connections go, and mark the service as for members
alone, so that juist never sends it a public name:

```sh
juist publish add wiki 127.0.0.1:3000 --members
```
{{< /step >}}

{{< step on="an admin's device" >}}
Without an access policy every member opens the name. To limit it, name it
in a rule:

```text
table <team> { laptop, laptop2, phone }

pass from <team> to name wiki
```

and set the policy with `juist policy set policy.conf`. A rule to the device
or to `any` does not open the name.
{{< /step >}}

## Watch out for

- **The policy holds for the whole network.** Once one is set, whatever no
  rule passes is refused between all devices, not only for the wiki.
- **The name is not secret.** Like every certificate's, it appears in the
  CA's public certificate logs. What it serves stays with the members.
- **The tool needs a service of its own.** If another name or a share on the
  same device reaches the same service, juist does not serve the
  members-only name, and `juist health` says why.
- **`tools` itself does not reach the name through juist.** Open the tool
  there at `127.0.0.1:3000`.
- **A member that does not resolve the network's names does not reach it.**
  `juist health` on that member warns about the name and says why.

## Read more

- [Members-only names]({{< relref "docs/members-only" >}})
- [Access policy]({{< relref "docs/access" >}})
- [Names]({{< relref "docs/names" >}})
