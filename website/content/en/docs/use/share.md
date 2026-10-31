---
title: Share from your laptop
linkTitle: Share from your laptop
description: Put a file, a directory or the web server you are working on onto the internet in one command, under your laptop's own name, as you would with ngrok or cloudflared.
lead: A file for a customer, a directory of photos, the web app you are working on. One command puts it on the internet at https://laptop.example.org, for as long as you choose, with no account at a tunnel provider.
---

## What you get

`juist share` puts a file or a directory at a random link under your
laptop's own name, and `juist publish PORT` does the same for a web server
running on the laptop. This is what ngrok or a cloudflared quick tunnel do,
but under your own domain and through your own ingress. TLS ends on the
laptop, so the ingress never sees the content.

A share ends with its command, when `--for` runs out, or after seven days at
most.

## What you need

- A network with a domain and an ingress, a device with a public address
  that passes connections on. [Publishing services]({{< relref "docs/publishing" >}}#setting-it-up)
  sets both up once, in its first three steps.
- The laptop running Linux or FreeBSD.

## Setting it up

{{< step on="an admin's device" >}}
Let the laptop publish under its own name without asking an admin each
time:

```sh
juist grant laptop publish
```
{{< /step >}}

{{< step on="laptop" >}}
Share a directory, or the web server on port 8000:

```sh
juist share ~/photos/2026
juist publish 8000 --for 2h
```

The first prints its link, `https://laptop.example.org/…/` with a random
path, and runs until Ctrl-C. The second prints
`publishing 127.0.0.1:8000 at https://laptop.example.org, until …`.
With `-b`, a share keeps running in the background until
`juist share --stop` or `--for` ends it.
{{< /step >}}

{{< step on="laptop" >}}
See what is shared, and end it:

```sh
juist share
juist share --stop ~/photos/2026
```
{{< /step >}}

## Watch out for

- **A share is public to anyone who has the link.** The random path keeps
  it from being guessed; every other path answers 404.
- **`juist publish PORT` has no random path.** It answers every path at
  `https://laptop.example.org`, and the name is in the CA's public
  certificate logs, so expect scanners. Publish only a server that may face
  the internet, and give it a `--for`.
- **The laptop is a full member.** If someone breaks into the web server you
  publish, they reach your network from it. For a server that runs for
  longer, use a [service member]({{< relref "docs/service-member" >}}).
- **The share needs the laptop.** When the laptop goes away, its shares end
  at most ten minutes later.

## Read more

- [Quick sharing]({{< relref "docs/sharing" >}}): paths,
  directories as ZIP, limits
- [Publishing services]({{< relref "docs/publishing" >}}): the domain and the
  ingress
