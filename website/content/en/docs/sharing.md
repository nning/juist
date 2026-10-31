---
title: Sharing
linkTitle: Sharing
description: Share a file, a directory or a local web server on the internet right away, under the device's own name.
lead: A device with the publish role shares a file, a directory or a local web server under its own name, without asking an admin each time.
status: [Linux, FreeBSD]
---

## Setting it up

You need a domain and an ingress, as
[Publishing services]({{< relref "docs/publishing" >}}#setting-it-up) sets them
up. Then an admin gives the device the role once:

```sh
juist grant laptop publish
```

The laptop then shares under `laptop.example.org`:

```sh
juist share ~/photos/2026          # at https://laptop.example.org/RANDOM/, until Ctrl-C
juist publish 8000 --for 2h        # this device's web server on port 8000, for two hours
juist share -b --for 7d ~/talk.pdf # in the background, for a week
juist share                        # lists this device's shares, with their links
juist share --stop ~/talk.pdf      # ends one, by its file, port or link
```

## What others see

- A share is reachable only under its random path. Every other path answers
  404, unless a `juist publish PORT` serves it. Entries such as `.git` stay
  hidden.
- A directory is shown as a list, sortable by name, size or date, and
  downloads as a ZIP, whole or folder by folder. A folder with an
  `index.html` shows that page instead.
- One certificate for the device's name covers every share, so the paths
  never appear in a certificate log.

## How long a share lasts

- A share ends when its command ends, or when `--for` runs out, after seven
  days at most. If the device goes away, the share ends within ten minutes.
- With `--background` (`-b`), the command returns once the share is up. The
  share runs until `juist share --stop` or `--for` ends it, under the same
  link even across a restart of juistd.
- `juist share` lists the shares with their links, and `juist status` counts
  them under `Sharing`.

## Limits

- A device holds up to 16 shares, each under its own path, plus one
  `juist publish PORT`, which answers every path no share has.
- `juist share --stop` without an argument ends the only share. If several
  run, it asks you to name one.
- If the device is [renamed]({{< relref "docs/network-changes" >}}), it shares
  under its new name, and `juist share` prints the new link.
- Shares use TCP only, not HTTP/3.

## Troubleshooting

| You see | What to do |
|---|---|
| `this device holds no publish role` | An admin runs `juist grant DEVICE publish`. |
| `this device publishes a port already` | Another `juist publish PORT` runs, perhaps in the background. `juist share` lists it; `juist share --stop PORT` ends it. |
| `this device holds 16 shares already` | `juist share` lists them. End one with `juist share --stop`. |
| `warning: nothing answers on 127.0.0.1:8000 yet` | Start the web server that `juist publish 8000` points at. |
| `juist status`: `Sharing` says `reached by nobody: the terminator does not run` | `juist share` starts it. `journalctl -u juist-serve` shows why it stopped. |
