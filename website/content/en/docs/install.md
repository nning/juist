---
title: Install
linkTitle: Install
description: Install juist's released package on Debian, Ubuntu, Fedora or FreeBSD, check the download, or build the package from source.
lead: Install juist as a system package on every device that should be in a network. Each release comes with ready-made packages and a signed list of their checksums.
---

## Supported systems

juist runs on Linux and FreeBSD. It comes as a `.deb` for Debian and Ubuntu,
an RPM for Fedora, and a pkg package for FreeBSD 15. Every
[release](https://github.com/nning/juist/releases/latest) has packages for
amd64 and arm64, except the RPM, which is only available for x86_64. A phone
joins with the app instead; see [Android]({{< relref "docs/android" >}}).

## Installing the package

{{< step on="a Debian or Ubuntu device" >}}
Download the package and install it:

```sh
curl -LO https://github.com/nning/juist/releases/latest/download/juist_amd64.deb
sudo apt install ./juist_amd64.deb
```

On arm64, use `juist_arm64.deb`.
{{< /step >}}
{{< step on="a Fedora device" >}}
Install the package:

```sh
sudo dnf install https://github.com/nning/juist/releases/latest/download/juist.x86_64.rpm
```
{{< /step >}}
{{< step on="a FreeBSD 15 device" >}}
As root, install the package with pkg, then start the daemon:

```sh
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd15-amd64.pkg
sysrc juistd_enable=YES && service juistd start
```

On arm64, use `juist-freebsd15-aarch64.pkg`. On Linux the package starts the
daemon itself; on FreeBSD you start it once, as shown above.

On FreeBSD, juistd runs pf with rules of its own, which keep the device's
network addresses to the tunnel: the LAN does not reach them. If the host
loads pf rules of its own, `/etc/pf.conf` has to call juist's anchors,
`nat-anchor "juist/*"`, `rdr-anchor "juist/*"` and `anchor "juist/*"`, before
any rule that passes `quick`; otherwise `juist health` warns.
{{< /step >}}

Installing a newer release later replaces the old one, and the device keeps
its state; [Updating juist]({{< relref "docs/updating" >}}) has the details.

## Verifying a download

Each release lists the SHA-256 checksums of its files in `SHA256SUMS`, signed
with the key in [packaging/release-signers](https://github.com/nning/juist/blob/main/packaging/release-signers).
Put that file, the download, `SHA256SUMS` and `SHA256SUMS.sig` in one
directory and run:

```sh
ssh-keygen -Y verify -f release-signers -I juist -n juist-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

The first command prints `Good "juist-release" signature for juist with ED25519 key
SHA256:a2nq8txrPWVfLfF4XGzyKrFo4t71aXkcDOGZNQJABLM`, the second prints `OK`
for each file you downloaded.

## Building from source

Building needs Go 1.21 or newer and `make`. `make` has Go download go1.27.3
and builds with it, so that a given commit produces the same bytes on any
machine.

```sh
git clone https://github.com/nning/juist
cd juist
make install      # gmake install, as root, on FreeBSD
```

`make install` builds the package for the system it runs on (the `.deb` on
Debian and Ubuntu, the RPM on Fedora, the pkg package on FreeBSD) and installs
it. Run it again later to install a new build over the old one.

To install juist on a machine that should not build it, build only the package
and copy it over:

| System | Build | Install on the other machine |
|---|---|---|
| Debian, Ubuntu | `make deb` | `sudo apt install ./juist_*.deb` |
| Fedora | `make rpm` | `sudo dnf install ./juist-*.rpm` |
| FreeBSD | `make pkg-freebsd` | `pkg add ./juist-*.pkg` |

The packages end up in `build/deb`, `build/rpm/RPMS` and `build/freebsd`.
`make deb DEB_ARCH=arm64` builds the `.deb` for another architecture; `armhf`
and `i386` work the same way.

## In a container

An app in a container can be a device of its own, with its own addresses and
its own place in the [access policy]({{< relref "docs/access" >}}): juistd
runs in a second container that shares the app's network namespace and makes
`juist0` there. Whatever the app opens to a member's address goes through the
tunnel. The image comes from `make image` in the source tree, followed by
`docker load`.

{{< step on="an admin's device" >}}
```sh
juist invite app
```
{{< /step >}}

{{< step on="the container host" >}}
In a `compose.yaml`, a service of its own, `netns`, holds the namespace, so
that juist and the app keep it when either restarts; `JUIST_JOIN` takes the
invite link:

```yaml
services:
  netns:
    image: registry.k8s.io/pause:3.10
    restart: unless-stopped
  juist:
    image: juist:VERSION
    network_mode: service:netns
    user: "0:0"
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun]
    environment:
      JUIST_JOIN: "juist:…"
    volumes:
      - type: volume
        source: juist
        target: /var/lib/juist
        volume:
          nocopy: true
    restart: unless-stopped
  app:
    image: …   # the app
    network_mode: service:netns
    depends_on: [juist]
    restart: unless-stopped
volumes:
  juist: {}
```

```sh
docker compose up -d
```

`docker compose logs juist` shows how the join went, and
`docker compose exec juist juist status` the device's addresses. Once
joined, the link is spent and `JUIST_JOIN` ignored.
{{< /step >}}

- juistd needs `CAP_NET_ADMIN` and `/dev/net/tun`, not `privileged`. Docker
  gives a capability to root alone, so juistd runs as root there, with no other
  capability, on a volume of root's: `nocopy` keeps the image's user from
  owning it. Podman gives it to the image's own user; add the example's
  `compose.podman.yaml` there.
- The network's names do not resolve in the containers, which have no
  systemd-resolved, and `juist health` says so. Use the addresses
  `juist devices` lists, or put names in the namespace's `/etc/hosts` with
  `extra_hosts` on `netns`, with the IPv6 address, which renumbering does not
  change.
- If `netns` restarts, `docker compose restart netns` restarts juist and the
  app with it; they are left in its old namespace otherwise.
- A Tailscale container in userspace mode can hold the namespace instead of
  `netns`, with `network_mode: service:tailscale`; the two do not get in each
  other's way.

The same with comments, an `.env` and Podman's override:
[examples/sidecar](https://github.com/nning/juist/tree/main/examples/sidecar)
in the repository.

## What the package installs

- The command `juist` and the daemon `juistd`.
  [How juist works]({{< relref "docs/how-it-works" >}}) explains which does
  what.
- On Linux, the `juistd` service. It starts right away and waits until you
  create or join a network. It runs as the user `juist`, with only
  `CAP_NET_ADMIN`, plus `CAP_NET_BIND_SERVICE` on a
  [relay on port 443]({{< relref "docs/relays" >}}). Further networks run as
  the users `juist1` to `juist9`, which the package also creates.
- On Linux, two more services: `juist-ingress` for an
  [ingress]({{< relref "docs/publishing" >}}), started by
  `juist ingress serve`, and `juist-serve`, juist's TLS terminator, which
  systemd starts when `juist publish` or `juist share` needs it.
- Firewall profiles for ufw and firewalld: `juist`, `juist-relay`,
  `juist-relay-443`, `juist-invite` and `juist-ingress`. If ufw or firewalld
  runs, the package also allows traffic on `juist0`, which log sync and
  published services need. It does this only on the first install, so an
  upgrade leaves your firewall alone.
- A polkit rule that lets juistd set the network's DNS through
  systemd-resolved. It needs polkit, which the package recommends; minimal
  installs such as Fedora Cloud lack it. On Ubuntu 22.04, whose polkit reads
  no rules, the .deb puts the same permission in
  `/var/lib/polkit-1/localauthority/10-vendor.d/60-juist.pkla`.
- Shell completion for bash, zsh and fish, and the man pages `juist(1)` and
  `juistd(8)`.

To check that the daemon is running:

```console {device="nas"}
$ juist status
nas · no network
```

Next, [create your first network]({{< relref "docs/first-network" >}}).

## Uninstalling

To leave a network but keep juist installed, run `juist reset` instead; see
[Removing a device]({{< relref "docs/remove" >}}).

If the device is in a network, take it out of the network first, so that the
network does not keep listing it: an admin runs `juist remove nas` on their
own device. Then remove the package:

```sh
sudo apt remove juist      # Debian, Ubuntu
sudo dnf remove juist      # Fedora
pkg delete juist           # FreeBSD, as root
```

This stops juistd for every network on the device and undoes what juist set
up on the host. On Linux, that is the firewall rule for `juist0`, an ingress,
a relay on port 443, and the changes made by `juist exit serve`.

## What stays after uninstalling

- On Linux, the device's keys and log stay in `/var/lib/juist`, a further
  network's in `/var/lib/juist1` and so on, and the system users `juist`,
  `juist1` to `juist9`, `juist-ingress` and `juist-serve` stay too. On Debian and
  Ubuntu, `sudo apt purge juist` removes each of these directories only if it
  is empty, and otherwise says:
  `juist: kept /var/lib/juist, which still holds this device's keys and log`.
- `/var/lib/juist-serve` stays as well (on FreeBSD, `/var/db/juist-serve`). It
  holds the TLS terminator's ACME account, which the CAA records of your
  published names may refer to. `sudo apt purge juist` on Debian and Ubuntu,
  and `sudo dnf remove juist` on Fedora, say so:
  `juist: kept /var/lib/juist-serve, the terminator's ACME account, which CAA records may name`.
- On FreeBSD, the removal prints a single line starting with `juist: kept`
  that lists everything that stays.
- Your admin keys in `~/.config/juist` are not part of the package, so
  removing it does not touch them.

## Troubleshooting

- `make install` says
  `make install knows apt (Debian, Ubuntu), dnf (Fedora) and pkg (FreeBSD); use make deb, rpm or pkg-freebsd`:
  this system uses none of these package managers. Build the package for one
  of the supported systems and install it there.
- `juist status` says `juist0 · not running`, or on FreeBSD before juistd is
  enabled `juistd not running`: start the daemon with
  `sudo systemctl enable --now juistd`, or on FreeBSD, as root, with
  `sysrc juistd_enable=YES && service juistd start`.
- On Linux, `journalctl -u juistd` shows the daemon's log; on FreeBSD it is
  `/var/log/juistd.log`.
