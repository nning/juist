---
title: Install
linkTitle: Install
description: Install juist's released package on Debian, Ubuntu, Fedora or FreeBSD, check the download, or build the package from source.
lead: Install juist as a system package on every device that should be in a network. Each release comes with ready-made packages and a signed list of their checksums.
---

## Supported systems

juist runs on Linux and FreeBSD. It comes as a `.deb` for Debian and Ubuntu,
an RPM for Fedora, and a pkg package for FreeBSD. Every
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
{{< step on="a FreeBSD 14 device" >}}
As root, install the package with pkg, then start the daemon:

```sh
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd14-amd64.pkg
sysrc juistd_enable=YES && service juistd start
```

On arm64, use `juist-freebsd14-aarch64.pkg`. On Linux the package starts the
daemon itself; on FreeBSD you start it once, as shown above.
{{< /step >}}

Installing a newer release later replaces the old one. The device keeps its
state.

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

Building needs Go 1.27. `make` then downloads go1.27.2 and builds with it, so
that a given commit produces the same bytes on any machine.

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

## What the package installs

- The command `juist` and the daemon `juistd`.
  [How juist works]({{< relref "docs/how-it-works" >}}) explains which does
  what.
- On Linux, the `juistd` service. It starts right away and waits until you
  create or join a network. It runs as its own user, `juist`, with only
  `CAP_NET_ADMIN`, plus `CAP_NET_BIND_SERVICE` on a
  [relay on port 443]({{< relref "docs/relays" >}}).
- On Linux, two more services. `juist-ingress` runs an ingress and is started
  by `juist ingress serve`. `juist-serve` is juist's own TLS terminator;
  systemd starts it, without sudo, whenever `juist publish` or `juist share`
  needs it ([Publishing services]({{< relref "docs/publishing" >}})).
- Firewall profiles for ufw and firewalld: `juist`, `juist-relay`,
  `juist-relay-443`, `juist-invite` and `juist-ingress`. Where ufw or
  firewalld is running, the package also allows traffic on the `juist0`
  interface. The network needs this to sync its log, and published
  services need it to be reachable. The package does this only on the first
  install, so an upgrade leaves your firewall settings alone.
- A polkit rule that lets juistd set the network's DNS through
  systemd-resolved. The rule needs polkit, which the package recommends;
  minimal installs such as Fedora Cloud do not have it otherwise.
- Shell completion for bash, zsh and fish, and the man pages `juist(1)` and
  `juistd(8)`.

To check that the daemon is running:

```console {device="nas"}
$ juist status
nas · no network
hint: juist join CODE, or juist create
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

- On Linux, the device's keys and log stay in `/var/lib/juist`, and the system
  users `juist`, `juist-ingress` and `juist-serve` stay too. On Debian and
  Ubuntu, `sudo apt purge juist` removes `/var/lib/juist` only if it is empty,
  and otherwise says:
  `juist: kept /var/lib/juist, which still holds this device's keys and log`.
- `/var/lib/juist-serve` stays as well (on FreeBSD, `/var/db/juist-serve`). It
  holds the TLS terminator's ACME account, which the CAA records of your
  published names may refer to. The removal says so:
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
- `juist status` says `juistd not running`: start it with
  `sudo systemctl enable --now juistd`, or on FreeBSD with `service juistd start`.
- On Linux, `journalctl -u juistd` shows the daemon's log.
