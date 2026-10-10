---
title: Install
linkTitle: Install
description: Install juist's released package on Debian, Ubuntu, Fedora or FreeBSD, check the download, or build the package from the source.
lead: juist is installed as a package of your system, on every device that will be in a network. Each release has the packages ready, with a signed list of their checksums.
---

## What it is

juist runs on Linux and FreeBSD. On Debian and Ubuntu it is a `.deb`, on
Fedora an RPM, and on FreeBSD a pkg package. Every
[release](https://github.com/nning/juist/releases/latest) has them for amd64
and arm64, the RPM for x86_64 alone. A phone joins with the app instead, see
[Android]({{< relref "docs/android" >}}).

## Installing on this device

{{< step on="a Debian or Ubuntu device" >}}
Download the package and install it:

```sh
curl -LO https://github.com/nning/juist/releases/latest/download/juist_amd64.deb
sudo apt install ./juist_amd64.deb
```

On arm64 it is `juist_arm64.deb`.
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

On arm64 it is `juist-freebsd14-aarch64.pkg`. On Linux the package starts the
daemon by itself; on FreeBSD you start it once, as here.
{{< /step >}}

Installing a newer release later replaces the old one, and the device keeps
its state.

## Checking a download

Each release lists the SHA-256 of its files in `SHA256SUMS`, signed with the
key in [packaging/release-signers](https://github.com/nning/juist/blob/main/packaging/release-signers).
With that file, the download and both lists in one directory:

```sh
ssh-keygen -Y verify -f release-signers -I juist -n juist-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

The first says `Good "juist-release" signature for juist with ED25519 key
SHA256:a2nq8txrPWVfLfF4XGzyKrFo4t71aXkcDOGZNQJABLM`, the second `OK` for each
file you downloaded.


## Building from the source

You need Go 1.27 to build it. `make` then fetches and uses go1.27.2 itself, so
that a commit builds to the same bytes on any machine.

```sh
git clone https://github.com/nning/juist
cd juist
make install      # gmake install, as root, on FreeBSD
```

This builds the `.deb` on Debian and Ubuntu, the RPM on Fedora, or the pkg
package on FreeBSD, and installs it. Running it again later installs the new
build over the old one.

To install juist on a machine that should not build it, build only the package
and copy it there:

| System | Build | Install on the other machine |
|---|---|---|
| Debian, Ubuntu | `make deb` | `sudo apt install ./juist_*.deb` |
| Fedora | `make rpm` | `sudo dnf install ./juist-*.rpm` |
| FreeBSD | `make pkg-freebsd` | `pkg add ./juist-*.pkg` |

The packages land in `build/deb`, `build/rpm/RPMS` and `build/freebsd`.
`make deb DEB_ARCH=arm64` builds the `.deb` for another processor; `armhf` and
`i386` work the same way.

## What the package brings

- `juist`, the command, and `juistd`, the daemon. See
  [How juist works]({{< relref "docs/how-it-works" >}}) for which does what.
- On Linux, the service `juistd`, which starts right away and waits, outside
  any network, until you create one or join one. It runs as its own user,
  `juist`, with `CAP_NET_ADMIN` only, and `CAP_NET_BIND_SERVICE` too on a
  [relay on 443]({{< relref "docs/relays" >}}). Beside it, the service `juist-ingress`
  for an ingress, which `juist ingress serve` starts, and `juist-serve`,
  juist's own TLS, which systemd starts without sudo whenever `juist publish`
  or `juist share` needs it ([Publishing services]({{< relref "docs/publishing" >}})).
- Firewall profiles for ufw and firewalld: `juist`, `juist-relay`,
  `juist-relay-443`, `juist-invite` and `juist-ingress`. Where ufw or firewalld runs, the package
  also lets in traffic on the device `juist0`, which the network needs to sync
  its log, and published services to be reached. It does so at its first
  install alone, so that an upgrade leaves the firewall as you set it.
- A polkit rule that lets juistd set the network's DNS through
  systemd-resolved. The package recommends polkit, which runs the rule;
  minimal installs such as Fedora Cloud lack it otherwise.
- Shell completion for bash, zsh and fish, and the man pages `juist(1)` and
  `juistd(8)`.

To check that the daemon runs, ask it:

```console {device="nas"}
$ juist status
nas · no network
hint: juist join CODE, or juist create
```

Next, [create your first network]({{< relref "docs/first-network" >}}).

## Uninstalling

If the device is in a network, take it out first, so that the network does not
keep listing it. An admin runs `juist remove nas` on their own device. Then
remove the package:

```sh
sudo apt remove juist      # Debian, Ubuntu
sudo dnf remove juist      # Fedora
pkg delete juist           # FreeBSD, as root
```

Removing it stops every juistd and undoes what juist set up on the host. On
Linux that is the firewall rule for `juist0`, an ingress, a relay on 443, and
what `juist exit serve` changed.

## Good to know

- On Linux, the package leaves the device's keys and log in `/var/lib/juist`,
  and the system users `juist`, `juist-ingress` and `juist-serve`. On Debian
  and Ubuntu, `sudo apt purge juist` removes `/var/lib/juist` only when it is
  empty, and otherwise says so:
  `juist: kept /var/lib/juist, which still holds this device's keys and log`.
- It leaves `/var/lib/juist-serve` too, the terminator's ACME account, which
  the CAA records for published names name, and says so:
  `juist: kept /var/lib/juist-serve, the terminator's ACME account, which CAA records may name`.
  On FreeBSD it is `/var/db/juist-serve`.
- On FreeBSD, the removal prints one line starting with `juist: kept` that
  lists what stays.
- Your admin keys in `~/.config/juist` are not part of the package. Removing
  it does not touch them.
- To leave a network but keep juist installed, run `juist reset` instead.
  See [removing a device]({{< relref "docs/remove" >}}).

## If something goes wrong

- `make install` says
  `make install knows apt (Debian, Ubuntu), dnf (Fedora) and pkg (FreeBSD); use make deb, rpm or pkg-freebsd`:
  this system has none of the three. Build the package for one of them and
  install it there.
- `juist status` says `juistd not running`: start it with
  `sudo systemctl enable --now juistd`, or on FreeBSD with `service juistd start`.
- `journalctl -u juistd` shows the daemon's log on Linux.
