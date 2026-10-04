---
title: Install
linkTitle: Install
description: Build juist's package and install it on Debian, Ubuntu, Fedora or FreeBSD, or build it here and install it on another machine.
lead: juist is installed as a package of your system, on every device that will be in a network. You build the package from the source with one command.
---

## What it is

juist runs on Linux and FreeBSD. On Debian and Ubuntu it is a `.deb`, on
Fedora an RPM, and on FreeBSD a pkg package. There are no released packages,
so you build the package from the source and then install it.

You need Go 1.27 to build it. `make` then fetches and uses go1.27.1 itself, so
that a commit builds to the same bytes on any machine.

## Installing on this device

{{< step on="every device" >}}
Get the source:

```sh
git clone https://github.com/nning/juist
cd juist
```
{{< /step >}}
{{< step on="a Debian, Ubuntu or Fedora device" >}}
Build the package and install it:

```sh
make install
```

This builds the `.deb` on Debian and Ubuntu, or the RPM on Fedora, and
installs it with sudo.
{{< /step >}}
{{< step on="a FreeBSD device" >}}
As root, build the package and install it with pkg, then start the daemon:

```sh
gmake install
sysrc juistd_enable=YES && service juistd start
```

On Linux the package starts the daemon by itself; on FreeBSD you start it
once, as here.
{{< /step >}}

Running `make install` again later installs the new build over the old one,
and the device keeps its state.

## Building the package for another machine

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
  `juist`, with `CAP_NET_ADMIN` only. Beside it, the service `juist-ingress`
  for an ingress, which `juist ingress serve` starts, and `juist-serve`,
  juist's own TLS, which systemd starts without sudo whenever `juist publish`
  or `juist share` needs it ([Publishing services]({{< relref "docs/publishing" >}})).
- Firewall profiles for ufw and firewalld: `juist`, `juist-relay`,
  `juist-invite` and `juist-ingress`. Where ufw or firewalld runs, the package
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
Linux that is the firewall rule for `juist0`, an ingress, and what
`juist exit serve` changed.

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
