---
title: Install
linkTitle: Install
description: Install juist from its package repository or a release on Debian, Ubuntu, Fedora, FreeBSD, macOS or the Steam Deck, check the download, or build the package from source.
lead: Install juist as a system package on every device that should be in a network. Each release comes with ready-made packages and a signed list of their checksums.
---

## Supported systems

juist runs on Linux, FreeBSD and macOS. It comes as a `.deb` for Debian and
Ubuntu, an RPM for Fedora, a pkg package for FreeBSD 15, and a tarball for
macOS 13 or later ([On a Mac](#macos)). Every
[release](https://github.com/nning/juist/releases/latest) has packages for
amd64 and arm64, except the RPM, which is only available for x86_64. On
another Linux with systemd, Arch or Gentoo say, `make install` installs it
from the source ([Building from source](#building-from-source)). On the
Steam Deck, juist installs as a system extension of SteamOS
([On the Steam Deck](#steam-deck)). A phone joins with the app instead; see
[Android]({{< relref "docs/android" >}}).

## Installing the package

juist's package repository installs juist, and the system's own updates then
bring each new release. The repository has the release's packages for
Debian, Ubuntu, Fedora and FreeBSD. To install a single file, take the
release's package instead ([From a release](#from-a-release)).

### From the package repository {#from-the-package-repository}

On Debian, Ubuntu and Fedora:

```sh
curl -fsSL https://juist.nning.io/install | sh
```

On FreeBSD 15, as root:

```sh
fetch -o - https://juist.nning.io/install | sh
```

The script adds the repository and its key to apt, dnf or pkg, installs
juist, and on FreeBSD starts the daemon; where it is not root, it takes sudo.
On SteamOS, it installs juist as a system extension instead
([On the Steam Deck](#steam-deck)). To read it first, download it to `install.sh` and run `sh install.sh`. By
hand, the steps are these:

{{< step on="a Debian or Ubuntu device" >}}
Add the repository and its key, then install juist:

```sh
sudo install -d -m 755 /etc/apt/keyrings
sudo curl -fsSL -o /etc/apt/keyrings/juist.gpg https://pkg.juist.nning.io/juist/key.gpg
echo "deb [signed-by=/etc/apt/keyrings/juist.gpg] https://pkg.juist.nning.io/juist/deb/ ./" | sudo tee /etc/apt/sources.list.d/juist.list
sudo apt update && sudo apt install juist
```

This is the same for amd64 and arm64.
{{< /step >}}
{{< step on="a Fedora device" >}}
Add the repository, then install juist:

```sh
sudo tee /etc/yum.repos.d/juist.repo <<'EOF'
[juist]
name=juist
baseurl=https://pkg.juist.nning.io/juist/rpm
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://pkg.juist.nning.io/juist/key.asc
EOF
sudo dnf install juist
```

The key signs the repository's index, which holds each package's checksum, so
the RPM stays the release's file, unsigned itself.
{{< /step >}}
{{< step on="a FreeBSD 15 device" >}}
As root, add the repository and its key, install juist, then start the
daemon:

```sh
mkdir -p /usr/local/etc/pkg/repos /usr/local/etc/pkg/keys
fetch -o /usr/local/etc/pkg/keys/juist.pub https://pkg.juist.nning.io/juist/freebsd.pub
cat > /usr/local/etc/pkg/repos/juist.conf <<'EOF'
juist: {
  url: "https://pkg.juist.nning.io/juist/freebsd/${ABI}",
  signature_type: "pubkey",
  pubkey: "/usr/local/etc/pkg/keys/juist.pub"
}
EOF
pkg install -r juist juist
sysrc juistd_enable=YES && service juistd start
```

This is the same for amd64 and arm64; what juist does with pf is under
[From a release](#from-a-release). `sha256 /usr/local/etc/pkg/keys/juist.pub`
prints the key's checksum,
`c649f2cd073f9e72825b0c1b8a2682f25c5c55405a178ea6d8a0f8b65ed89e3d`.
{{< /step >}}

dnf shows the key's fingerprint when it imports it, and
`gpg --show-keys /etc/apt/keyrings/juist.gpg` shows it on Debian and Ubuntu:
`1D57474BAAC54CEEAD9168110EBE32412D806005`.

### From a release {#from-a-release}

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
A package from the repository and one from a release are the same, so either
updates the other.

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

## Building from source {#building-from-source}

Building needs Go 1.21 or newer and `make`. `make` has Go download go1.27.4
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

Where there is neither apt, dnf nor pkg, on another Linux with systemd,
`make install` installs the RPM's files to the same places itself, creates
the `juist` user and starts `juistd`. It does not install over a juist from
a package. `make uninstall` removes them again, and without the source tree
`sudo /usr/lib/juist/manual-install.sh uninstall`; the users and
`/var/lib/juist`, which holds the device's keys, stay.

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

## On the Steam Deck {#steam-deck}

SteamOS keeps `/usr` read-only and replaces it with each of its updates, so
juist comes to it as a system extension: the install script puts the
`.deb`'s files into `/var/lib/extensions/juist.raw`, which systemd lays over
`/usr` at every boot. juist, the device's keys and its networks stay across
SteamOS updates.

{{< step on="the Steam Deck, in desktop mode, in Konsole" >}}
Give the user `deck` a password for sudo, unless it has one, then install
juist:

```sh
passwd
curl -fsSL https://juist.nning.io/install | sh
```
{{< /step >}}

The script checks the repository's signed index and the package's
checksum, and starts juistd. Run it again to install a newer release:
SteamOS does not update juist itself. Next is the
[first network]({{< relref "docs/first-network" >}}), as on any other
Linux.

- What juist changes in `/etc`, the firewall's trusted zone, an exit node's
  forwarding and the avahi setting `juist health` may ask for, SteamOS keeps
  across its updates by `/etc/atomic-update.conf.d/juist.conf`.
- `sudo /usr/lib/juist/sysext.sh uninstall` removes juist again; what stays
  is listed under [What stays after uninstalling](#what-stays-after-uninstalling).

## On a Mac {#macos}

On macOS 13 or later, Apple silicon or Intel, the same line installs juist
from the latest release:

```sh
curl -fsSL https://juist.nning.io/install | sh
```

The script downloads `juist-macos-arm64.tar.gz` (on Intel
`juist-macos-amd64.tar.gz`), checks it against the release's signed
`SHA256SUMS` ([Verifying a download](#verifying-a-download)) and runs its
`setup.sh` with sudo. That puts `juist` and `juistd` into `/Library/juist`,
links `/usr/local/bin/juist`, makes the hidden system user `_juist`, and loads
the LaunchDaemon `io.nning.juist.juistd`, which starts juistd now and at every
boot. juistd keeps a helper as root, which creates the device `utun100` and
sets its addresses and routes, and runs the rest as `_juist`. The network's
names resolve through files in `/etc/resolver`, one per domain, which juistd
removes as it stops. Its log is `/var/log/juistd.log`, which only root
can read and nothing rotates. The tarball has no man pages or shell completion; `juist help
COMMAND` says what each command does.

A Mac joins several networks as other devices do. It uses exit nodes, through which it also
answers connections from the internet, and a subnet router's subnets, but
cannot be an exit node, route a subnet, relay, share or publish, or carry
multicast. juist turns pf on under macOS's own rules and keeps the Mac's
overlay addresses to the tunnel with it; where the host's pf rules call no
`com.apple` anchor, `juist health` says that a device on the LAN can reach
those addresses. A program that turns pf off (`pfctl -d`) turns this guard,
and the block that keeps traffic in while an exit node cannot be used, off
too, until juist next changes its rules; where another program turns pf on
again meanwhile and later off, that goes unnoticed until then as well. Running the script again updates juist, and leaves a juistd you stopped
stopped. To stop juistd until you start it again:

```sh
# stop
sudo launchctl disable system/io.nning.juist.juistd && sudo launchctl bootout system/io.nning.juist.juistd
# start
sudo launchctl enable system/io.nning.juist.juistd && sudo launchctl bootstrap system /Library/LaunchDaemons/io.nning.juist.juistd.plist
```

To remove juist, run `sudo /Library/juist/setup.sh remove`. It keeps the
Mac's keys in `/var/db/juist`, and another network's in `/var/db/juist1` and
so on, and the `_juist` users who own them;
`sudo /Library/juist/setup.sh remove --keys` removes those too. Once juist
is removed, the `setup.sh` in a release's tarball does that.

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
sudo /usr/lib/juist/sysext.sh uninstall   # SteamOS
sudo /Library/juist/setup.sh remove       # macOS
```

This stops juistd for every network on the device and undoes what juist set
up on the host. On Linux, that is the firewall rule for `juist0`, an ingress,
a relay on port 443, and the changes made by `juist exit serve`.

## What stays after uninstalling {#what-stays-after-uninstalling}

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
- On macOS, `/var/db/juist`, `/var/db/juist1` and so on and their `_juist` users stay; the removal says so
  in a line starting with `juist: kept`.
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
