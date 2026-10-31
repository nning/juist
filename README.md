# juist

> [!WARNING]
> **Developed with Opus 5.5, no human (security) audit yet!**

A peer-to-peer mesh VPN in the spirit of Tailscale, with **no coordination
server at all**, neither a vendor's nor your own. WireGuard carries the traffic.
Who belongs to the network is a log signed by your admins, and every device
checks that log for itself.

- **Nothing to run or trust in the middle.** Devices find each other on the
  LAN, through each other, or through the public BitTorrent DHT. They punch
  through NAT and fall back to a relay that one of your own devices runs.
- **Changes need your admins.** Admitting or removing a device takes a k-of-n
  quorum of admins, each with a key on their own devices. The keys stay in your
  keystore; the daemon never holds them.
- **Fail-closed, where you want it.** Once you name vouchers, always-on
  devices that vouch hourly, a device that too few of them have vouched for
  in 48 h keeps tunnels only to vouchers, so it cannot carry a removed device
  along indefinitely.

![A laptop on Debian creates a network and invites a NAS on FreeBSD, which joins, pings it and reaches it directly](website/static/demo.gif)

[Watch the tour](https://docs.juist.nning.io/en/#tour): a network made, a device invited and a phone joining, in under a minute.

juist runs on Linux and FreeBSD, and an app makes an Android phone a member.

The [handbook](https://docs.juist.nning.io/en/docs/) explains every feature step by step;
`juist help COMMAND` and `man juist` say what each command does.

## Install

On every device, the package of the [latest release](https://github.com/nning/juist/releases/latest):

```sh
# Debian, Ubuntu (juist_arm64.deb on arm64)
curl -LO https://github.com/nning/juist/releases/latest/download/juist_amd64.deb
sudo apt install ./juist_amd64.deb

# Fedora (x86_64)
sudo dnf install https://github.com/nning/juist/releases/latest/download/juist.x86_64.rpm

# FreeBSD 15, as root (juist-freebsd15-aarch64.pkg on arm64)
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd15-amd64.pkg
sysrc juistd_enable=YES && service juistd start
```

The Android app is `juist-android-arm64.apk` there. `SHA256SUMS` is signed
with the key in [packaging/release-signers](packaging/release-signers).

Or build the package from the source and install it: `make install`, or
`gmake install` as root on FreeBSD. The package brings `juist`, the command,
and `juistd`, the daemon, with shell completion and man pages. Checking a
download, and building for another machine:
[Install](https://docs.juist.nning.io/en/docs/install/).

An app in a container becomes a device of its own through a juist container
sharing its network namespace: [examples/sidecar](examples/sidecar).

## Your first network

On the first device, as yourself:

```sh
juist create          # a new network, named like "belfast-hazardous"; asks for sudo once
juist invite          # prints a code and a link, then waits for the new device
```

On the new device:

```sh
sudo juist join 42-drumbeat-tolerance-glucose    # the code: same LAN
sudo juist join 'juist:Kx7…@192.168.1.20:41642'  # or the link: from anywhere
```

`juist invite` shows four words and asks whether the new device shows the same
ones. Answering yes admits it. Then, on either device:

```sh
juist status          # connected? -d lists the devices too
juist health          # anything wrong?
juist devices         # who is in the network, with their addresses
ping 198.18.36.2      # the second device, at the address juist devices lists
```

Behind NAT nothing needs opening in a firewall; a device with a public address
needs 41643/udp. More in [Your first network](https://docs.juist.nning.io/en/docs/first-network/)
and [Invites](https://docs.juist.nning.io/en/docs/invites/).

## Everyday use

| To … | run | more |
|---|---|---|
| see whether this device is connected | `juist status` | [status](https://docs.juist.nning.io/en/docs/status/) |
| see what needs attention, and how to fix it | `juist health` | [status](https://docs.juist.nning.io/en/docs/status/) |
| add a device | `juist invite`, then `sudo juist join …` on it | [invites](https://docs.juist.nning.io/en/docs/invites/) |
| remove a device, on every device at once | `juist remove phone` | [remove](https://docs.juist.nning.io/en/docs/remove/) |
| reach a device by name | `ssh laptop.home.juist`, or `ssh laptop` | [names](https://docs.juist.nning.io/en/docs/names/) |
| leave this device's DNS alone, names and exit node alike | `sudo juist set --dns=false` | [names](https://docs.juist.nning.io/en/docs/names/) |
| route a group, as SSDP's, into the network for programs on the default interface; or carry no multicast | `sudo juist set --groups 239.255.255.250`, `sudo juist set --multicast=false` | [multicast](https://docs.juist.nning.io/en/docs/multicast/) |
| let a device with a public address relay for the others | `juist grant vps relay` | [relays](https://docs.juist.nning.io/en/docs/relays/) |
| reach the network from a hotel or office that only lets HTTPS out | one relay on 443: the ingress's serves `relay.DOMAIN` by itself, another `sudo juist set --relay-name relay.example.org`; `sudo juist set --https-only` here where traffic is inspected | [HTTPS only](https://docs.juist.nning.io/en/docs/https-only/) |
| send this device's internet traffic through another | `juist grant vps exit`, `juist exit serve` there, `juist exit use vps` here | [exit nodes](https://docs.juist.nning.io/en/docs/exit-nodes/) |
| let every device reach the LAN behind one | `juist subnet add nas 192.168.1.0/24`, then `juist subnet serve` on it | [subnets](https://docs.juist.nning.io/en/docs/subnets/) |
| say which device may open what on which, and use which exit node or subnet | `juist policy edit`, or `juist policy set policy.conf` | [access policy](https://docs.juist.nning.io/en/docs/access/) |
| publish a service on the internet, or share a file | `juist publish add immich 127.0.0.1:2283`, `juist share ~/photos` | [publishing](https://docs.juist.nning.io/en/docs/publishing/) |
| rename or renumber the network, or rename a device | `juist network rename office`, `juist network renumber 10.7.0.0/22`, `juist rename phone tablet` | [changes](https://docs.juist.nning.io/en/docs/network-changes/) |
| see every change, who approved it, and what it did | `juist log`, `juist log show 3` | [admins](https://docs.juist.nning.io/en/docs/admins/) |
| manage this device without sudo from now on | `sudo juist set --operator=$USER` | [operator](https://docs.juist.nning.io/en/docs/operator/) |
| give this device new keys | `juist rotate` | [keys](https://docs.juist.nning.io/en/docs/keys/) |
| back an admin key up in a password manager | `juist admins export alice@home \| pass insert -m juist/alice` | [keys](https://docs.juist.nning.io/en/docs/keys/) |
| end the network for good, with a break-glass secret | `juist network disable` | [changes](https://docs.juist.nning.io/en/docs/network-changes/) |
| leave the network, as on a fresh install | `juist reset` | [remove](https://docs.juist.nning.io/en/docs/remove/) |
| move the network to a new release's schema, once every device runs it | `juist log upgrade` | [updating](https://docs.juist.nning.io/en/docs/updating/) |

Any local user may run `juist status` and `juist health`; everything else is
for root and the device's operator. Commands never ask which network or device
you mean: where that is unclear they stop and say what to add.

## Publishing services

A device's service, such as Immich on a NAS at home, can be reached from the
internet by name through an **ingress**: a device with a public address that
passes connections through the tunnel. TLS ends on the device, never at the
ingress.

```sh
juist network domain pub.example.org    # DNS: *.pub.example.org points at the vps
juist grant vps ingress                 # then juist ingress serve, on the vps
juist publish add immich 127.0.0.1:2283 # on the nas: https://immich.pub.example.org
juist publish add nas mc 25565 --tcp    # a service without TLS on a port of its own: mc.pub.example.org:25565
juist publish add nas photos --members  # members only; the access policy says which: pass from <family> to name photos
juist share ~/photos/2026               # with the publish role: a directory under this device's name
juist share                             # what this device shares, and where
```

Each step names the next and the device it is run on.
[Publishing services](https://docs.juist.nning.io/en/docs/publishing/) has the rest:
shares, the status page, and a service member that keeps a published server
in Docker from the rest of the network
([examples/service-member](examples/service-member)).

## Android

The app, for Android 12 or newer, joins one network as a member by scanning
the QR code `juist invite` shows in a terminal, or by the code typed in on the
same LAN. While its VPN is on, every app on the phone reaches the other
devices at their addresses; the phone's other traffic and its DNS are left
alone.

```sh
make android    # needs a JDK 21, the Android SDK and NDK; the APKs land in android/app/build/outputs/apk
```

It resolves the network's names, sends its internet through an exit node
where one is chosen, turns no public names on, uses no subnets, and takes no
roles.
Building, signing and what the app shows: [Android](https://docs.juist.nning.io/en/docs/android/).

## Several networks and several admins

A device can be in several networks at once, each with a juistd of its own;
a command about one takes it first, by name: `juist invite work`. See
[Several networks](https://docs.juist.nning.io/en/docs/networks/).

An admin is a person, with a key on each device they approve from. More admins
and a quorum make every change need more than one of them:

```sh
juist admins add bob nid:…      # once per device of bob's
juist grant nas voucher         # carries changes waiting for votes
juist admins quorum 2           # every change needs alice and bob
juist approve                   # on a voucher device: asks about each change waiting for your vote
```

[Admins](https://docs.juist.nning.io/en/docs/admins/) covers a second laptop's key, one
key per network, approving offline and upgrading the log;
[Keys](https://docs.juist.nning.io/en/docs/keys/) what to keep where. Losing every key
of the admins a change needs locks the network for good.

## Relays, ports and firewalls

Two devices that cannot reach each other directly relay through a member that
has a public address, never through a third party.

| Port | For | Open it where |
|---|---|---|
| 41643/udp | WireGuard and path discovery | a device with a public address |
| 41645/tcp, 41645/udp | the relay, and the STUN answers members measure it by | a device granted `relay` |
| 443/tcp | the relay under its public name | a relay given a name; `juist set --relay-name` opens it |
| 41642/tcp | an invite taken as a code on the LAN | the inviting device, while `juist invite` runs |
| 443/tcp, 443/udp, 80/tcp | the names devices publish, by TLS and QUIC | a device granted `ingress`; `juist ingress serve` opens them |
| the ports names are published on by TCP | those names | every ingress; it opens and closes them as they come and go |

The packages install ufw and firewalld profiles by the names `juist`,
`juist-relay`, `juist-relay-443`, `juist-invite` and `juist-ingress`. Log sync runs inside the
tunnel, on TCP 41644 on `juist0`, which a firewall configured by hand must let
in. [Relays and ports](https://docs.juist.nning.io/en/docs/relays/) has the rest:
further networks' ports, and running without public STUN servers or the DHT.

## When something is wrong

`juist health` says what needs attention, and prints a hint to fix it;
`journalctl -u juistd` shows the daemon's log.
[Troubleshooting](https://docs.juist.nning.io/en/docs/troubleshooting/) lists what each
message means and what to do.

## Security, in short

- **Trust root:** the log's genesis and a k-of-n quorum of admins. There
  is no coordinator. Every record is verified by every device, and the
  transport is untrusted.
- **Key custody:** admin keys live in the operator's keystore
  (`~/.config/juist`). juistd runs as its own user with `CAP_NET_ADMIN` only,
  and `CAP_NET_BIND_SERVICE` on a relay on 443, and holds no admin key.
- **Invites:** SPAKE2 (RFC 9382), then ML-KEM-768. A code admits exactly one
  guess, from the LAN only, and a link is a 128-bit secret.
- **Revocation** is eventually consistent; the freshness TTL (48 h) bounds how
  long a partitioned device can keep a removed peer.
- **Quantum-safe:** every WireGuard handshake mixes in a preshared key, one
  each two devices exchange by ML-KEM-768; group secrets are hybrid
  X25519 + ML-KEM-768; every change and message is signed with ML-DSA-44;
  joining agrees a key by ML-KEM-768; TLS between juist's
  own ends is 1.3 with X25519MLKEM768 alone.

[Security](https://docs.juist.nning.io/en/docs/security/) explains it, and
[02-threat-model.md](docs/02-threat-model.md) lists every residual weakness.
Report a vulnerability privately, as [SECURITY.md](SECURITY.md) says.

## Status

juist is usable on Linux and FreeBSD, but it is not v1 yet and has not had
a security audit.

What works:

- a network whose members are a log your admins sign, a quorum of them for
  each change
- WireGuard tunnels through NAT, and a relay on one of your own devices where
  that fails
- invites by a code on the LAN or a link from anywhere
- several networks on one device
- exit nodes and subnet routers
- names for devices, and services published to the internet, over HTTPS,
  HTTP/3 or plain TCP, or to members only, by name in the access policy
- a way in from networks that let nothing but HTTPS out
- an access policy: which device may reach what on which
- ending a network with a break-glass secret, and a backup of admin keys
- quantum-safe tunnels: a preshared key in every WireGuard handshake, so that
  traffic recorded now cannot be decrypted later; and quantum-safe signatures,
  so that a quantum computer cannot forge a change to the network
- connections that stay up while a device's keys, addresses or routes change
- packages for Debian, Ubuntu, Fedora and FreeBSD

Still open before v1, as [05-roadmap.md](docs/05-roadmap.md) plans it:

- the Android app, which joins and reaches the network but is not finished
- a security audit by a second model; a human audit is not planned

## Development

Go 1.21 or newer; `make` has it fetch and use go1.27.3, so that a commit
builds to the same bytes anywhere, and lists the targets.

```sh
make check                      # what CI gates on: lint, tidy, race tests, TCB and audit budgets
sudo -E make test-os-plumbing   # real TUN devices, namespaces, the NAT matrix (root)
make build cross deb rpm        # binaries, all platforms, packages
```

What each gate covers is in [12-validating.md](docs/12-validating.md).

**Try it on one machine**, with no package, no privileges and no TUN device:

```sh
make build
export JUIST_HOME=/tmp/K     # a keystore for the demo, not your own
./build/juistd --home /tmp/A --socket /tmp/a.sock --tun "" &
./build/juistd --home /tmp/B --socket /tmp/b.sock --tun "" &
./build/juist --socket /tmp/a.sock create home
./build/juist --socket /tmp/a.sock invite --yes &
./build/juist --socket /tmp/b.sock join '<the link it printed>'
./build/juist --socket /tmp/b.sock status
```

| Doc | Contents |
|---|---|
| [01-requirements.md](docs/01-requirements.md) | Goals, priorities, decided constraints |
| [02-threat-model.md](docs/02-threat-model.md) | Adversaries, scope, residual weaknesses |
| [03-control-plane-options.md](docs/03-control-plane-options.md) | Why a signed log, not a coordinator |
| [04-architecture.md](docs/04-architecture.md) | Components, protocols, local security |
| [05-roadmap.md](docs/05-roadmap.md) | Milestones and their security exit criteria |
| [06-verification.md](docs/06-verification.md) | Test and fuzzing strategy |
| [07](docs/07-embedding-notes.md)–[11](docs/11-enrollment-and-freshness-notes.md), [13](docs/13-multi-network-notes.md) | The rules each layer keeps, and why: embedding, trust log, mesh, connectivity, enrollment and freshness, several networks |
| [12-validating.md](docs/12-validating.md) | Running the gates, and what each claim is checked by |

## License

BSD 3-Clause, in [LICENSE](LICENSE), the documentation and the website
included. What carries its own license keeps it: the IBM Plex fonts (SIL
OFL), the outline of Juist (ODbL) and the code adapted from wireguard-go
(MIT). The packages carry the licenses of what juist links, in
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES); `make licenses` writes it anew.
