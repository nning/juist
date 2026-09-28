# juist

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
- **Fail-closed.** A device that no voucher has vouched for in 48 h keeps
  tunnels only to vouchers, so it cannot carry a removed device
  along indefinitely.

juist runs on Linux; FreeBSD and Android are on the
[roadmap](docs/05-roadmap.md). It has not had a security audit yet.

**Contents:** [Install](#install) · [Your first network](#your-first-network) ·
[Everyday use](#everyday-use) · [Several networks](#several-networks-on-one-device) ·
[Several admins](#several-admins) · [Relays, ports and firewalls](#relays-ports-and-firewalls) ·
[When something is wrong](#when-something-is-wrong) · [Security](#security-in-short) ·
[Status](#status) · [Development](#development)

## Install

On every device:

```sh
make install     # builds the .deb (Debian, Ubuntu) or the RPM (Fedora) and installs it with sudo
```

`make deb` and `make rpm` build the package only, for copying to another
machine (`sudo apt install ./juist_*.deb`, `sudo dnf install ./juist-*.rpm`).
The package brings `juist`, the command, and `juistd`, the daemon, which
starts right away and waits, outside any network, until you create one or
join one. It also brings shell completion for bash, zsh and fish, and the man
pages `juist(1)` and `juistd(8)`.

## Your first network

On the first device, as yourself:

```sh
juist create          # a new network, named like "belfast-hazardous"; asks for sudo once
juist invite          # prints a code and a link, then waits for the new device
```

`juist create home` names it yourself. On the new device:

```sh
sudo juist join 42-drumbeat-tolerance-glucose    # the code: same LAN
sudo juist join 'juist:Kx7…@192.168.1.20:41642'  # or the link: from anywhere
```

`juist invite` shows four words and asks whether the new device shows the same
ones. Answering yes admits it. Then, on either device:

```sh
juist status          # connected? anything wrong?
juist devices         # who is in the network, with their addresses
ping 198.18.36.2      # the second device, at the address juist devices lists
```

The link also works when both devices sit behind NAT on different networks:
they meet through the public DHT, which takes about a minute. It fails only
where both NATs are symmetric; then join from a network that can reach the
inviting device, or give the network a [relay](#relays-ports-and-firewalls)
first. The code works only on the same LAN, and a wrong code voids it; the
link still works.

Behind NAT nothing needs opening in a firewall; a device with a public address
needs 41643/udp.

## Everyday use

| To … | run |
|---|---|
| see whether this device is connected, and what needs attention | `juist status` |
| list the devices and their addresses | `juist devices` |
| add a device | `juist invite`, then `sudo juist join …` on it |
| remove a device, on every device at once | `juist remove phone` |
| let a device with a public address relay for the others | `juist grant vps relay` (`revoke` takes it back) |
| have a device vouch that the network's state is current | `juist grant vps voucher` |
| let a device carry the others' internet traffic | `juist grant vps exit`, then `juist exit serve` on it |
| send this device's internet traffic through it | `juist exit use vps` (`off` goes direct again) |
| let every device reach the LAN behind one | `juist grant nas 192.168.1.0/24`, then `juist subnet serve` on it |
| see every change, and who approved it | `juist log` |
| rename the network, on every device | `juist network rename office` |
| move every device's IPv4 address | `juist network renumber 10.7.0.0/22` |
| move one device's | `juist network renumber phone 10.7.0.9` |
| move one device's and retire its old address now | `juist network renumber phone 10.7.0.9 --finish` |
| retire every old address now | `juist network renumber --finish` |
| give this device new keys | `juist rotate` |
| manage this device without sudo from now on | `sudo juist set --operator=$USER` |
| leave the network, as on a fresh install | `juist reset` |
| read what a command does | `juist help remove`, or `man juist` |

Any local user may run `juist status`. Everything else is for root and the
device's operator, one local user named with `juist set --operator`. Commands
never ask which network or device you mean: where that is unclear they stop
and say what to add. After a renumbering the old IPv4 addresses keep working
for 7 days, so a device that is offline meanwhile is not cut off; `--finish`
retires them at once, one device's or all. IPv6 addresses never change.

## Several networks on one device

A device can be in several networks at once: a home network and a work one,
say. Creating or joining another on a device that is in one already runs it
beside the first, with a juistd of its own; `juist` asks for sudo once to
start it.

```sh
sudo juist join 'juist:…'             # on a device already in "home": "work" runs beside it
juist status                          # both networks, one after the other
juist devices                         # every network's devices
juist devices work                    # one network's, by name or by juistd (juist1)
juist invite work                     # with several networks, say which
juist network renumber work 10.7.0.0/24
juist reset work --force              # leave work; its juistd goes too, home stays as it is
```

A command about one network takes it first, by name or by juistd, and may
leave it out where the device is in one. Listings (`status`, `devices`,
`network`, `admins`) show every network; any other command stops, naming the
networks, rather than ask. `--network NAME` and `$JUIST_NETWORK` do the same
for any command.

The networks' juistds are `juistd.service` and `juistd@juist1`,
`juistd@juist2`, …, each with its own device (`juist0`, `juist1`, …), state
directory and ports. Two networks whose IPv4 ranges overlap still both work on
one device, the one in the higher-numbered juistd over IPv6 only, and
`juist status` says which to renumber. See
[13-multi-network-notes.md](docs/13-multi-network-notes.md).

## Several admins

An admin is a person, and holds a key on each device they approve from; never
copy a key. A person's keys cast that person's votes once, whichever signs.

**Approve from either of your two laptops.** Your admin name is what
`juist create` printed, and `juist admins` lists (your login name, unless you
gave `--admin-name`). Use it for the second laptop's key, or it becomes a
second admin:

```sh
juist admins new alice                      # on the second laptop, with your admin name
juist admins add alice nid:… --on laptop2   # on the first, as printed
```

`juist admins` then lists which machine each key is on, and a change waiting
for approval says where the keys that can give it are.

**One key per network.** Each network gets an admin key of its own
(`admins/alice@home.key`), so a lost or stolen key costs one network, and
the two logs share no key. A key from
`juist admins new` is filed under the first network whose log names it;
`--network home` names it at once. To govern a new network with a key you
have, say so: `juist create lab --admin-key alice@home`. `juist admins`
lists the keys here and the networks each governs. On a machine in no
network, `juist approve --key alice@home FILE` says which key signs.

**Two people, each with two devices, and neither decides alone:**

```sh
juist admins add bob nid:…      # once per device of bob's: bob holds two keys
juist admins quorum 2           # every change needs alice and bob
juist admins vouchers 2         # and two vouchers must confirm freshness
```

**Alone, but every change needs two of your devices:**

```sh
juist admins require alice 2    # hold three keys, so losing one device is no lockout
```

A change that needs someone else waits for them on the network's voucher
devices, where `juist status` says so and they run:

```sh
juist approve                   # asks about each change waiting for your vote
```

That needs each admin to have run `juist admins receive` once (a new
network's founder has). The change is saved as a file too; for an admin on a
machine in no network, send it to them, and they run:

```sh
juist approve remove-phone.rec  # shows what it does, asks, and applies it once complete
```

Losing every key of the admins a change needs locks the network for good: the
break-glass secrets `juist create` writes are for a recovery that is not
implemented yet. Keep them offline anyway.

## Relays, ports and firewalls

Two devices that cannot reach each other directly relay through a member of
the network, never through a third party. Any device with a public address can
be that relay. Only members can use it, and it sees only encrypted WireGuard
traffic. It also carries invites: `juist invite` on a laptop behind NAT waits
at the relay too, and the link names it, so a new device joins from anywhere.
The invite's secret never reaches the relay.

On a VPS, or any host with a public address:

```sh
sudo juist join 'juist:…'
sudo ufw allow juist && sudo ufw allow juist-relay
# or, with firewalld:
sudo firewall-cmd --permanent --add-service=juist --add-service=juist-relay && sudo firewall-cmd --reload
```

and on an admin's device: `juist grant vps relay`. In a network of more than
two devices, `juist status` warns while none may relay.

| Port | For | Open it where |
|---|---|---|
| 41643/udp | WireGuard and path discovery | a device with a public address |
| 41645/tcp, 41645/udp | the relay, and the STUN answers members measure it by | a device granted `relay` |
| 41642/tcp | an invite taken as a code on the LAN | the inviting device, while `juist invite` runs |

The packages install ufw and firewalld profiles by the names `juist`,
`juist-relay` and `juist-invite`. A link invite needs no port: where it cannot
reach the inviting device directly, it meets it through a relay at once or
through the public DHT in about a minute. A device in several networks runs
one juistd for each, and the n-th one's ports are these plus 10·n: 41653/udp
for `juistd@juist1`. The profiles name the first network's ports; `juist
status` gives the others' by number.

Log sync runs inside the tunnel: TCP 41644 on `juist0` (41654 on `juist1`, and
so on). What arrives on `juist0` has already passed WireGuard and juist's own
filter, and the packages let it in where ufw or firewalld runs. A firewall
configured by hand must let it in too, or the device keeps its tunnels but
misses changes to the network, removals included; `juist status` says so.
An exit node answers its members' DNS there too, UDP and TCP 41646, which such
a firewall must let in, or their lookups go nowhere.

Upgrading from a build whose `juist` profile opened every port: ufw keeps the
old ports for an allowed profile until `sudo ufw app update juist`, and
firewalld narrows `juist` to 41643/udp at once, so a relay needs `juist-relay`
added in either case.

**No public helpers at all.** By default juistd asks public STUN servers
(Google, Cloudflare) for its public address and uses the public DHT to find
members it has lost track of. Both see addresses, never contents. Once you
have a relay of your own, a network can run without either. Put this on every
device:

```sh
sudo systemctl edit juistd
# [Service]
# ExecStart=
# ExecStart=/usr/bin/juistd --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0 --no-dht --no-stun
```

Devices then find each other on the LAN and through members they already know.
The relay tells each device its public address, and invite links meet through
it. `man juistd` lists every option.

## When something is wrong

`juist status` says what needs attention, and prints a hint to fix it. The
common cases:

| `juist status` says | what to do |
|---|---|
| juistd not running | `sudo systemctl start juistd` (`juistd@juist1` for the second network) |
| read-only; to manage this device … | `sudo juist set --operator=$USER`, once |
| no answer from a device | it is offline, or its 41643/udp is closed |
| no tunnel traffic from a device | open 41643/udp on a device with a public address, or grant one `relay` |
| no device reaches this relay | open 41645/tcp and udp on the relay, in any firewall in front of it too |
| log sync fails in the tunnel | let `juist0` in through the host firewall, as the hint says |
| no device may relay | `juist grant DEVICE relay`, on a device with a public address |
| Freshness: expired; vouchers only | no voucher has been reachable for 48 h; bring one back |
| removed | this device is out of the network: join again with a new invite, or `juist reset` |
| no IPv4 on this host | two networks here overlap; renumber one of them |
| Exit node: vps, internet refused: … | bring vps back, or `juist exit off` to go direct |
| this device does not serve: IP forwarding is off … | `juist exit serve` again, which sets it up with sudo |
| DNS goes to …, outside the tunnel: systemd-resolved refused juistd … | install the package, whose polkit rule allows juistd that |

`journalctl -u juistd` shows the daemon's log.

## Security, in short

- **Trust root:** the log's genesis and a k-of-n quorum of admins. There
  is no coordinator. Every record is verified by every device, and the
  transport is untrusted.
- **Key custody:** admin keys live in the operator's keystore
  (`~/.config/juist`). juistd runs as its own user with `CAP_NET_ADMIN` only,
  holds no admin key, and cannot get one to sign anything the CLI has not
  rebuilt from its own verified log. The link binds the new device to the
  inviting admin's signature.
- **Invites:** SPAKE2 (RFC 9382). A code admits exactly one guess, from the LAN
  only, and a link is a 128-bit secret. The admin compares four words with the
  new device before signing anything, made so that nobody in between can
  search for a match.
- **Revocation** is eventually consistent. The freshness TTL (48 h) bounds how
  long a partitioned device can keep a removed peer, and `juist admins
  vouchers M` makes that bound hold against M − 1 dishonest vouchers.
- **Accepted limits:** losing a quorum of admin keys makes the network
  unrecoverable: the break-glass recovery its secrets are for is not
  implemented yet, and without them it never will be, by design. A network
  where every device sits behind symmetric NAT needs a relay member. Public
  DHT and STUN servers see the addresses that use them, and nothing more.
- **Post-quantum:** group secrets are hybrid X25519 + ML-KEM-768. WireGuard
  traffic is not hedged yet: a per-pair ML-KEM preshared key is deferred past
  v1. Signatures are Ed25519.

All residual weaknesses are in [02-threat-model.md](docs/02-threat-model.md).

## Status

Milestones up to **M6** of [05-roadmap.md](docs/05-roadmap.md), exit
nodes, subnet routers and the exit node's DNS, are done; next is M7,
FreeBSD. What works:

- The membership log, with quorum, fork choice, fork alarm and a versioned
  schema.
- WireGuard on a real TUN device, and NAT traversal with member relays.
- LAN, gossip and DHT discovery.
- Invites by code and link, including across two NATs.
- Freshness leases, and a removed device told of its removal.
- The daemon, and an operator who manages a device without sudo.
- Several networks on one device, each with an admin key of its own, and
  renumbering a network.
- Changes that need more admins carried to their devices, sealed to them.
- Exit nodes on Linux, failing closed, and DNS through them where
  systemd-resolved runs.
- Subnet routers on Linux, leaving every device's own LAN to it.
- Debian and Fedora packages, with man pages.

Not yet: FreeBSD, Android, ACLs (every member reaches every port on the
others), names, break-glass recovery, the post-quantum data plane,
and QR codes.

## Development

Go 1.26; `make` fetches and uses go1.26.8, so that a commit builds to the
same bytes anywhere, and lists the targets.

```sh
make check                      # what CI gates on: lint, tidy, race tests, TCB budget
sudo -E make test-os-plumbing   # real TUN devices, namespaces, the NAT matrix (root)
make fuzz                       # every fuzz target, briefly
make build cross deb rpm        # binaries, all platforms, packages
make man                        # build/man/juist.1 and juistd.8, from the commands' own help
```

`make check` skips everything that needs privileges. What each gate covers,
and what none of them does, is in
[12-validating.md](docs/12-validating.md).

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

A daemon without a TUN device has no tunnel to sync through, and listens for
log sync on TCP 41644 on every address instead.

| Doc | Contents |
|---|---|
| [01-requirements.md](docs/01-requirements.md) | Goals, priorities, decided constraints |
| [02-threat-model.md](docs/02-threat-model.md) | Adversaries, scope, residual weaknesses |
| [03-control-plane-options.md](docs/03-control-plane-options.md) | Why a signed log, not a coordinator |
| [04-architecture.md](docs/04-architecture.md) | Components, protocols, local security |
| [05-roadmap.md](docs/05-roadmap.md) | Milestones and their security exit criteria |
| [06-verification.md](docs/06-verification.md) | Test and fuzzing strategy |
| [07](docs/07-embedding-notes.md)–[11](docs/11-enrollment-and-freshness-notes.md), [13](docs/13-multi-network-notes.md) | What each milestone decided: embedding, trust log, mesh, connectivity, enrollment and freshness, several networks |
| [12-validating.md](docs/12-validating.md) | Running the gates, and what each claim is checked by |
