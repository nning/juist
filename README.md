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

## Quick start

Install on every device. The daemon starts right away and waits, outside any
network, until you create one or join one.

```sh
make install     # builds the .deb (Debian, Ubuntu) or the RPM (Fedora) and installs it with sudo
```

`make deb` and `make rpm` build the package only, for copying to another
machine. Behind NAT nothing needs opening in a firewall; a device with a
public address needs 41643/udp (see [Ports and firewalls](#ports-and-firewalls)).

On the first device, as yourself:

```sh
juist init            # a new network, named like "belfast-hazardous"; asks for sudo once
juist invite          # prints a code and a link, then waits for the device
```

On the new device:

```sh
sudo juist join 42-drumbeat-tolerance-glucose    # the code: same LAN
sudo juist join juist:Kx7…@192.168.1.20:41642    # or the link: from anywhere
```

`juist invite` shows four words and asks whether the new device shows the same
ones. Answering yes admits it. Then, on either device:

```sh
juist status          # connected? anything wrong?
juist devices         # who is in the network, with their addresses
ping 198.18.0.2       # the second device
```

The link also works when both devices sit behind NAT on different networks:
they meet through the public DHT, which takes about a minute. It fails only
where both NATs are symmetric; then run the join from a network that can reach
the inviting device. The code works only on the same LAN, and a wrong code
voids it; the link still works.

Shell completion for bash, zsh and fish comes with the package.

## Everyday use

```sh
juist remove phone              # out of the network, on every device, at once
juist rotate                    # new keys for this device
juist reset                     # forget the network: a fresh install, with new keys
juist grant vps relay           # let a device relay for others (revoke takes it back)
juist grant vps voucher         # vouches that the network state is current
juist log                       # every change, and who approved it
juist network renumber 10.7.0.0/22      # move every device's IPv4 address
juist network renumber phone 198.18.0.9 # or one device's; the old ones work 7 more days
juist network rename office             # another name for the network, on every device
sudo juist set --operator=$USER # manage this device without sudo from now on
```

Any local user may run `juist status`. Everything else is for root and the
device's operator, one local user named with `juist set --operator`.
`juist help <command>` explains any command.

## Your own relay, and no public helpers at all

Two devices that cannot reach each other directly relay through a member of the
network, never through a third party. Any device with a public address can be
that relay. Only members can use it, and it sees only encrypted WireGuard
traffic.

On a VPS, or any host with a public IP:

```sh
sudo apt install ./juist_*.deb          # built with "make deb", copied over
sudo juist join <link from an admin>
sudo ufw allow juist && sudo ufw allow juist-relay        # see "Ports and firewalls"
# or, with firewalld:
sudo firewall-cmd --permanent --add-service=juist --add-service=juist-relay && sudo firewall-cmd --reload
```

and on an admin's device:

```sh
juist grant vps relay
```

In a network of more than two devices, `juist status` warns while none may
relay.

The relay also carries invites: `juist invite` on a laptop behind NAT waits at
the relay too, and the link names it, so a new device joins from anywhere. The
relay only passes bytes; the invite's secret never reaches it.

By default juistd asks public STUN servers (Google, Cloudflare) for its public
address and uses the public DHT to find members it has lost track of. Both are
untrusted helpers: they see addresses, never contents. Once you have a relay
of your own, a network can run without either. Put this on every device:

```sh
sudo systemctl edit juistd
# [Service]
# ExecStart=
# ExecStart=/usr/bin/juistd --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0 --no-dht --no-stun
```

Devices then find each other on the LAN and through members they already know.
The relay tells each device its public address, and invite links meet through
it.

**Try it on one machine**, with no package, no privileges and no TUN device:

```sh
make build
export JUIST_HOME=/tmp/K     # a keystore for the demo, not your own
./build/juistd --home /tmp/A --socket /tmp/a.sock --tun "" &
./build/juistd --home /tmp/B --socket /tmp/b.sock --tun "" &
./build/juist --socket /tmp/a.sock init home
./build/juist --socket /tmp/a.sock invite --yes &
./build/juist --socket /tmp/b.sock join <the link it printed>
./build/juist --socket /tmp/b.sock status
```

## Ports and firewalls

A device needs one port open, and only where it has a public address and a
firewall that drops what comes in: **41643/udp**, for WireGuard and for
finding paths. Devices behind NAT need nothing opened; they punch through.
Log sync runs inside the tunnel, so it needs no port of its own.

| Port | For | Open it where |
|---|---|---|
| 41643/udp | WireGuard and path discovery | a device with a public address |
| 41645/tcp, 41645/udp | the relay, and the STUN answers members measure it by | a device granted `relay` |
| 41642/tcp | an invite taken as a code on the LAN | the inviting device, while `juist invite` runs |

The packages install a profile for each, for ufw and firewalld:

```sh
sudo ufw allow juist                  # 41643/udp
sudo ufw allow juist-relay            # on a relay: 41645/tcp and udp
sudo ufw allow juist-invite           # only while inviting by code on the LAN

sudo firewall-cmd --permanent --add-service=juist && sudo firewall-cmd --reload
```

(`juist-relay` and `juist-invite` likewise for firewalld.) A link invite
needs no port: where it cannot reach the inviting device directly, it meets
it through a relay at once or through the public DHT in about a minute.

Upgrading from a build whose `juist` profile opened every port: ufw keeps
the old ports for an allowed profile until `sudo ufw app update juist`, and
firewalld narrows `juist` to 41643/udp at once, so a relay needs
`juist-relay` added in either case.

What arrives on `juist0` has already passed WireGuard and juist's own
filter, and the packages let it in on install where ufw or firewalld runs. A
firewall configured by hand must let it in too: log sync uses TCP 41644 on
`juist0`, and without it a device keeps tunnels but misses changes to the
network, removals included. `juist status` says so when it happens.

When `juist status` reports no answer from a device with a public address,
its 41643/udp is likely closed; when its relay line says no connection, the
relay's 41645, which the relay's own status warns of once no device reaches
it for a few minutes.

A daemon run without a TUN device (`--tun ""`, as in the one-machine demo
above) has no tunnel to sync through and listens for log sync on TCP 41644 on
every address, as tests and demos need.

## More than one admin, and more than one device each

An admin is a person, and holds a key on each device they approve from; never
copy a key. A person's keys cast that person's votes once, whichever signs.

**Approve from either of your two laptops.** Your admin name is what
`juist init` printed, and `juist admins` lists (your login name, unless you
gave `--admin-name`). Use it for the second laptop's key, or it becomes a
second admin:

```sh
juist admins new alice          # on the second laptop, with your admin name
juist admins add alice nid:… --on laptop2   # on the first, as printed
```

`juist admins` then lists which machine each key is on, and a change waiting
for approval says where the keys that can give it are.

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

Losing every key of the admins a change needs locks the network for good: the
break-glass secrets `juist init` writes are for a recovery that is not
implemented yet.

A change that needs someone else is saved as a file for them:

```sh
juist approve remove-phone.rec  # shows what it does, asks, and applies it once complete
```

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
  implemented yet, and without them it never will be, by design. A network where every
  device sits behind symmetric NAT needs a relay member. Public DHT and STUN
  servers see the addresses that use them, and nothing more.
- **Post-quantum:** group secrets are hybrid X25519 + ML-KEM-768. WireGuard
  traffic is not hedged yet: a per-pair ML-KEM preshared key is deferred past
  v1. Signatures are Ed25519.

All residual weaknesses are in [02-threat-model.md](docs/02-threat-model.md).

## Status

Milestone **M4** of [05-roadmap.md](docs/05-roadmap.md). What works:

- The membership log, with quorum, fork choice, fork alarm and a versioned
  schema.
- WireGuard on a real TUN device, and NAT traversal with member relays.
- LAN, gossip and DHT discovery.
- Invites by code and link, including across two NATs.
- Freshness leases.
- The daemon, and an operator who manages a device without sudo.
- Debian and Fedora packages.

Not yet: Android, ACLs (every member reaches every port on the others), exit
nodes, the post-quantum data plane, and QR codes.

The numbered notes in [docs/](docs/) record what each milestone decided and
why.

## Development

Go 1.26.5 or newer; `make` lists the targets.

```sh
make check                      # what CI gates on: lint, tidy, race tests, TCB budget
sudo -E make test-os-plumbing   # real TUN devices, namespaces, the NAT matrix (root)
make fuzz                       # every fuzz target, briefly
make build cross deb rpm        # binaries, all platforms, packages
```

`make check` skips everything that needs privileges. What each gate covers,
and what none of them does, is in
[12-validating.md](docs/12-validating.md).

| Doc | Contents |
|---|---|
| [01-requirements.md](docs/01-requirements.md) | Goals, priorities, decided constraints |
| [02-threat-model.md](docs/02-threat-model.md) | Adversaries, scope, residual weaknesses |
| [03-control-plane-options.md](docs/03-control-plane-options.md) | Why a signed log, not a coordinator |
| [04-architecture.md](docs/04-architecture.md) | Components, protocols, local security |
| [05-roadmap.md](docs/05-roadmap.md) | Milestones and their security exit criteria |
| [06-verification.md](docs/06-verification.md) | Test and fuzzing strategy |
| [07](docs/07-embedding-notes.md)–[11](docs/11-enrollment-and-freshness-notes.md) | What each milestone decided: embedding, trust log, mesh, connectivity, enrollment and freshness |
| [12-validating.md](docs/12-validating.md) | Running the gates, and what each claim is checked by |
