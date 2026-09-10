# juist

A radically peer-to-peer, Tailscale-like mesh VPN. WireGuard data plane; **no central
control plane** — no company-run and no self-hosted coordination server that must be
trusted. Membership, key distribution, revocation, and rendezvous are all peer-to-peer.

**Status: M3b — a mesh that works off the local segment.**

- `types`, `trust/log`, `trust/secrets`, `trust/store` (M1) — the membership log:
  the genesis ceremony, k-of-n quorum verification, checkpoints and compaction,
  deterministic fork choice with a fail-closed fork alarm, epoch group secrets by
  hybrid post-quantum HPKE fan-out, crypto-derived addressing, and quorum-granted
  route validation. No networking; the transport that moves records is untrusted
  by construction and lives above this layer. The record schema is versioned, so
  changing it after the M3 freeze costs a quorum-signed record and an upgrade
  window rather than a new network.
- `conn` (M0, extended at M3a and M3b) — the connectivity layer: a direct
  WireGuard tunnel through an embedded Tailscale engine with no coordination
  server, on a real TUN device whose addresses and peer routes are programmed
  into the host, so ordinary host tools reach the overlay. Off the local segment
  it punches through NAT: full-cone, restricted and port-restricted pairs, a
  symmetric NAT against an easy one, and a subscriber behind carrier-grade NAT.
  A symmetric pair cannot be punched by anyone and falls back to a member's
  relay, as does a network that passes no UDP at all.
  `packaging/systemd/juistd.service` holds the privilege story that comes with a
  real device: one unprivileged user, `CAP_NET_ADMIN`, and nothing else.
- `gossip`, `discovery/mdns`, `daemon` (M2) — the mesh. The reconciler renders
  log state into a WireGuard peer set and nothing else can; anti-entropy keeps
  every member's log in step, with each frame sealed under the epoch group
  secret; blinded multicast lets members find each other on a LAN with no
  internet and no rendezvous service. Five nodes converge on a full mesh in
  ~140 ms and a revocation crosses it in ~80 ms.
- `relay`, `discovery/dht` (M3b) — how members reach each other from anywhere. A
  member the log grants `relay-capable` runs an embedded DERP relay that only
  members may use, and a STUN responder that tells a member its own reflexive
  address without asking a third party. Two devices that share no LAN and hold
  no address for each other meet through the public BitTorrent DHT, at an
  address only a holder of the epoch group secret can compute and with a payload
  only a holder of it can read — a storage node cannot tell which network an item
  belongs to, who is in it, or how many there are
  ([10-connectivity-notes.md](docs/10-connectivity-notes.md)).
- `cmd/juist`, `cmd/juistd` — the CLI and the daemon.

[05-roadmap.md](docs/05-roadmap.md) is what comes next; the numbered notes in
[Documents](#documents) are what each milestone decided and why.

## Scope and priorities

In this order, and several decisions below cite the ordering:

1. **Security** — the control plane must not require trusting any third party or any
   single machine.
2. **Ease of use** — Tailscale-grade onboarding (invite codes / QR), automatic NAT
   traversal.
3. **Performance** — WireGuard data plane; kernel WireGuard as a post-v1 fast path.

Within these constraints, which are decided rather than open:

- Scale: small team, 25–100 devices, a few admins.
- P2P strictness: **zero trusted infrastructure**; untrusted public helpers (STUN,
  BitTorrent DHT) permitted for reachability only.
- Platforms v1: Linux desktop, Android, FreeBSD.
- Implementation: Go, reusing Tailscale's BSD-3 open-source components (the
  disco/magicsock stack, DERP) where sensible. The trust layer follows tailnet lock's
  *design* but shares no code with it, and depends on nothing from Tailscale — a
  constraint CI enforces.

## The design in one paragraph

Membership truth is a **hash-chained, append-only log of admin-signed records**
(generalizing the design of Tailscale's tailnet lock / TKA — see
[08-trust-layer-notes.md](docs/08-trust-layer-notes.md) for what was taken from it and
what was not), fully replicated and independently verified by every node — the transport that moves
log records is untrusted by construction. Membership changes require a **k-of-n admin
quorum** (plain attributable multi-signatures). Revocation is a first-class signed log
event, propagated by gossip and enforced with **fail-closed freshness leases** (M4):
peers refuse to use membership state older than a TTL. Discovery is member gossip first, with
the public BitTorrent DHT (encrypted, blinded, strictly trust-free) for cold start and
blinded mDNS on LAN. NAT traversal reuses Tailscale's disco/magicsock stack with
member-volunteered, E2E-blind relays. The data plane is WireGuard — Tailscale's
wireguard-go fork on all v1 platforms, kernel WireGuard as a post-v1 fast path for
public-endpoint nodes — with per-pair ML-KEM-768-derived preshared keys as a
post-quantum hedge (planned; see below for what is actually in place today).

## Can this be highly secure? (honest verdict)

**Yes — and in one important dimension stronger than a coordinated design: there is no
trusted coordinator to compromise.** But three properties are fundamentally weaker than
a centralized system and are accepted consciously, not accidentally:

- **Revocation is eventually-consistent.** A revoked device keeps access to peers it
  can still reach until they learn of the revocation. The freshness TTL (24–72 h,
  M4) is the knob: max revocation latency = max survivable partition. Instantaneous global
  revocation in a partitioned P2P system is impossible (a CAP-style limit).
- **Admin-quorum custody is the crown jewel.** Losing a quorum of admin keys *and* the
  pre-committed break-glass secrets makes the network unrecoverable **by design** —
  that unrecoverability is the security property.
- **Cold start needs one reachable point** — a public (untrusted) DHT entry or one
  reachable member. A network that is 100 % hard-NAT with no relay-capable member
  cannot form.

The full list of residual weaknesses is in [docs/02-threat-model.md](docs/02-threat-model.md).

## Post-quantum posture

Partly hedged, and the gap is deliberate rather than overlooked. What matters is
which properties a future quantum computer could break *retroactively*, against
traffic and records recorded today, versus which it could only break *while
attacking*.

| Property | Today | Retroactively breakable? |
|---|---|---|
| Group-secret confidentiality (discovery, gossip) | **Hedged.** HPKE with `DHKEM(X25519)+ML-KEM-768` | No — breaking X25519 later still leaves ML-KEM-768 |
| Data-plane traffic confidentiality | **Not hedged.** WireGuard Noise IKpsk2 over Curve25519, no preshared key | **Yes** — this is the real exposure |
| Membership authenticity (all signatures, quorum) | Not hedged. Ed25519 | No — forging needs a quantum computer at the time of the attack |
| Record hashing, addressing, break-glass commitments | SHA-256 | No |

The one that would hurt is the data plane: an adversary recording tunnel traffic
now and breaking Curve25519 in twenty years could read it. The fix is the
sanctioned one — mix an ML-KEM-768-derived secret into each pair's WireGuard
preshared key — and the schema already carries every node's ML-KEM key for it.
It is unconsumed because the embedded engine exposes no path to a preshared key
([07-embedding-notes.md](docs/07-embedding-notes.md)). M3b settled what to do
about that: **defer past v1**. The schema was never what stood in the way — a
KEM ciphertext travels over gossip, not in the log — so what is left is the cost
of patching a vendored dependency and carrying it through every upgrade, inside
the audit scope, for a hedge against an adversary that does not exist yet.

Post-quantum *authentication* (ML-DSA co-signatures) stays a roadmap item on
purpose: signatures are not harvest-now-decrypt-later exposed, so the ordering
is confidentiality first.

## Trying it

`juist` administers the membership log — the signing ceremonies — and `juistd`
runs a member, rendering the log into a live WireGuard peer set and keeping it in
step with the other members by gossip.

```sh
make build        # both, into build/
```

### Enroll two devices

Enrollment records still move between machines by hand — the invite/join flow is
M4 — which is the shape a k-of-n ceremony has anyway, since the point of a quorum
is that no single machine holds *k* keys.

```sh
# Device A: create the network and enroll A as its first member.
./build/juist init -network demo -node-name laptop

# Device B: generate B's keys, and print the enrollment command for them.
./build/juist key -create -name phone
```

`key -create` prints the `juist propose add-node …` line an admin has to run,
with B's four public keys already filled in. Copy that command to A rather than
retyping it: the ML-KEM key alone is some 1.5 kB.

```sh
# Device A (it holds the admin key): propose, sign to quorum, apply.
./build/juist propose add-node -name phone -identity nid:… -wg wg:… -x25519 x25519:… -mlkem mlkem:… -o add.rec
./build/juist sign add.rec          # each admin signs on its own machine
./build/juist verify add.rec        # says how much vote weight is still missing
./build/juist apply add.rec         # applies to A's log: admits B, bumps the epoch, seals B a wrap

# Give B the log A just built. B keeps its own node.keys; copy only the log.
# Copy the directory's *contents*: anything B has already run created
# ~/.config/juist/log there, and a plain "scp -r …/log B:…/log" would then
# land the copy inside it, where nothing reads it.
#   ssh B mkdir -p ~/.config/juist/log
#   scp -r ~/.config/juist/log/. B:~/.config/juist/log/
```

`juist verify` on B then reports `group secret readable by this device`, which is
the check that the enrollment actually took: B can open the epoch's group secret,
so it can read discovery and gossip. `juist log show` prints the chain and the
resolved state on either machine. A machine whose only job is to sign holds an
admin key and no network at all: `juist key -create-admin alice`.

### Bring up the mesh

On each device, on the same LAN, with no internet and nothing configured about
where anyone is:

```sh
sudo setcap cap_net_admin+ep ./build/juistd   # or run under the systemd unit below
./build/juistd -verbose                        # the banner names the network, member count, and device
```

`juistd` creates a real TUN device (`juist0` by default) and programs
the host's routes for the peer set, so overlay addresses are reachable with
ordinary tools. That needs `CAP_NET_ADMIN` — grant it with `setcap` as above, or
install `packaging/systemd/juistd.service`, which runs the daemon as a dedicated
unprivileged user with that one capability and nothing else. Pass `-tun ""` to
run without a device at all.

Then, in another shell on either machine:

```sh
./build/juist status
```

Each node should report the other under `peers up` — a member the log carries
and that this node has now discovered on the LAN. A member not yet heard from
shows as `unreachable`, which is a mesh still coming up, not a denial. The
daemon's `-verbose` log shows the blinded mDNS discovery and the WireGuard
handshake as they happen.

With a device up you can also `ping` a peer's overlay address directly, or open a
TCP connection to it, which is what shows the tunnel reaching the host stack and
not just the engine. What the mesh demonstrates: log state becomes a peer set and
nothing else can make one, a node with valid WireGuard keys but absent from the
log gets no route and no handshake, blinded multicast finds members with no
rendezvous service, and gossip keeps every node's log in step.

### Volunteer a relay

Off the LAN, a pair whose NATs cannot be punched needs a member to relay for
them, and every member needs somewhere to learn its own reflexive address.
Both are the same grant, and it is an ordinary quorum-signed record:

```sh
./build/juist propose set-routes -identity nid:… -roles relay-capable -o relay.rec
./build/juist sign relay.rec && ./build/juist apply relay.rec
```

The granted member starts an embedded DERP relay and a STUN responder within a
reconcile, says so in its `-verbose` log, and announces where they listen. Every
other member picks it up from gossip: `juist status` then reports `relays 1 of 1
granted`, and the daemon's log shows netcheck learning that member's reflexive
address through it. Only members are admitted, and the relay's certificate is
authenticated by the hash in that member's signed announcement rather than by
any authority. Below two relay-capable members `juist status` says so — one
relay is a network that loses its fallback whenever that member is off.

Members that share no LAN and hold no address for each other find one another
through the public BitTorrent DHT, which needs no configuration and is on unless
`juistd -no-dht` turns it off.

### Both nodes on one machine

The whole loop above runs on a single machine with no privileges at all, which is
the quickest way to see it work: give each node its own state directory and no
device.

```sh
./build/juist -home /tmp/A init -network demo -node-name laptop
./build/juist -home /tmp/B key -create -name phone
# …propose / sign / apply on A, then copy the log's contents into B's:
#   mkdir -p /tmp/B/log && cp -r /tmp/A/log/. /tmp/B/log/

./build/juistd -home /tmp/A -tun "" -verbose &
./build/juistd -home /tmp/B -tun "" -verbose &
./build/juist -home /tmp/A status
```

Both daemons discover each other over blinded mDNS on the host's own LAN
interface and complete a WireGuard handshake, so `peers up` reaches 1 on each and
a revocation converges exactly as it does across two machines. What it cannot
show is M3a's half: with `-tun ""` nothing is plumbed into the host, and two real
devices do not fit in one network namespace either — both nodes' overlay
addresses would be local to the host, so a `ping` between them never enters a
tunnel. Reaching a peer over the overlay for real needs two machines, or two
network namespaces on one; `sudo -E make test-os-plumbing` builds exactly that
second arrangement and pings and streams TCP across it.

### Watch a revocation converge

With both daemons running, remove B from A:

```sh
./build/juist propose remove-node -identity nid:… -o rm.rec
./build/juist sign rm.rec
./build/juist apply rm.rec          # a running daemon applies it over its control socket
```

Within a couple of seconds `juist status` on A drops B from `peers up` and the
epoch advances: B loses its WireGuard peer entry immediately, and at the next
epoch the group secret that let it read discovery and gossip.

## Validating it

Every milestone in [05-roadmap.md](docs/05-roadmap.md) has a security exit
criterion, and each one is a test that keeps running after its milestone
closes. The walkthroughs above are the manual loop; this is the gates — how to
run them yourself, and, more importantly, which ones a green run does *not*
cover.

### Three gates, and what each leaves out

```sh
make check                     # what CI gates on; needs no privileges
sudo -E make test-os-plumbing  # real devices, network namespaces, NAT; needs root
make fuzz-long                 # the parser gate: hours per target, never on CI
```

**`make check` silently skips everything that needs privilege.** The real-device
and namespace tests call `t.Skip` when they cannot create a TUN device or a
namespace, so a machine without them reports green while testing none of the OS
plumbing or NAT traversal. That is deliberate — an unprivileged `go test ./...`
has to stay useful — and it is why the privileged tests have a target of their
own, which sets `JUIST_REQUIRE_OS_PLUMBING=1` so a skip there becomes a failure.
If you are checking a claim about devices, routes or NAT, `make check` is not the
command.

**Fuzzing never runs on CI.** [06-verification.md](docs/06-verification.md) sets
the gate at 72 clean CPU-hours per input surface, which is far more hosted-runner
time than this project will spend, so it is run by hand before a milestone
closes. `make fuzz` smoke-runs every target in seconds and belongs in the
pre-push routine; `make fuzz-matrix` lists the targets so `make fuzz-one` can
give each its own preserved corpus.

**The DHT tests never touch the public network.** They run against a private
swarm on loopback, including the crawler that must learn nothing. Reaching the
real BitTorrent DHT is `juistd` without `-no-dht`, and it is the one thing here
that sends traffic to strangers.

### What checks what

`go test ./<pkg> -run <name> -count=1 -v` runs any single one of these; the
privileged ones need `sudo -E` and `JUIST_REQUIRE_OS_PLUMBING=1` to fail rather
than skip. A NAT cell can be run alone with
`-run 'TestNetnsNATMatrix/symmetric_x_symmetric'`.

| Claim | Where it is checked | Privileged |
|---|---|---|
| M0 — a tunnel with no coordination server | `conn`: `TestTwoNodeOverlayPing`, `TestTwoNodeOverlayPingBothFamilies` | no |
| M0 — nothing reaches a third party | `conn`: `TestNoThirdPartyEgress`; the AF_PACKET tap inside `TestNetnsOverlayCarriesTraffic` | for the tap |
| M1 — the adversarial suite is rejected 100 % | `trust/log`: `adversarial_test.go`, one test per attack | no |
| M1 — parsers survive fuzzing | `make fuzz-long` over `FuzzDecodeAUM`, `FuzzValidateAUM`, `FuzzChainValidate` | no |
| M2 — default-deny: no log entry, no handshake | `daemon`: `TestNonMemberIsNeverAPeer`; `conn`: `TestNonMemberIsDenied`, `TestFilterRejectsNonMembers` | no |
| M2 — revocation converges inside the budget | `daemon`: `TestRevocationConvergesWithinTheBudget`, `TestRevokedDeviceLosesTheDataPlane` | no |
| M2 — LAN-only, zero internet | `daemon`: `TestMeshFormsOnTheLanAlone` | no |
| M3a — a real device is programmed into the host | `conn`: `TestRealDevicePlumbsOverlayIntoHost` | **yes** |
| M3a — two nodes carry ICMP over both families, and TCP | `conn`: `TestNetnsOverlayCarriesTraffic` | **yes** |
| M3a — default-deny survives the router | `conn`: `TestNetnsDefaultDenySurvivesTheRouter` | **yes** |
| M3a — the daemon's privilege footprint | the package, by hand — see [Check the privilege footprint](#check-the-privilege-footprint) | **yes** |
| M3b — direct paths across the NAT matrix | `conn`: `TestNetnsNATMatrix` | **yes** |
| M3b — relay fallback, and relay over TCP | `conn`: `TestNetnsNATMatrix/symmetric_x_symmetric`, `TestNetnsRelayCarriesWhatUDPCannot` | **yes** |
| M3b — a DHT observer learns nothing | `discovery/dht`: `TestCrawlerLearnsNothing`, `TestAnItemIsUselessWithoutTheGroupSecret` | no |
| M3b — non-members cannot use member relays | `relay`: `TestNonMemberCannotUseTheRelay`, `TestRemovedMemberLosesTheConnectionItHolds` | no |
| M3b — the record schema is versioned | `trust/log`: `schema_test.go`; `types`: `TestUnknownEpochSuiteRejected` | no |

### Check the privilege footprint

M3a's third exit criterion is a claim about the *installed* daemon, so it is
checked against the package rather than against a binary in `build/`:

```sh
make rpm && sudo dnf install ./build/rpm/RPMS/*/juist-*.rpm
sudo -u juist juist -home /var/lib/juist init -network testbox -node-name $(hostname -s)
sudo systemctl enable --now juistd
```

```sh
pid=$(systemctl show -p MainPID --value juistd)
ps -o user,pid,comm -p $pid                 # juist, never root
getpcaps $pid                               # cap_net_admin=eip, and nothing else
grep -E 'CapBnd|NoNewPrivs' /proc/$pid/status   # CapBnd 0x1000, NoNewPrivs 1
ip -br addr show juist0                     # the device, carrying the derived overlay address
systemd-analyze security juistd.service
```

`CapBnd` matters as much as `CapEff`: the effective set alone would still pass
if the bounding set were left wide, and the criterion is that nothing beyond
`CAP_NET_ADMIN` is reachable. A node enrolled without an explicit overlay IPv4
address carries only its derived ULA address on the device, and a network of one
member programs no peer routes — both are the expected picture, not a half-built
device.

### Reading a failure in the NAT matrix

The matrix classifies each NAT before it tests anything — one socket, two
reflectors — and logs the mapped ports it saw. A cell that fails on
`is configured as … but maps one socket to …` is a fault in the lab's own
netfilter rules and not in juist. Past that point the nodes log magicsock's
NAT-traversal chatter: `sent ping … (10.77.0.22:41641)` with no matching
`got ping` on the other side means the punch packets are being dropped, and
`learned no address on the lab's LAN` means STUN never answered, so there was
nothing to punch to. In CI the whole log is in the `OS plumbing (privileged)`
job; `gh run view <id> --log-failed` is more readable with the job prefix
stripped:

```sh
gh run view <id> --log-failed | sed 's/.*make test-os-plumbing\t//'
```

### What no test does for you

- **Two real machines on a real LAN.** Everything above runs namespaces or
  loopback. M2's multicast-socket bug was found by running two real daemons and
  by nothing else, because the tests inject a socket
  ([09-mesh-layer-notes.md](docs/09-mesh-layer-notes.md)).
- **The public DHT.** `juistd -verbose` without `-no-dht` bootstraps from the
  public routers and logs `discovered … through the DHT` when rendezvous
  succeeds. This publishes an encrypted blob to a network of strangers and tells
  a passive observer that this host speaks the BitTorrent DHT — residual
  weakness 5 in [02-threat-model.md](docs/02-threat-model.md). Turn it on
  deliberately.
- **Upgrades.** Nothing yet tests a network whose members run different builds;
  the schema version exists so that case fails loudly rather than silently, but
  the readiness check that would stop an admin stranding members is M4/M5
  ([08-trust-layer-notes.md](docs/08-trust-layer-notes.md)).

## Development

Go 1.26.5 or newer; no other build dependencies (linters are fetched at pinned
versions on demand). `make` lists the available targets.

```sh
make check      # lint, tidy, compile, race tests, TCB budget
make build      # the binaries, into build/
make test       # tests only
make cover      # race tests with a coverage summary
make cross      # compile for every v1 target platform
make rpm        # build an installable RPM (Fedora; needs rpm-build)
make tcb        # audit-scope size against its budget
```

[Validating it](#validating-it) covers the other three —
`test-os-plumbing`, `fuzz` and `fuzz-long` — and what each of them leaves out.

CI (`.github/workflows/ci.yml`) invokes these same targets, so what `make check`
gates on locally is what it gates on there. It is not the whole pipeline: CI also
runs `make cross` and, in a job of its own, `make test-os-plumbing`, which is the
only place the real-device and NAT tests ever run. Milestone exit criteria from
[05-roadmap.md](docs/05-roadmap.md) are cumulative and land here as ordinary
tests, so they keep being enforced after their milestone closes.

## Documents

| Doc | Contents |
|---|---|
| [01-requirements.md](docs/01-requirements.md) | Goals, priorities, decided constraints |
| [02-threat-model.md](docs/02-threat-model.md) | Adversaries, scope, residual weaknesses |
| [03-control-plane-options.md](docs/03-control-plane-options.md) | Evaluation of five control-plane architectures; why the signed log wins; libp2p decision record |
| [04-architecture.md](docs/04-architecture.md) | Component architecture, protocols, local security |
| [05-roadmap.md](docs/05-roadmap.md) | Milestones with security exit criteria |
| [06-verification.md](docs/06-verification.md) | Test and validation strategy |
| [07-embedding-notes.md](docs/07-embedding-notes.md) | What embedding Tailscale's stack actually requires; findings from M0 |
| [08-trust-layer-notes.md](docs/08-trust-layer-notes.md) | What the membership log actually does; M1's decisions, tightenings, and deferrals |
| [09-mesh-layer-notes.md](docs/09-mesh-layer-notes.md) | What the mesh actually does; M2's decisions and what the review rounds changed |
| [10-connectivity-notes.md](docs/10-connectivity-notes.md) | Relays, rendezvous and NAT traversal; M3b's decisions and the schema freeze |
| [research/project-survey.md](docs/research/project-survey.md) | Survey of ~25 P2P/decentralized VPN projects (verified Aug 2026) |
| [research/building-blocks.md](docs/research/building-blocks.md) | Protocol/crypto building-block research (verified Aug 2026) |

