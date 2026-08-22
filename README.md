# wg-p2p

A radically peer-to-peer, Tailscale-like mesh VPN. WireGuard data plane; **no central
control plane** — no company-run and no self-hosted coordination server that must be
trusted. Membership, key distribution, revocation, and rendezvous are all peer-to-peer.

**Status: M1 (trust layer, offline).** The architecture plan, threat model, and
research are in `docs/`.

- `conn/` — the connectivity layer (M0): two nodes reach a direct WireGuard tunnel
  through an embedded Tailscale engine, with no coordination server.
- `types/`, `trust/log`, `trust/secrets`, `trust/store` — the membership log (M1):
  the genesis ceremony, k-of-n quorum verification, checkpoints and compaction,
  deterministic fork choice with a fail-closed fork alarm, epoch group secrets by
  hybrid post-quantum HPKE fan-out, crypto-derived addressing, and quorum-granted
  route validation. No networking; the transport that will move records is untrusted
  by construction and arrives in M2.
- `cmd/wgp2p` — the CLI that drives it.

See [05-roadmap.md](docs/05-roadmap.md) for what is next and
[08-trust-layer-notes.md](docs/08-trust-layer-notes.md) for what M1 decided.

## Priorities

1. **Security** — the control plane must not require trusting any third party or any
   single machine.
2. **Ease of use** — Tailscale-grade onboarding (invite codes / QR), automatic NAT
   traversal.
3. **Performance** — WireGuard data plane; kernel WireGuard as a post-v1 fast path.

## The design in one paragraph

Membership truth is a **hash-chained, append-only log of admin-signed records**
(generalizing the design of Tailscale's tailnet lock / TKA — see
[08-trust-layer-notes.md](docs/08-trust-layer-notes.md) for what was taken from it and
what was not), fully replicated and independently verified by every node — the transport that moves
log records is untrusted by construction. Membership changes require a **k-of-n admin
quorum** (plain attributable multi-signatures). Revocation is a first-class signed log
event, propagated by gossip and enforced with **fail-closed freshness leases**: peers
refuse to use membership state older than a TTL. Discovery is member gossip first, with
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
  can still reach until they learn of the revocation. The freshness TTL (24–72 h) is
  the knob: max revocation latency = max survivable partition. Instantaneous global
  revocation in a partitioned P2P system is impossible (a CAP-style limit).
- **Admin-quorum custody is the crown jewel.** Losing a quorum of admin keys *and* the
  pre-committed break-glass secrets makes the network unrecoverable **by design** —
  that unrecoverability is the security property.
- **Cold start needs one reachable point** — a public (untrusted) DHT entry or one
  reachable member. A network that is 100 % hard-NAT with no relay-capable member
  cannot form.

The full list of residual weaknesses is in [docs/02-threat-model.md](docs/02-threat-model.md).

## Post-quantum posture (as of M1)

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
([07-embedding-notes.md](docs/07-embedding-notes.md)); whether v1 patches the
vendored engine or defers the hedge is the open decision, and it has to be
settled before the record schema freezes at M3.

Post-quantum *authentication* (ML-DSA co-signatures) stays a roadmap item on
purpose: signatures are not harvest-now-decrypt-later exposed, so the ordering
is confidentiality first.

## Trying it

`wgp2p` creates a network and runs the signing ceremonies. Nothing here talks to
the network yet — moving records between machines is the operator's job in M1,
which is the shape a k-of-n ceremony has anyway, since the point of a quorum is
that no single machine holds *k* keys.

```sh
go build -o wgp2p ./cmd/wgp2p

# Create a network and enroll this device as its first member.
./wgp2p init -network demo -node-name laptop

# On the joining device: generate its keys. It prints the enrollment command
# for an admin to run, filled in.
./wgp2p key -create

# On an admin's machine: propose, collect signatures, apply.
./wgp2p propose add-node -name phone -identity nid:… -wg wg:… -x25519 x25519:… -mlkem mlkem:… -o add.rec
./wgp2p sign add.rec        # each admin signs on their own machine
./wgp2p verify add.rec      # says what is still missing
./wgp2p apply add.rec

./wgp2p log show
```

A machine whose only job is to sign holds an admin key and no network at all:
`wgp2p key -create-admin alice`.

## Development

Go 1.26.5 or newer; no other build dependencies (linters are fetched at pinned
versions on demand). `make` lists the available targets.

```sh
make check      # what CI gates on: lint, tidy, build, race tests, TCB budget
make test       # tests only
make cover      # race tests with a coverage summary
make cross      # compile for every v1 target platform
make fuzz       # smoke-run every fuzz target
make fuzz-long  # the milestone fuzz gate (hours, not seconds)
make tcb        # audit-scope size against its budget
```

CI (`.github/workflows/ci.yml`) invokes these same targets, so a green
`make check` locally means a green pipeline. Milestone exit criteria from
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
| [research/project-survey.md](docs/research/project-survey.md) | Survey of ~25 P2P/decentralized VPN projects (verified Aug 2026) |
| [research/building-blocks.md](docs/research/building-blocks.md) | Protocol/crypto building-block research (verified Aug 2026) |

## Decided constraints

- Scale: small team, 25–100 devices, a few admins.
- P2P strictness: **zero trusted infrastructure**; untrusted public helpers (STUN,
  BitTorrent DHT) permitted for reachability only.
- Platforms v1: Linux desktop, Android, FreeBSD.
- Implementation: Go, reusing Tailscale's BSD-3 open-source components (the
  disco/magicsock stack, DERP) where sensible. The trust layer follows tailnet lock's
  *design* but shares no code with it, and depends on nothing from Tailscale — a
  constraint CI enforces.
