# wg-p2p

A radically peer-to-peer, Tailscale-like mesh VPN. WireGuard data plane; **no central
control plane** — no company-run and no self-hosted coordination server that must be
trusted. Membership, key distribution, revocation, and rendezvous are all peer-to-peer.

**Status: M0 (walking skeleton).** The architecture plan, threat model, and research
are in `docs/`. `conn/` is the first code: the connectivity layer, with two nodes
reaching a direct WireGuard tunnel through an embedded Tailscale engine and no
coordination server. See [05-roadmap.md](docs/05-roadmap.md) for what is next.

## Priorities

1. **Security** — the control plane must not require trusting any third party or any
   single machine.
2. **Ease of use** — Tailscale-grade onboarding (invite codes / QR), automatic NAT
   traversal.
3. **Performance** — WireGuard data plane; kernel WireGuard as a post-v1 fast path.

## The design in one paragraph

Membership truth is a **hash-chained, append-only log of admin-signed records**
(generalizing Tailscale's tailnet lock / TKA, whose BSD-3 Go implementation we reuse),
fully replicated and independently verified by every node — the transport that moves
log records is untrusted by construction. Membership changes require a **k-of-n admin
quorum** (plain attributable multi-signatures). Revocation is a first-class signed log
event, propagated by gossip and enforced with **fail-closed freshness leases**: peers
refuse to use membership state older than a TTL. Discovery is member gossip first, with
the public BitTorrent DHT (encrypted, blinded, strictly trust-free) for cold start and
blinded mDNS on LAN. NAT traversal reuses Tailscale's disco/magicsock stack with
member-volunteered, E2E-blind relays. The data plane is WireGuard — Tailscale's
wireguard-go fork on all v1 platforms, kernel WireGuard as a post-v1 fast path for
public-endpoint nodes — with per-pair ML-KEM-768-derived preshared keys as a
post-quantum hedge.

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

## Development

Go 1.26.5 or newer; no other build dependencies (linters are fetched at pinned
versions on demand). `make` lists the available targets.

```sh
make check   # what CI gates on: lint, tidy, build, race tests
make test    # tests only
make cover   # race tests with a coverage summary
make cross   # compile for every v1 target platform
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
| [research/project-survey.md](docs/research/project-survey.md) | Survey of ~25 P2P/decentralized VPN projects (verified Aug 2026) |
| [research/building-blocks.md](docs/research/building-blocks.md) | Protocol/crypto building-block research (verified Aug 2026) |

## Decided constraints

- Scale: small team, 25–100 devices, a few admins.
- P2P strictness: **zero trusted infrastructure**; untrusted public helpers (STUN,
  BitTorrent DHT) permitted for reachability only.
- Platforms v1: Linux desktop, Android, FreeBSD.
- Implementation: Go, reusing Tailscale's BSD-3 open-source components
  (`tka`, disco/magicsock stack, DERP) where sensible.
