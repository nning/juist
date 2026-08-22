# 01 — Requirements & decided constraints

## Goal

A mesh VPN with Tailscale-grade usability but no central control plane: no company-run
service and no self-hosted coordination server that must be *trusted*. WireGuard
provides the data plane. The control plane — membership, key distribution, revocation,
endpoint discovery, NAT traversal assistance — must be peer-to-peer.

## Priorities (ordered)

1. **Security.** No single trusted machine or third party. Every security-relevant
   decision favors the smaller trusted computing base and the auditable, boring
   primitive. Where security and availability conflict (revocation under partition),
   fail closed by default with a tunable knob.
2. **Ease of use.** Onboarding by invite code or QR scan; connectivity "just works"
   through NATs; no config files for members. Ease of use may be *reduced* by security
   (e.g. quorum signing ceremonies for admin changes) but never the reverse.
3. **Performance.** WireGuard data plane. v1 runs Tailscale's wireguard-go fork on all
   platforms (a consequence of reusing the magicsock NAT-traversal stack — see
   [04-architecture.md](04-architecture.md)); kernel WireGuard is a post-v1 fast path
   for public-endpoint nodes. Control-plane overhead must be negligible at target
   scale.

## Decided constraints

| Question | Decision | Consequence |
|---|---|---|
| Audience / scale | Small team: 25–100 devices, a few admins | Full state replication on every node is cheap; k-of-n admin quorum instead of SSO; basic ACLs sufficient |
| P2P strictness | Zero **trusted** infra; untrusted public helpers (public STUN, BitTorrent DHT) allowed for reachability | DHT/STUN must be *trust-free by construction*: their compromise may delay connectivity, never corrupt membership |
| Platforms v1 | Linux desktop, Android, FreeBSD | Tailscale's wireguard-go fork + magicsock on all three (gomobile + VpnService on Android); kernel WG (Linux netlink, FreeBSD if_wg) post-v1 |
| Stack | Go, reusing Tailscale's BSD-3 OSS parts | `tailscale.com/tka` (membership log), disco/magicsock NAT traversal, DERP relay protocol are importable and production-tested |

## Functional requirements

- Create a network (genesis ceremony: initial admin keys, quorum policy, break-glass
  secrets), invite/enroll devices, list members, remove/revoke devices, rotate keys.
- Full mesh connectivity between all authorized members, direct where NAT allows,
  via member-run relays otherwise.
- LAN-only operation must work with zero internet connectivity.
- A network survives any single node disappearing — including any admin's node —
  without loss of connectivity or manageability (up to quorum policy).

## Non-goals (v1)

- Org-scale identity (SSO/OIDC), fine-grained per-port ACLs, MagicDNS-equivalent
  naming. (Naming stays a v1.x candidate; **coarse ACLs are now scheduled** as
  [05-roadmap.md](05-roadmap.md) M7a — the log schema must not preclude either.)
- Exit nodes and subnet routers **in v1** — but no longer out of scope. They are a
  planned v1.1 feature, sequenced strictly after coarse ACLs (who may *use* an exit
  node is an access-control question): see [05-roadmap.md](05-roadmap.md) M7 and
  [04-architecture.md](04-architecture.md) "Exit nodes and subnet routes". v1
  therefore *reserves* their schema — node roles and advertised-route grants, with
  full validation — even though no component consumes routes before M7.
- Anonymity/unobservability against a global passive adversary (Tor-class problem).
- iOS, macOS, Windows clients.
