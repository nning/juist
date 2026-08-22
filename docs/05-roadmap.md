# 05 — Roadmap

Scoped for 1–2 experienced developers part-time. Each milestone has a **security exit
criterion** — the milestone is not done until it passes, and they are cumulative (CI
keeps enforcing all previous criteria).

## M0 — Walking skeleton *(demo-able)*

Two Linux nodes, statically configured, tunnel up via embedded Tailscale wgengine
(wireguard-go + magicsock in direct-only mode), ping over the overlay.

- Proves: the vendored-engine embedding works without `controlclient`/`tsnet`.
- **Exit criterion:** E2E encrypted tunnel between two nodes with zero Tailscale
  infrastructure touched (verified by egress capture: no traffic to *.tailscale.com).

## M1 — Trust layer, offline

The membership log as a pure library: genesis ceremony, AddNode/RemoveNode,
admin keys + vote weights, k-of-n quorum verification, checkpoints, fork choice,
epoch group secret records (HPKE fan-out), address derivation/collision rules, and
node roles + advertised-route grants (`SetNodeRoutes`) with their validation rules —
reserved here, unconsumed until M7, because the record schema freezes at M3.
CLI: `wgp2p init / sign / verify / log show`. No networking.

- **Exit criterion:** an adversarial test suite — forged signatures, replayed AUMs,
  reordered chains, rollback to lower epoch, sub-quorum membership changes, colliding
  addresses, conflicting concurrent records, fork injection, self-asserted or
  overlay-overlapping route grants — is rejected 100 %; fuzz targets for AUM decoding
  run clean for 72 CPU-hours.

## M2 — Log-driven mesh on LAN *(demo-able)*

Reconciler: log state ⇒ WG config ⇒ netmap. Gossip anti-entropy + log-head beacons.
Blinded mDNS discovery. Two-to-five nodes on one LAN, no internet.

- **Exit criteria:** (1) default-deny proven — a node holding valid WG keys but absent
  from (or removed from) the log cannot complete a handshake with any member;
  (2) revocation converges across a connected 5-node mesh in <5 s including WG peer
  removal and PSK/epoch rotation; (3) LAN-only operation with zero internet works.

## M3 — NAT traversal, relays, DHT cold start

Full magicsock integration (disco, hole punching), member-run membership-authenticated
DERP relays from log roles, BEP 44 announcements with blinded rotating topics + AEAD
payloads, persistent endpoint cache. NAT simulation harness (netns) lands here.

- **Exit criteria:** (1) direct connections established across the simulated NAT
  matrix (full-cone, restricted, port-restricted, symmetric×easy, CGNAT double-NAT),
  relay fallback for symmetric×symmetric, UDP-blocked → relay-over-TCP;
  (2) a DHT observer (test crawler) can extract neither network identity, membership,
  nor member count from announcements; (3) non-member cannot use member relays.

## M4 — Enrollment + freshness + revocation UX *(demo-able — full product loop)*

QR invites (full-entropy) and wormhole-style typed codes (SPAKE2, single-use,
one-guess). `wgp2p invite / join / revoke / rotate`. Quorum freshness leases,
fail-closed TTL enforcement (including the startup gate), two-tier revocation
(routine vs. emergency epoch bump + forced re-handshake).

- **Exit criteria:** (1) invite brute-force yields exactly one online guess, failure
  is loud, code is dead after use/timeout; (2) with a simulated partition and
  fake-clock control: a revoked node loses access to reachable peers within gossip
  convergence and to partitioned peers at exactly the TTL boundary — fail-closed
  verified both directions (stale *victim* also refuses); (3) an admin quorum can be
  exercised with admin keys on separate machines (no single machine ever holds k
  keys).

## M5 — Platforms & packaging

Android app (gomobile + VpnService, Keystore-held identity), FreeBSD port, distro
packages, reproducible builds, signed releases.

- **Exit criterion:** 3-platform interop matrix green in CI (Linux/FreeBSD via qemu,
  Android emulator smoke test); release artifacts reproducible byte-for-byte from two
  independent builders.

## M6 — Hardening → v1

External security audit of the trust layer + enrollment (the ≈7–9 k LOC TCB), fix
findings, mature fuzz corpus (consider OSS-Fuzz), implementation-vs-threat-model
review, documentation of the residual-weakness acceptances for operators.

- **Exit criterion:** audit complete, all high/medium findings fixed and regression-
  tested; v1.0 tag.

## M7 — policy and routing *(v1.1, post-audit)*

Two features in strict order: the second is unscopeable without the first.

**M7a — coarse ACLs.** Per-node allow-lists as quorum-signed log records; the netmap
adapter renders them into `wgengine`'s packet filter, replacing v1's
allow-all-members rule, on sender and receiver alike.

- **Exit criterion:** under a policy denying A→B, B drops A's packets even when A's
  daemon is patched to ignore its own outbound filter (receiver-side enforcement
  proven independently of sender cooperation); a node whose policy state is past the
  freshness TTL fails closed.

**M7b — exit nodes and subnet routers.** The `exit-node` role and route grants
consumed from log state (schema and validation landed in M1), widened `AllowedIPs`
and filter destinations, privileged-helper forwarding/NAT, client-side default-route
capture with LAN bypass and DNS handling. Design in
[04-architecture.md](04-architecture.md#exit-nodes-and-subnet-routes-v11--schema-reserved-in-v1).

- **Exit criteria:** (1) a member that forwards traffic without a route grant is
  dropped by every peer; (2) a grant overlapping the overlay ULA or 100.64/10 is
  rejected by the log validator, so an exit node can never intercept member-to-member
  traffic; (3) with a full tunnel up, no DNS query and no non-LAN packet leaves the
  host outside the tunnel (asserted by capture on the physical interface) while LAN
  destinations still resolve and route locally; (4) withdrawing the `exit-node` role
  cuts egress within gossip convergence for reachable clients and at the TTL boundary
  for partitioned ones.

## Deferred (post-v1, schema must not preclude)

Kernel WireGuard fast path for public-endpoint nodes · naming (MagicDNS-equivalent) ·
hardware-backed admin keys (FIDO2/PIV signing) · update transparency log ·
macOS/Windows/iOS · PQ authentication (ML-DSA checkpoint co-signatures).
