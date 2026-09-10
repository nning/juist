# 05 — Roadmap

Scoped for 1–2 experienced developers part-time. Each milestone has a **security exit
criterion** — the milestone is not done until it passes, and they are cumulative (CI
keeps enforcing all previous criteria).

*(demo-able)* marks a milestone that closes a loop an outsider can be shown end to
end. It is not a claim about testability: every milestone here is testable by hand
when it lands, and M3a in particular is the first one that is *useful* — it just
leaves the enrollment ceremony as manual as M2 left it, which is why the label sits
on M4 instead.

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
CLI: `juist init / sign / verify / log show`. No networking.

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

## M3 — Off the local segment

Two slices, in this order. **M3a** makes the overlay carry traffic at all; **M3b**
makes it reach past the local segment. They are independent as code — neither needs
the other's mechanism — but M3b's NAT harness is built on the real devices M3a
introduces, and M3a is the slice that turns this from a thing you read
`juist status` on into a thing you use.

The record schema freezes at the end of M3. M3a defines no records, so the freeze
gate is in practice M3b, and every "before the M3 freeze" note elsewhere in these
docs means that point. What the freeze means after M3b is that a schema change
costs a quorum-signed record and a coordinated upgrade, not that it is
impossible.

### M3a — OS plumbing: a real device, a real router

Everything between the tunnel and the host stack. The data plane and the
reconciler both run against `tstun.NewFake` and `router.NewFake`, so the overlay
exists and nothing on the host can reach it. That is what M3a removes.

Scope: a real TUN device; a real `router.Router` wired at engine construction; a
route set for the peers, derived on every reconfiguration; and the privilege
story that comes with both. Explicitly *not* DNS — naming is post-v1, so the DNS
configurator stays the no-op one. The netns harness lands here rather than in
M3b, because two nodes with real devices no longer fit in one namespace; M3b
builds its NAT matrix on top of it.

The constraints the wiring has to respect are in
[07-embedding-notes.md](07-embedding-notes.md).

- **Exit criteria:** (1) two nodes on one LAN, each with a real device in its own
  netns, exchange ICMP echo over *both* address families and carry a TCP stream,
  driven by ordinary host tools rather than by the engine's internal ping;
  (2) default-deny survives the router — a node holding valid WireGuard keys but
  absent from (or removed from) the log gets no route, no filter entry and no
  handshake, asserted against a real device rather than the fake one; (3) the
  daemon's privilege footprint is exactly device creation plus `CAP_NET_ADMIN` on
  a dedicated user, documented in a unit file, with no part of it running as root.

### M3b — NAT traversal, relays, DHT cold start

Full magicsock integration (disco, hole punching), member-run membership-authenticated
DERP relays from log roles, BEP 44 announcements with blinded rotating topics + AEAD
payloads, persistent endpoint cache. The NAT simulation matrix extends M3a's netns
harness. Off-LAN endpoint exchange — the one thing M2 has no answer for — uses
hand-sealed `disco.CallMeMaybe` frames sent over a relay with
`magicsock.Conn.SendDERPPacketTo`, so the peer's stock magicsock processes them
natively; see [07-embedding-notes.md](07-embedding-notes.md).

Reflexive addresses learned through disco and relays are *added* to the local
interface scan M2 announces from, rather than replacing it — and the scan's known
weaknesses on a multi-homed host (09-mesh-layer-notes.md) are an input to that
decision.

**The freeze obligations land here too.** M3b is the last milestone that can add
a field for free: it spends that on versioning the schema itself, so a later
kind, role or field costs a quorum-signed `SchemaUpgrade` record and an upgrade
window rather than a new network, with builds too old for the version stopping
loudly instead of acting on the part they understand
([08-trust-layer-notes.md](08-trust-layer-notes.md)). The scaling question the target scale hides — the epoch wrap
set is O(n) *inline* in both `EpochRecord` and `Snapshot`, so one add or remove
re-replicates it to everyone — was settled by measuring a record at `MaxNodes`
rather than from the arithmetic: the fan-out costs bandwidth and not CPU, and
only above the target range. Four candidate hedges are declined and one, a
ciphersuite identifier, is taken; what each decision now binds is in
[08-trust-layer-notes.md](08-trust-layer-notes.md). The relay and DHT work
needs no record of its own: `relay-capable` is already a role, and where a
relay listens is a claim a node makes about itself, which belongs in its signed
endpoint announcement and not in the log.

- **Exit criteria:** (1) direct connections established across the simulated NAT
  matrix (full-cone, restricted, port-restricted, symmetric×easy, CGNAT double-NAT),
  relay fallback for symmetric×symmetric, UDP-blocked → relay-over-TCP;
  (2) a DHT observer (test crawler) can extract neither network identity, membership,
  nor member count from announcements; (3) non-member cannot use member relays.

## M4 — Enrollment + freshness + revocation UX *(demo-able — full product loop)*

QR invites (full-entropy) and wormhole-style typed codes (SPAKE2, single-use,
one-guess). `juist invite / join / revoke / rotate`. Quorum freshness leases,
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
