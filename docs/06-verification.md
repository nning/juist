# 06 — Verification strategy

Security claims are tested, not asserted. Every property in
[02-threat-model.md](02-threat-model.md) maps to at least one automated test below.

## 1. Trust-layer unit & property tests

- Golden adversarial vectors (checked into the repo): forged/missing/duplicate
  signatures, sub-quorum changes, replay, reorder, rollback to lower epoch, dropped
  checkpoints, address collisions, conflicting concurrent AUMs, fork injection.
- Property-based tests (e.g. `pgregory.net/rapid`): random valid+invalid AUM sequences
  ⇒ all honest validators converge to identical state or identical alarm; no sequence
  reaches a state that skips quorum policy.
- Determinism check: two independent validation orders of the same AUM set produce
  byte-identical state (fork choice is deterministic).

## 2. Fuzzing (native `go test -fuzz`, run in CI continuously)

Targets, added the milestone their input surface appears:

| Target | Input | Milestone |
|---|---|---|
| AUM/record decoder | raw CBOR | M1 |
| Chain validator | AUM sequences | M1 |
| Gossip frame parser | raw frames | M2 |
| DHT payload decrypt/parse | BEP44 values | M3 |
| Invite string / QR token parser | strings | M4 |
| IPC request decoder | socket payloads | M2 |

72 CPU-hour clean runs gate each milestone; corpus is preserved and grows. OSS-Fuzz
application once public.

## 3. Multi-node integration harness

Go test driver orchestrating **network namespaces** (Linux CI) with nftables/tc:

- **NAT matrix:** full-cone, address-restricted, port-restricted, symmetric
  (endpoint-dependent), CGNAT double-NAT, UDP-blocked. Assert: direct connection where
  theoretically possible, relay fallback otherwise, and the *measured* direct rate
  per pair-class recorded as a regression metric.
- **Membership scenarios:** enrollment (QR + code paths), routine removal, emergency
  revocation (epoch bump), key rotation, admin add/remove, break-glass disablement.
- **Partition & freshness:** iptables-partition a victim with a revoked peer; with an
  injectable fake clock verify fail-open window ends at exactly TTL; verify a stale
  node refuses to *initiate* as well as accept; verify startup gate blocks tunnels
  until sync when state is stale.
- **Fork / split-view:** a simulated malicious quorum feeds divergent chains to
  disjoint node sets; assert both sides alarm on first cross-contact and refuse
  silent adoption of either head.
- **DHT adversary:** local mainline-DHT swarm; an eclipse of the topic delays cold
  start but never yields a false member; a crawler on the swarm cannot link
  announcements to the network or count members.
- **Relay abuse:** non-member and *revoked* member attempt relay use ⇒ rejected.
- **Policy & routing (M7):** a peer denied by ACL is dropped by the *receiver* even
  with a sender patched to ignore its own filter; a node forwarding traffic it holds no
  grant for is dropped by every peer; a full-tunnel client leaks no DNS query and no
  non-LAN packet outside the tunnel (capture on the physical interface) while LAN
  destinations keep resolving and routing locally; withdrawing an `exit-node` role cuts
  egress at gossip convergence (reachable) and at the TTL boundary (partitioned).
- **Chaos:** packet loss/reorder/duplication on gossip paths; node kill/restart
  mid-sync; clock skew between members (±minutes) — assert convergence and no
  state corruption (fsync/rollback tests with `kill -9`).

## 4. End-to-end / platform

- CI interop matrix: Linux + FreeBSD (qemu VMs), Android emulator smoke test —
  enrollment by QR, ping over tunnel, revocation.
- Egress assertion on every E2E run: **zero packets to any third-party service**
  except declared untrusted helpers (DHT bootstrap, optional public STUN) — catches
  accidental Tailscale-infra dependencies from vendored code.
- Manual pre-release drill on real networks: two hard-NAT'd home connections + one
  VPS relay member + one mobile (Android on LTE); full lifecycle including emergency
  revocation from a phone.

## 5. Cryptographic review gates

- Internal design review of the trust layer before M3 (log rules frozen).
- External audit at M6 scoped to `trust/*`, `enroll`, `gossip` (~7–9 k LOC) plus the
  reconciler's default-deny property.
- A short machine-checkable model (e.g. Tamarin/ProVerif sketch or TLA+ for the
  epoch/freshness state machine) is a stretch goal — valuable for the freshness and
  fork-choice rules, which are where novel logic lives.

## 6. Continuous regression metrics

Tracked per commit in CI: direct-connection rate per NAT class, revocation
convergence time (connected case), sync time after 1-week offline, TCB LOC count
(`trust/*` + `enroll` — budget alarm if it grows past 10 k), fuzz corpus coverage.
