# 06 — Verification strategy

Security claims are tested, not asserted. Every property in
[02-threat-model.md](02-threat-model.md) maps to at least one automated test below.

## 1. Trust-layer unit & property tests

- Adversarial cases, one test per attack: forged/missing/duplicate signatures,
  sub-quorum changes, replay, reorder, rollback to lower epoch, dropped checkpoints,
  address and key collisions, conflicting concurrent AUMs, fork injection. Each
  builds its record from live keys rather than replaying a checked-in vector: a
  frozen vector stops testing the validator the moment a schema field moves, and
  every one of these attacks is cheaper to construct than to store. A whole state
  arriving at once — a genesis naming founders, a checkpoint adopted as an anchor —
  is covered as its own path, since it is admitted on a quorum's word rather than
  record by record.
- Property-based tests over generated valid+invalid AUM sequences ⇒ all honest
  validators converge to identical state or identical alarm; no sequence reaches a
  state that skips quorum policy. The generator is ours and each case is a numbered
  seed rather than `pgregory.net/rapid` drawing fresh: a failure is replayed by
  running the subtest it names, with no shrinking step and no recorded corpus to
  keep. Reconsider if the sequences ever get complex enough that shrinking earns
  the dependency.
- Determinism check: two independent validation orders of the same AUM set produce
  byte-identical state (fork choice is deterministic).

## 2. Fuzzing (native `go test -fuzz`, run off CI)

Targets, added the milestone their input surface appears:

| Target | Input | Milestone |
|---|---|---|
| AUM/record decoder | raw CBOR | M1 |
| Chain validator | AUM sequences | M1 |
| Gossip frame parser | raw frames | M2 |
| Gossip catch-up messages, and the asking side's reading of them | raw frames | M4b |
| DHT payload decrypt/parse | BEP44 values | M3 |
| Invite code and link parser | strings | M4 |
| Enrollment handshake and message decoder | raw frames | M4 |
| Invite rendezvous stream | UDP packets on a punched path | M4 |
| LAN discovery beacon (`FuzzBeaconHandle`) | multicast DNS datagrams | M2 |
| Invite nameplate question and answer (`FuzzInviteMessages`) | multicast DNS datagrams | M4 |
| Relay invite forwarding (`FuzzForwardRequests`, `FuzzRelayAnswers`) | upgrade requests; a relay's answers to host and guest | M4 |
| IPC request decoder | socket payloads | M2 |
| QUIC Initial parser and ClientHello reassembly (`FuzzParse`, `FuzzPayloads`, `FuzzHello`) | a client's datagrams at the ingress | M11b |
| PROXY v2 header for UDP, and its LOCAL form (`FuzzReadUDP`) | an ingress's datagrams at the terminator, a terminator's at the ingress | M11b |

72 CPU-hour clean runs gate each milestone; corpus is preserved and grows. This
does not run on CI — hours per input surface is far more hosted-runner time than
the project wants to spend — so the gate is run by hand before a milestone
closes (`make fuzz-long`, or `make fuzz-one` per target to fan it out), against
a corpus kept outside the repository. `make fuzz` smoke-runs every target in
seconds and belongs in the pre-push routine. OSS-Fuzz application once public
would move the long runs onto someone else's hardware.

## 3. Multi-node integration harness

Go test driver orchestrating **network namespaces** (Linux CI), with Linux
netfilter doing the translation rather than a simulation of it:

- **NAT matrix (M3b, `conn/netnsnat_linux_test.go`):** full-cone,
  address-restricted, port-restricted, symmetric (endpoint-dependent), CGNAT
  double-NAT, UDP-blocked. Whether a path ended up direct is asked by stopping the
  relay — a pair that keeps reaching each other was never relying on it — and the
  lab classifies its own NATs with two reflectors before testing anything, so a
  rule that did not do what its name says cannot make a cell pass for the wrong
  reason.
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
- **Exit nodes and subnet routes (M6):** a node forwarding traffic it holds no
  grant for is dropped by every peer; a full-tunnel client leaks no DNS query and no
  non-LAN packet outside the tunnel (capture on the physical interface) while LAN
  destinations keep resolving and routing locally; withdrawing the `exit` role cuts
  egress at gossip convergence (reachable) and at the TTL boundary (partitioned).
- **Coarse ACLs (M14):** a peer denied by ACL is dropped by the *receiver* even with a
  sender patched to ignore its own filter; a member without a grant for an exit node
  gets nothing forwarded by it.
- **Chaos:** packet loss/reorder/duplication on gossip paths; node kill/restart
  mid-sync; clock skew between members (±minutes) — assert convergence and no
  state corruption (fsync/rollback tests with `kill -9`).

## 4. End-to-end / platform

- CI interop matrix: Linux + FreeBSD (qemu VMs), and from M10 an Android emulator
  smoke test — enrollment by QR and by code, ping over tunnel, revocation.
- Egress assertion on every E2E run: **zero packets to any third-party service**
  except declared untrusted helpers (DHT bootstrap, optional public STUN) — catches
  accidental Tailscale-infra dependencies from vendored code.
- Packaged-privilege drill, manual for now: install the RPM, start the unit, and
  assert from `/proc` that the daemon runs as the dedicated user with
  `CAP_NET_ADMIN` as its whole bounding set and a real device up (README, "Check
  the privilege footprint"). The privileged CI job proves the device and the
  namespaces, not the packaging — a hosted runner is the wrong place to install
  a package and create a system user. Automating it needs a VM in CI, which is
  the same dependency the FreeBSD interop matrix above wants; decide both at once.
- Manual pre-release drill on real networks: two hard-NAT'd home connections + one
  VPS relay member + one mobile (Android on LTE, from M10); full lifecycle including
  emergency revocation from a phone (from M19).

## 5. Cryptographic review gates

- Internal design review of the trust layer before M3 (log rules frozen).
- External audit at M16 scoped to `trust/*`, `enroll`, `gossip` (~7–9 k LOC) plus the
  reconciler's default-deny property, M6's route consumption and M8's resolver.
- A short machine-checkable model (e.g. Tamarin/ProVerif sketch or TLA+ for the
  epoch/freshness state machine) is a stretch goal — valuable for the freshness and
  fork-choice rules, which are where novel logic lives.

## 6. Continuous regression metrics

Tracked per commit in CI: direct-connection rate per NAT class, revocation
convergence time (connected case), sync time after 1-week offline, encoded size
of an epoch record and of a checkpoint at `MaxNodes` members, TCB LOC count
(`trust/*` + `enroll` — budget alarm if it grows past 10 k). Fuzz corpus coverage
is tracked per milestone instead, from the manual runs above.

The record-size metric exists because the O(n) epoch wrap fan-out is the term
that grows fastest with membership, and every figure written about it so far is
struct sizes multiplied out rather than anything measured. Before the M3 freeze
it is paired with a one-off: a gossip round against a `MaxNodes` log, timed.
Those two numbers are what the pre-freeze schema hedges in
[08-trust-layer-notes.md](08-trust-layer-notes.md) are decided against — they
either confirm the fan-out is the binding constraint or point at whatever is.
