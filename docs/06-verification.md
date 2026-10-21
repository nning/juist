# 06 — Verification strategy

Security claims are tested, not asserted. Every property in
[02-threat-model.md](02-threat-model.md) maps to at least one automated test below;
what has none yet is listed as open where its section says so.
[12-validating.md](12-validating.md) says which gate runs which test, and records
the runs.

## 1. Trust-layer unit & property tests

- Adversarial cases, one test per attack (`trust/log/adversarial_test.go` and
  beside it): forged/missing/duplicate signatures, sub-quorum changes, replay,
  reorder, rollback to a lower epoch, lost checkpoints, address and key
  collisions, conflicting concurrent records, forks below the anchor. Each builds
  its record from live keys rather than replaying a checked-in vector, so a schema
  change cannot leave a frozen vector testing nothing. A whole state arriving at
  once — a genesis naming founders, a checkpoint adopted as an anchor — is covered
  as its own path, since it is admitted on a quorum's word, under the rule a
  record is admitted by: `FuzzAdmissibleAlike` holds the two to one verdict on
  any member set.
- Property tests (`trust/log/property_test.go`) over generated valid record sets
  delivered in different orders and increments ⇒ all validators converge to an
  identical state or an identical alarm, no trusted state falls below the epoch
  floor, and a refused record changes nothing. Each case is a numbered seed of our own generator, not
  `pgregory.net/rapid`: a failure is replayed by running the subtest it names.
- Determinism: several topological orders of one record set produce byte-identical
  state (fork choice is deterministic).

## 2. Fuzzing (native `go test -fuzz`, run off CI)

Targets, added the milestone their input surface appears:

| Target | Input | Milestone |
|---|---|---|
| Record decoder and validator (`FuzzDecodeAUM`, `FuzzValidateAUM`) | raw CBOR | M1 |
| Chain validator (`FuzzChainValidate`) | record sequences | M1 |
| Gossip frames and announcements (`FuzzDecodeFrame`, `FuzzOpenFrame`, `FuzzDecodeEndpoint`) | raw frames | M2 |
| IPC wire (`FuzzDecodeIPCRequest`, `FuzzDecodeIPCResponse`, `FuzzDecodePublished`) | socket payloads | M2 |
| LAN discovery beacon (`FuzzBeaconHandle`) | multicast DNS datagrams | M2 |
| DHT item (`FuzzOpenItem`) | BEP 44 values | M3 |
| Invite code and link (`FuzzParseInvite`) | strings | M4 |
| Enrollment messages (`FuzzDecodeEnrollFrames`) | raw frames | M4 |
| Invite rendezvous stream (`FuzzStreamPackets`) | UDP packets on a punched path | M4 |
| Invite nameplate question and answer (`FuzzInviteMessages`) | multicast DNS datagrams | M4 |
| Relay invite forwarding (`FuzzForwardRequests`, `FuzzRelayAnswers`) | upgrade requests; a relay's answers to host and guest | M4 |
| Gossip catch-up, and the asking side's reading of it (`FuzzDecodeCatchUp`, `FuzzAskCatchUp`) | raw frames | M4b |
| QUIC Initial and ClientHello reassembly (`FuzzParse`, `FuzzPayloads`, `FuzzHello`) | a client's datagrams at the ingress | M11b |
| PROXY v2 header, TCP and UDP (`FuzzRead`, `FuzzReadUDP`) | a terminator's input from the ingress, and back | M11b |
| Access policy text (`internal/policy` `FuzzParse`) | policy files | M14 |
| Pair-key messages and store (`FuzzTake`, `FuzzDecodeStore`) | signed messages; the pairs file | M15 |

Open (M25): waiting changes (`waiting.Decode`), leases (`types.DecodeLease`), the
root helper's protocol and the resolver's input.

The gate is 72 clean CPU-hours per input surface before a milestone closes, run
by hand with `make fuzz-long` or `make fuzz-one` per target (`make fuzz-matrix`
lists them; 6 h on 4 workers a run), against a corpus kept outside the repository.
It does not run on CI: hours per input surface is far more hosted-runner time than
the project wants to spend. So far it is recorded for `FuzzPayloads` alone (M11b,
[12-validating.md](12-validating.md)); M25 runs it over every target. `make fuzz`
smoke-runs every target for 30 s each. OSS-Fuzz, once the project qualifies,
would move the long runs onto someone else's hardware.

## 3. Multi-node integration harness

Network namespaces with Linux netfilter where the kernel's part is what is
tested (NAT, devices, exit nodes), in-process meshes of daemons
(`daemon/mesh_test.go`) elsewhere:

- **NAT matrix (`conn/netnsnat_linux_test.go`):** full-cone, address-restricted,
  port-restricted, symmetric (endpoint-dependent), CGNAT double-NAT; UDP-blocked in
  its own test. Whether a path ended up direct is asked by stopping the relay, and
  the lab classifies its own NATs with two reflectors before testing anything, so
  a rule that did not do what its name says cannot make a cell pass for the wrong
  reason.
- **Membership scenarios:** enrollment by link and by code, removal, epoch bump,
  key and identity rotation, admin add/remove, break-glass disablement.
- **Partition & freshness:** with an injectable fake clock, a victim the removal
  does not reach refuses the removed peer at exactly the TTL; the startup gate
  keeps tunnels down until sync when state is stale.
- **Fork alarm:** a forked or rolled-back chain drops every peer and clears every
  derived field.
- **DHT adversary:** on a private DHT swarm, a crawler cannot link items to the
  network, count members, or read an item's epoch or size.
- **Relay abuse:** a non-member and a *removed* member are refused relay use.
- **Exit nodes and subnet routes (M6):** a node forwarding traffic it holds no
  grant for is dropped; a full-tunnel client leaks no DNS query and no non-LAN
  packet outside the tunnel (capture on the physical interface) while LAN
  destinations stay local; a stale exit node serves nothing.
- **Access policy (M14):** a peer the policy denies is dropped by the *receiver*
  even from a sender patched to ignore its own filter; a stale view under a policy
  fails closed.
- **Crash consistency:** a store write cut short at any point is finished or
  cleaned up at open.

Open: a multi-node split view (a malicious quorum feeding divergent chains to
disjoint sets, both sides alarming on first contact); an eclipse of the DHT
delaying cold start without yielding a false member; egress cut at gossip
convergence when an `exit` role is withdrawn across a mesh; chaos on gossip paths
(loss, reorder, duplication, `kill -9` mid-sync, clock skew between members).

## 4. End-to-end / platform

- Interop (`interop/`, `make interop`, part of `make ci-vm`): Debian and FreeBSD in
  qemu, each installed from its package, through the lifecycle and an upgrade from
  the previous release. The Android app is tested by hand in an emulator.
- Egress: `conn/egress_test.go` and the namespace captures assert **zero packets
  to any third-party service** except declared untrusted helpers (DHT bootstrap,
  public STUN), which catches Tailscale-infra dependencies from vendored code. The
  interop run has no blanket capture yet.
- Packaged privilege: that the daemon runs as the dedicated user with
  `CAP_NET_ADMIN` as its whole bounding set is checked by hand
  ([12-validating.md](12-validating.md), "Check the privilege footprint"), and so
  is the RPM on Fedora; interop could assert it from `/proc`.
- Manual pre-release drill on real networks: two hard-NAT'd home connections + one
  VPS relay member + one Android phone on LTE; full lifecycle including emergency
  revocation from a phone (from M29).

## 5. Cryptographic review gates

- Internal review of the audit scope before the external audit (M25,
  [15-security-review.md](15-security-review.md)).
- External audit at M26 of the audit scope: what [`audit-scope`](../audit-scope)
  places `core` or `in`, the code that decides who may do what, holds or derives a
  key, parses input from outside the membership, or runs as root. Every package
  is placed there, `out` ones with their reason, and `make tcb` fails on one
  placed nowhere. The scope is audited in tiers, so the deep part stays the core:
  - **The core** (`types`, `trust/`): line by line, the cryptography included.
  - **Parsers of input from outside** (gossip, the IPC wire, the QUIC Initial,
    waiting changes, the resolver, the policy): fuzzed first, then reviewed where
    the fuzzer cannot judge.
  - **The rest** (reconciler, filter, root helpers, key custody, the app's API):
    reviewed for their invariants (default deny, dropped privileges, keys that
    stay where they are put), not line by line.
- After v1, each milestone that grows the audit scope gets an audit of what it
  added, scoped by the sizes its "Done" line records.
- A short machine-checkable model (Tamarin/ProVerif, or TLA+ for the
  epoch/freshness state machine) is a stretch goal — valuable for the freshness and
  fork-choice rules, which are where novel logic lives.

## 6. Continuous regression metrics

`make tcb`, in `make check`, holds the core (`types`, `trust/`) to 11 k lines and
reports the audit scope's size, which is measured, not budgeted: features grow it,
and each milestone's "Done" line in [05-roadmap.md](05-roadmap.md) records both.

Bounded by tests, pass or fail rather than tracked as a series: direct paths per
NAT class (the matrix above), revocation convergence in the connected case (5 s,
`TestRevocationConvergesWithinTheBudget`), and the encoded size of an epoch record
and of a checkpoint at `MaxNodes` members under `MaxRecordSize`
(`trust/log/scale_test.go`), the term that grows fastest with membership. Open:
sync time after a week offline, and a record of these figures per milestone. Fuzz
corpus coverage is tracked per milestone, from the manual runs above.
