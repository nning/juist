# 15 — The security review before the audit

An internal review of the whole audit scope against
[02-threat-model.md](02-threat-model.md), before M25's external audit, so
the auditor's hours go to what a reader cannot find. It answers, for every
defense the threat model claims, where the code enforces it and which test
fails without it. It attests nothing: a review by a model, like one by a
person, misses things, and the external audit stays.

## 1. Scope and tiers

What [`audit-scope`](../audit-scope) places `core` or `in`, in the tiers of
[06-verification.md](06-verification.md) §5, with one change: the root
boundary (`internal/plumber`, `cmd/juistd`'s privsep, `daemon`'s peercred,
`conn/confine.go`) and the key glue (`internal/aead`, `pairkey`, `addrkey`,
`keys`, `keyring`) are read line by line as the core is, though §5 places
them in the third tier, since a bug in a root helper or a key derivation is
as grave as one in the core.

| Tier | Packages | Lines | How |
|---|---|---|---|
| 1, the core | `types`, `trust/enroll`, `trust/log`, `trust/secrets`, `trust/store` | 9 954 | line by line |
| 1, the boundary | `internal/plumber`, `cmd/juistd`, `daemon` (peercred, control, ipc), `conn/confine.go`; `internal/aead`, `pairkey`, `addrkey`, `keys`, `keyring` | ~5 500 | line by line |
| 2, parsers of outside input | `gossip`, `ipc`, `internal/quicinitial`, `waiting`, `dnsfwd`, `policy`, `names`, `relay` | ~9 000 | fuzzed first, then read for what the fuzzer cannot judge |
| 3, invariants | the rest of `daemon`, `cmd/juist`, `internal/ingress`, `statuspage`, `mobile` | ~6 200 | default deny, dropped privileges, keys that stay where they are put |

Sizes are `make tcb`'s at M16; the review records its own when it
closes. The embedded Tailscale stack is reviewed at its boundary alone: what
juist hands it and what it trusts from it
([07-embedding-notes.md](07-embedding-notes.md)). Tests are read as
evidence for a property, never line by line.

## 2. Before the first session

Compute first, reading after:

- The fuzz targets M24 lists as missing (`waiting.Decode`,
  `types.DecodeLease`, the helper's protocol, the resolver's input) exist,
  and `make fuzz-long` has run over every target and is recorded in
  [12-validating.md](12-validating.md). A parser the fuzzer has not seen
  costs a reader's time on what a machine finds for free.
- `make lint` and `make govulncheck` pass.
- The review takes the tree after M17 to M23, whose changes it reads
  whole. What lands after it is reviewed as a diff by the same protocol,
  scoped by its size, as §5 says of every milestone after v1.

## 3. The inventory

The first session writes `private/review/inventory.md`, which every later
session reads first:

- one row per adversary and per residual weakness of the threat model, and
  per invariant of tier 3: the defense claimed, the functions that enforce
  it, the tests that claim to cover it;
- one row per surface where bytes from outside the membership are parsed
  (gossip frames and catch-up, the IPC wire, the QUIC Initial, DHT values,
  mDNS, the rendezvous, enrollment, invite codes, leases, waiting changes,
  the resolver, the relay's HTTPS): who may speak on it, what is
  authenticated before it is parsed, which fuzz target covers it.

A row with no enforcing function or no test is itself a finding. The
inventory is a map, not a judgement: each deep session checks its own rows
before trusting them.

## 4. A session

One package, or one property cluster, per session, in a fresh context. It
reads the inventory's rows for its package, the package and its tests once,
whole, and the design notes the package implements
([08-trust-layer-notes.md](08-trust-layer-notes.md) for the core,
[11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md)
for enrollment and leases, [09-mesh-layer-notes.md](09-mesh-layer-notes.md)
for gossip, [13-multi-network-notes.md](13-multi-network-notes.md) for the
IPC tiers). It fixes nothing: a fix in the reviewer's context dilutes the
review, and fixes have their own protocol (§5).

What tier 1 asks of every line:

- every byte the code acts on is under a signature, derived from signed
  bytes, or bounded before verification; what is parsed before a signature
  is checked costs a bounded amount;
- one record has one encoding, and two encodings of one record hash the
  same or are refused;
- epochs are monotonic, the chain's parent hashes hold, fork choice is
  deterministic, a quorum is counted by distinct keys of the epoch, a
  revoked key counts nowhere afterwards;
- a record, signature or hash of one network, chain or purpose is refused
  by every other: domain separation everywhere;
- keys are derived under their own domains, never reused across purposes,
  compared in constant time where secret, and never written where the read
  tier, a log line or the status page can see them;
- freshness fails closed: lease validation, clock skew, the TTL boundary,
  the vouching threshold, the startup gate;
- enrollment binds the key it admits to the transcript the admin saw, an
  invite dies on one wrong guess and on its expiry;
- the store is atomic and durable under `kill -9`, its files have the
  permissions the design says, and no path is checked then used;
- caps hold at `MaxNodes`, `MaxRecordSize` and `MaxHashesPerFrame`, and
  no length from outside sizes an allocation unchecked;
- at the root boundary: what the helper accepts, from whom, through which
  check, and what it refuses.

What tier 2 asks: who may speak on the surface, what is authenticated
before it is parsed, what of a frame is trusted and what is checked, that
an unexpected message order leaves the state machine where it was, that
allocation is bounded, and that the fuzzer's seeds reach the states the
protocol has.

What tier 3 asks, of each invariant: where it is enforced on the receiving
side, and the test in which the sending side is patched to ignore it.

The output is findings, appended to `private/review/findings.md` as they
come, so a session cut short loses nothing. A finding names the property
violated, the lines, the attacker's steps, and the test that would fail.
Nothing found is said as the list of what was checked, property by
property, with the lines read for each: a session that reports nothing and
lists nothing has reviewed nothing.

## 5. From finding to fix

In this order, each step in a context of its own:

1. **Refute.** A fresh reader tries to show the finding wrong. What
   survives gets a severity: high (membership truth, admin authority, a key
   or the root boundary), medium (confidentiality or integrity of the data
   plane, a bound a member can exhaust), low (the rest).
2. **The test that fails.** Written before the fix, as
   [AGENTS.md](../AGENTS.md) requires of every fix; reverted fix, failing
   test, restored fix.
3. **The fix**, one commit per round, `M24 review <k>: …`, through `make
   check`, and through the privileged gate where it touches one.
4. **The fix read again** by the tier's reviewer, for high findings: the
   diff alone.

A finding the project accepts rather than fixes becomes a residual weakness
in [02-threat-model.md](02-threat-model.md), numbered, in the same commit.
`private/` is never published, so open findings stay there until their fix
is on `main`.

## 6. Closing

Two sessions over the whole, with the inventory and every finding in view:

- **Implementation against the threat model.** For each adversary row, does
  the implementation deliver the defense the row claims, and is there a
  defense the row claims that no code enforces; for each residual
  weakness, is it still bounded as described; and is there a weakness the
  list lacks.
- **The operator's reading** of the residual weaknesses, which M25 owes:
  drafted from the threat model, checked against the findings.

The closing commit records in [12-validating.md](12-validating.md), as the
privileged runs are recorded: the sizes reviewed, the sessions, the
findings by severity and what became of each, the fuzz hours per target,
and what did not run.

## 7. Open

- Whether the inventory joins [06-verification.md](06-verification.md)
  once the findings it points at are fixed, as the map the external
  auditor starts from.
- Whether a machine-checked sketch of freshness and fork choice (§5's
  stretch goal) is worth writing before the external audit, which is where
  the novel logic lives and where a reader is least reliable.
- Who the external auditor is; unchanged by this review.
