# 08 — Trust layer notes

What M1 actually built, where it diverges from the plan in
[04-architecture.md](04-architecture.md), and what it deliberately left open.
Companion to [07-embedding-notes.md](07-embedding-notes.md), which does the same
for the connectivity layer.

Packages: `types` (record schema, canonical encoding, addressing), `trust/log`
(chain, quorum, fork choice, alarms), `trust/secrets` (epoch group secret),
`trust/store` (on-disk log). CLI: `cmd/juist`.

## Decision: the log is ours; `tka` is the design, not the dependency

[03-control-plane-options.md](03-control-plane-options.md) and the module map in
[04-architecture.md](04-architecture.md) both say `tailscale.com/tka`,
"adapted/vendored". Reading it against what this milestone needs, importing or
forking it turned out to buy little:

- **Its records are about the wrong thing.** tka is a *key* authority: its AUM
  set is `AddKey`/`RemoveKey`/`UpdateKey`/`Checkpoint`/`NoOp`, and nodes are
  authorized out-of-band by node-key signatures its `sig.go` verifies. Our log
  holds the members themselves. Of tka's five record types, the two that
  correspond to anything here are the admin-key ones.
- **Its authorization rule is weaker than ours.** `aumVerify` requires that
  every signature come from a trusted key; it does *not* require a quorum.
  Vote weight is used only to resolve forks, and its retroactive-revocation
  path leans on out-weighing a compromised key. We need k-of-n on every change,
  which is a different check in a different place.
- **The parts we would keep are small.** Chain walking, checkpoint semantics and
  fork resolution are a few hundred lines each, and they are exactly the lines
  that must change: tka gets ordering and distribution from the coordination
  server it was built to distrust for everything else, and supplying those is
  the new security-critical code
  [03-control-plane-options.md](03-control-plane-options.md) predicted.
- **The coupling is real.** `tka` sits behind a `ts_omit_tailnetlock` build tag
  and threads `tailscale.com/types/{key,tkatype}` through its API. Vendoring it
  would put the connectivity stack's types in the trust layer's audit scope —
  the opposite of the layering rule.

**Adopted from tka, deliberately and by name:** the hash-chained record with a
canonical CBOR encoding in CTAP2 mode (their reasoning about signed formats is
quoted in `types/cbor.go`); the discipline for evolving the schema (CBOR key
numbers never reused, new fields optional and absent-by-default, no floats);
keys carrying vote weights with policy checked at verification time rather than
in threshold crypto; checkpoints as quorum-signed compactions; pre-committed
break-glass preimages; and the convention of putting signatures at CBOR key 23.

`TestTCBHasNoTailscaleDependency` enforces the layering: nothing in `types` or
`trust/*` may reach `tailscale.com`, so a vendored-engine upgrade can never
change who is a member.

## Encoding: one record, one byte string

A record's identity is the hash of its serialization, and a signature is over
the hash of its serialization minus the signatures. A record with two valid
encodings would therefore have two hashes, and one gathered quorum could
authorize two distinct chain entries. The rule the codec enforces is:

> Decode is injective: for every byte string `Decode` accepts,
> `Encode(Decode(b)) == b`.

Strict decoder options (no duplicate map keys, no indefinite lengths, no tags,
no unknown fields) rule out the ambiguities they know about; the re-encode
comparison in `decodeCanonical` proves the rest, including non-minimal integers
and misordered keys, and removes any need to reason about which lenient
behaviours the CBOR library has. Every field holding a set — admin keys, nodes,
signatures, epoch wraps, roles, routes — must be sorted and duplicate-free for
the same reason. `FuzzDecodeAUM` asserts the property directly.

**Closed sets, not forward compatibility.** Unknown record kinds and unknown
role names are rejected, where tka ignores what it does not understand.
Tailscale can afford that because their coordination server orders the log and
decides what it means. Here every node must reach the same verdict on the same
bytes from the bytes alone, and a node that ignores a record its peers act on
holds a different view of who is a member — the split-view failure the log
exists to prevent. Adding a kind or a role is a schema change, subject to the
M3 freeze.

**SHA-256, not BLAKE2s.** No deep reason: it is in the standard library,
hardware-accelerated everywhere, and already the hash
[04-architecture.md](04-architecture.md) specifies for address derivation. One
hash function for the whole project is one less thing to get wrong. Every digest
and derived key is computed over a NUL-terminated domain-separation label, so no
digest can be reinterpreted as a digest of another kind.

## Rules that came out stricter than the plan

Each of these closes a gap found while writing the validator. All are
*tightenings*: a record the plan allowed and this rejects.

**Every membership or key change carries an epoch bump, not just
`RemoveNode`.** [04-architecture.md](04-architecture.md) requires one on
removal. Making it uniform buys a state invariant worth having: the current
epoch's wrap set covers exactly the current member set, always. That in turn is
what makes the two attacks below checkable.

**The wrap set must match the member set exactly.** One wrap per member, none
for a non-member. Without it an epoch bump could quietly exclude a member —
taking discovery away from a device with nothing in the log saying it was
removed — or hand the group secret to a device that is not a member.

**Epochs are strictly sequential (`+1`), not merely increasing.** A record
cannot jump the counter, which keeps a node's persisted epoch floor an exact
statement rather than a lower bound.

**The epoch record commits to its secret.** `EpochRecord.Commit` is a labelled
hash of the group secret, and each recipient checks what it decrypts against it.
Without the commitment nothing ties the wraps to one another and a malicious
quorum could seal a *different* secret to each member, partitioning discovery
invisibly. This is a new field, not in the plan's schema.

**Small-order identity keys are rejected.** A small-order Ed25519 public key
admits a signature for any message that anyone can compute. Quorum guards who
gets added to the log; it cannot notice that what was added is a key with no
owner. Admitting one as an admin key would silently convert that key's votes
from "held by an admin" to "held by anybody" — a way to launder authority past a
ceremony. This is the only reason `filippo.io/edwards25519` is a dependency.

**Members may not share WireGuard, X25519 or ML-KEM keys.** Two members with one
WireGuard key collide in the data plane, where a peer is keyed by exactly that,
and one would silently displace the other. Duplicate encryption keys are
rejected on the same principle: one device's state copied onto a second and
applying for a second membership is the stolen-device case from
[02-threat-model.md](02-threat-model.md), and it should not be admissible by
accident.

**A checkpoint must equal the state its ancestry produces.** Where the parent
state is known — everywhere except bootstrapping from a checkpoint handed to you
— the claimed snapshot is compared byte for byte against the derived one.
Otherwise a quorum could rewrite membership by *asserting* a state instead of
authoring the changes that reach it, leaving no record of what it altered.

**Removing an admin key that strands the quorum is rejected**, since it would
leave a network nobody can ever change again, including to undo it.

**Route grants may not cover loopback, link-local or multicast space**, on top
of the no-overlay-overlap rule the plan states. None is a plausible
subnet-router target, and pointing a client's own local traffic at another
member's host is the same class of attack as intercepting overlay traffic. The
one exemption is the exact default route (`0.0.0.0/0`, `::/0`), which is legal
only with the `exit-node` role and which by construction covers everything —
see the obligation this puts on M7b below.

**Names are checked for control and bidi-formatting characters.** They are
attacker-supplied strings that end up in operator-facing output; rejecting them
once at admission beats escaping at every print site.

## Fork choice, and what it refuses to decide

Fork choice is `(1)` a revocation beats a non-revocation, `(2)` otherwise the
lower record hash wins — exactly what
[04-architecture.md](04-architecture.md) specifies, and deliberately *without*
tka's signature-weight rule. Every change here already needs quorum, so weight
would only let one quorum outbid another by collecting extra signatures: a
tie-break that invites grinding and explains nothing to an operator reading the
log.

The branch that loses is not lost, but it is not applied either — its author
reissues it against the new head. Two cases are not left to a deterministic rule
at all, and raise a persistent alarm instead:

- **An orphaned revocation.** The revocation bias only compares immediate
  siblings, so a removal buried deeper on a losing branch would vanish
  silently. Any revocation on an orphaned branch alarms.
- **An orphan that cannot be reissued.** Each orphaned record is replayed
  against the winning head with the position-dependent rules relaxed (epoch
  sequencing, wrap coverage — both things reissuing would fix). If its
  *substance* no longer applies, the two branches disagree about something
  concrete, and no rule should be picking between them.

While an alarm is raised, `Authority.TrustedState` refuses to hand out
membership. That is the same trade as the freshness TTL: where security and
availability conflict, deny. `Authority.State` still returns the state, so an
operator can see what the fork did.

Nothing prevents a colluding quorum from creating such a fork —
[02-threat-model.md](02-threat-model.md) residual weakness 3 — and nothing here
claims to.

## The two ratchets, and what they cost

Both are node-local by design: two nodes that have seen different histories
refuse different things, and that divergence is what a fork alarm surfaces
rather than something to average away.

**The anchor** is the genesis record, or the newest checkpoint this node has
adopted. Chain resolution starts there and never walks past it, so a branch
forking before it is not outvoted — it is not considered at all. That is "never
drop a checkpoint you hold", enforced structurally.

**The epoch floor** is the highest epoch ever adopted. `Inform` *rejects* a
batch that would resolve below it, stores nothing, and returns a `RollbackError`
carrying the refused records. Reaching an older epoch through individually valid
records takes admin signatures, so this is what a quorum rewriting history looks
like from a node that saw the earlier version.

The cost is real and worth stating: two nodes offered the same fork in different
orders can end up in different states — one alarmed, one refusing the records.
Both fail closed. This is the CAP-style limit
[02-threat-model.md](02-threat-model.md) already accepts, surfacing in a new
place.

## Group secret: hybrid HPKE, and its size

HPKE (RFC 9180) base mode, `DHKEM(X25519)+ML-KEM-768`, HKDF-SHA256,
ChaCha20-Poly1305. The hybrid KEM is the harvest-now-decrypt-later hedge: an
adversary recording epoch records today and breaking X25519 later still faces
ML-KEM-768. `TestCiphersuiteIsTheIntendedOne` pins the KEM, so a change in what
the standard library assembles cannot quietly cost the property.

Cost: **1168 bytes per member per epoch**, so an epoch bump on a 100-member
network is a ~120 KB record, and so is the checkpoint that carries the current
epoch. Accepted at the target scale of 25–100 devices; it is the reason the
schema's `MaxNodes` is 512 rather than something larger, and the reason
checkpoint compaction is implemented in this milestone rather than deferred.

A node's recipient key is recorded as **two fields** (`X25519`, `MLKEM`) rather
than one opaque hybrid blob, so each half is validated as the key it is, and so
the ML-KEM half is a first-class field for the per-pair preshared-key hedge
[07-embedding-notes.md](07-embedding-notes.md) reserves. Domain separation
between the two uses comes from HPKE's own suite labelling and from a distinct
HKDF label on the reserved side.

Each epoch's secret is **fresh randomness, not a derivation from the last**, so
producing a bump never requires reading the previous secret. An admin can rekey
the network holding only a signing key, which is what keeps admin keys off
member devices.

The HPKE `info` string binds each wrap to one epoch and one recipient, so a wrap
cannot be lifted between epochs or re-addressed. It does *not* bind the network:
that would be circular for the genesis record, whose own hash names the network.
Network binding comes from the signatures over the record instead.

`juist propose rotate-key` therefore rotates *all* of a device's rotatable keys
at once and generates them locally: a record naming a public key whose private
half the device does not hold would be applied happily by the log and would
leave the device unable to handshake or to read the group secret.

Two details of that are load-bearing. All of a device's secrets live in **one
file**, so promoting a rotation is a single rename and there is no state in
which the device holds a new encryption key and an old WireGuard key — a device
that either cannot handshake or cannot read the group secret, and would stay
that way until someone noticed. And promotion is conditional on **what the log
ends up naming**, not on which record kinds were in the batch: a rotation record
can be fully authorized and still lose fork choice, so `apply` promotes only
after checking that the adopted state names the staged keys.

**Known limitation.** Nothing in the log can prove a wrap was sealed to the
*right* key — a wrap is opaque to everyone but its recipient. After a
`RotateNodeKey`, a member that finds its wrap unopenable reports it; the log
cannot reject it. The commitment makes that report unambiguous, which is as far
as this design goes.

Two review findings sit on the same rule: **a keystore refuses at the point of
choice, not at the point of use.** Staging replacement keys before the record
was built meant a proposal the log went on to reject still wrote `node.keys.next`
— and since staging refuses to write over an earlier rotation, one failed
command made every later rotation fail too, over a file the tool never named.
Staging now happens only once the record exists. Likewise a member name is
checked against `types.ValidateName` where the device chooses it, because the
alternative is that the device persists a name the schema will not accept, prints
an enrollment command built around it, and the limit is discovered by a different
operator on a different machine. `init` validates every name it was given before
writing any of the three files a ceremony cannot simply be re-run over.

**The genesis ceremony has to be completable by the tool that starts it.** A
k-of-n genesis cannot be authorized on the machine that builds it — that is what
the threshold means — so `init` builds the record, signs it with whatever local
key exists, and, if that does not reach k, writes it to `genesis.rec` and stops.
The other admins sign it where their keys are (`juist sign` works on a keystore
with no network, and reports a genesis against the policy the record itself
declares, via `log.GenesisStatus`), and `juist apply` on a home directory with
no network creates it. Previously the record was built in memory and discarded
on failure, so the one artefact that had to travel was the one thing thrown
away — while the admin key and break-glass secrets it commits to were already on
disk under files a second `init` refuses to overwrite. The ceremony could be
neither finished nor restarted, and the error advised performing it "where the
keys are", which is the one place a threshold guarantees they are not.

**A signature is irrevocable, so `sign` refuses to guess.** A record whose
parent is no longer the head is judged against the state at that parent. Usually
that is benign — it forks, and its author reissues it. It stops being benign
when the admin set moved in between: a key that is an admin now was not one
there, and an untrusted signature does not merely fail to count, it invalidates
the record outright. `sign` therefore warns when the parent is not the head and
withholds the verdict rather than reporting one computed against a state the
record will never be judged by.

The same distinction applies to reading key material: a key file that is
**absent** is an ordinary state — a signing-only keystore has no node keys — but
one that is **present and unloadable** is a fault. Conflating them turned a
wrong file mode into "this device has no keys": `key` sent the operator to
`-create`, which then refused to overwrite; `sign` quietly omitted the signature
a rotation needed; `apply` reported success while silently declining to promote
the keys the log had just started naming. The two cases are now told apart by
`errors.Is(err, fs.ErrNotExist)` and only the first is treated as absence.

## Storage

Records are content-addressed: the file name is the hash, and every read checks
that the bytes still hash to the name. That catches bit rot and editing alike,
and it is the only integrity check available when the file is the only copy.

The anchor and the epoch floor are fsynced before anything acts on them. Record
writes are staged and fsynced before any is renamed into place, so a crash
cannot publish a half-written record under a name claiming to hash to it. A
crash *between* renames can store part of a batch, which is safe by
construction: a record whose parent is missing does not descend from the anchor,
so resolution never looks at it and the sender offers it again.

`Inform` re-resolves from storage after writing rather than adopting the
in-memory result, so the epoch floor is never raised above a chain storage can
actually reproduce — otherwise a dropped write would leave a node that refuses
to start.

Corruption makes the store refuse to open, with an error naming the file and
telling the operator to recover from another member. It never repairs itself and
never re-genesises: that is what turns a disk fault into a network with two
histories. A store directory writable by group or other is refused too — anyone
who can write there can lower the ratchets.

Refusing everything unexplained has one sharp edge, and M1's review found the
store on the wrong side of it: an interrupted write leaves a temporary file, and
a temporary file the sweep does not recognize is an unexplained entry. The store
then refuses to open — permanently, from an ordinary power loss, with an error
that reads like corruption and points at recovery the node does not need. The
two categories have to be told apart by name, and the set of names a crash can
leave has to be the set the sweep covers. Record bodies are therefore staged
under one prefix, written directly rather than through the atomic-replace helper
that would interpose a second one, and both prefixes are swept on open so a
store written by an earlier build still opens. A test asserts the sweep for
every prefix this package can produce, rather than for the one the staging code
happens to use today.

## Schema additions beyond the plan's record list

Flagged here for the M3 freeze review:

- **`SetQuorum`.** [04-architecture.md](04-architecture.md) follows tka in
  treating the quorum policy as fixed at genesis. Without a way to change it, a
  network that grows from three admins to ten keeps whatever *k* it chose on day
  one, and policy can never be tightened short of recreating the network.
- **`EpochBump`.** Rotates the group secret without a membership change: the
  routine half of the two-tier revocation response in
  [research/building-blocks.md](research/building-blocks.md) §5, and the answer
  to a suspected group-secret leak.

`RotateIdentity` is implemented as the plan names it, requiring quorum plus a
signature by the **new** key. The old key is deliberately not required: a
planned rotation away from a key being retired is exactly the case where it may
already be gone. It is otherwise equivalent to remove-then-add, and exists to
preserve a member's roles, routes, v4 address and name across the change.

## Not built in M1, on purpose

- **`FreshnessLease`.** M4 (leases, TTLs, the startup gate). It is not chained
  into the log, so it is not part of the record schema and does not constrain
  the M3 freeze.
- **A disablement record.** The genesis ceremony commits to break-glass secrets
  and `State.ValidDisablement` verifies a preimage, which is what the schema
  needs. *What revealing one authorizes* — recovering a network whose quorum is
  lost — is an operational design question that belongs with the revocation UX
  in M4.
- **Route consumption.** Validated from M1, read by nothing until M7b.

### The obligation M1 hands to M7b

The default route is exempt from the no-overlay-overlap rule, because it covers
everything by construction. Whoever consumes route grants **must subtract the
overlay space** — the genesis-derived ULA /48 and 100.64/10 — when rendering
`AllowedIPs` and filter destinations. Without that subtraction, an exit-node
grant would re-open exactly the member-to-member interception the overlap rule
exists to prevent. The rule is stated in `types.ValidateRoute`; M7b's exit
criterion (2) is where it gets proven.

## Verification

- `trust/log/adversarial_test.go` is the milestone's exit criterion, one test
  per attack, each stated in the terms an attacker would use.
- `TestResolutionIsOrderIndependent` and `TestIncrementalDeliveryNeverRegresses`
  are the property tests from [06-verification.md](06-verification.md) §1,
  seeded rather than randomized so a failure can be replayed.
- Fuzz targets: `FuzzDecodeAUM` (asserts injectivity, not just absence of
  crashes), `FuzzValidateAUM`, `FuzzChainValidate` (asserts that a rejected
  batch changes nothing and that the epoch never regresses). `make fuzz` is the
  seconds-long smoke run; `make fuzz-long` is the gate. Neither runs on CI —
  see [06-verification.md](06-verification.md) §2.
- `TestTCBDependencies` keeps the audit scope's dependency closure to the
  standard library plus two small modules, and keeps the clock and the
  filesystem out of the packages that decide validity.
- `make tcb` reports the audit scope's size against the 10k-line budget
  [06-verification.md](06-verification.md) §6 sets. At M1 it is ~4.8 k lines.
