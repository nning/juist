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
ceremony. This, and the group SPAKE2 runs in at enrollment, are why
`filippo.io/edwards25519` is a dependency.

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
only with the `exit` role and which by construction covers everything —
see the obligation this puts on M6 below.

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

What counts as a revocation grew with M4. Removing a device or an admin key
always did. Since the admin role carries vouching authority, schema 2 adds
taking a device's admin role away and raising the vouching threshold
(`State.Revokes`): otherwise a concurrent change with a lower hash could orphan
the withdrawal and keep a distrusted admin device vouching. It is a rule of
fork choice, which every node must apply alike, so it waits for the schema:
networks at schema 1 keep the old rule until `juist log upgrade`.

**Votes belong to people (schema 3).** A quorum of k meant k keys, and a person
with a key on each of two laptops was two votes, so "two admins must agree"
could be met by one. From schema 3 an admin key can name its holder, and a
holder's keys are one voter: they carry its votes and cast them once, when at
least `Needed` of them signed (`types.CountVotes`). One person can so hold a
key per device, lose one without the others losing anything, and be made to
need two of them (`KindSetHolder`), which is how one person running a network
alone asks for two devices per change. What the network can still cast is
counted per holder too (`types.AchievableVotes`): a holder needing more keys
than it holds casts nothing, and a change that would leave the quorum out of
reach is refused, as removing a key already was. Asking more keys of a holder,
or giving it fewer votes, is a revocation for fork choice. Keys without a
holder, which is every key before schema 3, stay voters of their own. The
upgrade to schema 3 names each such key's holder after the key, where no other
key's name folds to the same, so every holder has one key, no vote changes,
and an admin's further keys join under the name they already have.

**A removed key cannot undo its removal (schema 3).** A sibling is verified
against its parent's state, where a key removed later still votes, so the key
could sign a branch rooted before its removal and win on the revocation bias or
a ground hash, undoing its removal and everything after. So one rule comes
before both: a branch loses to a sibling whose branch removes an admin key that
signed anything on it. Two keys removing each other at once are symmetric,
since at the quorum they had either could do anything, and alarm.

The branch that loses is not lost, but it is not applied either — its author
reissues it against the new head. Two cases are not left to a deterministic rule
at all, and raise a persistent alarm instead:

- **An orphaned revocation that cannot be reissued.** The revocation bias only
  compares immediate siblings, so a removal buried deeper on a losing branch,
  or one of two removals made at once, would vanish silently. One that the
  chosen chain could take as it is is named instead, as not in effect, on
  every device's status and in "juist log", for an admin to run again;
  stopping the network at every two concurrent removals would be an outage for
  what is a routine race. One already in effect on the chosen chain is
  nothing. One the chosen chain cannot take alarms.
- **An orphan that cannot be reissued.** Each orphaned record is replayed
  against the winning head with the position-dependent rules relaxed (epoch
  sequencing, wrap coverage, an admission's IPv4 address — all things
  reissuing would fix). If its *substance* no longer applies, the two branches
  disagree about something concrete, and no rule should be picking between
  them. The address belongs in that list because it is allocated from the
  chain the admission was built on: two admins admitting two devices at once
  both take the lowest free one, and treating that as a conflict stopped every
  tunnel of a network over a record whose device no longer existed. The CLI
  counts the addresses of orphaned admissions as taken, so a reissue does not
  collide again.

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
What it forecloses above that range, and by when, is a section of its own below.

A node's recipient key is recorded as **two fields** (`X25519`, `MLKEM`) rather
than one opaque hybrid blob, so each half is validated as the key it is, and so
the ML-KEM half is a first-class field for the per-pair preshared-key hedge
of M11a ([05-roadmap.md](05-roadmap.md)). Domain separation
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

`juist rotate` therefore rotates *all* of a device's rotatable keys
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
operator on a different machine. `create` (then `init`) validates every name it was given before
writing any of the three files a ceremony cannot simply be re-run over.

**The genesis ceremony has to be completable by the tool that starts it.** A
k-of-n genesis cannot be authorized on the machine that builds it — that is what
the threshold means — so `create` builds the record, signs it with whatever local
key exists, and, if that does not reach k, writes it to `genesis-NETWORK.rec` and stops.
The other admins sign it where their keys are (`juist approve` works on a keystore
with no network, and reports a genesis against the policy the record itself
declares, via `log.GenesisStatus`), and `juist apply` on a home directory with
no network creates it. Previously the record was built in memory and discarded
on failure, so the one artefact that had to travel was the one thing thrown
away — while the admin key and break-glass secrets it commits to were already on
disk under files a second `create` refuses to overwrite. The ceremony could be
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

## The schema is versioned, so the freeze is a price rather than a wall

[05-roadmap.md](05-roadmap.md) froze the record schema at the end of M3. Taken
literally that means a new record kind, a new role or a new field is
unavailable for the life of the network — and the cost of being wrong is not a
bad release but a network that has to be recreated. So M3b spends its last
opportunity on the thing that makes every later opportunity possible.

The state every genesis and checkpoint states carries a `Schema` version, and
`KindSchemaUpgrade` raises it under the same k-of-n quorum as any other
authority change. The version is `types.CurrentSchema`, which is 0 and
`omitempty`, so it costs nothing to encode until there is a second one. Version
numbers are numbers: there is no "schema v1", only schema 0 and schema 1, and
they are unrelated to the project's release names.

**What a build too old for the network does.** It stops, and says so. The chain
resolves up to the upgrade record and no further; `Authority.SchemaAlarm`
reports the version and the record, and `juist status` prints it. It does not
ignore the record — a node acting on the subset of the log it understands holds
a different view of who is a member, which is the split the closed record set
exists to prevent — and it does not treat it as invalid, because it is not.

Three consequences follow, and each is a rule:

- **The upgrade record is stored and relayed; nothing after it is.** A stopped
  node must not swallow the one record that explains why its peers have gone
  quiet, so that record is kept and offered on. What comes after it cannot be
  verified — this build does not know the rules those records are judged by —
  and storing unverified records would let any member fill a stopped node's
  disk. `Inform` therefore drops them from the batch rather than failing it,
  and gossip applies the readable prefix of a frame rather than refusing the
  whole. Both are the same rule: never discard the explanation along with the
  thing it explains.
- **A schema alarm does not withdraw membership state.** Unlike a fork alarm,
  the state below the upgrade was correct, and taking every tunnel down the
  moment an admin raises the schema would turn a planned change into an outage
  on every device that has not been updated yet. The cost is that a stopped
  node will not apply a revocation authored after the upgrade. What bounds how
  long it may act on that state is the freshness TTL, which is M4's — the same
  bound that already covers a partitioned node, arrived at from a new
  direction.
- **Fork choice is not taught to prefer the upgrade.** "No lower-version branch
  may win" is enforced by a node-local ratchet — a schema floor beside the epoch
  floor, persisted and never lowered — and not by a second bias in
  `pickPrimary`. A preference there could let a schema upgrade orphan a
  revocation, which is exactly the ordering "revoked wins" exists to prevent. A
  node offered a branch below its floor refuses it and fails closed, which is
  the answer this design gives everywhere else the same tension appears.

Compaction is refused while the alarm is up, because it deletes what the anchor
cannot reach and that is precisely the set a newer build resumes from. The
checkpoint rule needs nothing new: a checkpoint must equal the state its
ancestry produces, and the version is part of that state, so a checkpoint can
never be the record that changes it.

**What this buys, and what it does not.** New kinds, new roles and new optional
fields become reachable after the freeze, at the price of a quorum-signed
record and an upgrade window in which old devices are stopped and visible.
It does not rescue the shape changes declined below: a Merkle root over the
wrap set still costs a second transport for the record a member cannot read
without, and an addition that does not bump the epoch stays foreclosed by
admin-key custody, not by the schema. And it deliberately provides **no
extension bucket and no ignorable-unknown-field path** — either would reintroduce
the split view by letting two builds act on different subsets of the same
record.

What is still open, and belongs with M13's packaging: the
gossip hello does not carry the versions a node supports, `juist status` cannot
say which members would be stranded, and nothing stops an admin authoring an
upgrade before the network is ready for it. Until those exist, raising the
schema is an operation whose blast radius the operator has to know by other
means.

## The freeze: what the fan-out measurement decided

The 1168 bytes per member per epoch above are accepted at 25–100 devices, but
`MaxNodes` is 512, so the schema admits a network five times the target. The
M3 freeze required measuring that before spending schema space on it rather
than reasoning from the struct sizes, so `TestRecordSizeAtMaxNodes` encodes
both records at the ceiling and `TestRecordsBatchIsBoundedByBytes` puts a
gossip round against them. At 512 members:

| | bytes | per member per change | network-wide per change |
|---|---|---|---|
| epoch bump | 618 682 | 604 KiB | 302 MiB |
| checkpoint | 1 284 375 | 1254 KiB | — |

Sealing, opening, encoding and decoding a frame carrying the epoch bump is
about 2.6 ms in total, and decoding and validating the checkpoint 6.4 ms. So
**the fan-out costs bandwidth and not CPU, and only at a scale the project does
not target.** A member on a 512-device network pays 604 KiB for a change that
happens when someone joins or leaves; at the 100-device target it is 118 KiB.
Nothing in that range makes the inline wrap set the binding constraint.

Four of the five candidate hedges are therefore **declined**, and the fifth
taken. What each decision now binds:

- **A Merkle root over the wrap set: declined.** It would take a node's cost
  from O(n) to O(log n), which the measurement says the network is not short
  of, and in exchange every member would need a second transport to fetch the
  one record the trust layer cares most about — the wrap it cannot read
  without. Recovering this later means a coordinated upgrade, and the number
  that would force it is a member count around 2000, where a change costs each
  member a megabyte. `MaxNodes` stays at 512 so that ceiling is stated in the
  schema and not only here.
- **Batched membership changes: declined.** `KindAddNode` and `KindRemoveNode`
  keep carrying one node each. A set-valued record would amortise the fan-out
  over an enrollment run, but it multiplies the cases fork choice has to decide
  between — two batches that overlap in one member are neither identical nor
  independent — and the ceremony it would save is not the expensive part: k
  admins signing ten records in one sitting is ten invocations of `juist approve`,
  not ten ceremonies. **M4 enrolls one device per record**, and that is now a
  constraint on its design rather than a preference.
- **An addition that does not bump the epoch: declined, and it could not have
  been taken.** Appending one wrap for the current epoch would make an add
  O(1), but whoever authors the record must hold the *current group secret* to
  seal that wrap — and the design deliberately keeps group secrets off admin
  devices, so that an admin can rekey the network holding only a signing key.
  The only author who could produce such a record is a member, which would mean
  a record kind that changes the member set without quorum. The trade in
  [05-roadmap.md](05-roadmap.md) was stated as metadata against O(1); the real
  trade is admin-key custody, and it is not one this design can make.
- **Reserved space for logarithmic rekey: declined.** TreeKEM-style wrapping
  removes the fan-out outright and costs the property that one wrap has one
  recipient and is opaque to everyone else, which is what makes the epoch
  record auditable. Reserving space for a shape nobody has designed reserves
  the wrong shape. It is a v2 design and a coordinated upgrade.
- **A ciphersuite identifier: taken.** `EpochRecord.Suite` and
  `Snapshot.EpochSuite` name the HPKE suite the wraps are sealed under. It is
  the one hedge that is a *value* rather than a field: `SuiteHybridX25519MLKEM768`
  is zero and `omitempty`, so it costs nothing to encode today, and a future
  suite is a number an existing decoder already understands. A node meeting one
  it does not implement rejects the record — the pinned `SealedSecretSize` is a
  per-suite rule, so accepting an unknown suite would mean accepting a length
  rule that does not exist. 1088 of the 1168 bytes are the ML-KEM-768
  ciphertext, and dropping the hybrid is not on the table
  ([01-requirements.md](01-requirements.md)), so a more compact hybrid is the
  change this exists for.

**The size constraint that outlives the freeze.** A records frame is bounded by
bytes, not only by record count, because at these sizes
`MaxRecordsPerFrame`-many epoch records are several times `MaxFrameSize` — a
batch that cannot be encoded, produced identically every round, which wedges
that pair's sync rather than converging over more rounds. A batch is a
parents-first prefix, so truncating it stays applicable, and the next round
carries the rest. The same reasoning has not been carried through
`MaxHashesPerFrame`: a node holding more than 4096 records sends a truncated
`Have`, the peer re-offers records it already holds, and the two make no
progress. That is unreachable until a network has authored 4096 records without
a checkpoint, and closing it is part of deciding **when compaction runs without
an admin asking** — undecided, and the decision this binds; M12 makes it.

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

## Renumbering

Schema 5 moves v4 addresses after admission. The rules a later change has to
keep:

- **The log stays time-free.** A renumbering's deadline is data, applied by
  whoever renders addresses (`State.Addrs(id, now)`), never by `apply`: every
  node must reach the same state from the same records, whatever its clock. A
  skewed clock only keeps an old address live a little longer, which is safe
  because the address stays bound to its member's key and is held against
  collisions until a record retires it.
- **A retiring address is held like a current one.** No admission, rotation or
  renumbering — a network renumbering included — may give it to another
  member while it is recorded, and a range a network renumbering leaves with
  such addresses in it rejects admissions and overlapping route grants until
  it retires. Only a retiring address may lie in such a range, and a genesis
  retires nothing, so every state still validates once the range is gone. After that, the CLI's allocator still skips every
  address the history gave out, as it does a removed member's.
- **A member keeps one old address.** A second renumbering replaces the first
  one's, dropping it before its deadline; the CLI asks before doing so.
- **A network renumbering covers the member set exactly**, as an epoch's wraps
  do, so none is left in a range that is going away. The addresses a
  renumbering or an admission gives are where it sits, not what it says:
  replayed against another chain it is a change to start again, never a
  conflict, since a fork alarm takes every tunnel down for what is routine.
  An admission's address is reallocated then; a single member's move has an
  operator choose again.
- **IPv6 does not move.** It follows from the identity key, so no record can
  claim one; `RotateIdentity` is the only way to change it.
- **A deadline of `RetireAtOnce` is a move at once**, not a transition that
  ran out: the log treats it as any past deadline, and what is shown to an
  admin must say which it is.

## Renaming

Schema 6 changes the network's name. The rule a later change has to keep:
**nothing identifies a network by its name.** Records, pins, invites and
admissions name it by its genesis hash, and so must anything added later. A
name keyed on locally, as the keystore's break-glass and genesis files are,
is the one it had when that was written, and stays so.

## Admin encryption keys

Schema 7 gives admin keys an encryption key, which changes waiting for votes
are sealed to (M5b). The rules a later change has to keep:

- **Only the key sets its own.** A `SetAdminRecipient` needs the subject key's
  signature as well as the quorum, and a genesis naming one is signed by that
  key; `AddAdminKey` carries none. Otherwise a quorum could have what is sealed
  to an admin sealed to a key of its own choosing. A checkpoint a device
  bootstraps from is the exception, taken on its signers' word like the rest
  of what it states.
- **It is derived from the admin key's seed**, under a label of its own, so no
  file holds one without the other.
- **Nothing in the log is sealed to it.** It decides who can read a change
  before it counts, never whether it counts.

## Names

Schema 8 points public DNS names at members (M8): a node record's `Names`,
replaced by `SetNodeNames`. The rules a later change has to keep:

- **A name points at a member, never at an address**, so it follows
  renumbering and an identity rotation, and goes with the member. No name
  can send traffic outside the network.
- **One form of a name alone:** lowercase ASCII, a Unicode name as xn--,
  checked in the TCB without IDNA tables, which the CLI applies before. Two
  spellings are never two names.
- **One member per name**, as for subnet routes, and no name of juist's
  own domain, `.juist`, nor of a domain the host keeps to itself (`local`,
  `localhost`, `arpa`, `onion`, `invalid`), nor one that is an address.
- **The log only says what may be answered.** Whether a device answers, it
  decides itself: it has to agree to, and stops while its view is stale or
  the member is out of reach (docs/05-roadmap.md, M8).

## Published names

Schema 9 publishes members' services through an ingress (M9): the roles
`ingress`, `service` and `publish`, the network's `Domain` set by
`SetDomain`, and a node record's `Published`, replaced by `SetPublished`.
The rules a later change has to keep:

- **An ingress holds nothing else:** never beside `admin` or `exit`, and
  routing no subnet, so a compromised one vouches for no view, carries no
  traffic but spliced connections, and sends from its overlay addresses
  alone, by which its peers confine it.
- **A service member holds no other role and routes nothing**, and neither
  does a holder of `publish` hold `ingress`, whose port 443 it would share.
- **A published name is one label under the domain, on one member**, or
  the domain itself, the empty label, and never also a name pointed at a
  member, the domain itself included, checked again whenever the domain
  moves. Publishing needs the domain, and the domain is withdrawn only once
  nothing is published under it; shares under members' names then end.
- **A holder of `publish` holds the label its name gives**, lowercased, as a
  published label: no other member's published label, share label or name,
  and a name that gives none is refused the role. Anything that changes a
  member's name, as M9e's rename, checks it again (`checkNodeAdmissible`).
- **Withdrawing is no revocation**, as for the exit role and names: an
  ingress or a name taken away converges at gossip speed, and a partitioned
  ingress stops at the freshness TTL.
- **The log only says what may be published.** Whether a device serves a
  name, its operator decides (docs/05-roadmap.md, M9a).

## Renamed members

Schema 10 renames a member by `RenameNode`, which replaces its name alone.
The rules a later change has to keep:

- **No two members' names fold alike**, which the log refuses for a rename
  as it does for holders; admissions are numbered apart by the CLI alone,
  so a state may hold two from before, and neither is renamed to the other.
- **A rename is checked as an admission is** (`checkNodeAdmissible`), since
  a holder of `publish` shares under the label its name gives.

## Not built in M1, on purpose

- **Freshness leases.** Built at M4, outside the record schema: see
  [11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md).
- **A disablement record.** The genesis ceremony commits to break-glass secrets
  and `State.ValidDisablement` verifies a preimage, which is what the schema
  needs. *What revealing one authorizes* is planned in
  [05-roadmap.md](05-roadmap.md) as M11.
- **Route consumption.** Validated from M1, read by nothing until M6.

### The obligation M1 hands to M6

The default route is exempt from the no-overlay-overlap rule, because it covers
everything by construction. Whoever consumes route grants **must subtract the
overlay space** — the genesis-derived ULA /48 and the overlay v4 ranges — when rendering
`AllowedIPs` and filter destinations. Without that subtraction, an exit
grant would re-open exactly the member-to-member interception the overlap rule
exists to prevent. The rule is stated in `types.ValidateRoute`; exit nodes
subtract the overlay in `conn.Internet`, and M6b's subnet routes, which carry
no default route, are held to the overlap rule by the validator itself.

## Verification

- `trust/log/adversarial_test.go` is the milestone's exit criterion, one test
  per attack, each stated in the terms an attacker would use.
- `TestResolutionIsOrderIndependent` and `TestIncrementalDeliveryNeverRegresses`
  are the property tests from [06-verification.md](06-verification.md) §1,
  seeded rather than randomized so a failure can be replayed.
- Fuzz targets: `FuzzDecodeAUM` (asserts injectivity, not just absence of
  crashes), `FuzzValidateAUM`, `FuzzChainValidate` (signs what it mutates, so
  the input reaches the state machine; asserts that a rejected record changes
  nothing and that the epoch never regresses). `make fuzz` is the
  seconds-long smoke run; `make fuzz-long` is the gate. Neither runs on CI —
  see [06-verification.md](06-verification.md) §2.
- `TestTCBDependencies` keeps the audit scope's dependency closure to the
  standard library plus two small modules, and keeps the clock and the
  filesystem out of the packages that decide validity.
- `make tcb` reports the audit scope's size against the 10k-line budget
  [06-verification.md](06-verification.md) §6 sets. It is ~8 k lines.

- Fork-choice tests that need one record to beat another on the hash tiebreak must
  redraw *both* sides each attempt, or assign the roles after drawing. Redrawing
  against a fixed target makes the per-attempt chance `target/2^256` — itself
  uniform, and sometimes tiny — so a 65-attempt budget fails 1/66 of the time
  rather than 2^-65.
