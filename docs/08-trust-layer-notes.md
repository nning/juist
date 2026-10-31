# 08 — Trust layer notes

The rules the membership log enforces, why, and what a later change has to
keep. Companion to [07-embedding-notes.md](07-embedding-notes.md), which does
the same for the connectivity layer; freshness leases are in
[11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md).

Packages: `types` (record schema, canonical encoding, addressing), `trust/log`
(chain, quorum, fork choice, alarms), `trust/secrets` (epoch group secret),
`trust/store` (on-disk log). CLI: `cmd/juist`.

## Decision: the log is ours; `tka` is the design, not the dependency

[03-control-plane-options.md](03-control-plane-options.md) chose `tailscale.com/tka`
as the model; importing or forking it buys little:

- **Its records are about the wrong thing.** tka is a *key* authority
  (`AddKey`/`RemoveKey`/`UpdateKey`/`Checkpoint`/`NoOp`) and authorizes nodes
  out of band; our log holds the members themselves.
- **Its authorization rule is weaker.** `aumVerify` requires trusted signers,
  not a quorum; weight only resolves forks. We need k-of-n on every change.
- **The parts worth keeping are the parts that must change.** tka gets
  ordering and distribution from the coordination server; supplying those is
  the new security-critical code.
- **The coupling is real.** It threads `tailscale.com/types/{key,tkatype}`
  through its API, which would put the connectivity stack in the trust layer's
  audit scope.

**Adopted from tka by name:** the hash-chained record in canonical CBOR (CTAP2
mode, reasoning quoted in `types/cbor.go`); schema evolution by never reusing
CBOR key numbers, optional absent-by-default fields and no floats; vote weights
checked at verification rather than threshold crypto; checkpoints as
quorum-signed compactions; pre-committed break-glass preimages; signatures at
CBOR key 23.

`TestTCBHasNoTailscaleDependency` enforces the layering: nothing in `types` or
`trust/*` may reach `tailscale.com`, so an engine upgrade can never change who
is a member.

## Signatures

Every signature that changes or carries state is ML-DSA-44, so a quantum
computer forges no change to the network; what it still forges is weakness 13
in [02-threat-model.md](02-threat-model.md).

- **ML-DSA-44 from `crypto/mldsa`,** pure, never HashML-DSA, signing
  deterministically what Ed25519 signs; keys kept as 32-byte seeds, derived
  by HKDF from the Ed25519 seed, so `node.keys`, admin key files and M12's
  backups cover them. No composite with Ed25519.
- **One key, one identity.** No ML-DSA key is named by two identities, so a
  signature by one key never counts as another's. `types.Identity`, the
  Ed25519 public key, still names a member, derives its IPv6 address and keys
  every map; no record is verified against it.
- **Where a key enters.** An admin key enters as `juist admins new` prints
  it, identity, signing key and endorsement in one token; a member brings its
  key in its join request, which proves it holds it; an identity rotation
  names the new identity's key in what the quorum, the old key and the new
  one sign.
- **Messages carry both.** Announcements, address keys, leases, waiting
  changes, pair-key and catch-up messages and admissions carry an Ed25519 and
  an ML-DSA signature, and the ML-DSA one is required. Discovery (the DHT, a
  relay's rendezvous, mDNS) carries announcements without it, sealed under
  the epoch's key, as hints that say where to dial and nothing else.
- **Enrollment** adds an ML-KEM-768 exchange inside the SPAKE2 channel, which
  the session's binding covers (protocol version 3, no fallback).
- **TLS 1.3 with X25519MLKEM768 alone** between juist's own ends: the relay,
  the HTTPS-only client and `relay/forward`. ACME's challenge, the terminator
  and the TLS to an HTTPS proxy keep 1.2.
- **Sizes.** `MaxRecordSize` (4 MiB) and `MaxFrameSize` (8 MiB); a records
  frame keeps 2 MiB beside its records, a lease takes up to 4 KiB, a catch-up
  message 8 KiB. A member's public names and published labels take at most
  2048 bytes between them, so a checkpoint at `MaxNodes` fits.
- **Still classical, on purpose:** the DHT's BEP 44 item key (it guards
  liveness alone), WireGuard's static keys (a pair's preshared key holds),
  the relay's certificate and a host's forward proof (a relay is trusted for
  liveness alone), the CLI's rotation proof on the local socket, and the APK
  signature, which Android keeps to RSA and EC.

## Encoding: one record, one byte string

A record's identity is the hash of its serialization, and a signature covers
the hash of its serialization minus the signatures. Two valid encodings would
give two hashes, and one quorum could authorize two chain entries. So:

> Decode is injective: for every byte string `Decode` accepts,
> `Encode(Decode(b)) == b`.

Strict decoder options rule out the known ambiguities; the re-encode
comparison in `decodeCanonical` proves the rest, so nothing depends on which
lenient behaviours the CBOR library has. Every set-valued field (admin keys,
nodes, signatures, wraps, roles, routes) must be sorted and duplicate-free for
the same reason. `FuzzDecodeAUM` asserts the property.

**Closed sets, not forward compatibility.** Unknown record kinds and role names
are rejected. Every node must reach the same verdict from the bytes alone, and
a node that ignores a record its peers act on holds a different view of who is
a member. Adding a kind or a role is a schema change (below).

**SHA-256, not BLAKE2s:** standard library, hardware-accelerated, and already
the address-derivation hash. Every digest and derived key is computed over a
NUL-terminated domain-separation label, so no digest can be reinterpreted as
another kind.

## Validation rules

Each rejects a record that is well formed and signed.

**Every membership or key change bumps the epoch**, not only `RemoveNode`, so
the current epoch's wraps always cover exactly the current members.

**The wrap set matches the member set exactly**, one wrap per member and none
for a non-member. Otherwise a bump could quietly cut a member off discovery or
hand the group secret to a non-member.

**Epochs are strictly sequential (`+1`)**, so a node's epoch floor is exact.

**The epoch record commits to its secret** (`EpochRecord.Commit`), and each
recipient checks what it decrypts against it; otherwise a quorum could seal a
different secret to each member and partition discovery invisibly.

**Small-order identity keys are rejected** (`Identity.Validate`). Anyone can
compute an Ed25519 signature by one, and identities still sign their ML-DSA
key's endorsement and their leases with Ed25519; quorum cannot notice a key
with no owner. This and SPAKE2 are why `filippo.io/edwards25519` is a
dependency.

**Members may not share WireGuard, X25519 or ML-KEM keys.** One WireGuard key
on two members would let one displace the other in the data plane; duplicate
encryption keys are the stolen-device case of
[02-threat-model.md](02-threat-model.md).

**A checkpoint must equal the state its ancestry produces**, byte for byte,
wherever the parent state is known, so a quorum cannot rewrite membership by
asserting a state.

**Removing an admin key that strands the quorum is rejected**: nobody could
ever change the network again.

**Route grants may not cover loopback, link-local or multicast space**, nor the
overlay. The exact default route is the one exemption, legal only with the
`exit` role; see "Default routes" below.

**Names are checked for control and bidi-formatting characters** once, at
admission, rather than escaped at every print site.

## Fork choice, and what it refuses to decide

Of two siblings, `(1)` a revocation beats a non-revocation, `(2)` otherwise the
lower hash wins — without tka's signature-weight rule, which would let one
quorum outbid another by collecting signatures and invites grinding.

A revocation is any record that withdraws authority (`State.Revokes`):
removing a device or an admin key, taking a device's admin role away, raising
the quorum or the vouching threshold, and asking more keys of a holder or giving
it fewer votes without granting it any. Otherwise a concurrent change with a
lower hash could orphan the withdrawal.

**Votes belong to people.** An admin key can name its holder; a holder's keys
are one voter and cast its votes once, when at least `Needed` of them signed
(`types.CountVotes`, `KindSetHolder`). What the network can still cast is
counted per holder (`types.AchievableVotes`), and a change leaving the quorum
out of reach is refused.

**A removed key cannot undo its removal.** A sibling is verified against its
parent's state, where the key still votes, so before both rules above: a branch
loses to a sibling whose branch removes an admin key that signed anything on
it. Two keys removing each other at once alarm.

**Copies of one record are that record.** Siblings with one `SigHash` and other
signature sets are copies, not a fork, and fork choice must not depend on which
copies a node holds. From schema 19 it reads what they say and the union of
their signatures: copies tie on the lower `SigHash`, and a key is a signer for
the rule above only where the record needed it (a required self-signature, or a
vote without which the union falls short of quorum). At schema 18 any signature
counts and the lower hash wins. The lowest hash stands for the copies, and what
hangs from any of them hangs from it. A store keeps a copy while it is one of
the two lowest, carries a signature no other does, or something hangs from it;
of a checkpoint it keeps up to eight, so a peer anchored at any is served. The
CLI pins a head with its `SigHash`, so a copy continues it.

The losing branch is kept but not applied; its author reissues it. Two cases
raise a persistent alarm instead:

- **An orphaned revocation that cannot be reissued.** The revocation bias only
  compares immediate siblings, so a deeper removal on a losing branch would
  vanish. One the chosen chain could take is shown as not in effect, on every
  device's status and in `juist log`, for an admin to run again; one already in
  effect is nothing; one the chosen chain cannot take alarms.
- **An orphan that cannot be reissued.** Each orphan is replayed against the
  winning head with position-dependent rules relaxed (epoch sequencing, wrap
  coverage, an admission's or renumbering's IPv4 address). If its substance no
  longer applies, the branches disagree about something concrete. Addresses are
  relaxed because two concurrent admissions both take the lowest free one; the
  CLI counts orphaned admissions' addresses as taken so a reissue does not
  collide again. A checkpoint has no substance and never conflicts.

While an alarm is raised, `Authority.TrustedState` refuses membership — the
same trade as the freshness TTL — and `Authority.State` still shows what the
fork did. Nothing stops a colluding quorum from forking
([02-threat-model.md](02-threat-model.md), residual weakness 3).

## The two ratchets, and what they cost

Both are node-local: nodes that saw different histories refuse different
things, and a fork alarm surfaces that rather than averaging it away.

**The anchor** is the genesis, or the checkpoint this node's log starts from.
Resolution never walks past it, so a branch forking below it is not considered
at all. juistd compacts to the checkpoint before the newest on its chain, once
every other live member has been heard with a head on or past the newest, or
once a member heard has compacted to that checkpoint or past it; so what hangs
past the anchor is decided as on a device that never compacted. The chain from
the previous anchor up to the new one is kept for a device behind to catch up
along. No device compacts while an alarm is raised or a revocation that lost
fork choice waits to be redone. A hello's head is unsigned, so a lying member
can make devices compact early; a device further behind than the kept chain is
invited again by a link naming its admin, which moves its log to the invite's
chain (`Authority.Rebase`) only where that chain's anchor carries a quorum of
the admins the log trusts and is at a later epoch. A typed code never replaces
a log, since the device answering it could hand over a chain of its own.

**The epoch floor** is the highest epoch adopted, never lowered. A chain that
resolves below it is stored but held under a *rollback alarm*, derived from what
is stored so a restart keeps it, until the chain is back at the floor. A quorum
rewriting history and a concurrent branch at a lower epoch winning fork choice
look the same from here, so both fail closed. Refusing the records instead would
leave the node serving the losing branch and, since sync sends a branch parents
first in one batch, refusing later batches, removals included, with no alarm.
The alarm clears with the record that lifts the chain to the floor: a lost
change redone, or `juist rotate group-secret`. An admin's CLI resolves without
a floor, so it signs on the winning head even from a stuck device.

The cost: two nodes offered one fork in different orders can end in different
states, one following the winner, one alarmed. Both fail closed — the CAP-style
limit [02-threat-model.md](02-threat-model.md) accepts.

## Group secret: hybrid HPKE, and its size

HPKE (RFC 9180) base mode, `DHKEM(X25519)+ML-KEM-768`, HKDF-SHA256,
ChaCha20-Poly1305: the harvest-now-decrypt-later hedge.
`TestCiphersuiteIsTheIntendedOne` pins the KEM.

Cost: **1168 bytes per member per epoch**, so an epoch bump or checkpoint on a
100-member network is ~120 KB. It is why `MaxNodes` is 512; see "The freeze"
below.

A node's recipient key is **two fields** (`X25519`, `MLKEM`), each validated as
the key it is; the ML-KEM half also feeds the per-pair preshared key. Each
epoch's secret is **fresh randomness**, not derived from the last, so an admin
can rekey holding only a signing key, which keeps group secrets off admin
devices.

The HPKE `info` binds each wrap to one epoch and one recipient. It does not bind
the network, which would be circular for the genesis; the signatures do that.

`juist rotate` rotates **all** of a device's rotatable keys at once and
generates them locally: a record naming a key whose private half the device
lacks would apply fine and leave the device unable to handshake or read the
group secret. All of a device's secrets live in **one file**, so promotion is a
single rename, and promotion follows **what the adopted state names**, not
which records were in the batch, since an authorized rotation can still lose
fork choice.

**Known limitation.** Nothing in the log proves a wrap was sealed to the right
key. A member that cannot open its wrap reports it; the commitment makes that
report unambiguous.

**A keystore refuses at the point of choice, not of use.** Replacement keys are
staged only once their record exists, and a name is checked against
`types.ValidateName` where it is chosen; `create` validates every name before
writing any file a ceremony cannot be re-run over.

**The genesis ceremony is completable by the tool that starts it.** Where the
local keys do not reach k, `create` writes the record to `genesis-NETWORK.rec`
and stops; the other admins `juist approve` it on keystores with no network
(`log.GenesisStatus` reports it against the policy it declares), and `juist
apply` creates the network.

**`sign` refuses to guess.** A record whose parent is not the head is judged
against the state at that parent, where the admin set may differ, so `sign`
warns and withholds the verdict.

**Absent is not unloadable.** A missing key file is an ordinary state; one that
is present but cannot be loaded is a fault (`errors.Is(err, fs.ErrNotExist)`
alone means absence).

## The schema is versioned, so the freeze is a price rather than a wall

The state every genesis and checkpoint states carries a `Schema` version, and
`KindSchemaUpgrade` raises it under the usual quorum. A build implements
`types.CurrentSchema` (20) and reads from `types.MinSchema` (18) up; raising
`MinSchema` drops the rules below it, so a network below has to move up with an
older build first. Schema numbers are unrelated to release versions.

**A build too old for the network stops, and says so.** The chain resolves up
to the upgrade record and no further; `Authority.SchemaAlarm` reports it and
`juist status` prints it. It neither ignores the record (a split view) nor
treats it as invalid.

- **The upgrade record is stored and relayed; nothing after it is.** A stopped
  node must not drop the record that explains why its peers went quiet, and
  must not store records it cannot verify. `Inform` drops them from the batch
  and gossip applies a frame's readable prefix.
- **A schema alarm does not withdraw membership**, unlike a fork alarm, so a
  planned upgrade is not an outage on every device not yet updated. A stopped
  node will not apply later revocations; the freshness TTL bounds that.
- **Fork choice is not taught to prefer the upgrade.** A persisted schema floor
  beside the epoch floor refuses lower-version branches; a bias in fork choice
  could let an upgrade orphan a revocation.

Compaction is refused while the schema alarm is up: it would delete what a
newer build resumes from. A checkpoint can never change the version, since it
must equal the state its ancestry produces.

There is **no extension bucket and no ignorable-unknown-field path**: either
would let two builds act on different subsets of one record. A schema bump does
not rescue the shape changes declined below.

**A stopped build must still read the upgrade.** Gossip frames decode strictly,
so a field a schema adds to the wire goes only to a peer whose announced schema
reads it. Every member announces the newest schema its build implements, and
`juist devices` shows a live member announcing an older one.

Open, for M33: nothing says before an upgrade which members it would strand,
or stops an admin authoring one too early.

## The freeze: what the fan-out measurement decided

The wrap set is inline in every epoch record and checkpoint.
`TestRecordSizeAtMaxNodes` and `TestRecordsBatchIsBoundedByBytes` measure it at
`MaxNodes` = 512:

| | bytes | per member per change | network-wide per change |
|---|---|---|---|
| epoch bump | 618 682 | 604 KiB | 302 MiB |
| checkpoint | 1 284 375 | 1254 KiB | — |

Processing either costs milliseconds, so **the fan-out costs bandwidth, not
CPU, and only above the target scale** (118 KiB per member at 100 devices).
What each decision binds:

- **A Merkle root over the wrap set: declined.** It would need a second
  transport for the one record a member cannot do without. It becomes necessary
  around 2000 members (a megabyte per member per change), which is why
  `MaxNodes` stays at 512 in the schema.
- **Batched membership changes: declined.** Overlapping batches multiply fork
  choice's cases. One device per `KindAddNode` / `KindRemoveNode`.
- **An addition that does not bump the epoch: impossible.** Its author would
  need the current group secret, which admin devices do not hold; only a member
  could write it, without quorum.
- **Reserved space for logarithmic rekey: declined.** TreeKEM costs the
  auditable one-wrap-one-recipient property; it is a v2 design.
- **A ciphersuite identifier: taken.** `EpochRecord.Suite` /
  `Snapshot.EpochSuite`, zero (`SuiteHybridX25519MLKEM768`) and omitted today.
  An unknown suite is rejected, since `SealedSecretSize` is per suite. It exists
  for a more compact hybrid; dropping the hybrid is not on the table.

**The size constraint that outlives the freeze.** A records frame is bounded by
bytes, not only by count: `MaxRecordsPerFrame` epoch records exceed
`MaxFrameSize`, and a batch that cannot be encoded, rebuilt identically every
round, wedges the pair. A batch is a parents-first prefix, so truncating it
stays applicable. `MaxHashesPerFrame` binds the same way, so a hello lists only
what the sender resolves from its anchor, those nothing hangs from first, and
from a list so cut short a peer is taken to hold the ancestors of what it lists:
two nodes converge however
long the log is. Checkpoints keep it short: the admin's CLI that applies a
change drafts one every 256 records or 32 MiB, which needs the quorum like any
change.

## Storage

Records are content-addressed and every read checks the bytes still hash to the
name, catching bit rot and editing alike.

The anchor and floors are fsynced before anything acts on them. Records are
staged and fsynced before any is renamed into place; a crash between renames
leaves records whose parent is missing, which resolution ignores and the sender
offers again. `Inform` re-resolves from storage after writing, so the floor is
never raised above what storage can reproduce.

Corruption makes the store refuse to open, naming the file; it never repairs
itself or re-genesises, which would turn a disk fault into two histories. A
store directory writable by group or other is refused, since it would let
anyone lower the ratchets.

Every temporary-file prefix a crash can leave is swept on open, and a test
covers every prefix the package can produce: an unrecognized leftover would
otherwise read as corruption after an ordinary power loss.

## Kinds with a rule of their own

- **`SetQuorum`**, so a network can change *k* as it grows.
- **`EpochBump`**, rotating the group secret without a membership change: the
  answer to a suspected group-secret leak.
- **`RotateIdentity`** requires quorum plus signatures by the old identity and
  the new, and from schema 19 names the new signing key in what is signed; at
  schema 18 identities do not rotate. It keeps a member's roles, routes, v4
  address and name.

## Renumbering

v4 addresses move after admission. The rules a later change has to keep:

- **The log stays time-free.** A renumbering's deadline is data, applied by
  whoever renders addresses (`State.Addrs(id, now)`), never by `apply`. A
  skewed clock only keeps an old address live longer, which is safe because it
  stays bound to its member's key and held against collisions.
- **A retiring address is held like a current one.** Nothing may give it to
  another member while it is recorded, and a range a network renumbering leaves
  with such addresses rejects admissions and overlapping route grants until it
  retires. Only a retiring address may lie in such a range, and a genesis
  retires nothing, so every state validates once the range is gone. The CLI's
  allocator still skips every address the history gave out.
- **A member keeps one old address.** A second renumbering replaces the first
  one's; the CLI asks first.
- **A network renumbering covers the member set exactly.** The addresses a
  renumbering or admission gives are where it sits: replayed against another
  chain it is a change to start again, never a conflict. An admission's address
  is reallocated then; a single member's move has an operator choose again.
- **IPv6 does not move.** It follows from the identity key; only
  `RotateIdentity` changes it.
- **A deadline of `RetireAtOnce` is a move at once**, treated as any past
  deadline; what an admin is shown must say which it is.

## Renaming

**Nothing identifies a network by its name.** Records, pins, invites and
admissions use the genesis hash, and so must anything added. A name keyed on
locally, as the keystore's admin key and genesis files are, keeps the name it
had when written.

## Admin encryption keys

Admin keys carry an encryption key, to which changes waiting for votes are
sealed (M5b):

- **Only the key sets its own.** `SetAdminRecipient`, and a genesis naming one,
  need the subject key's signature; `AddAdminKey` carries none. A checkpoint a
  device bootstraps from is taken on its signers' word.
- **It is derived from the admin key's seed** under its own label.
- **Nothing in the log is sealed to it.** It decides who can read a change
  before it counts, never whether it counts.

## Names

A node record's `Names` (set by `SetNodeNames`) are public DNS names for it
(M8):

- **A name points at a member, never at an address**, so it follows
  renumbering and rotation and goes with the member.
- **One form of a name:** lowercase ASCII, Unicode as xn--, checked in the TCB
  without IDNA tables, which the CLI applies before.
- **One member per name**, and none under `.juist`, a host-reserved domain
  (`local`, `localhost`, `arpa`, `onion`, `invalid`), or that is an address.
- **The log only says what may be answered.** A device decides whether it
  answers, and stops while stale or the member is out of reach.

## Published names

Roles `ingress`, `service` and `publish`, the network's `Domain`
(`SetDomain`) and a node's `Published` (`SetPublished`) publish members'
services through an ingress (M9):

- **An ingress holds nothing else:** never beside `admin` or `exit`, routing no
  subnet, so a compromised one vouches for nothing and carries only spliced
  connections from its overlay addresses.
- **A service member holds no other role and routes nothing**, and a holder of
  `publish` does not hold `ingress`, whose port 443 it would share.
- **A published name is one label under the domain, on one member**, or the
  domain itself, never also a name pointed at a member, rechecked whenever the
  domain moves. The domain is withdrawn only once nothing is published under
  it.
- **A holder of `publish` holds the label its name gives** as a published
  label; a name that gives none is refused the role, and anything changing a
  member's name checks it again (`checkNodeAdmissible`).
- **Withdrawing is no revocation**: it converges at gossip speed, and a
  partitioned ingress stops at the freshness TTL.
- **The log only says what may be published**; the operator decides what a
  device serves.

## Renamed members

`RenameNode` replaces a member's name alone:

- **No two members' names fold alike.** Admissions are numbered apart by the
  CLI alone, so a state may hold two such names, and neither is renamed to the
  other.
- **A rename is checked as an admission is** (`checkNodeAdmissible`).

## Disable records

A `Disable` record reveals a break-glass secret and ends the network (M12):

- **Its secret is its whole authority.** It carries no signature, which could
  only give it a second encoding, and is checked against the genesis
  commitments every checkpoint restates.
- **It counts wherever it hangs**: below the anchor, past the orphan budget or
  past a schema this build stops at. Gossip hands it to every peer lacking it,
  and a device hands it to every member before dropping the tunnels log sync
  runs through. Nothing follows it.
- **It is valid under every schema**, since a network that lost its admins
  cannot upgrade first.
- **It disables, it never recovers.** Every relaying member reads the secret,
  so a record granting authority could be reissued by any of them.

## Default routes

The default route is exempt from the overlay-overlap rule, so whoever consumes
route grants **must subtract the overlay space** (the ULA /48 and the overlay v4
ranges) from `AllowedIPs` and filter destinations, or an exit grant reopens
member-to-member interception. `types.ValidateRoute` states it; exit nodes
subtract in `conn.Internet`, and subnet routes carry no default route.

## Verification

- `trust/log/adversarial_test.go`: one test per attack, in an attacker's terms.
- `TestResolutionIsOrderIndependent`, `TestIncrementalDeliveryNeverRegresses`:
  the property tests of [06-verification.md](06-verification.md) §1, seeded so
  a failure replays.
- Fuzz targets `FuzzDecodeAUM` (injectivity), `FuzzValidateAUM`,
  `FuzzChainValidate` (signs what it mutates; a rejected record changes nothing
  and no state it trusts falls below the epoch floor), `FuzzAdmissibleAlike`
  (a member set is admitted by records exactly where a whole state is).
  `make fuzz` is the smoke run, `make fuzz-long` the gate; neither runs on CI
  ([06-verification.md](06-verification.md) §2).
- `TestTCBDependencies` keeps the audit scope to the standard library plus two
  small modules, and the clock and filesystem out of the packages that decide
  validity.
- `make tcb` holds the core to its 11k-line budget
  ([06-verification.md](06-verification.md) §6).
- A fork-choice test that needs one record to beat another on the hash
  redraws *both* sides each attempt; redrawing against a fixed target can fail
  far more often than the budget suggests.
