# 09 — Mesh layer notes

What M2 decided, and why, in the same spirit as
[08-trust-layer-notes.md](08-trust-layer-notes.md): the record of the choices a
reader of the code would otherwise have to reverse-engineer.

M2 is the reconciler, gossip anti-entropy, blinded LAN discovery and the daemon
that holds them together — "log state ⇒ WG config ⇒ netmap", two to five nodes
on one LAN, no internet ([05-roadmap.md](05-roadmap.md)).

## The disco key is not in the log

[04-architecture.md](04-architecture.md) says "every member gets a disco key"
but does not say where it comes from, and the M1 record schema has no field for
one. That absence turned out to be right, and M2 makes it deliberate.

A node's NAT-traversal key is **connectivity material with a lifetime of one
process**. The connectivity layer already treats a changed disco key as the
signal "that peer restarted" and resets its WireGuard session accordingly
(`conn.peerDelta`). Putting it in the log would mean a k-of-n admin ceremony
per reboot.

So a disco key travels in a **signed endpoint record** (`gossip.Endpoint`),
alongside the node's underlay addresses and its gossip port, signed by the
node's own identity key and by nothing else. That is the right amount of
authority for what it claims — a node may say where it is, and no node may say
anything about another — and everything it could lie about costs connectivity
and nothing more. What it can never do is make its subject a member: the
reconciler reads the member set from the log and *joins* announcements onto it,
dropping any whose subject the log does not carry.

Consequence worth stating plainly: **a member with no announcement gets no peer
entry.** That is not denial, it is "not heard from yet", and the daemon's
status reports the two separately so an operator can tell a mesh coming up from
a mesh that is refusing someone.

## Gossip runs on the underlay, not in the tunnel

[04-architecture.md](04-architecture.md) calls WireGuard tunnels the normal
case for moving records. At M2 it is the other way round, for a plain reason:
reaching a peer *over* the overlay needs the tunnel that gossip is what brings
up. Running the sync layer inside the tunnel needs either a real TUN device
plumbed into the host stack or a userspace netstack, so neither is possible
before M3a.

The layering is unchanged — records are self-certifying either way, which is
exactly why [04-architecture.md](04-architecture.md) can call the transport
untrusted by construction. What changes is metadata, and that is covered by
sealing every frame under the epoch group secret.

The protocol is one TCP session per round, four frames, strictly alternating:

```
initiator → hello    what network, where my chain is, what I hold
responder → hello    the same, answered
initiator → records  what the responder turned out to be missing
responder → records  what the initiator turned out to be missing
```

Symmetric, because one round making both sides whole halves the rounds a
revocation needs to cross a five-node mesh. "What I hold" is the full hash set
rather than a walk back to a common ancestor: at this scale a whole log is a
few kilobytes of hashes, and sending it makes the exchange stateless and immune
to branch bookkeeping. `MaxHashesPerFrame` is where that stops being true.

Every frame also names the sender's **anchor** — its genesis, or the newest
checkpoint it has compacted to — and each side answers "what are you missing"
by walking the *peer's* anchor, not its own roots. That is what keeps sync
alive across compaction asymmetry: a record below the receiver's anchor is one
its log refuses, and because `Inform` is atomic, a single refused record would
poison every acceptable one in the same batch — a node with longer history
would never again teach a compacted peer anything. A peer whose anchor this
node does not hold gets nothing, correctly: that peer is the one with history
to offer, and the other half of the same session is where it offers it.

## Epoch skew, and the keyring

Sealing gossip under the epoch secret creates a problem the design does not
mention: the node that authors a change is **one epoch ahead of everyone else**
for the length of a convergence round. If it could only speak its own epoch,
the very push carrying a revocation would be unreadable to exactly the members
that have not applied it yet, and revocation would converge at the anti-entropy
timer instead of at push speed.

Two mechanisms fix it:

- A **keyring** (`secrets.Keyring`) retains the last `KeyringDepth` = 4 epoch
  secrets, so a node can still open a frame from a peer that is behind.
- The initiator seals under **the recipient's last-known epoch** when it still
  holds that secret, and a responder always answers under the epoch the request
  came in on. So a session runs entirely at one epoch, chosen to be one both
  sides can read.

**The trade this makes.** A revoked device also holds an epoch secret, and
until the network has moved four epochs past it, members will still open its
gossip frames and answer its LAN queries. What that window costs is metadata —
the member set and where its members are — and nothing else: the revoked device
gets no WireGuard peer entry anywhere from the moment the removal converges,
because peers come from the log and not from anything the sync layer says.
Since every membership change carries an epoch bump, four changes retire the
window completely. Bounding it in *time* rather than in changes is what the
freshness leases in M4 are for, and that is the right place for it — a
time-bounded window needs a clock the trust layer deliberately does not have.

The same window applies to discovery, for the same reason and with the same
cost.

## Discovery: blinded, but not DNS-SD browsing

`discovery/mdns` sends ordinary multicast DNS on 224.0.0.251:5353 — a TXT query
at a name that is a keyed derivation of the epoch group secret
(`secrets.Secret.MDNSName`), answered with TXT records carrying an
AEAD-sealed [gossip.Endpoint].

There is deliberately **no PTR browsing and no SRV or A record**. There is
nothing to browse: only a holder of the group secret can construct the one name
that means anything, and the sealed payload already carries the port. A LAN
observer sees that some host is asking about some opaque 32-character label
under `_juist._udp.local` — enough to conclude that juist is in use, which
[02-threat-model.md](02-threat-model.md) accepts as residual weakness 5 — and
cannot tell which network, who is on it, or how many.

Two consequences fall out, both wanted: a revoked device stops being able to
compute the name (subject to the keyring window above), and two juist networks
sharing a coffee-shop LAN are mutually invisible rather than merely mutually
incompatible.

A beacon announces under its newest name and **answers to every name in its
keyring**, and queries as well as announces on each interval. Announcing alone
is not enough — a node announces under one name, so a member an epoch behind
would never hear it — and asking alone is not enough either, since a node
arriving on the LAN should not have to wait for someone else's question.

IPv4 only at this milestone. The IPv6 group (`ff02::fb`) needs per-interface
join handling, which wants the multi-namespace harness M3a brings to test it
against more than one interface.

**Answers are rate-limited, and the interface set is not fixed.** A member
transmits its record under any one name at most once a second, whether as an
answer or as an announcement. The floor is RFC 6762 §6's, and the reason it
matters here is not etiquette: the blinded name travels in the clear, so an
attacker who holds no secret at all can replay a question at it, and DNS
compression makes a datagram of a couple of hundred copies cheap. Multicast
membership is also per interface and refreshed on a timer, since an interface
that appears after startup would otherwise never carry discovery.

**The socket is not the obvious one.** `net.ListenMulticastUDP` binds to the
*group* address, so a datagram sent from it carries a multicast source address
and the kernel drops it. The failure is silent in both directions — the join
succeeds, `/proc/net/igmp` shows the membership, reads work, and no beacon ever
arrives — which is indistinguishable from "all my peers are offline". Found by
running two real daemons rather than by any test, because the tests inject a
socket. What works: a wildcard bind with `SO_REUSEADDR` (5353 is a shared port
and other responders on the host must keep working), an explicit `JoinGroup`
per multicast-capable interface, and a send loop over those interfaces so that
a multi-homed host announces on every LAN it is attached to rather than on
whichever one the route table prefers. `TestRealMulticastSocket` is the
regression guard, and skips where multicast is genuinely unavailable.

## The open item 07 left for M2, resolved

[07-embedding-notes.md](07-embedding-notes.md) ends on: *magicsock will not
report its own local endpoints without a DERP map* — `Conn.setEndpoints`
returns early with neither a STUN result nor a DERP map — and offers two ways
out.

**Taken: read the host's interface addresses directly.** It is the one that
needs no third party at all, which is what exit criterion 3 ("LAN-only
operation with zero internet works") asks for. `daemon.underlayEndpoints`
enumerates up, non-loopback interfaces and filters out link-local addresses and
the overlay's own ranges — announcing an overlay address as an underlay
endpoint would ask peers to reach the tunnel through the tunnel. Reflexive
addresses discovered through disco and member relays arrive at M3b and are
*added* to this set rather than replacing it.

## What that interface scan actually announces on a real host

The filter `daemon.usableUnderlay` applies is the obvious one — down, loopback,
link-local, multicast, unspecified, plus the overlay's own `100.64/10` and this
network's ULA — and on a developer laptop it is visibly not enough. A node on a
machine with lxc, libvirt and Tailscale running announced itself as:

```
[10.0.3.1:41651 10.11.1.140:41651 192.168.122.1:41651
 [fc42:5009:ba4b:5ab0::1]:41651 [fd7a:115c:a1e0::2901:8d4e]:41651]
```

Exactly one of those five can carry a packet from another machine. The rest
produced `sendto: network is unreachable` disco pings until the peer settled on
the WLAN address. Nothing broke — disco probes every candidate and adopts the
one that pongs, which is what it is for — but two things in that list are worth
naming before M3b adds reflexive addresses on top.

**The foreign-overlay filter is split by address family.** `100.64/10` is
excluded, so Tailscale's IPv4 address is correctly absent; its ULA
`fd7a:115c:a1e0::/48` is announced. Same interface, same foreign overlay, one
family filtered and the other not. Announcing it is not wrong in the sense that
a tunnel over another tunnel would fail — it would work, slowly — but it is not
a *considered* decision, and the asymmetry is the evidence that it wasn't one.

**A private address is not a name.** `10.0.3.1` is the lxc bridge default and
`192.168.122.1` the libvirt one; every Linux host with those packages installed
has the same two. A member that announces them is telling every other member to
send disco to an address that, at the receiver, resolves to the receiver's own
bridge. This is the same defect `gossip.Endpoint.StaticValidate` already refuses
loopback for — "a peer is by construction not on this host" — one step out: an
address the announcer genuinely holds that means something else at the far end.
The consequence today is noise. The consequence worth writing down is that it
gives any member a way to make every other member emit UDP to a chosen RFC1918
address inside its own LAN, on a chosen port. It is a thin primitive — members
only, disco payloads only — but it is one the threat model does not currently
mention, and the fix is not another `StaticValidate` rule, because the sending
node cannot tell an ambiguous address from a useful one by looking at it.

Neither is fixed here. Both are inputs to the M3b decision about which local
addresses are worth announcing at all once disco supplies reflexive ones: the
answer may well be to prefer reflexive addresses and demote the interface scan
to a same-segment fallback, at which point the ambiguity stops mattering because
the addresses stop being load-bearing.

## Time to first packet: 10 s → 7 ms

Measured while building the mesh test, and worth recording because the cause is
structural rather than a bug in our code.

A WireGuard handshake to a peer magicsock has no verified path to is dropped —
`Failed to send handshake initiation: no UDP or DERP addr`. Disco then
establishes the path in about a millisecond, but WireGuard has already armed
its own five-second retry, and the *response* is dropped the same way on the
other side for the same reason. A LAN mesh therefore took **ten seconds** to
pass its first packet.

Tailscale does not hit this because a DERP home relay is always an immediately
available path and the direct one is an upgrade. A juist network at M2 has no
relays at all, so the direct path is the only path and it has to exist *before*
it is needed.

`conn.warmPaths` starts discovery towards a peer as soon as it appears, on a
short front-loaded schedule (0, 250 ms, 1 s, 3 s). The repetition is not
belt-and-braces: two nodes meeting for the first time install each other a
moment apart, and a disco ping arriving at a peer that has not been told about
us yet is discarded — and since a node only adopts a path on receiving a
*pong*, the side that pinged early gets nothing out of it. With the schedule,
the five-node mesh passes its first packet in ~7 ms.

This stays worth doing once relays land: it is the difference between a new
peer being reachable directly and being reachable through someone else's uplink
for the first few seconds.

## Concurrency: one mutex over the trust layer

`log.Authority` is documented as not safe for concurrent use, and `daemon` is
where the concurrency is — every inbound gossip session runs on its own
goroutine and every one of them reads or informs the log. The authority and its
store sit behind one mutex, taken for the duration of each trust-layer call and
never held across a call into the data plane. What it hands back is a
`log.State`, which is immutable, so the reconciler works from the snapshot
after releasing.

The loop on top of that is about *when*, not about safety: a change from
gossip, from IPC or from a tick marks the daemon dirty, and one goroutine
reconciles and then pushes, so a burst of arriving records costs one reconcile
rather than one each.

## The local API

[04-architecture.md](04-architecture.md)'s rules, implemented in `daemon/ipc.go`:
a unix socket at mode 0600 inside a 0700 directory, never a TCP listener,
`SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on the BSDs, and a canonical-CBOR
request codec with its own limits and its own fuzz target.

Two commands: `status`, and `inform` (hand over records a quorum has already
signed). Neither is privileged in any interesting sense — the daemon holds no
admin keys and cannot make an unauthorized record apply, so the most a caller
can do is what any member could have done by gossiping the same records. When a
daemon is running, `juist apply` uses `inform` rather than writing under it: two
writers would leave the on-disk log and the daemon's in-memory authority
disagreeing about the head until a restart.

## What the M2 review rounds changed

**Round 5** — two ways a single actor holding one epoch secret could hurt
availability past what the design admits, and the split-brain the local-API
hardening did not actually close:

- **A second daemon on the same home silently stole the control socket.** The
  IPC listener unlinked any socket at its path before binding, on the reasoning
  that a live daemon would have made the bind fail. For a unix socket that is
  backwards: unlinking the path a running daemon listens on succeeds — it keeps
  its file descriptor and merely becomes unreachable by name — and the bind on
  the freed path then also succeeds. So a second `juistd` on one home took the
  socket, and the CLI talked to it while the original kept a revoked peer's
  tunnel up: two log authorities on one store, the exact split brain `apply`'s
  direct-write refusal exists to prevent, defeated a layer down. The daemon now
  holds an exclusive `flock` on a lock file in the home for its lifetime and
  refuses to start if another holds it; the kernel drops the lock if the process
  dies, so a crash leaves nothing stale.
- **A remembered peer epoch was taken from an unauthenticated field, and its map
  could not be reclaimed.** `notePeer` stored the frame's plaintext `Epoch`
  beacon — attacker-chosen and decoupled from the signed `Self` — so one crafted
  hello could pin a member's remembered epoch at `2^64-1`, and round 4's fill
  bound, having no eviction, let a flood of minted identities lock every real
  peer out of the map. Either one forces pushes to that peer under this node's
  own epoch, so the push carrying a revocation is unreadable to a member an
  epoch behind and convergence drops to the two-minute anti-entropy backstop —
  against a five-second budget. The value stored is now the session's
  *authenticated* seal epoch (an epoch the peer demonstrably held), and the map
  is gated by membership exactly as the announcement cache is: a member always
  displaces a minted non-member, a former member is refused.
- **A LAN announcement for a non-member drove mesh-wide churn and unbounded log
  growth.** Every accepted announcement woke a reconcile, an eight-way gossip
  round, and a log line — and the cache accepts any rising `Seq`, which is a
  *signed* field, so an epoch-secret holder minting identities and signing a new
  `Seq` for each could sustain that across the whole mesh from one host. A
  non-member's announcement is inert at reconcile, so it is now cached (the
  early-join contract still needs that) but no longer wakes the loop or logs;
  the record that admits a member is what wakes it. This keeps the keyring
  window's cost to "metadata and nothing else", as claimed above.
- Smaller: the endpoint validator was a denylist that admitted the limited
  broadcast address `255.255.255.255`, which an announcement could point the
  member set at as an amplifier — a positive `IsGlobalUnicast` check closes it.
  The disco-collision resolver read the endpoint cache twice, so an announcement
  arriving between the two reads could still drive the whole-set rejection the
  round-4 fix was removing; it now decides over one snapshot. `WriteSecret` wrote
  key material in place under `O_EXCL`, so an interrupted write left a truncated
  file that then blocked every retry; it writes a temp and renames, like the
  store. And a fork alarm left `Members`/`Conflicted` and the rest stale beside
  the alarm, reading as though part of the mesh survived it; all derived fields
  are cleared now.

**Round 4** — one regression the previous round introduced, and the fields an
attacker chooses:

- **A displaced push was dropped.** Round 3 moved anti-entropy rounds off the
  loop so a slow one could not delay a revocation, and made them single-flight.
  What it did not do was remember a round it turned away — so a revocation
  arriving while a round ran was reconciled locally and never relayed, which is
  precisely the epidemic property the move was protecting. A displaced round is
  deferred now and marks the daemon dirty when the running one ends.
- **The disco key is the one peer-chosen field in a peer entry**, and the
  connectivity layer keys NAT-traversal state by it, so two peers sharing one
  make each other's paths ambiguous — a member could copy another member's key
  and unplug it. It cannot read anything that way, since traffic stays sealed
  to the logged node key. Duplicates are refused now, and, just as important,
  refused *in the reconciler* rather than only in `SetPeers`: the data plane
  rejects a whole set containing a duplicate, so passing the announcement
  through would have turned one signed record into a kill switch for every
  member's tunnels. The colliders lose their entries, the mesh stays up, and
  `Conflicted` says so.
- **Announcements could name addresses their author does not own.** An
  announcement points the whole member set at an address — UDP from the data
  plane, TCP from the sync layer — so loopback aimed peers at services on their
  own hosts, and any address at all made the member set into a connection
  source pointed wherever the announcer liked. The accepted set is now exactly
  what a correct node announces about itself. A peer also gets one session's
  worth of time across all its addresses, so announcing sixteen unreachable
  ones no longer costs every member sixteen full timeouts a round.
- **A revoked device's announcements re-entered through gossip.** Round 3 made
  members refuse them on the LAN path only, while a peer relaying its cache in
  a session went straight to `Cache.Add`. One rule in one place now — a rule
  enforced on one of two entries is not enforced.
- **Frame and IPC bodies were allocated from the announced size**, before
  anything authenticated it, so sixteen sessions announcing the maximum and
  sending nothing held hundreds of megabytes. Buffers grow as the bytes arrive.
- **`peerEpoch` grew without bound.** An announcement is signed only by the key
  it names and identity keys cost nothing to mint, so anyone able to open a
  frame could add an entry per session indefinitely.
- Smaller: a malformed announcement at our own name wrote a log line, which any
  bystander could flood, and the rest of that parser drops silently by design;
  `admins/` was not checked for a shared-writable mode, though it is where the
  signing keys are and losing them below quorum is unrecoverable by design; and
  a failed reconfiguration skipped path warm-up permanently, since the next
  reconcile sees nothing new.

**Round 3** — what the first two rounds' fixes left one layer short of, plus
the first findings about what a hostile *LAN* can do rather than a hostile
peer:

- **Discovery answered every question it was asked.** The blinded name is
  public on the wire — every announcement carries it — so anyone on the LAN can
  replay a query at it without holding any secret, and DNS name compression
  fits a couple of hundred copies into one datagram. Each copy cost every
  member a multicast answer: roughly a hundredfold amplification aimed at the
  whole segment for the price of one small packet. A member now transmits under
  a name at most once a second (RFC 6762 §6's floor, which turns out to carry
  security weight and not only etiquette), and names are derived once per epoch
  rather than once per received datagram.
- **The multicast interface set was frozen at startup.** Interfaces that
  appeared later — Wi-Fi associating, a cable plugged in — never joined the
  group and never carried a beacon, while the daemon's own announcements
  advertised their addresses. The join is refreshed on a slow cadence now. The
  per-interface send loop was also unsynchronized, and the multicast egress
  interface is per-socket state, so an answer and an announcement racing each
  other left on the wrong interface.
- **A removed device stayed loud on the LAN.** Round 2 took its tunnels down
  and stopped it gossiping, but its beacon kept announcing every two seconds
  under a name its old epoch secret still computes. Members oscillated on it —
  cache, log, reconcile, forget, repeat — a reconcile and a push round each,
  per member, per interval. A device that knows it was removed now makes no
  announcement at all, and members refuse announcements from a subject they
  have seen the log drop.
- **The announcement cache could be crowded out.** An announcement needs only a
  signature by the key it names, and identity keys cost nothing to mint, so any
  holder of an epoch secret could fill the cache with records for invented
  nodes and leave no room for a genuinely joining member. Membership now
  decides eviction and relay order — never entry, so early announcements still
  work.
- **The reconcile loop blocked on the network.** `pushAll` waited for every
  session, each address of an unreachable peer costing a full timeout, and
  while it waited the loop did not service `dirty` — so a revocation arriving
  mid-round kept its WireGuard entry until the round finished, well past the
  five-second budget. Rounds run beside the loop now. `Reconcile` also gained a
  mutex: `Inform` runs one on the IPC goroutine, and two interleaved reconciles
  could install their peer sets in the opposite order to their state reads.
- **A restart threw the keyring away.** `adoptEpoch` opens only the current
  epoch, so a restarted daemon held exactly one secret — unable to open a
  behind peer's frames or seal one it could read, which in a two-node network
  is a partition nothing heals. Past epochs are recovered from log history at
  startup.
- **Gossip could sync with itself.** Announced addresses are not unique to
  their announcer: a bridge address like `172.17.0.1` is identical on every
  host that has one, so dialling a peer there reaches the local listener. The
  session "succeeded", and since a peer's address list stops at the first
  address that completes, the real peer was never synced with — permanently.
- **`juist sign` destroyed records on unenrolled devices.** A device with node
  keys and no network gave every key the benefit of the doubt, so an operator
  signing their own enrollment record added a signature the network does not
  trust for it — which does not merely fail to count but invalidates the record
  outright, ruining the admins' finished ceremony. Only admin keys get that
  benefit now; a node key's one role is decided by the record alone.
- **A rotation applied elsewhere never promoted.** Promotion lived only in
  `juist apply`, but the tool tells whoever adds the last signature to apply it
  — normally an admin. The record then reached the device over gossip with no
  CLI involved, leaving it holding old keys while the log named new ones, and
  the daemon's "restart juistd" advice could not fix what nothing promoted.
  Opening the state directory promotes, which makes that advice true.
- **Opening a store deleted other processes' writes in flight.** Every command
  opens the store, including read-only ones, and the open swept staged files
  unconditionally — so `juist log` could delete a file a running daemon was
  between `writeSync` and `rename` on, and because `Inform` is atomic, that
  rejected the whole batch. Opening tolerates them; the writer sweeps.
- **`apply` treated a silent daemon as an absent one.** Any probe failure meant
  "no daemon", so a daemon whose IPC slots were all held sent `apply` down the
  direct-write branch — exactly the split brain the branch exists to prevent.
  Only "no socket" and "nobody listening" mean absence now.
- Key files and the staged-key promotion did not fsync their directory, so a
  power cut could leave a durable log naming keys that rolled back.

**Round 2**, mostly conditions one layer knew about and the next did not:

- **Sync died across compaction.** `Missing` offered everything from its own
  roots, so after any compaction asymmetry the batch always contained a record
  the peer's log refuses, and Inform's atomicity turned that into "these two
  nodes never exchange anything again". Hellos now carry the sender's anchor
  and the walk starts there — which is also cheaper, since a session now reads
  only the records it sends instead of the whole store.
- **A device's own removal left its data plane up.** The reconciler skipped
  self by identity, so a removed self kept tunnels to everyone and kept
  dialling them every round. Peers refuse it either way — that was never the
  security boundary — but a device that knows it was removed and keeps probing
  its former peers is indistinguishable from an attack. It now tears down,
  goes quiet, and says so in its status.
- **A key rotation applied while the daemon ran failed silently.** The log
  names the new keys, peers move immediately, and this process still holds the
  old ones — every symptom looks like a network problem. The daemon now
  compares the log's keys for itself against its own on every reconcile and
  reports `StaleKeys` with a restart instruction.
- `takeEndpoints`' comment claimed a bad announcement ends the session; the
  code drops it and continues, which is right — relays forward from caches,
  and integrity never rested on the transport. The comment now matches.
- `conn.NewDiscoKey`'s comment promised a `TestDiscoKeyAgrees` that did not
  exist. It does now, pinning that the announced public half equals the one
  the connectivity stack derives.

**Round 1** — same shape, a rule enforced in one layer and not the ones next
to it:

Five findings, all of them the same shape: a rule enforced in one layer and
not in the ones next to it.

- **An announcement was dropped before its record arrived.** `gossip.Cache`
  documents that early announcements must be kept — discovery routinely finds
  a joining node before gossip delivers the record admitting it — and the
  reconciler dropped every announcement whose subject the log did not carry,
  which is the same thing. Now it drops only subjects it has *seen* the log
  carry and no longer does, which is the revoked case the hygiene was for.
- **An expired membership lost the data plane and kept the sync layer.** The
  expiry backstop denied a peer entry but left the device in the gossip set
  and its address in the cache, so it was still being handed the member set
  and every member's address. Expiry now means the same thing everywhere.
- **A key rotation applied through a running daemon never promoted.** `juist
  apply` hands records to the daemon over IPC, and the staged-key promotion
  went with the branch that writes the log itself — leaving a device holding
  old keys while the log named new ones, unable to handshake and unable to
  open the group secret.
- **Push was a broadcast.** One change reached every member directly, so the
  network paid O(n²) sessions per change. Now it is epidemic with a fan-out of
  eight, which is above the milestone's scale and so changes nothing measured
  here, and turns into O(log n) rounds at the sizes
  [01-requirements.md](01-requirements.md) targets. `Node.Sync` gained a
  concurrency bound for the same reason.
- **Discovery queried unconditionally.** Every query is answered by every
  member, so asking on a timer is quadratic too. A node now asks only while it
  is missing someone; announcements, which are linear, keep a settled network
  in step.

## What M2 did not build

- **Gossip inside the tunnel.** M3a at the earliest: it needs a device that
  carries traffic, which is exactly what M3a adds.
- **Relays, DHT cold start, real NAT traversal.** M3b, as planned.
- **Endpoint-record persistence.** The cache is in memory, so a restarted node
  rediscovers its peers from the LAN. The persistent cache is a cold-start
  feature and belongs with the DHT work that needs it.
- **Freshness leases and the startup gate.** M4. Until they exist, a node with
  a stale log fails closed only in the sense that it has no peers it has not
  been told about — there is no TTL yet.
- **The per-pair ML-KEM PSK.** Still the open decision in
  [07-embedding-notes.md](07-embedding-notes.md), due before the M3 freeze.
  M2's "PSK/epoch rotation" is the epoch half: every membership change rotates
  the group secret, and the daemon follows it.

## Verification

- `daemon/mesh_test.go` is the exit criteria, against real logs, real HPKE
  wraps, real gossip over TCP and the real embedded data plane. The one
  substitution is the multicast group, replaced by a loopback fan-out that
  carries the same DNS-SD packets: a CI machine has no LAN segment and Linux
  loopback carries no multicast, so the alternative is a test that skips.
- `daemon/reconcile_test.go` covers what the reconciler decides — default-deny,
  expiry, the fail-closed fork alarm — against a recording data plane, where
  the assertions can be exact.
- Fuzz targets added this milestone, per
  [06-verification.md](06-verification.md) §2: `FuzzDecodeFrame`,
  `FuzzDecodeEndpoint`, `FuzzOpenFrame` (gossip frame parser) and
  `FuzzDecodeIPCRequest`, `FuzzDecodeIPCResponse` (IPC request decoder). Each
  asserts injectivity, not just the absence of crashes.
- Measured at five nodes on one host: full mesh in ~140 ms, revocation
  converged across the remaining four in ~80 ms against a five-second budget,
  a new member joined a running mesh in ~20 ms.
- Run by hand with the real binaries, which is where the multicast-socket bug
  above turned up: `juist init`, enroll a second device, start a `juistd` on
  each, and `juist status` on both reports a peer discovered on the LAN with
  nothing configured about where anyone is.
