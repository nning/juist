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

- A **keyring** (`keyring.Keyring`) retains the last `keyring.Depth` = 4 epoch
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
window completely. It is not bounded in *time*: freshness leases bound how long
a partitioned node carries a revoked peer's tunnel, not how long a keyring
accepts an old epoch.

The same window applies to discovery, for the same reason and with the same
cost.

**Past the window, catching up by identity.** A member further behind than the
keyring holds no epoch its peers speak, so no frame of its opens anywhere. It
asks for a catch-up instead:

```
initiator → ask        in the clear, under the reserved epoch label 0
responder → challenge  a fresh nonce
initiator → proof      its identity, and a signature over network ‖ nonce
responder → grant      a session key sealed to the recipient keys its log
                       names, signed — or a signed refusal naming its epoch
```

and the four frames above follow under the granted key, with the records
frames in the other order. The rules it keeps:

- The responder verifies the proof before it looks at the log, so one that
  does not verify learns nothing, not even whether the identity is listed.
- Only a responder that is itself a member and under no alarm answers, and it
  checks the initiator is still listed before it sends records: the grant is
  where the log was, and the initiator sets the pace.
- The initiator is the one that cannot check the other side yet — a grantor
  may be a member under an identity its log has not caught up with — so its
  hello names nothing but what it holds, and its records, announcements and
  leases go out only after the grantor's records have made its log list the
  grantor. Anyone holding the recipient keys the log names can seal a grant,
  which is every former member; without this rule each could harvest a
  sleeper by hanging up on its hellos. What it cannot tell apart is a device removed
  while it slept, which lists itself by feeding a prefix of the log that stops
  before its removal: that is the stale view it already holds, bounded as an
  ordinary session with that device would be.
- A refusal counts only signed by a member the initiator's log lists and past
  the initiator's epoch. Status reads a counted one as the device's removal.
- An ask stays on the budget for connections that have said nothing until it
  is granted.
- A node that applies several epochs at once backfills the ones it skipped, so
  its keyring holds the newest four rather than the ones it held before.

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
keyring**, and queries as well as announces each time. The gap doubles from
2 s to a minute while nothing changes, since every member's radio receives
every datagram, and starts over when the announcement, the epoch or the
interface set changes; a node arriving queries at once. Announcing alone
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

**The per-node rate limit is not an aggregate one.** Each member queries as well
as announces at each gap, and a query is answered by every member holding
that name, so traffic on one segment is O(n²) datagrams per interval — bounded
per sender, unbounded in total. At 25–100 devices, and rarely all on one
segment, that is noise. It stops being noise well before `MaxNodes`, and the fix
is a suppression rule rather than a schema change (RFC 6762 §7.1: withhold an
answer already seen from another responder in the same interval), so it can wait
for a deployment that needs it — unlike the record-size question in
[08-trust-layer-notes.md](08-trust-layer-notes.md), which cannot.

## Endpoints come from an interface scan

magicsock reports no endpoints of its own without a STUN result or a DERP map,
and an M2 network has neither. Of the two options 07 offered, the interface scan
is the one needing no third party, which is what "LAN-only with zero internet"
requires. Reflexive addresses from disco and member relays are *added* to that
set at M3b, never substituted for it.

## What that interface scan actually announces on a real host

A node on a machine with lxc, libvirt and Tailscale once announced
`10.0.3.1`, `10.11.1.140`, `192.168.122.1`, a ULA and Tailscale's
`fd7a:115c:a1e0::/48` address, of which only the WLAN address could carry a
packet from another machine. `internal/underlay` now leaves out interfaces that
lead only into this host — juist's own tunnel, other VPNs', and the bridges and
veth pairs of container and VM runtimes, recognised by name — and Tailscale's
ULA on any interface. Invite links, DHT rendezvous candidates and announcements
all read addresses through it, and the addresses magicsock reports pass the
same filter, since magicsock leaves out only Tailscale's ranges and would
otherwise announce this network's overlay.

**A private address is still not a name.** Recognition by name misses a bridge
named by its owner. Its address, such as lxc's default `10.0.3.1`, exists on
many hosts, and announcing it tells every member to send disco to an address
that resolves to the receiver's own bridge. That gives any member a way to make
every other member emit UDP to a chosen RFC1918 address inside its own LAN, on
a chosen port: members only, disco payloads only, and not in the threat model.
The sender cannot tell an ambiguous address from a useful one by looking at it,
so this is not a `StaticValidate` rule. It stays an input to deciding which
local addresses are worth announcing at all: preferring reflexive addresses and
demoting the scan to a same-segment fallback would stop them being
load-bearing.

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

[04-architecture.md](04-architecture.md)'s rules, served in `daemon/ipc.go` over the codec in `ipc/`:
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

## What M2 did not build

Gossip inside the tunnel, relays, DHT cold start, real NAT traversal and
endpoint-record persistence all arrived at M3b; see
[10-connectivity-notes.md](10-connectivity-notes.md). What is still open:

- **The per-pair ML-KEM PSK.** M15; see [05-roadmap.md](05-roadmap.md). M2's
  "PSK/epoch rotation" is the epoch half of it, and remains all of it until
  then: every membership change rotates the group secret, and the daemon
  follows it.

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
  above turned up: `juist create`, enroll a second device, start a `juistd` on
  each, and `juist status` on both reports a peer discovered on the LAN with
  nothing configured about where anyone is.
