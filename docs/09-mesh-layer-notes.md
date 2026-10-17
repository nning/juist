# 09 — Mesh layer notes

The reconciler, gossip, blinded LAN discovery and the daemon that holds them
together: the choices a reader of the code would otherwise have to
reverse-engineer, in the spirit of
[08-trust-layer-notes.md](08-trust-layer-notes.md).

## The disco key is not in the log

A node's NAT-traversal key lives as long as its process. The connectivity layer
reads a changed disco key as "that peer restarted" and resets its WireGuard
session (`conn.peerDelta`); in the log it would need a k-of-n ceremony per
reboot.

It travels in a **signed endpoint record** (`gossip.Endpoint`) with the node's
underlay addresses and gossip port, signed by the node's own key alone: a node
may say where it is, and no node may say anything about another. A lie costs
connectivity and nothing more, since the reconciler reads the member set from
the log and joins announcements onto it, dropping any whose subject the log
does not carry.

**A member with no announcement gets no peer entry.** That is "not heard from
yet", not denial, and the status reports the two apart.

## Gossip sessions

Records are self-certifying, so the transport is untrusted by construction.
Gossip runs through the tunnel where the node has a device or a netstack, and
on the underlay otherwise ([10-connectivity-notes.md](10-connectivity-notes.md));
every frame is sealed under the epoch group secret, which covers the metadata
the underlay would show.

One TCP session per round, four frames, strictly alternating:

```
initiator → hello    what network, where my chain is, what I hold
responder → hello    the same, answered
initiator → records  what the responder turned out to be missing
responder → records  what the initiator turned out to be missing
```

Symmetric, because one round making both sides whole halves the rounds a
revocation needs to cross the mesh.

- **"What I hold" is every record the sender resolves from its anchor,**
  sent outright rather than walked back to a common ancestor, which keeps the
  exchange stateless. Past `MaxHashesPerFrame` the list is cut short with the
  records nothing hangs from first, and only from a cut-short list does the
  receiver take the sender to hold the ancestors of what it lists.
- **Each side answers from the peer's anchor,** its genesis or the checkpoint
  it compacted to, not from its own. A record below the receiver's anchor is
  one its log refuses, and `Inform` is atomic, so one refused record would
  poison the whole batch.
- **Compaction leaves no peer behind.** A device compacts to the checkpoint
  one behind the newest only once every live member's head is past the newest,
  or a member has compacted that far, and keeps the chain from its previous
  anchor up to the new one, so a peer anchored there is still answered from
  its own anchor. A peer anchored where this node holds nothing is answered
  from this node's anchor, which it takes where it holds that checkpoint's
  parent.

## Epoch skew, and the keyring

The node that authors a change is one epoch ahead of everyone else until it
converges. If it could only speak its own epoch, the push carrying a
revocation would be unreadable to exactly the members that have not applied
it.

- A **keyring** (`keyring.Keyring`) keeps the last `keyring.Depth` = 4 epoch
  secrets, so a node still opens a frame from a peer that is behind.
- The initiator seals under **the recipient's last-known epoch** where it
  still holds that secret, and the responder answers under the epoch the
  request came in on, so a session runs at one epoch both sides read.

**The trade.** A revoked device holds an epoch secret too, and until the
network has moved four epochs past it, members still open its gossip frames
and answer its LAN queries. That costs metadata — the member set and where its
members are — and nothing else: it gets no WireGuard peer entry anywhere once
the removal converges, because peers come from the log. Every membership
change bumps the epoch, so four changes close the window; it is not bounded
in time. Discovery has the same window.

**Past the window, catching up by identity.** A member further behind than
the keyring holds no epoch its peers speak, so it asks for a catch-up:

```
initiator → ask        in the clear, under the reserved epoch label 0
responder → challenge  a fresh nonce
initiator → proof      its identity, and a signature over network ‖ nonce
responder → grant      a session key sealed to the recipient keys its log
                       names, signed — or a signed refusal naming its epoch
```

and the four frames follow under the granted key, the records frames in the
other order. The rules it keeps:

- The responder verifies the proof before it looks at the log, so one that
  does not verify learns nothing, not even whether the identity is listed.
- Only a responder that is itself a member and under no alarm answers, and it
  checks the initiator is still listed before it sends records.
- The initiator cannot check the grantor yet — it may be a member under an
  identity the initiator's log has not caught up with — so its hello names
  nothing but what it holds, and its records, announcements and leases go out
  only once the grantor's records make its log list the grantor. Every former
  member holds recipient keys the log names and can seal a grant; without this
  rule each could harvest a sleeper by hanging up on its hellos. What it cannot
  tell apart is a device removed while it slept, feeding a prefix of the log
  that stops before its removal: the stale view it already holds.
- A refusal counts only signed by a member the initiator's log lists and past
  the initiator's epoch. Status reads a counted one as the device's removal.
- An ask stays on the budget for silent connections until it is granted.
- A node that applies several epochs at once backfills the ones it skipped, so
  its keyring holds the newest four.

## Discovery: blinded, but not DNS-SD browsing

`discovery/mdns` sends ordinary mDNS on 224.0.0.251:5353: a TXT query at a
name derived from the epoch group secret (`secrets.Secret.MDNSName`), answered
with TXT records carrying a sealed `gossip.Endpoint`.

There is **no PTR browsing and no SRV or A record**: only a holder of the group
secret can construct the one name that means anything, and the sealed payload
carries the port. A LAN observer sees some host asking about an opaque label
under `_juist._udp.local` — enough to tell juist is in use, residual weakness 5
in [02-threat-model.md](02-threat-model.md) — but not which network or who,
though the hosts answering one label are one network's members on that LAN. A
revoked device stops computing the name (after the keyring window), and two
networks on one LAN are invisible to each other.

- **A beacon announces under its newest name and answers to every name in its
  keyring**; it queries while it misses a member, and once at start. Announcing
  alone would leave a member an epoch behind deaf to it; asking alone would make
  a node arriving wait for someone else's question.
- **The gap doubles** from 2 s to a minute while nothing changes, since every
  member's radio receives every datagram, and starts over when the
  announcement, the epoch or the interface set changes.
- **IPv4 only.** The IPv6 group (`ff02::fb`) needs per-interface join
  handling, not written yet.
- **One transmission per name per second** (RFC 6762 §6). The name travels in
  the clear, so anyone can replay a question at it, and name compression packs
  hundreds of copies into one datagram.
- **The interface set is not fixed.** Membership is per interface and
  refreshed on a timer, or an interface that appears after start never carries
  discovery.
- **The socket is not `net.ListenMulticastUDP`,** which binds to the group
  address, so what it sends carries a multicast source and the kernel drops it,
  silently in both directions. A wildcard bind with `SO_REUSEADDR` (5353 is
  shared with other responders), a `JoinGroup` per multicast-capable interface
  and a send per interface, so a multi-homed host announces on every LAN.
  `TestRealMulticastSocket` guards it; the other tests inject a socket.
- **The rate limit is per sender, not in total.** Every member answers each
  query, so a segment where members are missing carries O(n²) datagrams per
  interval. At 25–100 devices that is noise; past it the fix is RFC 6762 §7.1
  answer suppression, which needs no schema change.

## What the interface scan announces

magicsock reports no endpoints without a STUN result or a DERP map, so an
announcement starts from an interface scan
([07-embedding-notes.md](07-embedding-notes.md)). `internal/underlay` leaves out
interfaces that lead only into this host — juist's own tunnel, other VPNs', and
the bridges and veth pairs of container and VM runtimes, recognised by name —
and Tailscale's ULA on any interface; `daemon.usableUnderlay` leaves out the
overlay IPv4 ranges (198.18/15, 100.64/10), this network's ULA, loopback and
link-local. Invite links, DHT rendezvous candidates and announcements all read
addresses through it, and so do the addresses magicsock reports, since
magicsock leaves out only Tailscale's ranges.

**A private address is still not a name.** A bridge its owner named is not
recognised, and its address, such as lxc's default `10.0.3.1`, exists on many
hosts: announcing it has every member send disco to its own bridge. Any member
can so make the others emit UDP to a chosen RFC 1918 address and port in their
own LAN — members only, disco payloads only, outside the threat model. The
sender cannot tell an ambiguous address from a useful one, so this is no
`StaticValidate` rule; preferring reflexive addresses and demoting the scan to
a same-segment fallback would make such addresses stop mattering.

## Concurrency: one mutex over the trust layer

`log.Authority` is not safe for concurrent use, and every inbound gossip
session runs on its own goroutine. The authority and its store sit behind one
mutex (`authMu`), held for each trust-layer call and never across a call into
the data plane; the `log.State` it hands back is immutable, so the reconciler
works from that snapshot after releasing.

A change from gossip, IPC or a tick marks the daemon dirty, and one goroutine
reconciles and then pushes, so a burst of records costs one reconcile.

## The local API

[04-architecture.md](04-architecture.md)'s rules, served in `daemon/ipc.go`
over the codec in `ipc/`: a unix socket in a 0700 directory, never a TCP
listener, and a canonical-CBOR codec with its own limits and fuzz targets. The
socket is 0666 where the kernel names every caller (`SO_PEERCRED`,
`LOCAL_PEERCRED`) and each call is decided by the caller's tier (reader,
ingress, operator), and 0600 where it cannot. The daemon holds no admin keys,
so `inform` can apply nothing a member could not have gossiped. When a daemon
runs, `juist` hands it records through `inform` rather than writing the log
under it, which would leave the daemon's authority and the file disagreeing
about the head.

## Verification

- `daemon/mesh_test.go` runs real logs, HPKE wraps, gossip over TCP and the
  embedded data plane. The one substitution is the multicast group, replaced by
  a loopback fan-out carrying the same packets, since Linux loopback carries no
  multicast and the alternative is a test that skips.
- `daemon/reconcile_test.go` covers what the reconciler decides — default-deny,
  expiry, the fail-closed fork alarm — against a recording data plane.
- The parsers' fuzz targets, per [06-verification.md](06-verification.md) §2,
  assert injectivity, not just the absence of crashes.
