# 10 — Connectivity layer notes

What M3b decided, in the same spirit as
[08-trust-layer-notes.md](08-trust-layer-notes.md) and
[09-mesh-layer-notes.md](09-mesh-layer-notes.md): the choices a reader of the
code would otherwise have to reverse-engineer.

M3b is everything that makes the overlay work off the local segment —
NAT traversal, member-run relays, rendezvous through the public DHT, a
persistent endpoint cache — plus the record-schema freeze, which is
[08-trust-layer-notes.md](08-trust-layer-notes.md)'s.

## A relay is two halves, from two places

Quorum grants `relay-capable` in the log. Where the relay listens, and the hash
that authenticates its certificate, is the member's own signed announcement.
Neither half alone produces a relay: a member cannot volunteer itself as
everyone's, and a grant cannot point the mesh at an address nobody stated.

That split is why M3b needed **no new log record**. The role existed from M1,
and where a relay is has the lifetime of a process rather than of a membership
— the same argument that keeps the disco key out of the log
([09-mesh-layer-notes.md](09-mesh-layer-notes.md)).

**The certificate is pinned, not signed by anyone.** A member-run relay has no
certificate authority to ask and should not have one. It draws a self-signed
certificate once per set of device keys, keeps it in the state directory, and
announces its SHA-256; members put that in the DERP
map's `CertName` as `sha256-raw:…`, which makes the TLS check an exact-hash
comparison. The name in the certificate is derived from its own key under
`.invalid`, and is never resolved: a member dials the addresses in the
announcement, and both address families are stated explicitly so that an unused
one is not looked up in DNS.

**Membership is checked through an upstream hook, in this process.** The DERP
server offers two ways to admit clients and both assume a coordination server:
a query to a local `tailscaled`, and an HTTP admission controller. There is no
in-process callback. So the relay registers a scheme on the default HTTP
transport and answers the admission request itself — no socket is opened,
nothing listens, and a local user cannot turn the check into an oracle for who
is a member.

The hazard that carries is an upgrade one and it is silent: if the DERP server
ever stops consulting the hook, every non-member is admitted and nothing looks
wrong. `TestNonMemberCannotUseTheRelay` drives a real DERP client for exactly
that reason, and must keep doing so.

**Admission runs once per connection, so removal needs its own path.** A device
revoked while connected would keep relaying through the session it already
holds until it chose to reconnect. `Server.Reauthorize`, called on every
reconcile, closes those. The record it needs lives for as long as the HTTP
handler runs, which for a DERP session is the session — the admission
request's own context is cancelled as soon as it has an answer, and using that
would have deregistered every client the instant it was admitted.

**A relay reflects as well as relaying.** It answers STUN binding requests on
the same port number, over UDP, which is how a member learns its own reflexive
address without a public STUN server —
[04-architecture.md](04-architecture.md)'s "member disco reflection is
primary". It cannot be membership-authenticated, because a binding request
carries no identity; what it discloses is the querier's own address, back to
the querier, and it is rate-limited so that a two-times amplifier is not worth
using, per host as well as in all, so that one host's flood does not starve
everyone's netcheck.

**Public STUN servers stand in where no member relays** (added in M4). Two
devices behind NAT with no relay-capable member learned no reflexive address
at all, so each announced only its LAN addresses and they never met. juistd now
also asks public STUN servers (`--stun`, Google's and Cloudflare's by default,
`--no-stun` for none). They enter the data plane's map as STUN-only regions at
the top of the region space, below which member relays derive theirs, with a
home score that keeps any member relay preferred. Netcheck picks a home among
every region it measured, so with no member relay a STUN server becomes the
engine's home: the engine then retries a relay connection that fails before
sending anything, which juist leaves alone and keeps out of the log, and
`onNetInfo` tells peers of no home rather than a region with nothing to reach.
`SetHomeless` would have avoided the retries and also stopped the periodic STUN
that keeps the public address current.

## Relay regions are derived, not assigned

A peer announces the relay region it can be reached through, and member relays
are not meshed, so a packet sent to any other region reaches nothing. Every
member therefore has to compute the same number for the same relay without
agreeing on anything.

A sorted index over the relay-capable set never collides but **renumbers**
whenever that set changes, and two members a reconcile apart would then read
one announcement as two different relays. The number is a keyed derivation of
the network and the relay's identity instead, so it moves with nobody.

It is 16 bits wide because the data plane truncates a peer's home region to 16
bits. Collisions are therefore possible — at ten relays, under a thousandth —
and the lower identity keeps the region while the other simply does not relay.
Both members compute the same answer, which is what matters.

## The DHT could not use the topic M1 derived

[04-architecture.md](04-architecture.md) says "blinded rotating topics", and
`trust/secrets` duly derived a 20-byte topic ID. Nothing could have used it:
BEP 44 does not let a publisher choose where an item lands. A mutable item's
address is `SHA1(public key ‖ salt)`, so what a network gets to blind is the
key. The derivation now returns an Ed25519 seed.

**Per member, not per network.** One keypair with per-member salts would have
worked and would have been cheaper. It is wrong: the public key travels in the
clear with every item, so a storage node holding two of a network's items would
link them — and then count the members. A key per member per window leaves two
items of one network looking exactly like two items of two networks.

**Publish under one epoch, look under all of them.** Both sides must derive the
same address, so a member and a peer an epoch apart would miss each other. Each
node publishes under its newest epoch and looks under every epoch in its
keyring: whichever of the two is behind is the one that finds the other, and one
direction is enough, because everything after rendezvous is bidirectional.

**Queries are the leak, not the items.** A storage node sees each query name one
opaque address, so no query says who is being looked for — but a node that
asked after all of its missing peers at once would turn that into a count.
Lookups are capped per round, shuffled, and only for members this node holds no
address for. Recorded as residual weakness 5 in
[02-threat-model.md](02-threat-model.md), together with the fact that running
the DHT at all says this host speaks the BitTorrent DHT. `juistd --no-dht` is
the answer for a deployment that would rather not, at the cost of off-LAN cold
start.

**One library detail worth keeping.** `anacrolix/dht`'s default send limiter is
a package global. Two servers in one process share a budget sized for a torrent
client, and one node's burst costs the other its replies — which is
indistinguishable from a DHT that does not answer. Each node gets its own.

## Endpoints: the scan, the reflexive addresses, and the cache

M2 announced what an interface scan found
([09-mesh-layer-notes.md](09-mesh-layer-notes.md)). M3b adds what the data
plane learns — reflexive addresses, once there is a relay to learn them from —
and **adds** rather than substitutes. The scan is what makes a LAN with no
internet work at all; a reflexive address is what makes an off-LAN peer
reachable. Neither is a superset of the other.

The two weaknesses 09 recorded in the scan are still there: a private address
is not a name, and the foreign-overlay filter is split by address family. They
matter less than they did, because a reflexive address is now available where
one can be had, but neither is fixed and both remain inputs to whatever decides
which local addresses are worth announcing at all.

**The endpoint cache is written by this node and trusted by it no more than a
frame from a peer.** Every record is verified on the way in, so editing the
file drops a record rather than redirecting a peer entry. Only members are
persisted: a subject the log does not carry is an announcement this node was
handed and has not acted on, and persisting those would let anyone holding an
epoch secret grow the file without bound.

## Gossip reaches through the tunnel now

M2's anti-entropy dialled only the addresses a peer announced, which are
underlay addresses. Two members behind NAT can open no TCP session to each
other there, so they synced only through whichever member both could reach — a
partition that gossip's epidemic push papers over rather than solves.

With a TUN device gossip now runs through the tunnel alone: it listens on
the overlay addresses and dials only a peer's, so a device needs no port for
it from outside. Without one it listens and dials on the underlay, overlay
addresses last, as before. What a tunnel cannot bring up must then come some
other way: a new member's announcement travels with its join, a restarted
one's through the DHT or LAN discovery.

**Finding a peer again.** Because a tunnel cannot carry the announcement that
would bring it back up, how fast the DHT is asked decides how long a pair
stays cut off. The rules:

- A mesh restarted in the same process on the same keys announces the same
  disco key and relay certificate (`daemon.Session`), so peers reach it on the
  announcement they hold. New keys draw new ones: a rotation answers a device
  that may have been copied. The relay certificate is also kept on disk,
  bound to the device keys (`relay-cert.pem`), so a restarted process keeps
  the hash members pinned. A member that is stale has no tunnel to most
  relays, so it never finds them down, and learns a new hash only from its
  next DHT lookup; with the hash kept, there is none to learn. The disco key
  is not written, since a peer that is down is looked up anyway.
- A stale member looks up every member it holds an announcement for but
  keeps no tunnel to, on the schedule of a peer found down: those
  announcements carry the relays it still uses.
- A peer whose probes go unanswered twice in a row is down unless it
  completed a handshake in the last check interval; the 180 s a handshake
  stays fresh stands in only for a probe not sent or one lost, since a peer
  that restarted leaves the last one looking fresh for minutes.
- A peer found down is looked up at once, again after 30 s, then at doubling
  gaps up to an hour, counted from when each was due. Members never heard
  from share that schedule, and a round takes the four due longest, so none
  starves another. A round brought forward waits 15 s after the last one and
  puts this node's own announcement again only if it says something new; a
  round on the interval always puts it, freshly signed; a changed one brings
  a round forward at once.
- A new announcement for an installed peer is probed at once, past the probe
  backoff, and a tunnel back up is synced at once.
- A peer that answered is probed again only after 5 minutes where both ends
  have a home relay, its answer standing meanwhile: a probe keeps magicsock
  pinging the peer every 3 s for 45 s, so probing every check never lets a
  tunnel go quiet. A relay brings it back by CallMeMaybe; without one, every
  check probes, since that is what keeps the NAT mappings open.
- A running device signs its announcement again every 5 minutes, and for
  each DHT publication, though nothing in it changed. The sequence number is
  the signer's clock, so a signature made after a peer's tunnel went down is
  the one sign that the peer runs: finding the old record again proves
  nothing, since it stays in the DHT and the cache long after its author went
  quiet. A renewal that says nothing new is kept but not acted on: no
  reconcile, no push, and the endpoint cache is rewritten for it hourly.
- The status blames the way to a peer — a blocked UDP port, a missing relay —
  only where it has changed its announcement since it went down, or signed
  it more than two minutes after, allowing for a clock ahead of this one's.
  Without that it says the peer is offline once a renewal could have come
  (a DHT interval, a lookup gap, the clock skew both ways; less with no
  DHT), and at once where this device's relay holds the peer's home region
  and finds it disconnected; until then it says it does not know which. A
  device never seen renewing may be on a build that does not, so the window
  alone never calls it offline. A failed sync
  through a live tunnel is reported only once a retry through it failed too.

**Open: a relayed pair whose home relay moves.** The home region now follows
netcheck, and a peer reached only through a relay learns the new region from
the announcement, which gossip carries through the very tunnel the old region
no longer serves. Until the DHT or LAN discovery brings it, the pair is cut
off. A test with two relays and a pair that punches through neither is what
would show whether this needs the announcement sent over the relay as well.

## The hand-sealed CallMeMaybe, and why the announcement is what primes it

[07-embedding-notes.md](07-embedding-notes.md) records tailcat's technique for
distributing endpoints where a control plane would: seal a `disco.CallMeMaybe`
by hand and ship it as a DERP packet, so the peer's stock magicsock processes
it natively. M3b does not do this, and the reason is worth stating precisely,
because the NAT matrix found the version of it that is wrong.

With a DERP map installed, **magicsock does send `CallMeMaybe` over DERP
itself** — but only after it has pinged something.
`endpoint.sendDiscoPingsLocked` enqueues one when `sentAny`, and `sentAny` is
false for a peer it holds no candidate address for. So a peer given nothing at
all is a peer magicsock never asks to punch back, and two nodes behind NAT with
no hint about each other stay on the relay for ever. Tailscale never meets this
because its control plane always supplies peer endpoints.

What supplies them here is the **signed announcement**: a member's own
statement of where it is, now including the reflexive address the relay's STUN
responder told it, delivered by gossip, LAN discovery or the DHT. One address
each is enough — everything after the first disco ping is magicsock's. The NAT
matrix models exactly that: the nodes start knowing nothing, learn their own
reflexive addresses, and are then told each other's, which is the sequence a
daemon's reconciler performs.

The hand-sealed frame would be needed only where there is no announcement path
at all, which is tailcat's position and not ours. `SendDERPPacketTo` and
`OnDERPRecv` therefore stay unused. They remain the right shape for an
authenticated sideband over a relay, and the case that would want one is a
member reachable *only* through a relay needing something other than WireGuard
traffic carried — which today is nothing, since gossip reaches through the
tunnel.

## The NAT matrix is translated, not simulated

`conn/netnsnat_linux_test.go` puts a router namespace in front of each node and
has Linux netfilter do the translation. An approximation would have tested the
approximation.

- The cone kinds pin the external port to the internal one, which is what makes
  the mapping endpoint-independent; they differ only in what unsolicited
  traffic they admit, which is a filtering rule.
- Symmetric masquerades with `--random-fully`, so the kernel picks a fresh
  external port per destination.
- Double NAT is a port-restricted NAT behind a second one, with the carrier
  segment in 100.64/10 — the range carriers actually use, and the overlay's
  own v4 range before schema 4. A juist node never holds an address there,
  because it is behind the inner NAT, but it is worth knowing that
  `daemon.usableUnderlay` refuses to announce a 100.64/10 address: a node addressed there directly would have
  nothing but reflexive addresses to offer.

**Whether a path ended up direct is asked by stopping the relay.** A pair that
keeps reaching each other was never relying on it; a pair that stops was. Every
other way of asking depends on the layer under test to report on itself.

**The lab classifies its own NATs before testing anything.** Two reflector
addresses on one relay and one socket, exactly as a STUN client would: one
mapped port means endpoint-independent, two mean symmetric. A rule that did not
do what its name says would otherwise make a cell pass for the wrong reason.

**"symmetric × easy" is symmetric against full-cone**, not against
port-restricted. Port-restricted filtering rejects the symmetric side's packet
for coming from a port it has not sent to, which leaves only port prediction —
and a criterion should not be a probabilistic one.

## What M3b did not build

- **A DHT node identifier that rotates.** A storage node answering several of
  this node's queries sees one identifier behind all of them. The queries
  already say nothing about who is being looked for, and rotating the
  identifier costs a bootstrap each time; worth revisiting if the query
  pattern ever becomes load-bearing.
- **Relay capacity, or any check that a relay can be reached.** A relay accepts
  every member. There is no rate limit per client, no accounting, and no way for
  a member to say "not through me right now" short of `--no-relay`. Nor does
  anything test that a relay-capable member is reachable at all: a member behind
  NAT that is granted the role advertises its relay at each address it
  announces, including reflexive ones, where the relay's TCP port is not
  mapped — so those entries are dialled and fail. A relay is expected to be a
  member with a public address, and nothing but the grant says so.
- **More than two relays' worth of thought about selection.** The data plane
  picks a home region by latency, and that is all the policy there is.
  [04-architecture.md](04-architecture.md)'s warn-at-fewer-than-two floor is
  reported by `juist status` and the daemon's banner, counting the *grant*
  rather than the relays installed — a grant with no announcement behind it is
  a relay nobody can reach, and an operator has to be able to tell those apart.
  It stays a floor and not a capacity model: relay demand tracks the number of
  pairs that cannot be punched, which nothing here measures.
- **IPv6 on the lab's underlay.** The NAT matrix is IPv4, because NAT is. A v6
  network needs no traversal and no relay, and the code paths it would take are
  the ones M3a already covers.
