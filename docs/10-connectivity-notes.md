# 10 — Connectivity layer notes

What makes the overlay work off the local segment — NAT traversal,
member-run relays, rendezvous through the public DHT, a persistent endpoint
cache, HTTPS alone — and the choices a reader of the code would otherwise
have to reverse-engineer, in the spirit of
[08-trust-layer-notes.md](08-trust-layer-notes.md) and
[09-mesh-layer-notes.md](09-mesh-layer-notes.md).

## A relay is two halves, from two places

Quorum grants `relay-capable` in the log. Where the relay listens, and the
hash that authenticates its certificate, is the member's own signed
announcement. Neither half alone makes a relay: a member cannot volunteer
itself as everyone's, and a grant cannot point the mesh at an address nobody
stated. Where a relay is lives as long as a process, not a membership, the
same argument that keeps the disco key out of the log
([09-mesh-layer-notes.md](09-mesh-layer-notes.md)).

**The certificate is pinned, not signed by anyone.** A relay draws a
self-signed certificate once per set of device keys, keeps it in the state
directory (`relay-cert.pem`), and announces its SHA-256; members put that in
the DERP map's `CertName` as `sha256-raw:…`, which makes the TLS check an
exact-hash comparison. The name in it is derived from its key under
`.invalid` and never resolved: members dial the announced addresses, with both
families stated so that an unused one is not looked up in DNS.

**Membership is checked through an upstream hook, in this process.** The DERP
server admits clients through a local `tailscaled` or an HTTP admission
controller, and has no in-process callback. The relay registers a scheme on
the default HTTP transport and answers the admission request itself: no
socket, nothing listening, and no oracle for a local user. The hazard is
silent: if the DERP server ever stops consulting the hook, every non-member
is admitted. `TestNonMemberCannotUseTheRelay` drives a real DERP client for
that reason, and must keep doing so.

**Admission runs once per connection, so removal needs its own path.**
`Server.Reauthorize`, called on every reconcile, closes the sessions of
devices no longer members. The record it needs lives as long as the HTTP
handler, which for DERP is the session; the admission request's own context
is cancelled as soon as it is answered.

**A relay reflects as well as relaying.** It answers STUN binding requests on
the same port number over UDP, which is how a member learns its reflexive
address without a public STUN server. A binding request carries no identity,
so this cannot be membership-authenticated; it discloses the querier's own
address to the querier, and is rate-limited in all and per host, so that it
is no amplifier worth using and one host's flood does not starve everyone's
netcheck.

**Public STUN servers stand in where no member relays.** Without them two
devices behind NAT with no relay-capable member learn no reflexive address and
never meet. juistd asks public STUN servers (`--stun`, Google's and
Cloudflare's by default, `--no-stun` for none). They enter the data plane's map
as STUN-only regions at the top of the region space, with a home score that
keeps any member relay preferred. With no member relay a STUN server becomes
the engine's home: the engine then retries a relay connection that fails
before sending anything, which juist leaves alone and keeps out of the log,
and `onNetInfo` tells peers of no home. `SetHomeless` would end the retries
and also the periodic STUN that keeps the public address current.

## Relay regions are derived, not assigned

A peer announces the relay region it can be reached through, and member
relays are not meshed, so a packet sent to any other region reaches nothing;
a device that reaches some relays alone meets the others at its own home
([16-one-relay-on-443.md](16-one-relay-on-443.md)).
Every member must compute the same number for the same relay without agreeing
on anything. An index over the relay-capable set would renumber whenever the
set changes; the number is a hash of the network and the relay's identity
instead (`daemon.relayRegion`), so it moves with nobody.

It is 16 bits because the data plane truncates a peer's home region to 16
bits. Collisions are possible — under a thousandth at ten relays — and the
lower identity keeps the region while the other does not relay; every member
computes the same answer.

**A relay's addresses are ordered by where a member is.** Those on a network
of the member's own come first, then public ones, then the other private ones;
an address the member holds itself never counts as on its network, except for
its own relay, which comes first at an address this host holds, since behind
a NAT that does not hairpin its own public address answers it nothing.
netcheck sends STUN only to a region's first few nodes (three at first, then
one or two), so a first node the member cannot reach leaves the region
unmeasured and never its home.

## The DHT rendezvous

BEP 44 does not let a publisher choose where an item lands: a mutable item's
address is `SHA1(public key ‖ salt)`, so what a network can blind is the key.
`trust/secrets` derives an Ed25519 seed.

- **Per member, not per network.** The public key travels in the clear with
  every item, so one key per network would let a storage node link a
  network's items and count its members. A key per member per window makes two
  items of one network look like items of two.
- **Publish under one epoch, look under all of them.** Each node publishes
  under its newest epoch and looks under every epoch in its keyring, so
  whichever of two is behind finds the other; one direction is enough.
- **Who asks links who puts.** A storage node sees the address that put an
  item and each that asks for it. Lookups are capped per round, shuffled, and
  only for members unheard, down or set aside by a stale node, so a working
  mesh asks nothing. A lookup asks the member relays first, at their pinned
  addresses or their names on 443, and takes an answer newer than what it
  holds. The DHT is asked only by a device that reaches no member, is stale, or
  holds the lowest identity among those it reaches; two groups that reach no
  one in common each keep one seeker. Residual weakness 5 in
  [02-threat-model.md](02-threat-model.md) records this, and that running the
  DHT says the host speaks BitTorrent DHT; `juistd --no-dht` trades it for
  off-LAN cold start.
- **Items carry no epoch, and all have one size.** A cleartext epoch would be
  shared by every item of a network, and an item's length would show its
  author's addresses and roles. The reader knows which epoch it derived the
  address (or the beacon name) under, so items carry nonce and ciphertext
  alone, the epoch as additional data (`aead.SealPadded`): a DHT item, and a
  relay's answer, padded to the 996 bytes BEP 44 takes once bencoded; a beacon
  to the next multiple of 256 up to the 864 one datagram carries.
- **Each node gets its own DHT send limiter.** `anacrolix/dht`'s default is a
  package global sized for a torrent client, so two servers in one process
  would cost each other replies, which looks like a DHT that does not answer.

## Endpoints: the scan, the reflexive addresses, and the cache

An announcement carries what an interface scan finds
([09-mesh-layer-notes.md](09-mesh-layer-notes.md)) **plus** what the data plane
learns once there is a relay or STUN server to learn it from. The scan makes a
LAN with no internet work; a reflexive address makes an off-LAN peer
reachable. Neither is a superset of the other.

**The endpoint cache is trusted no more than a frame from a peer.** Every
record is verified on the way in, so an edited file drops a record rather than
redirecting a peer. Only members' announcements are written, or anyone holding
an epoch secret could grow the file without bound.

## Gossip through the tunnel

With a TUN device or the netstack, gossip runs through the tunnel alone: it
listens on the overlay addresses and dials only a peer's, so a device needs no
port for it from outside, and two members behind NAT sync directly. Without
one it listens and dials on the underlay, overlay addresses last. What a
tunnel cannot bring up comes another way: a new member's announcement with
its join, a restarted one's through the DHT or LAN discovery.

**Finding a peer again.** A tunnel cannot carry the announcement that would
bring it back up, so how fast the DHT is asked decides how long a pair stays
cut off. The rules:

- A mesh restarted in the same process on the same keys announces the same
  disco key and relay certificate (`daemon.Session`), so peers reach it on the
  announcement they hold; new keys draw new ones, since a rotation answers a
  device that may have been copied. The relay certificate is also kept on
  disk, bound to the device keys, so a restarted process keeps the hash
  members pinned: a stale member reaches few relays and would learn a new
  hash only from its next DHT lookup. The disco key is not written, since a
  peer that is down is looked up anyway.
- A stale member looks up every member it holds an announcement for but keeps
  no tunnel to, on the schedule of a peer found down: those announcements
  carry the relays it still uses.
- A peer whose probes go unanswered twice in a row is down unless it completed
  a handshake in the last check interval; the 180 s a handshake stays fresh
  stands in only for a probe not sent or lost, since a restarted peer leaves
  the last one looking fresh for minutes.
- A peer found down is looked up at once, again after 30 s, then at doubling
  gaps up to an hour, counted from when each was due. Members never heard from
  share that schedule, and a round takes the four due longest, so none starves
  another. A round brought forward waits 15 s after the last one and puts this
  node's own announcement again only if it says something new; a round on the
  interval always puts it, freshly signed; a changed one brings a round
  forward at once.
- A new announcement for an installed peer is probed at once, past the probe
  backoff, and a tunnel back up is synced at once.
- A peer that answered is probed again only after 5 minutes where both ends
  have a home relay and this device reaches the peer's, its answer standing
  meanwhile: a probe keeps magicsock pinging the peer every 3 s for 45 s, so
  probing every check would never let a tunnel go quiet. A relay brings it back
  by CallMeMaybe; without one every check probes, which keeps the NAT mappings
  open. A peer's relay this device's last measurement did not reach, as one
  whose role was revoked, wakes nothing: the peer is probed and, once found
  down, looked up for its next home.
- A running device signs its announcement again every 5 minutes, and for each
  DHT publication, though nothing changed. The sequence number is the signer's
  clock, so a signature made after a peer's tunnel went down is the one sign
  that the peer runs; an old record found again proves nothing. A renewal that
  says nothing new is kept but not acted on: no reconcile, no push, and the
  endpoint cache is rewritten for it hourly.
- The status blames the way to a peer — a blocked UDP port, a missing relay —
  only where it has changed its announcement since it went down, or signed it
  more than two minutes after, allowing for a clock ahead of this one's, and
  only until a renewal following that sign could have come; meanwhile the
  peer is looked up at least every 5 minutes. A device that wakes for moments
  while asleep, as a Mac does for Power Nap, reads as offline between them.
  Without a sign it says the peer is offline once a renewal could have come (a
  DHT interval, a lookup gap, the clock skew both ways; less with no DHT), and
  at once where this device's relay holds the peer's home region and finds it
  disconnected; until then it says it does not know which. A failed sync
  through a live tunnel is reported only once a retry through it failed too.

**A relayed pair whose home relay moves.** The home region follows netcheck,
and a peer reached only through a relay learns the new region from the
announcement, which gossip carries through the very tunnel the old region no
longer serves. A member holding a tunnel to both passes it on; a device on
HTTPS alone also asks the relays for it (below). Two members that punch
through neither and share no third still wait for the DHT or LAN discovery:
open.

## HTTPS alone, and relays on 443

A device on a network that passes TCP to 443 alone reaches the others as one
HTTPS client among others. The rules:

- **A relay's name is its own statement, checked at the name.** The
  relay-capable member announces the public name it serves on 443
  (`RelayInfo.Name`). A member takes the name as that relay's once the server
  at the name, asked over TLS at `/juist/relay/v1/whoami`, says it is that
  member's, and asks again every six hours: a CA's certificate binds the name,
  not the relay, so another member could otherwise claim it. An invite names a
  relay one relay alone claims unasked, since the host may reach no name, and
  of a name two claim only the one's its server names.
- **The name is verified by WebPKI, the port by its pin.** The DERP map gives a
  named relay nodes for the name on 443, with no `CertName`, after every
  address on its own port, since netcheck sends STUN to a region's first nodes
  alone: resolved in DNS first, then at its public addresses, for where DNS
  fails, as when an exit node routes it through a tunnel not up yet. The relay
  shows a CA's certificate to a client asking for the name by SNI and the
  pinned one to every other, so every member falls back to 443 by itself where
  the relay's port is blocked.
- **HTTPS alone sends nothing but TLS to those names, and DNS for them.**
  `SetOnlyTCP443` and the self node's only-TCP-443 capability keep magicsock
  off UDP and off peer relays; the DERP map holds the names alone and no STUN
  server; LAN discovery and the DHT are off; the announcement carries no
  address. Magicsock still names its local addresses in call-me-maybe over
  DERP, so members' pings may reach it on a LAN; it answers none. A flood of
  WireGuard handshakes from where UDP reaches it, by one who knows its node
  key, draws wireguard-go's cookie replies by UDP, which magicsock does not
  gate. Log sync runs in the tunnel, so it needs a device or the netstack.
- **The relays stand in for the DHT.** A device on HTTPS alone keeps its sealed
  announcement at, and asks for the members', the relays on 443, at a key
  derived from the DHT item's seed, which only members derive; not the item's
  public key, which every DHT message about it carries. A relay answers for its
  own network's live members alone, with the newest announcement it holds,
  under its newest epoch alone, as members publish: a device removed since
  holds the older ones. It takes one put there as found in the DHT, and only
  the member's own, under its own key. Requests are bounded per client, an
  IPv6 one by its /56, and in all, where a key of no member's costs the relay's
  budget nothing, and one under an older epoch, only ever put, a budget of its
  own.
- **443 is taken by address.** The relay binds 443 at each address of the
  host's members may reach it at, so the terminator keeps 443 of the overlay
  addresses. On FreeBSD the root helper binds it where root's grant, which the
  package's `relay.sh` leaves, is in place, and no program answers there yet:
  root's socket at an address would take a wildcard server's clients. On the
  ingress, which holds 443, the ingress hands the name's connections on after a
  PROXY v2 header at a Unix socket beside the control socket, which takes the
  ingress user's connections alone, asked of the kernel, and passes neither
  QUIC nor plain HTTP for it; a member's name the same as the relay's is not
  served. Clients' handshakes order no certificate: the relay does, five
  minutes apart at first, as a CA limits failed orders, and on the ingress once
  the ingress was told of the name.
- **A proxy is the HTTPS-only device's alone.** The DERP client's proxy hook
  answers for the names of an HTTPS-only data plane's relays, those dropped
  since included, never for a pinned relay, and without the proxy's user,
  which the DERP client logs; where the proxy cannot be told it fails closed,
  since the DERP client would dial direct. Its invites and the rendezvous take
  the same proxy; another device's invites none. Only an http or https proxy
  is taken, and no redirect is followed.

## The announcement is what primes CallMeMaybe

With a DERP map installed, magicsock sends `CallMeMaybe` over DERP itself, but
only after it has pinged something: `endpoint.sendDiscoPingsLocked` enqueues one
when `sentAny`, which is false for a peer it holds no candidate address for. A
peer given no address is never asked to punch back, and two nodes behind NAT
with no hint about each other stay on the relay for good; Tailscale's control
plane always supplies one.

Here the **signed announcement** supplies it — interface and reflexive
addresses, delivered by gossip, LAN discovery or the DHT — and one address each
is enough. A hand-sealed `CallMeMaybe` over `SendDERPPacketTo`
([07-embedding-notes.md](07-embedding-notes.md)) would be needed only where no
announcement path exists, which is not the case.

## The NAT matrix is translated, not simulated

`conn/netnsnat_linux_test.go` puts a router namespace in front of each node and
has Linux netfilter translate.

- The cone kinds pin the external port to the internal one, which makes the
  mapping endpoint-independent; they differ only in what unsolicited traffic
  they admit.
- Symmetric masquerades with `--random-fully`, so the kernel picks a fresh
  external port per destination.
- Double NAT is a port-restricted NAT behind a second one, with the carrier
  segment in 100.64/10. A node addressed there directly would have only
  reflexive addresses to offer, since `daemon.usableUnderlay` refuses to
  announce 100.64/10.
- **Whether a path ended up direct is asked by stopping the relay.** A pair
  that keeps reaching each other was never relying on it; every other way of
  asking depends on the layer under test to report on itself.
- **The lab classifies its own NATs first,** by two reflector addresses on one
  relay and one socket, as a STUN client would: one mapped port means
  endpoint-independent, two symmetric. A rule that did not do what its name
  says would otherwise make a cell pass for the wrong reason.
- **"symmetric × easy" is symmetric against full-cone,** not port-restricted,
  whose filtering would leave only port prediction, and a criterion should not
  be probabilistic.

## Open

- **A DHT node identifier that rotates.** A storage node answering several of
  this node's queries sees one identifier behind them. The queries say nothing
  about who is sought, and rotating costs a bootstrap each time; worth
  revisiting if the query pattern becomes load-bearing.
- **Relay capacity.** A relay carries every member's DERP traffic, with no
  per-client limit and no accounting, and a member can refuse only wholesale
  (`--no-relay`). A relay-capable member behind NAT advertises its relay at
  every address it announces, reflexive ones included, where the relay's TCP
  port is not mapped; the relay's status warns once it has served no device
  for three minutes while a live peer is homed at no member relay.
- **Relay selection.** The data plane picks a home region by latency, and
  that is all the policy there is. `juist status` counts the grants
  (`RelayCapable`) apart from the relays installed, since a grant with no
  announcement behind it is a relay nobody can reach, and warns where no
  member may relay in a network of more than two. Relay demand tracks the
  pairs that cannot punch through, which nothing measures.
- **IPv6 on the lab's underlay.** The NAT matrix is IPv4, because NAT is; a v6
  network needs no traversal and its paths are those the netns tests cover.
