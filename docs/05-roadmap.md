# 05 — Roadmap

Scoped for 1–2 experienced developers part-time. Each milestone has a **security exit
criterion** — the milestone is not done until it passes, and they are cumulative (CI
keeps enforcing all previous criteria).

*(demo-able)* marks a milestone that closes a loop an outsider can be shown end to
end. It is not a claim about testability: every milestone here is testable by hand
when it lands, and M3a in particular is the first one that is *useful* — it just
leaves the enrollment ceremony as manual as M2 left it, which is why the label sits
on M4 instead.

## M0 — Walking skeleton *(demo-able)*

Two Linux nodes, statically configured, tunnel up via embedded Tailscale wgengine
(wireguard-go + magicsock in direct-only mode), ping over the overlay.

- Proves: the vendored-engine embedding works without `controlclient`/`tsnet`.
- **Exit criterion:** E2E encrypted tunnel between two nodes with zero Tailscale
  infrastructure touched (verified by egress capture: no traffic to *.tailscale.com).

## M1 — Trust layer, offline

The membership log as a pure library: genesis ceremony, AddNode/RemoveNode,
admin keys + vote weights, k-of-n quorum verification, checkpoints, fork choice,
epoch group secret records (HPKE fan-out), address derivation/collision rules, and
node roles + advertised-route grants (`SetNodeRoutes`) with their validation rules —
reserved here, unconsumed until M6, because the record schema freezes at M3.
CLI: `juist init / sign / verify / log show` (`init` is `create` since M5). No networking.

- **Exit criterion:** an adversarial test suite — forged signatures, replayed AUMs,
  reordered chains, rollback to lower epoch, sub-quorum membership changes, colliding
  addresses, conflicting concurrent records, fork injection, self-asserted or
  overlay-overlapping route grants — is rejected 100 %; fuzz targets for AUM decoding
  run clean for 72 CPU-hours.

## M2 — Log-driven mesh on LAN *(demo-able)*

Reconciler: log state ⇒ WG config ⇒ netmap. Gossip anti-entropy + log-head beacons.
Blinded mDNS discovery. Two-to-five nodes on one LAN, no internet.

- **Exit criteria:** (1) default-deny proven — a node holding valid WG keys but absent
  from (or removed from) the log cannot complete a handshake with any member;
  (2) revocation converges across a connected 5-node mesh in <5 s including WG peer
  removal and PSK/epoch rotation; (3) LAN-only operation with zero internet works.

## M3 — Off the local segment

Two slices, in this order. **M3a** makes the overlay carry traffic at all; **M3b**
makes it reach past the local segment. They are independent as code — neither needs
the other's mechanism — but M3b's NAT harness is built on the real devices M3a
introduces, and M3a is the slice that turns this from a thing you read
`juist status` on into a thing you use.

The record schema freezes at the end of M3. M3a defines no records, so the freeze
gate is in practice M3b, and every "before the M3 freeze" note elsewhere in these
docs means that point. What the freeze means after M3b is that a schema change
costs a quorum-signed record and a coordinated upgrade, not that it is
impossible.

### M3a — OS plumbing: a real device, a real router

Everything between the tunnel and the host stack. The data plane and the
reconciler both run against `tstun.NewFake` and `router.NewFake`, so the overlay
exists and nothing on the host can reach it. That is what M3a removes.

Scope: a real TUN device; a real `router.Router` wired at engine construction; a
route set for the peers, derived on every reconfiguration; and the privilege
story that comes with both. Explicitly *not* DNS — naming is M8, so the DNS
configurator stays the no-op one. The netns harness lands here rather than in
M3b, because two nodes with real devices no longer fit in one namespace; M3b
builds its NAT matrix on top of it.

The constraints the wiring has to respect are in
[07-embedding-notes.md](07-embedding-notes.md).

- **Exit criteria:** (1) two nodes on one LAN, each with a real device in its own
  netns, exchange ICMP echo over *both* address families and carry a TCP stream,
  driven by ordinary host tools rather than by the engine's internal ping;
  (2) default-deny survives the router — a node holding valid WireGuard keys but
  absent from (or removed from) the log gets no route, no filter entry and no
  handshake, asserted against a real device rather than the fake one; (3) the
  daemon's privilege footprint is exactly device creation plus `CAP_NET_ADMIN` on
  a dedicated user, documented in a unit file, with no part of it running as root.

### M3b — NAT traversal, relays, DHT cold start

Full magicsock integration (disco, hole punching), member-run membership-authenticated
DERP relays from log roles, BEP 44 announcements with blinded rotating topics + AEAD
payloads, persistent endpoint cache. The NAT simulation matrix extends M3a's netns
harness. Off-LAN endpoint exchange — the one thing M2 has no answer for — uses
hand-sealed `disco.CallMeMaybe` frames sent over a relay with
`magicsock.Conn.SendDERPPacketTo`, so the peer's stock magicsock processes them
natively; see [07-embedding-notes.md](07-embedding-notes.md).

Reflexive addresses learned through disco and relays are *added* to the local
interface scan M2 announces from, rather than replacing it — and the scan's known
weaknesses on a multi-homed host (09-mesh-layer-notes.md) are an input to that
decision.

**The freeze obligations land here too.** M3b is the last milestone that can add
a field for free: it spends that on versioning the schema itself, so a later
kind, role or field costs a quorum-signed `SchemaUpgrade` record and an upgrade
window rather than a new network, with builds too old for the version stopping
loudly instead of acting on the part they understand
([08-trust-layer-notes.md](08-trust-layer-notes.md)). The scaling question the target scale hides — the epoch wrap
set is O(n) *inline* in both `EpochRecord` and `Snapshot`, so one add or remove
re-replicates it to everyone — was settled by measuring a record at `MaxNodes`
rather than from the arithmetic: the fan-out costs bandwidth and not CPU, and
only above the target range. Four candidate hedges are declined and one, a
ciphersuite identifier, is taken; what each decision now binds is in
[08-trust-layer-notes.md](08-trust-layer-notes.md). The relay and DHT work
needs no record of its own: `relay-capable` is already a role, and where a
relay listens is a claim a node makes about itself, which belongs in its signed
endpoint announcement and not in the log.

- **Exit criteria:** (1) direct connections established across the simulated NAT
  matrix (full-cone, restricted, port-restricted, symmetric×easy, CGNAT double-NAT),
  relay fallback for symmetric×symmetric, UDP-blocked → relay-over-TCP;
  (2) a DHT observer (test crawler) can extract neither network identity, membership,
  nor member count from announcements; (3) non-member cannot use member relays.

## M4 — Enrollment + freshness + revocation UX *(demo-able — full product loop)*

Full-entropy invite links (the payload a QR code carries) and wormhole-style typed
codes (SPAKE2, single-use, one-guess). `juist invite / join / remove / rotate`.
Freshness leases from admin devices, fail-closed TTL enforcement (including the
startup gate), two-tier revocation (routine vs. emergency epoch bump + forced
re-handshake) — which collapses into one tier, see
[11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md).

- **Exit criteria:** (1) invite brute-force yields exactly one online guess, failure
  is loud, code is dead after use/timeout; (2) with a simulated partition and
  fake-clock control: a revoked node loses access to reachable peers within gossip
  convergence and to partitioned peers at exactly the TTL boundary — fail-closed
  verified both directions (stale *victim* also refuses); (3) an admin quorum can be
  exercised with admin keys on separate machines (no single machine ever holds k
  keys).

## M4b — Coming back after many changes

A member that slept through more epoch bumps than `keyring.Depth` = 4 holds an
epoch nobody still speaks: every AddNode, RemoveNode, RotateNodeKey,
RotateIdentity and EpochBump bumps it, and a laptop suspended during an
afternoon of changes, or a phone away for a week, would otherwise have to be
invited again. It catches up by identity instead of by epoch.

**Why not a deeper keyring.** The epoch secret is also the membership proof of
gossip, the DHT and mDNS, so every epoch kept is one more change for which a
*removed* device is still answered — the log, every member's endpoints and the
leases (no tunnels: peers come from the log). Depth N, or a time window,
widens that to N changes or to the window, which gives up what the threat
model's "loses group secret → loses discovery" promises. It would also have
to be set on the peers that answer, not on the device that slept.

**The catch-up.** When no epoch a node holds is answered, it asks the peer for
a catch-up on the gossip port, under the reserved epoch label 0 that older
builds hang up on. The peer draws a nonce; the node signs it with its identity
key, bound to the network; the peer verifies the signature before anything
else, checks that its own current log lists the node as a live member, and
seals a session key to the recipient keys that log names, signing the grant
with its own identity. The four-frame session then runs under that key, so
records from the node's anchor, announcements and leases move both ways:
whichever side is far behind is caught up by whoever reaches it. The node that
asked cannot know yet whether the grantor is a member — its log may name it
under an identity since rotated — so it speaks last: it takes the grantor's
records first and sends its own, its announcements and its leases only once
its log lists the grantor. A node its peer's log does not list is refused — a
removed one at once, where an ordinary session is answered for four more
epochs — and one that is not yet listed tries another peer; the refusal goes
only to a node the peer's chain has named as a member since its anchor, whose
proof verifies under the ML-DSA key it was named with, so a restart forgets no
one, but a node removed before a compacted log's anchor is hung up on; anyone
else is hung up on, learning nothing. A refusal is
signed too, and counts only from a member the asking node's log lists that is
past its epoch: from anyone else it is noise, and from a member behind it only
means that member has not seen the node admitted. An unproved ask counts
against the budget for connections that have said nothing, and costs the peer
one Ed25519 verification. A node that applies several epochs at once fills its
keyring with the newest, so what it keeps is what peers speak and not what a
removed device holds. A device that every member it reaches refuses, and none
answers, says so in `juist status`: most likely removed, and a new invite is
the way back.

What remains outside it: the proof names the device's identity in the clear,
which in the tunnel only the peer sees. The DHT and mDNS stay keyed by epoch, so a device
that slept finds peers only through its endpoint cache or the addresses of
members that did not move — the always-on servers, in practice. In the
tunnel, a catch-up needs a WireGuard path first, and a device whose juistd
restarted announces its new disco key under an epoch its peers no longer hold:
the path is then a relay both use, since magicsock takes WireGuard from a
known node key over DERP whatever disco key it last announced.

- **Exit criteria:** (1) a member offline across more than `keyring.Depth`
  epoch bumps, including a rotation of its admin device's identity, syncs
  again from one reachable member without an invite and is fresh as soon as
  the vouchers' leases arrive; (2) a removed device's catch-up is refused by
  every member that holds the removal, while it still holds an epoch within
  the keyring; (3) a catch-up request with a replayed or foreign signature, or
  for a nonce the peer did not draw, gets nothing.

## M5 — Several networks on one host

Before M5 a juistd held one network, and `juist join` on a device that was in
one refused to join another. The keystore already kept its admin keys, anchors
and break-glass files per network; what was missing was a host being a member
of several. Running a second juistd by hand worked in part, but three things
broke: every network numbered its devices from the start of the same range, so
two TUN devices claimed overlapping IPv4 routes; the Linux router's table and
policy rule priorities were fixed, so one instance stopping deleted the rules
the other routed by; and the packaging knew one unit with fixed ports. The
overlay IPv6 prefix is derived from each network's genesis and does not
collide. How each was resolved, and the rules a later change must keep, are in
[13-multi-network-notes.md](13-multi-network-notes.md).

What was built, in the plan's order:

1. **An IPv4 prefix per network.** `juist create` draws a random /22 in
   198.18/15 (1022 addresses, one of 127) unless `--ipv4` names one. It never
   draws the first, where networks without a prefix of their own number
   from, nor one this host's interfaces or other networks claim.
2. **Instances.** `juistd.service` is instance 0; `juistd@juist1` to
   `juistd@juist9` run beside it. The number chooses the TUN device, the
   ports (the defaults plus ten times the number), the routing table and the
   policy rule priorities. Where two tables claim an address, the lowest
   instance's wins. Instances are numbered, not named after their network as
   planned: the name is needed before the join that learns it, and a device
   name has to fit IFNAMSIZ.
3. **Overlap on the host.** An instance whose network claims IPv4 that a
   lower instance holds runs without IPv4, and says which. The plan said to
   refuse to start, but a refused instance also stops syncing its log, and
   then never hears of the renumbering that would end the conflict. One that
   finds its own network held by another instance does not start at all.
4. **The CLI.** A command about one network takes it first (`juist devices
   home`, `juist reset juist1`), and may leave it out where there is one.
   Listings show every network, and no command asks which. `juist create` and `juist join` on a device in a
   network run the new one in an instance of its own, after asking for sudo
   once, and a reset removes that instance again.
5. **Packaging and firewall.** The template unit is packaged, and upgrades
   and removal cover instances. `firewall.sh` allows and revokes one device
   at a time, and each new instance is allowed as `juist0` is at install.
   The firewalld and ufw service definitions still name the default ports.
   Status hints give an instance's own ports by number.
6. **Renumbering.** Criteria (5) and (6) are netns tests. An approval shows
   how much of a renumbering's transition is left, since its deadline is
   fixed when it is proposed. Choosing the old address as the source on
   platforms other than Linux moves to M7, with the FreeBSD router. What
   juist cannot move is anything outside it that names the old addresses.

Instances share no state, and a TUN device routes its own network's prefixes
only, so no packet crosses from one network into the other through juist. They
do share the `juist` user, so one compromised instance holds every network's
device on the host: residual weakness 9 in
[02-threat-model.md](02-threat-model.md), and a user per instance is for M23.

- **Exit criteria:** (1) one host in two networks, in the netns matrix, pings
  members of both over IPv4 and IPv6, and no route of one prefix points into
  the other's device; (2) a second instance whose prefix overlaps a running
  one runs without IPv4 and says so, naming both, and one in a network the
  host runs already does not start; (3) removal from one network leaves the
  host's membership of the other untouched, across a restart of either
  instance, and stopping one leaves the other's routes and rules in place;
  (4) an existing network without `V4Prefix` keeps working as the default
  instance next to a new one; (5) a network renumbered while one member is
  offline keeps every pair of members reachable throughout, the offline one
  included once it returns; (6) a member renumbered on its own is reachable
  at both addresses until the deadline and at the new one only after it, and
  a record giving it an address another member holds, or one outside the
  network's range, is rejected by every node.
- **Validated on real hardware:** the privileged tests of (1), (3), (5) and
  (6), as the data plane sees them, passed on 2026-09-27
  ([12-validating.md](12-validating.md#the-last-privileged-run)). The rest are
  checked by `make check`.

## M5a — An admin key per network

Before M5a `juist create` took an admin key already in the keystore when one
was named for the admin (`admins/alex.key`, after the user by default), on
the rule that one person's key may govern several networks. With several
networks on one device (M5) that default cost more than it saved: one key
taken or lost was every network it governed taken or lost; its public half is
in every network's log, so a member of two saw that one person ran both; and
rotating, removing or backing up (M12's `juist admins export`) the key of one
network touched the others.

What was built, in the plan's order:

1. **A new key for every network.** `juist create` creates one, named for the
   network (`admins/alex@home.key`), so that a rename (schema 6) moves
   nothing. In the log the admin is still "alex".
   A key already under that name, made with `juist admins new --network`, is
   the one it was made for and is used. Where there is a log, signing needs no
   mapping from networks to keys: the CLI signs with every local key that has
   a part in a record.
2. **Sharing on purpose.** `juist create --admin-key NAME` governs the new
   network with a key already in the keystore; the admin name defaults to the
   key's.
3. **Keys made before their network.** `juist admins new NAME` makes a key
   named for the admin alone and marked unfiled. The first network whose log
   (or genesis, signed with it) names it files it under that network. Given
   `--network`, it is named for that network at once. Not planned: without a
   log, keys filed under different networks do not sign one record together,
   since each would spoil the other's; `juist approve --key NAME` picks one.
4. **Existing keystores.** A key named `admins/NAME.key` without the mark
   keeps working and keeps its name. `juist admins` ends with the keys here
   and the networks each governs, so a shared one is visible as such.

- **Exit criteria:** (1) two networks founded one after the other in one
  keystore are governed by different keys, and neither key's signature counts
  in the other network; (2) `--admin-key` governs a second network with an
  existing key, and `juist admins` lists that key under both; (3) a keystore
  from before M5a signs for its networks unchanged; (4) a key made with
  `juist admins new` before its network is used for that network once added,
  and not offered for any other.
- **Validated:** by `make check`; the tests are in
  `cmd/juist/adminkeys_test.go`. Nothing in M5a runs privileged.

## M5b — Changes that wait for other admins, carried to them

With a quorum above one, no machine finishes a change alone. Before M5b the
CLI signed what it could and wrote the change to a file (`add-phone.rec`),
which a person carried to the next admin, who ran `juist approve` on it. That
is sound, since every signature and the quorum are checked where the change
applies, but it left the carrying to people. M5b carries it: another admin,
or the same person on another device with a key of their own, sees the change
waiting and signs it there.

**Not through the DHT.** A BEP 44 item holds 1000 bytes, and a change that
bumps the epoch carries 1168 bytes per member. The DHT's addresses and payloads
are keyed on the epoch secret, so every member could read them and a
signing-only keystore could not. Items expire within about two hours and a
lookup takes up to a minute. Every item is also more public traffic from
members' addresses (02, weakness 5). Two admin devices in a network already
have a tunnel or a relay between them, and log sync runs through it.

What was built, in the plan's order:

1. **Waiting changes in log sync** (`internal/waiting`, `daemon/waiting.go`,
   `gossip/waiting.go`). A change that lacks votes travels as one admin key's
   copy of it, signed by that key; each admin who signs hands on a copy of
   their own, and where the change is read the copies' signatures merge. Each
   juistd keeps the copies handed on by a current admin key that build on its
   head and have not expired: at most 64, 32 MiB, 8 MiB per signing key and
   seven days, persisted across a restart. A copy leaves once the log moves
   past it, which applying it does. Only admin devices take copies from their
   peers, and none is sent to a device without the role or to one the change
   is about. Not a frame kind of its own, as planned, but a field of the hello
   (what a device holds) and of the records frame (what it hands over),
   sealed to the receiving device's encryption key: a peer claiming another's
   identity gets nothing it can open, and the exchange stays four frames.
2. **The CLI.** `juist status` says "1 change waits for your vote: removes
   the device phone (…), proposed by alice", and `juist approve` without files
   asks about each one, shown from the local log, discarding what was typed
   before the question; it takes no `--yes`. The signature that completes the
   quorum applies the change there. A change that still lacks votes is
   written to a file as before, and is carried as well where a juistd runs.
   An admission's copies wait five minutes at a time, renewed by the running
   invite with the votes they gathered, and one is never carried from its
   file: approved after its invite, it would admit a device without the log.
3. **Readable by the admins alone**, built with stage 1 rather than after it:
   a change is only ever carried sealed, to every admin key with an
   encryption key, so the daemons that carry it cannot read it. Schema 7 gives
   admin keys an encryption key (`AdminKey.Recipient`), set by
   `KindSetAdminRecipient`, which the key must sign as well as the quorum, or
   by a genesis the key signs. It is derived from the admin key's seed, so the
   key file and its backup hold both. `juist create` puts the founder's in the
   genesis; any other admin runs `juist admins receive` once, after
   `juist log upgrade` on an older network.

The trust stays where it is: the transport may withhold, replay or flood,
and cannot make a change count. What becomes easier is a compromised admin
key putting a change in front of the other admins, rather than handing them
a file (02, weakness 10). The decision remains a person's, and the log says
who signed.

- **Exit criteria:** (1) a change proposed on one admin device appears on
  another admin device of the network within gossip convergence, and is
  applied once that one's signature completes the quorum; (2) a change
  carrying no valid signature of a current admin key, or a replayed one that
  no longer fits the log, is dropped by every daemon and shown to nobody;
  (3) no device without the admin role, and not the device a change is about,
  receives it, asserted on the wire; (4) nothing is signed without the admin
  being asked, and what they are shown is the effect computed from their own
  log; (5) after stage 2, a change sealed to an admin cannot be read with any
  other key, the group secret included.
- **Validated:** by `make check`; the tests are listed in
  [12-validating.md](12-validating.md#what-checks-what). Nothing in M5b runs
  privileged.

## M5c — Moving one device without a transition

`juist network renumber core desktop 10.11.111.12 --finish` moves the device
and retires its old address at once. Before M5c a move always kept the old
address for `--for`, and `--finish` took no arguments and retired every old
address in the network, so this took two changes and cut other devices'
transitions short.

What was built:

- A renumber-node record whose deadline is `types.RetireAtOnce`, the first
  second of 1970, and so no schema change. The plan had the deadline be now;
  a deadline that is simply past reads, to an admin approving it later, as a
  transition that ran out ("BUT that deadline has passed"), and the marker
  lets the approval say "moves desktop to 10.11.111.12 at once" instead. The
  old address stays recorded, unused and held against collisions, until the
  next plain `--finish` or the device's next move, since devices not yet told
  still route it to the device. `juist network` lists what is held, and how
  to free it.
- It warns that connections to the old address end and devices not told yet
  reach the device over IPv6 only until they are, and asks "move desktop
  from … to …, retiring … now?". A plain `--finish` retires what still works
  and frees what is held, and says which. `--for` beside it, and `--finish` with a PREFIX or a
  device alone, are usage errors: moving the whole network at once would cut
  every device off from every one not yet told.
- `juist status` names the devices not told yet of a renumbering for as long
  as an old address is recorded, not only while one works. The moved device
  starts on its new address as the move applies there.
- A device that misses the move is not cut off: its IPv6 address does not
  change, and log sync through the tunnel tells it of its new address.

- **Exit criterion:** after the command, every node that has applied the record
  reaches the device at the new address only, other devices' old addresses
  stay live until their deadlines, and the test runs through the in-process
  app.
- **Validated:** by `make check`; the tests are listed in
  [12-validating.md](12-validating.md#what-checks-what). Nothing in M5c runs
  privileged.

## M6 — Exit nodes and subnet routers

The `exit` role and route grants consumed from log state (schema and
validation landed in M1), widened `AllowedIPs` and filter destinations,
privileged-helper forwarding/NAT, client-side default-route capture with LAN bypass
and DNS handling. Design in
[04-architecture.md](04-architecture.md#exit-nodes-and-subnet-routes-m6). It
covers Linux; FreeBSD's side (pf) comes with M7, Android's use of an exit
node with M10, and the rest of Android's with M28. Split
in three, each shipped on its own: exit nodes first, as the feature asked for,
then subnet routers, then the exit node's DNS.

**Done** on 2026-09-28: M6a, M6b and M6c are built and validated as their
sections say, privileged and by hand against the packages. Untried: a
client below systemd 256, whose resolved polkit asks without the device.

**Scoped by the access policy.** The quorum grants the role per exit node, and
each client's owner chooses whether to use one; which members may is the access
policy's (M14), and without one every member may, as every member reaches a
subnet router's prefixes ([02-threat-model.md](02-threat-model.md) item 7).

## M6a — Exit nodes

`juist exit use vps` sends the device's internet traffic through vps, a
member the network made an exit node and whose operator agreed to serve.

What was built:

1. **Route grants consumed from the log.** `juist grant vps exit` gives
   the role and the default routes (`0.0.0.0/0`, `::/0`); `revoke` takes
   both.
   A client installs them for the one exit node it uses, and nowhere else,
   as *the internet*: public IPv4 and `2000::/3`, without the overlay space
   (the obligation M1 left, [08-trust-layer-notes.md](08-trust-layer-notes.md))
   and without private and special-use ranges (`conn.Internet`). The exit
   node's filter accepts the same, less the networks the exit node is on,
   public or not, of which only its own addresses stay. An exit node
   therefore never intercepts member-to-member traffic and never opens its
   own LAN; that is M6b's, as a subnet route. While it serves, its forward
   path drops what arrives from elsewhere with an overlay source, and what
   comes new into the overlay from public space.
2. **Both sides agree.** The quorum grants the role; the exit node's operator
   agrees on that host with `juist exit serve` (and `--stop`), kept in
   the state directory, and its signed announcement says so, so that a
   client lists it as serving or not and `use` refuses one that does not
   (`--force` chooses it anyway). It serves while it holds the grant, has
   agreed, its view is fresh and the host forwards; `juist status` says
   which of these is missing.
3. **Once as root on the exit node.** `serve` asks for sudo once and runs the
   packaged `/usr/lib/juist/exit-node.sh on juist0`:
   `/etc/sysctl.d/60-juist-exit.conf` with IPv4 and IPv6 forwarding,
   `accept_ra=2` where an interface took router advertisements, and the
   forward path in ufw (`route allow in on juist0`) and Docker's
   `DOCKER-USER` chain; firewalld's trusted zone forwards already. The file
   records what forwarding was before, so `--stop` and removing the package
   put it back, and the removal also clears what a juistd that failed left
   refusing (`exit-node.sh clear`). `serve` runs it again wherever the host
   does not forward. juistd writes no sysctl, so the unit keeps
   `ProtectKernelTunables`; it masquerades overlay sources in an nftables
   table of its own over netlink (`juist0` in `ip` and `ip6`).
4. **The client.** `juist exit` lists the exit nodes, `use DEVICE` and
   `off` choose. The choice is the device's, held by its juistd per network,
   by identity, followed through the node's identity rotations: "never
   chosen", "off" and a node are three states, which a default an admin sets
   later (below) needs. Internet traffic goes to a table of juist's own at
   5200, before the host's routes, which throws back to them what no exit
   node carries (private, link-local, multicast and other special space,
   tailscaled's among it); routes a network pushes, as DHCP option 121 does,
   therefore take nothing out of the tunnel. A LAN in public space goes
   through the exit node too, since a network could claim any public prefix
   for itself. Answers to connections that came in by another device leave
   by it, so that a server stays reachable at its own address: conntrack
   marks such a connection where it comes in, and a rule at 5160 sends its
   answers by the host's routes, past the guard; on FreeBSD pf keeps state
   for them, and sends them back to the gateway they came from, where
   juist's ruleset is pf's, and `use` and the status say where the host's
   own passes what comes in instead. `use --isolate` sends them through the
   exit node too, and stops where that would end the ssh session it runs in,
   found by `SSH_CONNECTION`, an ancestor's under sudo; `--force` goes on.
   An nftables guard (`juist0guard`) drops whatever
   would still leave by another device to anywhere else, such as a socket
   bound to the LAN's device, or traffic whose routes someone flushed.
   Refused, the internet still goes into the tunnel, where the guard rejects
   it, so that a loose reverse-path check (rp_filter 2, firewalld's
   `IPv6_rpfilter=loose`) keeps admitting the exit node's answers; a strict
   one drops them all the same, which `use` and `juist status` say, with the
   setting to change. So is a family the exit node does not carry, refused
   at once rather than dropped unsaid, so that a program falls back to the
   other; routed subnets pass.
   juistd's own traffic, by its user, goes by the host's routes at 5180 and
   past the guard, so that it can always find its exit node again; an exit
   node is therefore refused unless juistd runs as a system user, as the
   packaged service does, and where another network's juistd on the host
   uses one or serves as one, which the CLI refuses. Where it happens all
   the same, the refusal wins: of two that use one, the lower instance's
   routes and the higher routes nothing of its own, and one that serves
   stops beside one that uses an exit node. A device that uses one serves as none. Everything is installed
   again on each reconcile, since a table someone flushed is not announced.
5. **Failing closed.** While the chosen exit node cannot be used — not a
   member, not granted, not reachable, not serving, or this device's view
   stale — internet traffic meets an unreachable route rather than going out
   directly, and `juist status` says why; one that stopped answering is shown
   so. So does a choice kept that cannot be read. The refusal holds while the
   mesh restarts or does not run, as on a device the network removed, and a
   juistd that fails leaves it until the service runs again (or
   `exit-node.sh clear`); a clean stop of the service lifts it, so a
   `systemctl restart` goes direct for the moment in between. Where even the
   refusal cannot be installed, `juist status` says the traffic may leave
   directly.
6. **DNS is not handled yet (M6c).** A resolver on the LAN or link-local is
   reached outside the tunnel; `juist exit use` and `juist status` name
   it. IPv6 goes through the tunnel even where the exit node has none, and
   is refused there rather than sent out directly.

For later, and not to be precluded: **a default an admin sets.** A
quorum-signed default exit node per device, which `juist invite --exit`
could set at admission, applied below the device's own choice and so undone
by `juist exit off`, and shown in `juist status` as the network's. Open
then: whether it may be a requirement rather than a default, and whether a
device fails closed or goes direct while its default is down.

- **Exit criteria:** (1) a member that forwards traffic without a route grant is
  dropped by every peer; (2) a grant overlapping the overlay ULA or an overlay v4
  range is rejected by the log validator, and an exit node's default route
  leaves the overlay out, so an exit node can never intercept member-to-member
  traffic; (3) with a full tunnel up, no non-LAN packet leaves the host outside
  the tunnel but DNS to a LAN or link-local resolver, which the CLI names
  (asserted by capture on the physical interface), while LAN destinations still
  route locally; (4) withdrawing the `exit` role cuts egress within gossip
  convergence for reachable clients and at the TTL boundary for partitioned
  ones.
- **Validated:** (1), (2) and (4) by `make check`; the tests are listed in
  [12-validating.md](12-validating.md#what-checks-what). (3) is
  `TestNetnsExitNode`, privileged, and the hand test against the packages
  ([Check an exit node](12-validating.md#check-an-exit-node)), both passed on
  2026-09-28, IPv6 through a public exit node included.

## M6b — Subnet routers

`juist subnet add nas 192.168.1.0/24` lets every member reach the LAN behind nas
through it, once nas's operator agrees: `juist subnet serve`.

What was built:

1. **Grants.** A prefix in place of a role grants it, and `revoke` takes it:
   masked, outside the overlay and the ranges that never leave a link, clear
   of what overlays on a member's host may hold (100.64.0.0/10,
   198.18.0.0/15, tailscaled's `fd7a:115c:a1e0::/48`, and unique-local space
   wider than a /48, one of which another network's overlay may be), and
   overlapping no prefix another member routes, nor one of its own, which
   the log now refuses as it refuses a shared address; two such grants
   made at once on two branches are a conflict, as two admissions of one
   address are. No network held such a grant before these rules, so none is
   gated by a schema. The CLI says the
   masked form of a prefix with host bits, points `0.0.0.0/0` to `exit`,
   names the member already routing an overlapping prefix, and warns where a
   prefix is public space, which then goes through the router for everyone.
2. **Both sides agree,** as for exit nodes: the router's operator agrees
   with `juist subnet serve` (and `--stop`), which sets forwarding up with
   the same script, kept for as long as the host serves either; the
   announcement says the router routes. It routes while it holds a grant,
   has agreed and its view is fresh; its filter admits members' traffic to
   exactly its granted prefixes, and it masquerades overlay sources onto
   them, behind the same forward chain as an exit node.
3. **Clients take routes by themselves.** Each member routes a router's
   prefixes into the tunnel, in the overlay's table, less what the host
   reaches by routes of its own inside them, in the main table,
   tailscaled's and lower juist networks': its LANs, VPNs and container
   bridges among them, and the client says so. A wider route of the host's,
   as a DHCP netmask or a router advertisement's short prefix would give,
   takes none: the tunnel takes that part of it, and the client says that
   too. A route a network pushed, by DHCP or router advertisement, is not
   the host's own, so a hostile LAN takes a subnet out of the tunnel only by
   numbering itself inside it, which it could as the client's LAN anyway,
   or where its DHCP client marks the routes it installs as no one's, as
   Debian's dhclient does, by pushing a route inside it. A router or exit
   node without overlay IPv4 says so, and is sent none. Not with a stale
   view, so a withdrawn grant ends at the TTL; not IPv4 on a device without
   overlay IPv4; not while the router cannot be reached or has not agreed. `juist subnet off` turns them off on a device,
   and `on` back. `juist subnet` lists every prefix with its router and
   what this device makes of it; `juist status` sums it up.
4. **Beside an exit node,** a routed subnet goes through its router and the
   exit node's routes leave it out.

- **Exit criteria:** (1) a member forwarding for prefixes it holds no grant
  for is dropped by every peer; (2) a granted prefix is reached through the
  router from every member, and a client's own LAN inside it keeps that
  LAN's traffic, while a wider one gives the prefix up, both said; (3) withdrawing a grant removes the
  route within gossip convergence for reachable clients and at the TTL
  boundary for partitioned ones.
- **Validated:** (1), (3) and the LAN half of (2) by `make check`; the tests
  are listed in [12-validating.md](12-validating.md#what-checks-what). The
  data path of (2) is `TestNetnsASubnetThroughItsRouter`, privileged, which
  passed on 2026-09-28, as did
  [Check a subnet router](12-validating.md#check-a-subnet-router). A Docker
  network cannot be routed to, since Docker drops what reaches its
  containers from another device; `juist subnet serve` warns of it.

## M6c — The exit node's DNS

While an exit node is in use, the device's DNS goes through it, so that the
network the device sits in sees no lookup but for its own names.

What was built:

1. **The exit node answers.** While it serves, juistd answers DNS on its
   overlay addresses, UDP and TCP port 41646, bound to `juist0` so that
   nothing arriving on another device reaches it, and from the network's
   overlay alone; standard queries only, at a bounded rate, with bounded
   queries in flight and connections per source. It asks the host's own
   resolvers, resolved's stub itself where the host uses it, so that the
   exit host's own DNS routing, DNS-over-TLS and DNSSEC apply, passing over
   one that fails the query. Members ask it on port 53 of those
   addresses, which the data plane redirects to it, and no other server's
   53, as a resolver that takes no port, FreeBSD's, needs; the
   announcement names 53. No capability is added: the forwarder's port is
   no privileged one.
2. **The client points systemd-resolved at it,** over D-Bus, on `juist0`:
   the exit node's overlay addresses and port as its servers, `~.` as its
   routing domain and its default route, so that every name goes there but
   those a longer routing domain of the LAN's link claims, its router's own
   domain among them. A refused exit node keeps it, so that lookups go
   nowhere rather than to the LAN; `juist exit off` gives the link back to
   resolved, and so does juistd stopping, with the device. juistd runs as
   the `juist` user, so the package ships a polkit rule allowing it the four
   resolved actions it needs, on `juist0` to `juist9` alone where resolved
   names the device, from systemd 256 on, and on any link before, which
   juistd's CAP_NET_ADMIN could redirect DNS on by other means anyway. DNS counts as through the tunnel
   only where `/etc/resolv.conf` asks resolved's stub; else the host's
   programs ask their resolvers around resolved, and the CLI says so, with
   the stub as the hint where the file is resolved's list of every link's
   servers, as on Debian's cloud images.
3. **Without resolved,** or where it refuses, nothing is configured, and
   `juist exit use` and `juist status` name the resolvers left outside the
   tunnel and why; `juist status` says "DNS too" where it goes through.

- **Exit criteria:** (1) with a full tunnel up, no DNS query leaves the host
  outside the tunnel (asserted by capture on the physical interface) and
  names resolve; (2) `juist exit off` puts the host's DNS back as it was,
  and while the exit node cannot be used, its role withdrawn among the
  reasons, lookups go nowhere rather than to the LAN, as the traffic does;
  (3) without resolved, nothing is configured, and `juist exit use` says DNS
  stays outside the tunnel.
- **Validated:** (2) and (3) by `make check`, against a stand-in resolved on
  a private bus; the tests are listed in
  [12-validating.md](12-validating.md#what-checks-what). (1)'s data path is
  `TestNetnsExitNodeAnswersDNS`, privileged, which passed on 2026-09-28; its
  resolved half is the hand test
  ([Check an exit node](12-validating.md#check-an-exit-node)), since
  resolved runs one per host, not per namespace, which passed that day on
  systemd 259; below 256, where polkit sees no interface, it is untried.

## M7 — FreeBSD

**Done** on 2026-09-30: M7a, M7b and M7c are built and validated as their
sections say, and reviewed for security (M7 review 5). The first exit
criterion is met but for CI: the lab passes locally, and its workflow waits
for CI's budget to run once. Untried: a FreeBSD host outside qemu using an
exit node.

The FreeBSD port: M3a's real device, router and privilege story on FreeBSD,
M6's forwarding, NAT and default-route capture with pf, and a port that
installs it. Two things M5 left to it: keeping instances apart, where
Tailscale's router routes in the host's one table (a FIB per instance, or the
IPv4 yield of [13-multi-network-notes.md](13-multi-network-notes.md) read
from that table), and sending from the old address during a renumbering,
which Linux's router pins and FreeBSD leaves to the OS. Split in three, each
shipped on its own, against FreeBSD 14 in qemu:

- **M7a — device, router and privileges.** FreeBSD has no `CAP_NET_ADMIN`, and
  Tailscale's BSD router runs `ifconfig` and `route`, which need root. So
  juistd splits: started as root, it keeps a helper as root that creates the
  TUN device, sets its addresses and routes and destroys it, for juist's own
  devices alone, and runs the daemon as the `juist` user, which receives the
  device's descriptor and asks the helper for the rest over a socket pair.
  wireguard-go's FreeBSD device sets its MTU itself, which needs root, so
  juist opens its own on the descriptor. Instances share the host's one
  table: the IPv4 yield reads it, and a route names its source address, as
  Linux's pins it. An rc.d script, `/var/db/juist`, `/var/run/juist`, and the
  CLI's instance launcher through `service` and `sysrc`.
  - **Built:** `internal/plumber`, the helper and its client: a CBOR request
    per frame over a socket pair, the device's descriptor passed alongside,
    and nothing done to a device the helper did not make or whose name is not
    `juistN`, nor any default route. juistd started as root on FreeBSD keeps
    the helper and runs itself as `juist`, and stops once a pipe from the
    helper reads EOF: a parent-death signal does not survive the change of
    user there. The daemon's device reads and writes the descriptor; its
    router hands the helper the addresses and the routes, a route's source
    pinned by naming it as the gateway, since `-ifa` beside `-iface` is
    ignored. `InstanceHoldings` reads the instances' devices and the routes
    into them. `packaging/freebsd/juistd`, the rc.d script, runs the default
    and `juistd_instances`, and the CLI starts and stops instances through
    `sysrc` and `service`, and says so in its hints. `/var/db/juist` and
    `/var/run/juist`. `make test-freebsd` runs every test on a FreeBSD host.
  - **Validated:** `make test-freebsd` on FreeBSD 14.5 in qemu, as root:
    every package passes, `TestAPlumbedDeviceCarriesTheOverlay`,
    `TestRootSplitsOffTheDaemon` and `TestTheDaemonGoesWithItsHelper` among
    them; and [Check a FreeBSD node](12-validating.md#check-a-freebsd-node)
    by hand between two such VMs, both families through the tunnel. Exit
    nodes and subnet routers are refused on FreeBSD until M7b.
- **M7b — exit nodes, subnet routers and DNS.** Tailscale keeps its own
  traffic off the tunnel on FreeBSD by nothing. The internet goes into the
  device by two half routes; pf, in an anchor of juist's, sends juistd's own
  traffic (`user juist`) back to the host's gateway with its source
  translated, guards what else would leave, and does the exit node's NAT and
  forwarding filter. A FIB of the daemon's own was the other way: FIBs are
  not given back at runtime, and it would mirror every route of the host's.
  DNS through the exit node goes through resolvconf(8), on port 53, which an
  exit node redirects to its forwarder. FreeBSD's dhclient installs pushed
  routes as plain static ones, so `HostRoutes` counts them as the host's
  own, as Debian's dhclient has Linux do.
  - **Built:** serving and using. The helper has the host forward,
    recording how it found it, and loads pf, on with juist's anchors alone
    where it was off, and says what `/etc/pf.conf` lacks where the host's
    own ruleset calls none. A serving device's anchor masquerades the
    overlay onto each of the host's devices, redirects DNS on 53 to the
    forwarder, takes overlay sources and the forwarder by the tunnel alone,
    and keeps state for what peers send, so that nothing from the internet
    reaches into the overlay unasked. Using an exit node routes the
    internet but local space into the device; its anchor sends juistd's
    own traffic, by the uid the helper started the daemon as, back to the
    host's gateway, rejects a family no exit node carries, and drops what
    else would leave by another device, without state, so that answers to
    what came in still go out. Refusing outlasts the device; going direct,
    or stopping serving, puts pf, forwarding and the routes back as found.
    The host's DNS goes to the exit node by resolvconf(8), exclusively, and
    back. `juist exit` and `juist subnet` work on FreeBSD without
    `exit-node.sh`.
  - **Validated:** `make test-freebsd` on FreeBSD 14.5 in qemu, the
    helper's serving, egress and DNS tests among it; and by hand between two
    such VMs (Check a FreeBSD node): a subnet behind a router in a VNET
    jail, a FreeBSD exit node's internet and DNS from a FreeBSD client, no
    packet leaking on the client's uplink, a bound socket included,
    refusal with the exit node gone, and everything back after `exit off`.
    A Linux client through a FreeBSD exit node, and the other way, wait for
    M7c's lab.
- **M7c — the port, reproducible builds and the interop matrix.** A port
  that installs the rc.d script and the user; `make repro` for FreeBSD's
  artifacts too, from two builders; and a qemu lab of Linux and FreeBSD
  nodes that `make` runs without root, which CI runs once its budget allows.
  - **Built:** `make pkg-freebsd`, a package that
    `packaging/freebsd/mkpkg` writes rather than pkg-create(8), so that any
    system builds it, to the same bytes from one commit: juist, juistd, the
    rc.d script, completions, and man pages in FreeBSD's words, which the
    `freebsdman` tag renders elsewhere. Installing creates the juist user,
    uid 829, free in the ports tree's `UIDs`, or the next free below it.
    Removing stops every juistd and runs `service juistd clear`, new, which
    takes what a juistd left, a refusing guard among it; an upgrade leaves
    juistd running, since pkg kills what its scripts start. `gmake install`
    on FreeBSD builds and adds it. `make repro-freebsd` builds the binaries
    for both systems and the package here and on a FreeBSD host, and
    compares them. A port in the ports tree needs a release to fetch, and
    comes with M27's. `make interop` is the lab, `interop/`: a Debian 12
    and a FreeBSD 14.5 VM in qemu without root, their packages installed,
    one network across them, each the other's exit node, subnet router and
    DNS, and both packages removed cleanly; CI's `interop` workflow runs it
    with KVM. An exit node carries nothing to networks attached to it, so
    the lab's internet is a hop behind each.
  - **Validated:** `make repro-freebsd` between Debian 12 and FreeBSD 14.5
    in qemu, the binaries for both systems and the package the same bytes;
    the package installed, upgraded and removed there by hand, serving and
    using an exit node (Check a FreeBSD node); `make interop` passing under
    TCG here. The lab found Debian's cloud image asking every link's
    resolvers, which the CLI now names, with the stub as the hint.
  - **Open:** the lab's first run in CI, which waits for CI's budget.

Reproducible builds, for Linux and FreeBSD alike. The rest of the release work
— distro repositories — is M27 and the full Android app M28, after v1.0; a
minimal Android app is M10. Releases carry packages and a signed SHA256SUMS
already (`make release`).

- **Exit criteria:** (1) Linux/FreeBSD interop matrix green in CI (FreeBSD via
  qemu); (2) build artifacts for both reproducible byte-for-byte from two
  independent builders.

## M8 — Names

A resolver in juistd for two things: members' names (`mailer.home.juist`, the
MagicDNS equivalent), and **name overrides**, which point a public name at a
member so that members reach it through the tunnel instead of its public
address — `mx.example.net → mailer` puts every member's IMAP and submission
through the overlay, with the certificate still matching, since the name is
unchanged. Only members' lookups change; the rest of the internet still
resolves the public records.

Members are named under `.juist`, not under the network's name alone: a
network named as a public top-level domain is, `app` or `dev`, would have
the host route that whole domain to juistd. `NETWORK.juist` is also the
host's search domain, so `mailer` alone resolves. A device or network name
that is no DNS label has no name there.

Split in three, each shipped on its own:

- **M8a — the record.** Schema 8: a node record's `Names`, replaced whole by
  a quorum-signed `SetNodeNames`, so that a name points at a member, never
  at an address, follows renumbering and identity rotations, and goes with
  the member. The TCB takes a name in one form alone (lowercase ASCII, xn--
  for Unicode), of two labels or more, no address, nothing under `.juist` or
  a domain the host keeps to itself, and each name for one member.
  `juist names add DEVICE NAME` and `juist names remove DEVICE NAME` propose
  it, `juist names` and the device list show it, and an approver reads what
  each change points where. `juist grant` and `revoke` take roles alone and
  name the command for a subnet or a name given them.
  - **Built:** as above; `juist log upgrade` raises a network to schema 8.
  - **Validated:** `types`, `trust/log` and `cmd/juist` tests (see
    12-validating.md); a quorum short, a non-member, an address and a name
    another member holds are refused by the log, which every node runs.
- **M8b — the resolver and the host.** resolved takes one set of servers per
  link, and `juist0`'s is the exit node's where one is used. So juistd's
  resolver is the link's one server: on the device's IPv6 overlay address,
  port 41647, bound to the device, which the host's own queries come in by,
  and answering the host's own sources alone. resolved asks a link's
  servers through the link, which reaches a loopback address only from
  systemd 252.20 and 253, not Ubuntu 22.04's 249; the device's own address
  it reaches from 248, and takes a port from 246. It answers members' names,
  and overrides with A and AAAA of the member's overlay addresses, HTTPS
  and SVCB empty, since their hints carry the public address, and 30 s TTLs;
  everything else it forwards, to the exit node in use, else to the host's
  own resolvers, never resolved's stub. resolved gets `~NETWORK.juist` and
  `NETWORK.juist` as search domain, one routing domain per override in
  effect, and `~.` while an exit node is used. FreeBSD's resolvconf routes
  no domains: names are not wired there, and `juist status` says so.
  - **Built:** as above; `juist status` names the domain, or why the host
    does not resolve it, with the fix where resolv.conf bypasses the stub.
  - **Validated:** `internal/names`, `internal/dnsfwd`, `internal/resolved`,
    `daemon` and `cmd/juist` tests; by hand on Debian 12's cloud image
    (systemd 252), as the package: `mailer.home.juist` and `mailer` resolve
    to both addresses through resolved, a name the network lacks does not
    exist, a public name still resolves, and the uplink resolv.conf the
    image ships is named with its fix. The exit node's case goes into the
    interop lab with M8c.
- **M8c — opt-in, falling back, and visibility.** A device applies
  overrides only after its owner agreed (`juist names on`, like
  Tailscale's `--accept-dns`); members' names need no agreement, since they
  claim nothing outside the network. juistd stops answering an override
  while the device is stale, or while the member it points at is not
  reachable: the connection then goes to the public address, as without
  juist, instead of into a tunnel that is down, and a stale view redirects
  nothing beyond the TTL, like every other authority change. `juist status`
  lists the overrides in effect. Tested in the interop lab, where Debian
  runs resolved, without root.
  - **Built:** as above. Freshness and reachability are asked at each
    query, the last tunnel check's, so resolved keeps routing the name to
    juistd, which then forwards it as any other; a name is resolved
    publicly within a TTL of the check that finds its member down, at most
    a minute or so after it went. Answers carry EDNS where asked, without
    which resolved stops using EDNS with the server, for every name it
    forwards; the link's domains are negative trust anchors, so that a
    resolved validating DNSSEC takes juistd's unsigned answers. An exit node
    asks the host's resolvers, not its stub, for a member's query of a name
    it overrides itself, so that no member is answered an override it did
    not agree to. The resolver answers on the device's IPv4 address where
    the device holds no IPv6. `juist names add DEVICE NAME` hints at
    `juist names on` where the device granting has not.
  - **Validated:** `internal/names`, `internal/resolved`, `daemon`, `ipc`
    and `cmd/juist` tests; by hand on Debian 12 (systemd 252) as the
    package; and `make interop` under TCG, where each exit criterion but (2),
    which the log's tests hold, ran (see 12-validating.md).

**Still open: DNS over TLS for what juistd forwards.** Without an exit
node, what juistd does not answer itself, an overridden name's other types,
the names below it and one whose member is down, it asks the resolvers
resolved would, by resolved's routing read over D-Bus every 30 s but for
juist's own link, since its stub would route them back; it asks them in
plain DNS where resolved is configured for DNS over TLS.

**The trade.** Whoever can set an override can point any public name at a
member of their choosing on every device that accepted overrides. Verified
TLS turns that into an error, since the member lacks the certificate; plain
HTTP, SMTP with unverified STARTTLS and much internal tooling are exposed.
Hence a quorum, not an admin device, the opt-in per device, and the listing.
The cost of the feature itself: in normal operation the overridden names
depend on juistd, and a broken juistd on a device that accepted them loses
them for up to a TTL.

- **Exit criteria:** (1) in the interop lab, with resolved, an overridden
  name resolves to the member's overlay addresses and a connection to it
  crosses `juist0`, while no A, AAAA or HTTPS query for it reaches the public
  resolver (asserted by capture on the physical interface), and a name next
  to it in the same domain still resolves publicly; (2) an override signed
  below quorum, naming a non-member, or naming an address is rejected by
  every node; (3) a device that did not opt in resolves the name publicly;
  (4) a stale device, or one whose target member is unreachable, resolves the
  name publicly within one TTL; (5) withdrawing an override takes effect
  within gossip convergence plus one TTL for reachable devices and at the
  freshness TTL for partitioned ones.

## M9 — Publishing services

**Done** on 2026-10-03: M9a, M9b, M9c and M9d are built and validated as
their sections say, the exit criteria (1) to (7) among them, and reviewed
whole (M9 review 4), privileged on Fedora too and by hand against the RPM
(12-validating.md), and by hand with a public ingress and Let's Encrypt
(M9 review 6). M9e and M9f followed; with them M9 is closed, nothing of it
left open, and validated by `make ci-vm` on 2026-10-04 (12-validating.md).

A member's service reached from the internet by name, through an
**ingress**: a member with a public address that the quorum granted the role.
TLS ends at the service's side, so the ingress reads the name in the
ClientHello and nothing else. Public DNS needs one record per domain,
`*.pub.example.com` pointing at the ingress, never one per service:

```
browser ──TLS──▶ vps (ingress, SNI only) ──overlay──▶ target (TLS ends) ──▶ 127.0.0.1:2283
```

Inside the network, M8's override of each published name sends members to
the target directly, with the same certificate.

Split in four, each shipped on its own:

- **M9a — the ingress and published names.** Schema 9: the role `ingress`,
  which the validator refuses beside `admin` or `exit`; the network's public
  domain, set by quorum (`juist network domain pub.example.com`); and a
  member's published names, each one label under that domain with the port
  it is reached on, quorum-signed like a name (`juist publish add nas immich
  443`) and served once the target's operator agrees, as with a subnet
  (`juist publish serve`; until then `juist status` says "published, not
  served"). `juist ingress serve`
  on the device granted the role binds 443, and 80 for a redirect to https
  alone, with a firewall profile `juist-ingress`. The proxy reads SNI with
  `crypto/tls`'s own parser, splices TCP to the target through the overlay,
  and terminates nothing; PROXY protocol v2 is an option per name. It runs
  as a process of its own, with its own user and `CAP_NET_BIND_SERVICE`,
  dials the targets' overlay addresses, takes the published names read-only from juistd's
  socket, and holds no node key. Every member confines an ingress (below):
  it takes from one only connections to the ports it publishes and serves,
  and log sync, so a compromised ingress reaches nothing else. A stale
  ingress publishes nothing.
  - **Built so far:** schema 9, with `juist network domain`, `juist publish
    add` and `remove`, and `juist grant DEVICE ingress`; withdrawing a name
    or the role is no revocation, as for exit and names, and an ingress
    routes no subnet, so that its overlay addresses are all it sends from.
    `juist publish serve` and the confinement below, the ports a stale view
    or a withdrawn consent closes again. The ingress's call on the socket,
    below, read by `ipc.CallPublished`. The ingress itself, `juistd
    --helper ingress`: SNI read by `crypto/tls`, the ClientHello replayed to the
    target, PROXY protocol v2, and port 80 redirecting a served name;
    `juist ingress serve`, the `juist-ingress` unit and user, and the
    `juist-ingress` firewall profiles, in the deb and the RPM. The ingress
    is told only the names whose target announces it serves them; `juist
    status` there says whether it asked lately. `juist publish add` and
    `juist grant DEVICE ingress` hint the target's step, or take it where
    run on the target by its operator; `juist invite --ingress`.
  - **Validated:** unit tests of each part (see 12-validating.md), and
    `make interop`, where Debian, granted the role, serves a name FreeBSD
    publishes from the deb's unit, once FreeBSD's operator agreed, and
    FreeBSD takes nothing else from it, exit criterion (2). By hand, both
    packages as an ingress, the RPM on Fedora with firewalld and SELinux
    enforcing, the deb on Ubuntu with ufw (12-validating.md).
  - **Flows to confined peers** are bounded per address (4096) and in all
    (16384), so one peer's churn evicts its own flows and no other's.
- **M9b — TLS at the target, and the service member.** The target holds a
  certificate for each name it publishes, from ACME TLS-ALPN-01 through the
  ingress, terminates TLS and forwards plain HTTP or TCP to the local
  service its operator names (`juist publish add immich 127.0.0.1:2283`),
  which needs no certificate and no reverse proxy. A service that
  must not reach the network once compromised runs behind a **service
  member**: a juistd on gVisor through wireguard-go's `tun/netstack`, with
  no TUN, root or capability, as a container beside it on an internal
  network (`juistd --serve immich=immich-server:2283`). It answers its
  published ports alone. Its role, `service`, has every member confine it
  with no port open to it, so it opens no connection to any of them while
  its replies to theirs pass. Not `wgengine/netstack`, which imports `ipnlocal`
  and `controlclient`, 72 packages juistd does not have. `juist publish
  serve` on a full member warns that a compromised server there reaches the network
  and the LAN, and prints the CAA record that binds issuance to the target's
  ACME account.
  - **Decided:** TLS ends in a process of its own, `juistd --helper tls` as
    the user `juist-serve`, holding no key of the network's and asking
    juistd's socket only what this device serves, as the ingress asks what
    is published; it listens on the device's overlay addresses on the
    published port, and where another program holds that port it says so,
    and a name published on another port is served beside it, members then
    reaching it through the ingress. A service member has no way out. In
    Docker, its service sits on an internal network with it alone, in the
    isolated gateway mode, Docker 29's: an internal network otherwise leaves
    the host reachable at its gateway address, as measured on Docker 20.10
    and 29.8 (12-validating.md).
  - **Built so far:** `juist publish add NAME HOST:PORT`, which publishes
    NAME on this device where an admin key is here and adds where it goes
    to what the operator said before, kept apart from the word, which
    `juist publish serve --stop` withdraws alone; `juist publish remove NAME`
    takes both back;
    the terminator, with certificates from autocert by TLS-ALPN-01, ALPN
    offered for the challenge alone, a PROXY header believed from an
    ingress's address alone and passed on where the name asks for one;
    `juist-serve.service`, its user and `serve.sh` in the deb and the RPM;
    `juist-serve.path`, by which systemd starts the terminator while juistd
    keeps `/run/juist/serve-wanted`, for a name whose TLS juist ends or a
    share, and juistd telling it when it may stop, so that neither takes
    root on Linux;
    and a name published on 443 resolved to its target by members that
    accept names, where the target announces it serves it. The service
    member: `juistd --serve NAME=ADDR`, on a network stack of its own
    (`internal/netstack`, wireguard-go's adapted to the gVisor Tailscale
    pins, which wireguard-go's own copy no longer builds against), syncing
    the log there alone and ending TLS in its own process; the role
    `service`, alone and routing nothing, which every member confines with
    no port open to it. `juistd --ingress` and `--serve-tls` became
    `--helper ingress` and `--helper tls`. The CAA record: the terminator
    registers with the CA under autocert's own account key and tells juistd
    the account with each ask, and `juist publish add` and `serve` print a
    record for each name whose TLS it ends, which the terminator logs too,
    for a service member. On FreeBSD, the `juist_ingress` and `juist_serve` rc.d
    scripts and their users in the package: the ingress binds its ports as
    root and drops to its user, and the terminator runs as its user beside
    a parent that stays root to listen where juistd says this device
    serves, and nowhere else, there being no capability for the ports
    alone. `juistd --join LINK`, or `$JUIST_JOIN`, joins once started where
    in no network, so that a container joins by its environment;
    `examples/service-member`, a service and its service member in Compose,
    for Docker and Podman.
    `juist invite --service NAME` admits a service member publishing
    NAME in one step, which the approval says. The service member's image,
    `make image`, written by `packaging/image/mkimage` as docker save would,
    to the same bytes from one commit.
  - **Validated:** unit tests of each part, `make test-acme` with Pebble,
    and `make interop`, exit criteria (1) and (4), the terminator on Linux
    and FreeBSD, FreeBSD's ingress from its package, and with
    `JUIST_INTEROP_DOCKER=1` the service member as its image runs it, where
    see 12-validating.md.
- **M9c — sharing at once.** `juist grant mailer publish`, once and by
  quorum, lets a device publish under its own name,
  `mailer.pub.example.com`, without a vote each time: it signs a short-lived
  announcement of a port and an expiry and sends it to the ingresses through
  the overlay, outside the log; an ingress checks the grant, the name and the
  expiry. `juist share FILE|DIR` serves read-only under a random 128-bit
  path, until Ctrl-C or for `--for 24h`; `juist publish 8000` publishes a
  local HTTP server the same way. One certificate per device keeps shares
  out of Let's Encrypt's per-domain limit and out of CT logs.
  - **Decided:** the role `publish`, at schema 9 and never beside
    `ingress`; the device's name, lowercased, is its label, which the log
    holds as it holds a published one: a name that gives no label is
    refused the role, and the label is no other member's published label,
    publish label or name. The announcement is a field of the device's
    signed endpoint announcement, gossiped as the rest: a port and an
    expiry at most ten minutes ahead, renewed while the share runs, the
    share's own end where sooner; an ingress takes it from a live member
    holding the role, before the expiry. `juist share` and `juist publish
    PORT` hold a call to juistd open, which shares while it lasts and to
    `--for` at most; a device holds up to 16, each file's under its own
    path, which the terminator sends its requests by, and one port's beside
    them. The terminator ends TLS for
    the device's name and sends it to the CLI's server on loopback, which
    `juist share` runs as the user, from an `os.Root`, under a random
    128-bit path, and 404 outside it.
  - **Built:** the role, its label in the log, the announcement and its
    renewal, an ingress taking a share from a member holding the role while
    its announcement holds and ends no further ahead than a lease, the
    terminator ending TLS for it, the port opened to the ingresses, members
    resolving it directly, `juist share`, `juist publish PORT` and the
    status's Sharing line. Both take `--background`: the CLI runs again in a
    session of its own, which says the share and lets go of the terminal,
    and takes the share up again under its path where juistd restarts, for
    ten minutes at most; `juist share --stop` ends a device's share through
    juistd, whichever call holds it.
  - **Validated:** unit tests of each part (12-validating.md), and `make
    interop`, exit criteria (5) and (6) for shares: the ingress serves a
    share no longer once stopped or past its end; that one whose device is
    gone ends within a lease, the unit tests alone show.
- **M9d — the domain itself.** A member publishes the network's domain, not
  only a label under it, so that a site such as `juist.dev` is served from
  home: `juist network domain juist.dev`, then `juist publish add web
  juist.dev 443`, spelled out rather than by a sign such as `@`. Still
  schema 9, since M9 is not released: the empty label is the domain,
  published by one member at most, and every check that holds labels holds
  it too, against M8's names included, which today `publishedLabel` misses
  for a name equal to the domain. `Under` is the one place a name is made;
  the ingress and the terminator take the domain as its SNI, and an approval
  says that the domain itself is published. The apex needs its own A and
  AAAA records at the ingress, which a wildcard does not cover, and a CNAME
  may not be. Every device of a network runs a juistd that knows the empty
  label before an admin publishes it, since an older one refuses the state.
  - **Decided:** every member sends the whole domain to juistd, names on or
    not, which answers a name published there on 443, or shared, and the
    domain itself, with its device's addresses while fresh, and passes the
    rest on upstream; DNSSEC is off for the domain on members, by the
    negative trust anchor a routed domain takes. M8's names elsewhere still
    need `juist names on`: the domain's names are answered without it, as
    the approval of `juist network domain` says. CAA at the apex holds for
    every name under it without one of its own: `juist publish add` warns
    to give each device's names theirs. A name behind `--proxy` is reached
    through the ingress by members too, since its service may want the
    header.
  - **Built:** the empty label in the log, once and against M8's names,
    `@` for it in the names' file, the zone's public domain routed whole,
    `juist publish add [DEVICE] DOMAIN …`, `juistd --serve @=ADDR`, the
    approval's wording and the warning of `juist network domain`, the
    status naming the domain, and the hints for the apex's own records and
    its CAA.
  - **Validated:** unit tests of each part (12-validating.md), and `make
    interop`, exit criterion (7).

**The ingress on the socket.** A fourth caller beside root, the daemon's
user and the operator: the user `juist-ingress`, which the packages create
beside `juist` and leave as they leave it, and juistd looks up at start; no
appointment, and no such user, no ingress. It takes a pool of its own,
shared with the terminator, one slot each, with the readers' deadline and
request size, so no local user starves it and it starves no one. It may make one call, `published`, and no other, the status included:
for each name it serves, the target's overlay addresses, the port and
whether PROXY protocol is on, and nothing while this device is stale, so
that staleness is decided in juistd alone. The answer is a type of its own,
decoded with unknown fields ignored, so a juistd upgraded first does not
silence an ingress still running; every other call stays strict. The
ingress asks every 5 s and publishes nothing once two asks in a row go
unanswered: polling holds no slot, and a juistd that stops answering takes
the names down with it.

**Confined sources.** Tailscale's filter takes TCP without SYN, ICMP errors
and TSMP from any peer, to any address the node serves, routes and exit
included: a peer can be kept from opening connections, not from sending.
So conn confines the members whose role is `ingress` or `service` with two
hooks of its own, installed before `tundev.Start` and each calling the
engine's own after it (with `TS_DEBUG_CONNECT_FAILURES`, on by default, the
engine sets `PreFilterPacketInboundFromWireGuard` and
`PostFilterPacketOutboundToWireGuard` itself):

- outbound, after the filter: a TCP SYN, a UDP datagram or an ICMP echo
  request this node sends to a confined peer opens a flow in an LRU of
  bounded size, which every packet on it refreshes, so replies to what this
  node opened are known and a reply to the peer opens nothing; an RST ends
  a TCP flow, and FINs both ways a minute later, for retransmissions;
- inbound, before the filter: a packet from a confined peer passes only as
  the reverse of such a flow, or, from an ingress, as TCP to one of this
  node's own overlay addresses, on a port it publishes and serves or on its
  gossip port. An ICMP error passes where it quotes a flow this node
  opened to that peer. Everything else from it is dropped, UDP, ICMP and
  TSMP included, and so is anything for a route, subnet or exit this node
  serves. Packets from other members pass to the filter as now.

TSMP pings are answered before either hook, which tells a confined peer
only that the node is up. `conn.Peer` carries the role, and conn the ports
this node publishes and serves, both through `buildPeers` and the serve
state, rebuilt at each reconfig and swapped in atomically.

M9a is built in this order, each step tested on its own: schema 9 (the role,
the domain, the published names) with `juist network domain` and `juist
publish add`; `juist publish serve` and the confinement; the ingress's call
on the socket; then the ingress itself, with its unit and firewall profile.

Not planned: plain HTTP outward, which the ingress would have to parse,
reading every link; TLS ending at the ingress; and a domain run for every
network, as `ts.net` is, a central service
[01-requirements.md](01-requirements.md) excludes.

**The trade.** The ingress sees names, client addresses, timing and sizes,
and can drop; it logs them, a line per connection, and on port 80 the path
and User-Agent too, kept as long as its host's journal keeps them. Whoever controls it controls where the names point, and can get
a certificate for them by TLS-ALPN-01 to intercept public clients, though not
members, who reach the target directly; CAA with `accounturi`, one entry per
publishing device, closes that. A PROXY protocol header is believed from
an ingress's addresses, so any process on the ingress's host can name a
client to a service that takes one. The domain stays with its DNS provider:
delegated to the ingress by NS, a compromised ingress would serve the CAA
too. A server published from a full member is one compromise away from the
network and the LAN, hence the service member and the warning.

- **Exit criteria:** (1) in the interop lab, with Pebble as the ACME CA, a
  client outside the network fetches `https://NAME` through the ingress with
  a valid certificate, and a capture on the ingress holds no plaintext; (2)
  an ingress whose daemon is patched to connect to a port not published, to
  a name its target does not serve, or to a member publishing nothing, is
  dropped by that member; (3) a service
  member patched to open a connection to a member is dropped by it, while
  its replies pass; (4) a service member answers no port but its published
  ones; (5) a stale ingress, a withdrawn name, a removed target and an
  expired share publish nothing within gossip convergence, and at the
  freshness TTL for a partitioned ingress; (6) a share's path without its
  token gets 404 and lists nothing; (7) in the interop lab, a client outside
  the network fetches `https://DOMAIN` through the ingress, and a second
  member publishing the domain, or an M8 name equal to it, is refused.

## M9e — Renaming a device

**Done** on 2026-10-03, as below.

A device's name was fixed when it joined (`--name`, `--device`); the only way
to another was to remove it and join again, with new keys and addresses.
Schema 10 adds a record `RenameNode` that a quorum signs like any change,
naming the node by key, and `juist rename DEVICE NAME` beside `juist remove`.

- **Decided:** the new name passes `checkName`, and one that folds like
  another member's is refused rather than numbered as at a join, since a
  person chose it; the log refuses it too, as it does for holders. The name
  is a label, as the network's is: keys, addresses, roles, routes and public
  names stay with the node. Its share name, where it holds the publish role,
  follows it, so a rename is checked as an admission is
  (`checkNodeAdmissible`): refused where the new name gives no label, or one
  another member holds. `DEVICE.NETWORK.juist` follows the name, and the old
  one stops resolving; the approval says both. An admin key filed under the
  machine's old name keeps it, and the name a device proposes on joining
  another network stays its host's.
- **Built:** the record and its rule in the log, `juist rename`, the
  approval's wording, `juist log`'s line for it, the warning for a name that
  gives no DNS label, a running share said again under the new name, and a
  rename carried to the other admin devices, not the renamed one.
- **Validated:** unit tests of each part (12-validating.md), the in-process
  app renaming a device through a quorum of two, and `make interop`: lx
  resolves fb by its new name, at its addresses, and no longer by its old.
- **Exit criterion:** a renamed device is reached by its new name on every
  member that has applied the record, nothing else about it changes, and
  the test runs through the in-process app.

## M9f — The status page

**Done** on 2026-10-04, as below; the whole network's reach went to "Later".

A device serves the network's status page under a published name, in the
website's look (`juist publish status-page status`), until the Android app
shows the same: devices, how this device reaches them, published names and
shares, the alarms and the log's newest changes.

- **Decided:** the terminator renders it, holding no key of the network's
  and asking juistd's socket one call more, `status page`, answered only
  where the operator serves one; no helper or user of its own. Its target is
  `status-page[:WHAT]` where a name's HOST:PORT goes, so it is kept, listed
  and taken back as one. Members see all of it, known by the overlay address
  their connection comes from, never by a PROXY header; an ingress's address
  is the public's. The public sees what `--public` says: `none`, `services`
  (the default), `network` or `all`, the log's changes in `all` alone.
  Device names and the serving device are the network's, shown from
  `network` on.
- **Built:** as above; `internal/webstyle` holds the website's fonts,
  colours and wordmark for it and the share listing, and `internal/changelog`
  the log's lines for it and `juist log`. `juistd --serve
  status=status-page:WHAT` serves it from a service member.
- **Validated:** unit tests of each part (12-validating.md), and the page
  rendered in headless Chrome, day and night, at phone and desktop widths.
- **Review 1:** by hand, a member opening the page by `http://` reached
  another program on the target's port 80, members resolving the name to the
  target. A device's terminator now redirects port 80 of the addresses it
  serves on to https, where no other program holds it on every address, which
  `juist status` and the page warn of; the page sends HSTS. A service member
  answers no port 80, holding to exit criterion (4).

## M10 — Android, minimal

**Under way:** the app and its core are built, and by hand in an emulator it
joins by link, shows the network and pings a member; the exit criteria are
not met yet (below). Joining from another network and using an exit node,
added on 2026-10-04, are built; on a phone a Linux exit node carried its
internet, and is yet to across the VPN turned off and on and the phone
changing networks.

An Android app that joins a network as a member from anywhere, reaches the
others and sends its internet through an exit node, with none of the roles. It comes before the audit, so that M25 covers the app's key
custody and its in-process API; the full app is M28, after v1.

- **Joining.** The invite's link scanned as a QR code, which `juist invite`
  renders in the terminal beside the link; or the code typed or pasted, its
  words completed from enrollment's word list. Then the words to compare, in
  large type, and the wait for votes.
- **Joining from another network.** A link reaches its host from anywhere,
  as on Linux (M4): directly where the host can be reached, through the
  public DHT's rendezvous where both NATs can be punched, and through the
  relay of a member the link names where they cannot, as a carrier's NAT
  often cannot. A code stays LAN-only, as everywhere; where it finds no host
  the app says so and offers the link.
- **Using an exit node.** The app lists the network's exit nodes and
  chooses one or none, the choice the core keeps as `juist exit use` and
  `off` keep it. While one is in use the VPN routes `conn.Internet`, both
  families, beside the network's prefixes, listed since `excludeRoute`
  needs API 33, so private and special-use space stays outside, as on
  Linux; without `allowBypass`, so that no app leaves the tunnel by binding
  to the network beside it. The VPN's DNS server is the exit node's port 53
  (M6c), which the phone's every lookup then goes to. Failing closed as in
  M6a: while the chosen exit node cannot be used, the internet stays routed
  into the tunnel, the core refuses it, and the app says why. Where the
  service stops, the VPN ends and traffic goes direct, unless Android's
  always-on VPN blocks connections without it, which the app points to.
- **Status.** The network, this device and its addresses, freshness, and each
  member as reached: live, direct or through a relay, sought, absent. The
  alarms `juist status` reports are shown, and nothing `ipc.Status` does not
  carry.
- **Reaching members.** Ping and HTTP to a member's overlay address from the
  phone's own apps while the VPN is on, and a ping per member in the app.
- **Not in M10:** names, since with a DNS server set `VpnService` sends all
  the phone's DNS to it, so the resolver would have to forward everything
  else; serving as an exit node, and subnets; inviting; admin keys;
  relaying; several networks.

What it builds on: the tree builds for `android/arm64` (`make cross`), and
router, exit and holdings are left out there by build tag.

- **The core** is the daemon's service in the app's process, bound with
  gomobile, its control protocol over an in-process pipe instead of the
  socket: the app's sandbox takes the place of `SO_PEERCRED` and the operator.
- **A `conn.Plumber` for `VpnService`.** `OpenTUN` is `Builder.establish()`;
  addresses, routes and DNS are the builder's, and a change establishes
  again. Serving is refused.
- **The core's own sockets** stay out of the tunnel through
  `VpnService.protect`, by `netns.SetAndroidProtectFunc`;
  `netmon.RegisterInterfaceGetter` replaces the netlink enumeration Android
  refuses apps from API 30. Both are in the pinned Tailscale. `protect` sees
  only sockets opened through `netns`: the DHT (`discovery/dht`), the
  rendezvous (`internal/rendezvous`) and the guest's dial (`internal/guest`)
  open theirs through `net` and pass it by. Harmless while the VPN routes
  only the network, but with an exit node in use they would go through it,
  and stop with it, so that the core could not find it again; every socket
  the core opens on the underlay is protected before exit nodes are used
  (Linux exempts juistd's user for the same reason, M6a item 4).
- **Lifecycle.** A foreground service keeps the mesh up in Doze, and a
  multicast lock lets mDNS find members on the Wi-Fi.

The app looks finished from M10 on, not from M28: Kotlin and Compose, with a
theme of its own (colour, type, shape, spacing and motion as tokens), light
and dark, and every state `ipc.Status` can report designed rather than left
to an error. A screenshot test renders every screen in both themes, at 200 %
font scale, and in German and English, so a review needs no device. The
colours are `design/tokens.json`, by Material 3 role, which the website shares,
so that a member's reach (direct, relay, sought, absent) and an alarm look the
same in both; the launcher icon is `design/logo/icon.svg`, monochrome
`icon-mono.svg` ([14-website.md](14-website.md)).

Decided:

- **Key custody.** `node.keys` is sealed by an AES-256-GCM key Keystore
  holds, in StrongBox where the phone has one (`keys.SealWith`), and Go
  signs in memory, as on Linux. A copy of the app's files opens nowhere
  else; the WireGuard keys are in memory either way. A call through JNI per
  signature would put a signer interface in place of `types.PrivateIdentity`
  at each of its call sites, for an attacker who already runs code in the
  app.
- **Dynamic colour.** Not taken: the app's own theme alone, so that reach
  and alarms look as on the website.
- **minSdk.** 31.

- **Built:** the core in `mobile`, bound with gomobile (`make android-core`):
  the service in process (`ServiceOptions.InProcess`, `Service.Pipe`,
  `ipc.CallVia`), `conn.NewVPNPlumber`, whose router routes the network's
  prefixes whole, and the internet and the exit node's DNS
  (`daemon.VPNDNS`) while one is chosen, refused there where it cannot be
  used, establishes the device again only where that changes, and serves
  nothing; every socket the core opens on the underlay protected, the DHT's,
  the rendezvous's, the join's, the relay dial's and mDNS's through
  `underlay.ProtectWith`, the data plane's through `netns`; no subnet routes
  taken; the interfaces through `netmon`, which the app lists, for the
  announcement and mDNS; a ping per member (`CmdPing`, TSMP, which a member
  without a stack of its own answers too). `juist invite` draws the link as
  a QR code. The app in `android/` (`make android`): joining by QR code, link
  or code, the words to compare, the votes, the status with the alarms a
  phone can have, each member with a ping, a foreground service with a
  multicast lock, on again after a reboot or update; the exit nodes to
  choose from, or none, and why one is refused, with Android's always-on
  setting pointed to; a code that finds no host offers the QR code instead;
  the tokens generated
  from `design/tokens.json`, IBM Plex, the launcher icon from
  `design/logo`. Screenshots of every screen in four variants, both themes,
  both languages, 200 % in each theme (`android/app/screenshots`).
- **Validated:** `make check` and `make android-check` (12-validating.md);
  by hand in an Android 16 emulator: against a juistd without a device, the
  link pasted, the words compared, the admission, a direct tunnel, the
  status, a ping; against a service member, on a network stack, TCP from
  the phone's shell through the VPN, log sync both ways, and the phone
  removed, which it showed 3 s after `juist remove`; the DHT's rendezvous
  found a host behind another NAT, which the two NATs' one router, without
  hairpinning, kept from answering. Not yet: (1) in `make
  interop`, which runs no emulator, and a code, which needs the LAN the
  emulator's NAT is not; (2) past the freshness TTL; (3) to (5).

- **Exit criteria:** (1) in `make interop`, an Android emulator joins the
  network by the invite's QR code and by its typed code, pings a member and
  fetches a page from it over HTTP, directly and through a relay; (2) removed,
  it loses its tunnels as fast as a Linux member does, and past the freshness
  TTL keeps tunnels only to admin devices; (3) by hand, a phone on LTE joins
  by link a network whose members are all behind NAT, through the DHT and,
  with the invite's DHT off (`--no-dht`), through a member's relay, and
  reaches a member behind NAT; (4) in `make interop`, the emulator behind a
  NAT that picks a new port per destination joins by link through a
  member's relay; (5) in `make interop`, the emulator through a Linux exit
  node: its internet, IPv4 and IPv6, and its DNS leave by the exit node, and
  none of the core's own sockets; with the exit node stopped or its role
  withdrawn nothing leaves directly; after `off` everything goes direct
  again; and by hand, a phone on LTE through an exit node.

## M11 — More than HTTPS through the ingress

M9's ingress passes TCP to 443 alone, by SNI. M11 widens what it carries,
before the audit so that M25 covers it, in two parts shipped on their own:
a TCP service on a port of its own (M11a), then HTTP/3 over 443/udp (M11b).
Both are done.

## M11a — Publishing a TCP port

**Done** on 2026-10-05, as below, reviewed (M11 review 1) and validated by
`make interop` and by hand on Fedora and Ubuntu (12-validating.md).

A service that speaks no TLS, such as a Minecraft server on 25565/tcp,
reached from the internet through the ingress. With no ClientHello there is
no name to route by, so the ingress routes by port: a public port goes to
one published name, and every ingress of the network listens on it.

```
client ──TCP :25565──▶ vps (ingress, by port) ──overlay──▶ target :25565 ──▶ 127.0.0.1:25565
```

The name's record under the wildcard already points at the ingress, so a
client connects to `mc.example.org:25565`.

- **Decided:**
  - Schema 11: a published name may carry a public TCP port, signed by the
    quorum with the name. The log refuses a second name on the same public
    port, and 80, 443 and juist's own ports. The target's port stays the
    name's port, as now.
  - The ingress listens on each public port beside 443 and splices a
    connection to the target's overlay address at once, without waiting for
    a hello; PROXY v2 per name, the per-source and total limits, the idle
    timeout and the access log as on 443, the log line naming the port
    instead of an SNI. `juist ingress serve` opens and closes the ports in
    firewalld and ufw as the log changes; pf on FreeBSD stays the host's. A
    port another program holds on the ingress host is said by `juist status`
    there.
  - At the target, as for a name whose service ends TLS itself: the service
    listens on the overlay address once the operator agrees (`juist publish
    serve`), or juist passes the bytes on to HOST:PORT without ending TLS,
    from a full member or a service member. The confinement does not change:
    an ingress reaches only the ports a member publishes and serves.
  - Only the quorum publishes a TCP port. The publish role (M9c) shares on
    443 alone, since a public port is the network's, not the device's.
  - The spelling: `juist publish add DEVICE NAME PORT --tcp`, the public
    port the device's unless `--tcp=PUBLIC` gives another, such as 2222 for
    a device's sshd on 22, since an ingress's own sshd holds 22; and `juist
    publish add NAME HOST:PORT --tcp` on the device, the device taking the
    public port too. A name published by TCP stays so until removed: a
    command without `--tcp` is refused rather than turning it to TLS.
  - Members reach a TCP name at its device through M8's override where its
    public port is the device's and it has no `--proxy`, and through the
    ingress otherwise.
  - No SRV record is printed: its service name is the protocol's, which
    juist does not know; the handbook shows Minecraft's.
  - The log also refuses a public port that an ingress's own name goes to,
    which the ingress holds, and a name by TCP going to a port another name
    of its device goes to, or to 443 where the device holds the publish role.
  - The ingress holds every public port the log has while it runs, a name
    whose target does not serve it answering nothing, and so it does while
    juistd is silent: no other program on the host takes a port the
    firewall lets in. The firewall follows the log while the ingress runs:
    juistd lists the public ports in `/run/juist/ingress-ports` while this
    device is a fresh ingress, those alone the ingress says it listens on, a
    port another program held before staying that program's and its
    firewall rules', `juist-ingress-ports.path` runs `ingress.sh
    ports` as root, which juistd's `CAP_NET_ADMIN` could do by itself
    anyway, and the ingress's start and stop run it too, one run at a time.
    firewalld keeps the ports across reloads, `ingress.sh` noting its own
    in `/var/lib/juist-ingress-ports`; ufw marks them with a comment. A rule
    someone else made for the port stays theirs.
  - On FreeBSD, and wherever started as root, the ingress runs as its user
    beside a parent that stays root to bind 443, 80 and the public ports
    juistd says are published, as the terminator's does.
- **Built:** schema 11 and its rules; the ingress's listeners, splicing at
  once, PROXY v2, the bounds, the idle timeout and the access log shared with
  443; the report of the ports it listens on and those another program
  holds, which the status says; the terminator passing such a name's bytes on
  unread, on a full member and a service member; the CLI, the approval's
  wording ("by TCP on port P of every ingress"), the status page showing
  NAME:PORT with no link; `juist-ingress-ports.path` and `.service` in the
  deb and the RPM.
- **Validated:** unit tests of each part; `make interop`, exit criteria (1)
  and (3) at the ingress; by hand, exit criteria (3) in firewalld and ufw
  and (4), a Minecraft client through public ingresses (12-validating.md).
- **Not in M11a:** UDP, such as Minecraft's Bedrock edition on 19132/udp,
  which needs flows at the ingress, as M11b builds for QUIC.

**The trade.** For such a connection the ingress sees no name, only ports,
addresses, timing and sizes, but it sees the plaintext of every protocol
that does not encrypt itself, and CAA protects nothing there. A server
published from a full member stays one compromise away from the network
and the LAN, as in M9.

- **Exit criteria:** (1) in the interop lab, a client outside the network
  exchanges bytes with a TCP service published on a port other than 443
  through the ingress, and the service behind `--proxy` is told the
  client's address; (2) the log refuses a second name on a public port, and
  80, 443 and juist's own ports; (3) a withdrawn TCP name's port closes on
  the ingress, in its firewall too, within gossip convergence; (4) by hand,
  a Minecraft client joins a server on a member through a public ingress.

## M11b — HTTP/3 for published names

**Done** on 2026-10-06, as below, reviewed (M11 reviews 2 to 4) and
validated by `make interop`, `make load-lab`, 72 CPU-hours of fuzzing and by
hand on Fedora and Ubuntu (12-validating.md).

QUIC on the published path: a handshake in one round trip, no head-of-line
blocking on lossy links, and a connection that survives the client's
address changing. Until then the ingress passes TCP alone, by the SNI of
the ClientHello or by port (M11a), and the terminator passes the bytes TLS carried; HTTP/2 rides
that as it is (`--http2`), HTTP/3 cannot.

1. **The ingress on 443/udp.** It reads the SNI from the client's Initial
   packets: Initial keys from the Destination Connection ID (RFC 9001,
   5.2), header protection off, the CRYPTO frames reassembled until the
   ClientHello is whole. A browser's ClientHello spans several Initials with
   a post-quantum key share, and Chrome sends its CRYPTO frames out of order
   on purpose. What waits for the rest is bounded per source; a flow, keyed
   by the client's address and port, goes to the target's overlay address
   and idles out, within the per-source bounds TCP has.
2. **The terminator ends QUIC and HTTP/3** for names whose service speaks
   HTTP, and proxies each request to it as HTTP/1.1 or h2c: QUIC streams are
   no byte stream to pass on. golang.org/x/net/quic is not ready for
   production (v0.56.0 says so), so quic-go, pinned, which the TCB budget
   does not count.
3. **Advertising.** `Alt-Svc: h3=":443"` on the TCP path's answers, which
   only a terminator that proxies HTTP there can add, and the DNS `HTTPS`
   record `juist publish` prints, as it prints CAA.
4. **Firewalls and packages:** 443/udp in firewalld's, ufw's and pf's rules
   for the ingress, and both handbooks.

Decided:

- **The client's address:** a socket per flow on the tunnel, and ahead of
  the flow's datagrams, until the target answers, a datagram of its own
  holding a PROXY v2 header for UDP, behind `--proxy` alone. No room is
  left in the datagrams themselves: a browser's Initials take 1250 bytes,
  which the tunnel's MTU of 1280 carries over IPv4 alone, so the ingress
  sends a flow to the target's IPv4 address first. The terminator believes
  the header from an ingress's address alone, as for TCP.
- **The TCP path as a proxy:** `juist publish add NAME HOST:PORT --http3`
  says the service speaks HTTP; the terminator then proxies its requests
  over TCP too, HTTP/2 offered to clients whatever the service takes, and
  adds `Alt-Svc`. Its own Host goes to the service, and no header of the
  proxy's: `X-Forwarded-*` from the client are dropped. The status page is
  offered HTTP/3 as it is; `juistd --serve … --http3` offers it for a
  service member's names. A member lets an ingress send UDP to the port of
  a name offered HTTP/3 alone, whose QUIC juist ends: a service ending TLS
  itself stays on TCP. Each client connection has a proxy of its own to the
  service, at most 64 connections to it and 512 for all clients, gone with
  the client's; past 512 the idle ones go, and a request waits 5 s at most.
  An upgrade, as to a WebSocket, goes over HTTP/1.1.
- **Retry and amplification:** the terminator, by quic-go, sends Retry
  once 512 connections are open; the ingress, which cannot check QUIC's
  address validation, passes an address no more than three times what it
  sent until the terminator says, by a datagram holding a PROXY v2 LOCAL
  header naming the client, that the client completed its handshake, and by
  one carrying a NOOP TLV besides that a connection ended; the ingress sends
  the client's PROXY header for that, whatever the name asks, and believes
  one naming its flow's client alone, as a socket of its may have been
  another flow's. A connection ID proves nothing: a client moves to one the
  server gave inside the encryption as soon as its handshake completes. A
  flow unproven holds no slot of the bounds TCP shares, at most 16 from one
  host and 1024 in all, the oldest giving way past that, one still without a
  target first, and ends after
  twice the hello timeout; its access line is logged once a second at most.
  A first Initial is read only where its connection ID is of 8 bytes or
  more, and none past the rate of new flows, even from a flow's address. The
  terminator counts QUIC's connections against `--max-conns`. 0-RTT
  is off: it can be replayed.
- **One socket, several names:** a flow is the client's address; a
  connection from it to a name of the flow's target joins the flow, eight
  live at most, and one to another target is refused, as the ingress cannot
  tell their datagrams apart by connection IDs it cannot see; one arriving
  before the flow has a target is dropped, which its client sends again.
  juistd leaves the firewall's list as it was until the ingress says what it
  listens on, so that its restart closes no port the ingress holds.
- **Not in M11b:** a client's address changing keeps no connection through
  the ingress, which routes by address: QUIC's migration needs connection
  IDs an ingress can route by (QUIC-LB). Shares stay on TCP. The ingress
  cannot tell a name offered HTTP/3 from another, which the member's
  announcement does not say: a client's QUIC for one not offered ends at the
  member's confinement, holding an unproven flow meanwhile.
- **Built:** `internal/quicinitial`, the Initial packets of versions 1 and 2
  read with the keys their DCID gives, and the ClientHello's CRYPTO data,
  out of order and over datagrams, handed to crypto/tls's own QUIC parser,
  bounded at 8 KiB and 32 pieces; the ingress's QUIC on 443/udp, a flow per
  client address, a datagram of 1200 bytes the least that starts one, at
  most 16 waiting for the rest of a hello from one address and 1024 in
  all, the per-source and total bounds shared with TCP, the three-times
  bound, the access log's `access: quic` line; the confinement letting an
  ingress send UDP to the port of a name offered HTTP/3, and a fragment after the
  first to this node, as the filter does, since a datagram past the tunnel's
  MTU comes in fragments; the terminator's QUIC, quic-go pinned, a socket
  per address and port, the client from an ingress's datagram, HTTP/3
  proxied as HTTP/1.1 or h2c, the TCP path proxied with `Alt-Svc`;
  `--http3` on `juist publish add` and `juistd --serve`, and the HTTPS
  record printed; 443/udp in firewalld's and ufw's profiles, ufw's taken
  anew on upgrade, and the root parent binding it on FreeBSD.
- **Validated:** unit tests of each part, exit criteria (3) and (4) among
  them; `make interop`, exit criterion (1) with Chrome on the host; `make
  load-lab`, (5); `FuzzPayloads` clean for 72 CPU-hours, (2); by hand,
  Chrome through public ingresses with a Let's Encrypt certificate, over
  HTTP/3 and, with 443/udp blocked, HTTP/2 (12-validating.md).

- **Exit criteria:** (1) headless Chrome in the lab fetches a published name
  over HTTP/3 through the ingress, and over HTTP/2 where 443/udp is blocked;
  (2) the Initial parser has a fuzz target that runs clean for 72 CPU-hours,
  and drops what does not parse without state kept; (3) the ingress sends
  an unvalidated address no more than three times what it received from it;
  (4) a name not published gets no datagram forwarded; (5) `make load-lab`
  over HTTP/3 loses no visitor at the rate HTTP/2 holds.

## M12 — Break-glass disablement and key backup

**Done** on 2026-10-07, as below, reviewed (M12 reviews 1 to 5) and
validated by `make ci-vm` and `make android-check` (12-validating.md).

Genesis commits to one break-glass secret, which `juist create` shows once
and writes nowhere. Revealed, it ends the network for good; it does not
recover it. The threat model's custody property (02, item 2) rests
on this record, so the audit has to see it.

- **Decided:**
  - **Scope.** A revealed secret disables the network, as tailnet lock's
    disablement does: every member stops. Replacing the admin set was set
    aside: a secret in the log is read by every member that relays it, any
    of whom could reveal it again under admin keys of their own, and binding
    a record against that takes a commit and a reveal in two records and a
    delay the log, which has no clock, cannot measure. An end is the same
    whoever submits it.
  - **One secret, shown once.** `juist create` draws one and shows it as one
    line to keep offline, apart from the admin keys; nothing writes it. Ten
    in one file served nobody, and a file in the keystore sat beside the
    admin key, one vault that governs the network and ends it. The secret is
    shown wherever the genesis was handed over, failure or not, since the
    network may exist whatever the founder heard. A file `founded-NETWORK`
    marks the network as founded from the keystore, which the secrets' file
    did before. Networks from before keep their file of ten, which still
    works.
  - **Veto.** None. A stolen secret costs availability, never custody.
  - **The record.** `KindDisable` carries the secret and no signature, is
    valid under every schema, so existing networks gain it without a flag
    day, and counts wherever it hangs; nothing follows it. Its rules are in
    [08-trust-layer-notes.md](08-trust-layer-notes.md), "Disable records".
  - **Devices.** A device that sees the record hands it to every member,
    then drops every tunnel, which log sync runs through, and says
    `disabled` in `juist status`, juistd's report, the status page and the
    app; it raises no fork alarm. A device offline meanwhile finds no member
    to reach when it returns, so it says `no tunnel up`, not `disabled`.
    Changes to a disabled network are refused, and `juist reset` forgets it
    without `--force`. A build from before M12 cannot read the record and
    keeps running until it is updated.
  - **CLI.** `juist network disable` reads the line from stdin, without
    echo on a terminal, or from `--secrets FILE`, or an older network's
    file in the keystore; asks; and hands the record to juistd, which it
    needs.

- **Backing up the keystore.** `juist admins export NAME` prints an admin
  key as one line on stdout, for a pipe into a password manager, and `juist
  admins import NAME` reads that line from stdin and writes the key file with
  the keystore's modes, never through argv or a temporary file. The line
  carries a version tag and a checksum, so a truncated paste fails at import.
  Import refuses a name or a key the keystore holds already, and says whether
  the log still gives the key a vote. Node keys are not exported: a copy
  restored elsewhere is a clone of a member, and a lost device is removed and
  re-invited instead.

- **Exit criteria:** (1) a disable record revealing no secret of the network
  is refused, and one carrying a signature too; (2) one that reveals a secret
  ends the network on every device it reaches, wherever it hangs: on the
  chain, on a losing branch, below a compacted anchor, past a schema the
  build stops at; (3) a backup line cut short or altered is refused at
  import, and an import never replaces a key.

## M13 — HTTPS alone to the outside

**Done** on 2026-10-09, as below, reviewed (M13 reviews 1 to 6, the last for
security) and validated by `make ci-vm` and `make test-freebsd`
(12-validating.md).

A device on a network that passes TCP to 443 alone, or whose firewall
sorts traffic by simple DPI (a hotel's, a company's, a school's), reaches
its peers as one HTTPS client among others: with `juist set --https-only`
it sends nothing but TLS over TCP to port 443 of member relays, and DNS
queries for their names. Every packet then goes through a relay, at the
relay's throughput and latency. It does not hide juist from a censor that
probes servers or fingerprints ClientHellos (below). It is part of v1 and
comes before the audit, so that M25 covers it.

```
member ──TLS :443, SNI relay.example.org──▶ relay (DERP) ◀──UDP or :443── peers
```

- **Decided:**
  - **Settings, not flags.** `juist set --https-only[=false]`, `--proxy URL`
    and `--relay-name NAME` are the device's settings, kept in its state
    directory as its other choices are and changed by its operator, so that
    an installed package needs no unit edited. A change restarts the mesh.
    HTTPS alone is refused where juistd runs without a device or the
    netstack, since log sync runs in the tunnel.
  - **No UDP from the data plane.** magicsock's `SetOnlyTCP443(true)` and the
    self node's only-TCP-443 capability, which turns peer relays off: no
    WireGuard, disco or STUN over UDP, no peer relay, and netcheck measures
    by HTTPS (`/derp/latency-check`). The DERP map holds the relays' names on
    443 alone and no STUN server. No port mapper or captive-portal probe is
    linked at all.
  - **Nothing else outside TLS.** LAN discovery and the public DHT are off,
    the announcement carries no address, invite hosts are not dialled
    directly, and no code is looked for on the LAN.
  - **A relay on 443 under a real name.** `juist set --relay-name` names a
    relay-capable member's relay; the announcement carries the name from
    schema 12 on, which older members refuse; two relays announcing one
    name, the lower identity keeps it, and the name proves no relay's
    identity: WebPKI vouches for whoever holds the name's certificate. The relay shows a client asking for
    the name by SNI a certificate ACME issues by TLS-ALPN-01 (the terminator's
    path), and every other client the pinned one, so members on 443 verify it
    by WebPKI against the system roots and the rest by M3b's pin. A
    certificate forged for the name gains a relay's position (weakness 5 in
    [02-threat-model.md](02-threat-model.md)); a company's TLS interception
    passes. 443 is bound at each address members may reach the host at, not
    the wildcard, so the terminator keeps 443 of the overlay addresses:
    juistd gains `CAP_NET_BIND_SERVICE` for it on Linux by a drop-in
    `relay.sh` writes and takes back, never by default, and the root helper
    binds it on FreeBSD. On the ingress, which holds 443, the ingress hands
    the name's connections to the relay's own port on loopback after a PROXY
    v2 header, by TLS alone. STUN stays on the relay's own port.
  - **Every member falls back to 443.** A named relay's node at its name
    comes after its public addresses in every member's map, so a network
    that blocks the relay's port and UDP works without any setting.
  - **Announcements through the relay.** A device on HTTPS alone keeps its
    sealed announcement at the relays on 443, and asks them for the
    members', at the key the DHT would use. A relay answers for its
    network's live members alone, with the newest announcement it holds; it
    takes a member's own as found in the DHT. It learns nothing a member does
    not hold already, and bounds requests per client and in all.
  - **Invites.** A link names a relay by its name too (`r=` with a host
    name); a guest on HTTPS alone dials those alone, and a host waits there
    by name where it is on HTTPS alone or the relay's port fails it. A guest
    on a build from before M13 cannot read such a link.
  - **A company's proxy.** `juist set --proxy URL`, juistd's `HTTPS_PROXY`
    otherwise. DERP dials through it by the data plane's proxy hook, which
    answers for an HTTPS-only device's relay names alone; the rendezvous and
    invites take the same proxy; credentials in the URL go as Basic.
  - **Saying so.** `juist status` and the status page say `https only` and
    the relays on 443, and `warning: no relay on 443/tcp` where there is
    none; a relay's name, and why it is not served, has a line of its own.
    The Android app has no switch yet (M28); it falls back to 443 as every
    member does.

Not in this plan:

- **ALPN.** magicsock's DERP client offers none and, at v1.104.0, has no
  hook for its TLS config: a ClientHello as Go's programs send it, not a
  browser's. DERP needs HTTP/1.1 (`Upgrade`, a hijacked connection), so
  the most it could offer is `http/1.1`; that, or a ClientHello like
  Chrome's (uTLS), wants a hook upstream.
- **Active probing.** A non-member's `Upgrade: DERP` gets the server's key
  before admission refuses it, so a prober sees a DERP server.
- **HTTP/3.** WireGuard in HTTP datagrams (RFC 9298) would avoid TCP in
  TCP, but magicsock has no transport hook for it, and the networks this
  serves often block 443/udp.
- **A proxy that ends TLS.** One that passes no unknown `Upgrade` needs
  DERP over WebSocket, which v1.104.0 builds only under a debug tag and not
  on FreeBSD: read the pinned module again then.

- **Built:** the settings (`ipc.CmdSettings`, `juist set`), HTTPS alone in
  `conn` and `daemon`, the relay's name, certificate, 443 listeners and
  rendezvous (`relay`, `daemon`), the ingress's hand-off, links and invites
  by name, the proxy, `relay.sh` and the `juist-relay-443` firewall
  profiles, the root helper's 443, and the interop lab's walled devices.

- **Exit criteria:** (1) in `make interop`, a member whose namespace passes
  only TCP to 443 and DNS joins by a link, reaches its peers, keeps
  reaching a peer whose home relay moves, and does again after a restart;
  (2) a capture of its underlay holds nothing else, and nDPI classifies
  each flow as TLS, none as WireGuard, Tailscale or STUN; (3) its
  ClientHellos name the relay's DNS name, and the certificate is the lab's
  ACME CA's (Pebble); (4) a relay that is also the ingress serves both on
  443; (5) through a CONNECT proxy, criterion (1) holds.

## M14 — Coarse ACLs

**Done** on 2026-10-09, as below, reviewed (M14 reviews 1 to 3, two of them
for security) and validated by `make ci-vm` and `make test-freebsd`
(12-validating.md). Core 9 868 lines, audit scope 28 601, measured after it
(2026-10-10).

A policy in the log says which member may open what on which: one
quorum-signed record holds the whole of it, rendered by every member into
what its tunnel takes and sends. It also scopes M6: using an exit node, or
a subnet router's routes, takes a rule instead of being open to every
member. Without a policy record a network behaves as before.

Two members the policy keeps apart both ways are no peers at all: neither
installs the other, so no handshake or disco passes between them, and the log
reaches each through the members it may reach. Discovery follows the policy
too: a member's addresses are readable by its peers alone, in its
announcement wherever that travels (gossip, the DHT, mDNS, the relay's copy
of M13). Listings and `.juist` names show a member its peers alone. The log
stays whole on every member, names, keys and overlay addresses included:
hiding those conflicts with verifying the chain.

- **Decided:**
  - **One record, the whole policy.** `KindSetPolicy` (schema 13) carries
    the policy as structs, devices by identity key: rotation carries a
    reference along, removal drops it, and a rule left with no source or
    destination goes. Parsing, names and evaluation stay outside the TCB,
    which checks shape and references alone.
  - **The language is pf's filter subset.** `table <name> { … }` groups
    devices and tables, `service name = proto … port …` names ports, and
    `pass from SRC to DST [proto …] [port …] [service …]` allows. Sources
    are devices, tables or `any` (every member); destinations those, or
    `internet [via …]` for exit nodes, or a prefix inside a subnet router's
    routes. No `block`, `quick`, interfaces or addresses of members: what no
    rule passes is refused, and order means nothing. `test pass|block from
    DEVICE to …` lines are kept in the record and checked whenever it is
    set. No comments: the record could not keep them.
  - **One canonical text.** `juist policy` prints it from the record, with
    current names; `juist policy fmt` writes a file in the same form, as
    gofmt does, without the log (`-l` lists files not in it and fails).
    `edit`, `set`, `diff` and `check` read names against the log.
  - **Connections, enforced where they arrive.** `pass from A to B` lets A
    open connections to B and B answer them, not the reverse. Every member
    keeps every restricted peer to the flows it opened and the rules that
    peer has, statefully, in the confiner that keeps service members and
    ingresses today; Tailscale's filter takes TCP without SYN from any
    member. A sender drops what it may not open. Ping needs `proto icmp` or
    a rule without a protocol.
  - **Roles stay records.** The policy says who may use an exit node or a
    subnet; the role and the route grant say who may serve. Using an exit
    node passes its DNS too. A service member opens nothing whatever the
    policy says, and an ingress reaches what is published alone.
  - **Carriers.** Relays and vouchers are peers of every member, for
    juist's own traffic alone unless a rule passes more: they carry the
    log and its leases to members the policy keeps apart from the rest. In
    a network with neither, every two members stay peers for juist's own
    traffic, since nothing else would carry a change to them.
  - **Fails closed.** A member stale past the freshness TTL keeps its
    vouchers alone, as before, and under a policy passes nothing but
    juist's own traffic with them.
  - **Addresses for peers alone.** A member that is not every member's
    peer seals its addresses under a key of its own, derived per epoch and
    peer set, which gossip hands each peer wrapped under a key that pair
    derives from the X25519 keys the log holds. That pair key is classical
    until M15 mixes ML-KEM in. A member every member peers seals them
    under the group's key, as before.

- **Built:** the record (`types`, `trust/log`), the language and its
  evaluation (`internal/policy`), each peer's access in the confiner (`conn`),
  the peers, exit nodes, subnets and log sync it scopes (`daemon`), the sealed
  addresses (`internal/addrkey`, `gossip`), `juist policy`, and the lab's
  devices kept apart.

- **Exit criterion:** under a policy denying A→B, B drops A's packets even when A's
  daemon is patched to ignore its own outbound filter (receiver-side enforcement
  proven independently of sender cooperation); a node whose policy state is past the
  freshness TTL fails closed; a member without a grant for an exit node gets
  nothing forwarded by it, enforced at the exit node; two members kept apart
  both ways exchange no packet, and neither learns the other's endpoints.

## M15 — Post-quantum WireGuard

**Done** on 2026-10-11, as below. The post-quantum part, exit criteria (1)
to (5), reviewed (M15 reviews 1 to 4, the first three security reviews by
fresh reviewers); changes without a break and throughput, criteria (6) to
(8), reviewed (M15 reviews 5 to 7, two security reviews by fresh
reviewers). Both validated by `make ci-vm` and `make test-freebsd`, each
throughput step measured before and after (12-validating.md). Core 9 890
lines, audit scope 30 378, measured after it (2026-10-11).

Every pair of members mixes a preshared key into WireGuard's handshake that a
quantum computer cannot recover, so recorded tunnel traffic stays
confidential (harvest now, decrypt later). Authentication stays X25519 and
Ed25519; PQ authentication, which cannot be harvested now, is M17's. It
is part of v1 and comes before the audit, so that M25 covers it.

The engine carries a preshared key with no patch
([07-embedding-notes.md](07-embedding-notes.md)); what makes this a
milestone is agreeing on it. WireGuard holds one key per peer, the responder
cannot tell a wrong one from a lost packet, and a key held by one side alone
fails every handshake. Not Rosenpass: a daemon per link and no audit, where
juist's own key distribution and stdlib `crypto/mlkem` do the same
([research/building-blocks.md](research/building-blocks.md)).

- **Decided:**
  - **Schema 14, no record field.** At `types.SchemaPQ` every member sets a
    preshared key towards every peer, and its announcement names the newest
    epoch it holds and its store of pair keys (`Endpoint.Epoch`,
    `Endpoint.PairStore`), which older builds refuse; the gossip frame's
    `Pair` goes only to a peer that announces them. Below the schema nothing
    changes, so a member of the previous release and one of this one reach
    each other as before, and `juist status` says the network predates
    post-quantum tunnels.
  - **A group key first.** A pair's first key is `HKDF(seed, epoch, both
    WireGuard keys)`, the seed derived from the group secret of the lower of
    the two epochs the pair announce: the one both hold, so a member behind
    is reached without a message, and one that catches up moves the pair on
    by announcing. Seeds are kept for the last 64 epochs
    (`pairkey.SeedDepth`) apart from the keyring, since a seed answers no
    gossip or discovery; a peer further behind gets a key nobody holds and
    catches up from another member.
  - **A pair key next.** In the log sync between the two, the member with the
    lower WireGuard key leads four messages, each signed and naming both
    members, their WireGuard keys and both stores, so that none counts for
    a pair started over since: it encapsulates to the follower's ML-KEM key, the
    follower encapsulates back and confirms the key it derived, the leader
    commits with its own confirmation, and the follower takes it up. One
    session carries all four. The key is HKDF over both ML-KEM secrets, salted
    with the group key of the epoch the leader names, bound to the network,
    both WireGuard keys and both ciphertexts: no third member derives it, the
    group secret included. Every rise of the pair's epoch starts a new
    generation, so an epoch bump changes every key within a log sync; a
    change keeps the session and takes effect at the next handshake.
  - **Bound to WireGuard keys.** A pair key holds while both WireGuard keys
    and the peer's store are those it was made with: a rotation of node
    keys, or a store given up, takes the pair back to its group key. An
    identity rotation keeps it, and the leader is the lower WireGuard key, so
    a member that slept through one reaches the rotated device on the key the
    two had, which its catch-up needs. A pair goes once the log names
    neither key, not at an expiry, and a device the log no longer names,
    by identity or WireGuard key, starts a store of its own. No generation number is used twice in a
    store, and a follower names none past it: a leader whose follower says
    it uses a later generation, or none, starts one past both.
  - **No downgrade.** The follower uses one key, the last it took up, and
    moves only on the leader's confirmed commit. The leader, whose commit or
    its confirmation may be lost, uses the committed key, and tries the one
    before it where the tunnel is found down and the session gone, until the
    follower's message says it moved. Every key either side may use is a pair
    key or the group key, so blocking handshakes never takes a pair to none,
    and the probing cannot reach a key the follower does not use. A peer
    given a key where it had none loses the session it had, which mixes in
    none, passes nothing for 2 s and loses it again, past a peer the engine
    made from the lookup before. Towards a peer
    whose announcement names no epoch, an older build or one behind the
    upgrade, a member sets no key and keeps the peer to juist's own traffic,
    which seals itself: under schema 14 no traffic of the user's crosses a
    tunnel without a preshared key.
  - **Kept before told.** The pair keys and seeds live in `pairs.secret`,
    sealed as the keys are. A change is written and synced before any message
    shows it, and undone where it cannot be. A store lost or unreadable
    starts over under a new ID, which every peer reads as its pair keys given
    up.
  - **Paced.** A pair starts or answers one generation per 5 s
    (`pairkey.Pace`): what a peer can make a member encapsulate and write.
  - **Addresses too.** An address key derives from the X25519 scalar and the
    ML-KEM seed, and its wrap for a peer mixes in the pair key once the pair
    has one, so M14's sealed addresses are as post-quantum as the tunnels.
  - **Status.** `juist status` says how many tunnels are post-quantum and by
    which key, names those that are not and those with no key in common, and
    juistd logs each key a peer is given.

- **Built:** the derivations, the message, each pair's exchange and the store
  (`internal/pairkey`), the seed (`trust/secrets`), `conn.Peer.PSK` through
  both engine paths, the announcement's fields and the frame's (`gossip`), the
  store, the seeds, the exchange through log sync and the leader's probing
  (`daemon/pairkeys.go`), the address keys (`internal/addrkey`), and
  `juist status`.

- **Exit criteria:** (1) two members' handshakes carry a PSK, and a peer
  holding the right WireGuard key but the wrong PSK cannot complete one;
  (2) in `make interop`, an epoch bump changes the PSK while a ping across
  the tunnel loses nothing, and a member that slept through a bump reaches
  the others again without help; (3) blocking handshakes never makes two
  members that announce PSKs handshake without one; (4) a member of the
  previous release and one of this one still reach each other, and
  `juist status` says which tunnels are post-quantum; (5) with stage 2, a
  third member holding the group secret cannot derive a pair's PSK.

**Last in M15: changes without a break, and throughput.** The PSK is the
first change that reaches the data plane on every epoch bump, so M15 closes
by making every change to the device keep the tunnels running, and by tuning
the paths still slower than tailscaled's. Peers, endpoints, routes, the
filter and the nftables tables already change in place: peers through
`SyncDevicePeer`, routes as a diff, each table in one transaction, conntrack
never flushed. What still breaks connections, in this order:

1. **A test that holds a connection.** No test keeps a TCP stream open
   across a change; the existing ones check that a peer is reachable
   afterwards. A netns-lab test (`make ci-vm`) streams across `SetPeers`,
   egress and serve changes, a rotation and a renumbering, and counts
   resets and the longest stall. It is the measure for the steps below,
   so it comes first.
2. **A rotation in place.** `adoptRotation` restarts the whole mesh
   (`restartMeshLocked`): engine, magicsock, TUN, gossip, relay, HTTPS and
   DNS, refusing egress meanwhile and re-establishing Android's VPN. Instead
   the new key goes to `Reconfig`, which sets it on magicsock and the
   device, and `self` becomes replaceable in `conn`; peers re-handshake, as
   a new static key needs, and nothing else goes down. The rotation is
   noticed by the 5 s poll, which a log-change signal replaces.
3. **A renumbering in place.** `followAddrs` restarts the mesh twice per
   renumbering on every member, when the new address applies and when the
   old one expires. Instead the addresses change on the running device and
   the gossip listener rebinds. `linuxRouter.Set` deletes an address before
   reinstalling the routes naming it as source, a window without routes:
   routes with the new source go first.
4. **A router retry without an empty config.** After a failed `Reconfig`,
   `routerStale` hands the engine an empty router config to force a real
   retry, taking every overlay address and route off for one call; a
   recurring error would do that at every reconcile. The retry goes to the
   OS router directly instead, which retries only what failed.
5. **Fewer restarts for settings.** `--https-only`, `--proxy` and host
   conflicts restart the mesh in-process, `juist set --relay-name` and a
   package upgrade the process. Each applies in place where the test of
   step 1 shows it can; the disco key, drawn fresh at every start, is kept
   across a restart if that saves the gossip round before direct paths.

Throughput, where it lags tailscaled's defaults:

6. **The service member's netstack** (`internal/netstack`, all of a
   `juistd --serve` member's traffic): cubic and tailscaled's TCP buffer
   sizes instead of reno and 4 MiB, batches instead of `BatchSize` 1 and an
   unbuffered channel, RX checksum offload and GSO, GRO inbound. It
   registers TCP alone, so `ListenUDPAddrPort` fails with "unknown
   protocol" and `--serve … --http3` gets no UDP listener: fixed with a
   regression test.
7. **Confined peers without a global lock.** `confine.go` takes one mutex,
   `time.Now` and the LRU per packet in both directions for every confined
   peer, which every service member is: sharded by peer, flow state touched
   on SYN, FIN, RST and new UDP flows alone.
8. **UDP GRO forwarding on exit nodes and subnet routers.** tailscaled
   checks the uplink's `rx-udp-gro-forwarding` and `rx-gro-list`
   (`net/netkernelconf`); juist neither checks nor sets them. `juist status`
   warns on a serving node, or the exit-node setup sets them.
9. **Proxies that splice.** `internal/pipe` hides `*net.TCPConn`, so TCP to
   TCP in the ingress and terminator cannot use `splice(2)`, copies through
   32 KiB buffers and reads the clock per call.

Each throughput step is measured before and after, with `iperf3` across the
tunnel in the netns lab, and its numbers go into `12-validating.md`.

- **Exit criteria, this part:** (6) a TCP stream across the tunnel survives
  a peer change, an egress change, a rotation and a renumbering without a
  reset, and stalls no longer than a handshake; (7) a service member serves
  HTTP/3 on its overlay address; (8) steps 6 to 9 each show their
  measurement, before and after.

What still restarts, and binds a later change: the settings of 443
(`--https-only`, `--proxy`, `--relay-name`) restart the mesh in-process, as
each changes how every relay connection is made; a device that runs a relay
restarts on a rotation, its certificate going with the keys; `juist rotate
identity` restarts, its IPv6 address moving; a renumbering on the netstack
restarts, its listeners holding the addresses they were opened at; an
upgrade restarts the process. The disco key stays drawn per process: a peer
seeing a new one resets the sessions a new process no longer holds.

## M16 — Names for members alone

**Done** on 2026-10-11, as below, reviewed (M16 reviews 1 to 8, security
reviews by fresh reviewers in 1, 2 and 5 to 8, the sixth over the whole
milestone, area by area, with its completeness),
validated by `make ci-vm` and `make test-freebsd` (12-validating.md), the
Android app for schema 15 released. Core 9 954 lines, audit scope 30 633,
measured after it (2026-10-11).

A name published under the network's domain that the internet does not
reach: it holds a certificate from the CA as any other, so browsers take it
without a warning, and the access policy says which members may open it, by
name. A family's photos at `photos.example.org`, a team's wiki, an admin
page: on every member that should reach them, nowhere else.

- **The log** marks a published name `Members` (schema 15), set by
  `juist publish add … --members`, and kept by a later command that leaves
  it out until `--members=false`. On 443 by TLS alone, without `--proxy`:
  members reach it at its device; a share stays public.
- **The policy** takes a name as a destination, by its label under the
  domain: `pass from <family> to name photos`, and in tests and
  `juist policy test`. The rule lets its sources open the name's device on
  443, TCP and UDP, and the name alone there; to a public name, its port.
  Without a policy every member may open every name for members. A name
  published nowhere is warned of.
- **The device's word:** `--members` where the service is named, or
  `juistd --serve … --members` on a service member, marks it for members
  alone, and juistd serves it under its name only while the log has the
  name for members alone.
- **A service of its own:** a name for members alone is not served where
  another name's bytes, or a share's, reach its service as they are, since
  a client of that one could ask it for the name by Host; the terminator
  holds every name whose HTTP it proxies to its own Host. The device itself
  is no member it is for: a client of a public service there could make it
  ask.
- **Three places refuse what may not come:** the ingress passes a name for
  members to nobody but the CA, a TLS hello asking `acme-tls/1` alone,
  answers QUIC and port 80 for it as for no name, and logs `members only`;
  juistd tells the ingress and the terminator such names in a list of
  their own, which a helper too old to know it serves to nobody;
  the device ending its TLS takes it only from the overlay addresses of the
  members the policy passes, which juistd tells it, and from the ingress
  that same hello alone, so a compromised ingress gets no further; the data
  plane keeps everyone else from the device's port, as for any rule.
- **Certificates** come by TLS-ALPN-01 through the ingress, as for any
  published name: the name's public DNS points at the ingress for issuance
  and renewal, and the ingress learns nothing more of it than now.
- **Members reach it at its device**, by the name, through the tunnel, as
  juistd answers names published on 443 already. A member whose host does
  not route the domain to juistd (no systemd-resolved, FreeBSD, the Android
  app until M22) reaches it not at all: the ingress refuses it too, and
  `juist status`, where it runs, says so for each name for members.
- **Out of scope:** per-name access for a name passed by TCP, which carries
  no name to check; hiding that the name exists, which its certificate in
  the CT logs shows.
- **Exit criteria:** (1) from the internet, through the ingress and at the
  device's port through a compromised ingress, a name for members answers
  nothing but the CA's validation; (2) a member the policy passes opens it
  by its name with the CA's certificate, a member it does not is refused at
  the device though it send the right name, and the policy's tests and
  `juist policy test` say which passes; (3) the certificate is issued and
  renewed while it is for members alone; (4) a network on schema 14 takes
  it once upgraded, older members refusing what they cannot read, and the
  Android app for schema 15 is released.

## M17 — Post-quantum signatures

**Done** on 2026-10-13, as below, reviewed (M17 reviews 1 to 5, security
and performance reviews of the whole milestone by a fresh reviewer, its
findings re-checked twice), validated by `make ci-vm` and `make
test-freebsd` (12-validating.md), the Android app for schema 18 released.
Core 10 998 lines, audit scope 32 389, measured after it (2026-10-13).

Since M15 the tunnels and everything sealed are post-quantum, but every
signature is still Ed25519: records and their quorum, announcements, leases,
changes waiting for admins, join requests, pair-key messages, the relay's
forward proofs. A quantum computer forges with any public key the log names,
so a quorum of admin keys would admit whom it likes. Recording traffic
today does not help it, but the switch must reach every member before such
a computer exists, and the consensus target for the migration is 2029
([Valsorda, "Post-Quantum Cryptographic Right Answers"](https://words.filippo.io/right-answers/)).
That is why it comes first of what is left, and before the audit, so that M25
covers it. Closing the same gap, enrollment by code and juist's own TLS
connections become post-quantum too.

The rules it follows: ML-DSA-44 from the stdlib's `crypto/mldsa`, signing
the message whole, never HashML-DSA, deterministically as Ed25519 does;
keys kept as 32-byte seeds; no composite with Ed25519. The fallback the
article asks for in place of a hybrid is a cut-over: Ed25519, still sound,
introduces the new keys, then stops counting.

- **Decided:**
  - **Two schemas, one cut-over.** Schema 17 is a plain
    `KindSchemaUpgrade`, which every build can read: it caps a member's
    name bytes (below), and its members announce their ML-DSA keys.
    Schema 18 is reached by one record alone, `KindSetSigningKeys`, which
    takes every member's ML-DSA key and bumps the epoch: one ceremony, not
    one per member. Past it every record is signed
    by ML-DSA alone and an Ed25519 signature is refused; below it the
    reverse. It is never both required and never either accepted. An
    upgrade record cannot carry the keys itself, since a build too old for
    it must still decode it to stop. A new network starts at 18.
  - **Where a key enters.** At the cut-over a member's key comes in its
    announcement, with an endorsement, an Ed25519 signature by its identity
    over the key; the record carries both, since Ed25519 is sound when it
    is written. Admins hold their keys on no device the network knows, so
    at 17 each admin key registers its own beforehand, endorsed the same
    way, in a `KindSetAdminSigning` it signs beside the quorum
    (`juist admins receive`); the cut-over waits for all of them, so its
    quorum alone signs it, and every key it relies on is in the log before
    it. From 17 an admin key enters as `juist admins new` prints it, its
    identity, its signing key and the endorsement in one token, on the
    quorum's word as its identity always did, in a genesis or an added
    admin key; a member
    admitted brings its key in its join request, which proves it holds it;
    an identity rotated to brings its own in the rotation, which the
    quorum, the old key and the new one sign (schema 19). A member's
    key changes with its identity alone, which it signs, so no quorum moves
    a member's slot to a key of its own.
  - **One key, one identity.** No ML-DSA key is named by two identities,
    checked on every state, so a signature by one key never counts as
    another's. An identity that is both an admin key and a member's
    identity has one key for both.
  - **The identity stays a name.** `types.Identity`, the Ed25519 public key,
    keeps naming a member, deriving its IPv6 address and keying every map,
    but past the cut-over no record is verified against it. Making the
    identity a hash of the ML-DSA key instead would move every member's
    address.
  - **Derived from the seeds already held.** A device's and an admin's
    ML-DSA seed is HKDF of its Ed25519 seed, as an admin's sealing keys
    already are (`secrets.AdminRecipient`), so `node.keys`, an admin key
    file and M12's backups cover the new key with no new copy. A quantum
    computer recovers the Ed25519 scalar, not the seed it was hashed from.
  - **History below the cut-over stays Ed25519.** A device that has
    adopted the cut-over takes no record that does not descend from it:
    a branch hung below it, which a quantum computer could sign, is
    dropped unstored, and so cannot win fork choice or raise a fork alarm.
    For the devices still behind, a branch that reaches the cut-over beats
    one that does not, after the rule that a branch signed by a key its
    sibling removes loses and before every other, so that a revocation
    signed beside the cut-over cannot split those that saw it first from
    those that did not; it is to be reissued. A removed admin key that
    holds the quorum can still race its removal with a cut-over of its own:
    a device that adopts that first drops the removal, which a quantum
    forger could have signed as well, and is re-enrolled; `juist admins
    remove` at 17 says to cut over soon. Where each branch removes a key
    the other's signed, the cut-over does not decide. Copies of one
    cut-over signed by different keys, as two approvals completing its
    quorum at once make, are both kept, and the one built on further wins,
    then the lower hash: no Ed25519 forger extends it. Two different
    cut-overs from one head would split the network for good, so the CLI
    refuses to write one while another waits for votes. The cut-over's own
    epoch bump keeps that from moving a device's chain back an epoch. A
    device that adopts the cut-over only after such a computer exists is
    exposed to a forged branch from a member that holds one, until M18
    anchors it past the cut-over.
  - **Messages carry both.** Announcements, address keys, leases, waiting
    changes, pair-key and catch-up messages and admissions keep their
    Ed25519 signature and add an ML-DSA one once their signer's network
    is past the cut-over. A verifier past it requires the ML-DSA one,
    against the key the log names, and one behind it reads the Ed25519
    one, which is how a device that slept through the cut-over catches up.
    A catch-up answer by an identity the log does not name, as a member
    rotated to while this device slept, is taken on no authority, as
    before: the device speaks only once its log lists it. An admission
    names the admin's signing key, and the invite link its fingerprint.
  - **Discovery carries hints.** A signed announcement no longer fits
    BEP 44's 1000 bytes nor one mDNS answer. The DHT, a relay's
    rendezvous and the LAN carry it without its ML-DSA signature, sealed
    under the epoch's key as before, and a device past the cut-over takes
    it as a hint: held beside the full announcement, never in its place,
    dialed where newer, relayed to no one, saying nothing its author
    agrees to (an exit, subnets, DNS, published names, a share) and never
    lowering the epoch a full announcement names; one naming none makes its
    device look outdated, which carries none of a member's traffic. A hint
    numbered more than ten minutes past now is refused, so none pins
    itself in place. An echo of a device's own announcement moves its numbering only
    signed by ML-DSA. A member, or a
    device removed since the last epoch, with a quantum computer can point
    another member's hints elsewhere; the WireGuard handshake, keyed by
    the log, fails, which costs dials, not trust. An announcement claims a
    key or signs by one, never both, so a frame of them fits its budget.
  - **Enrollment.** After SPAKE2 the guest sends an ML-KEM-768 key inside
    the channel, the host encapsulates to it, and both take new channel keys
    from HKDF over SPAKE2's Ke, the ML-KEM secret and the transcript, which
    the session's binding then covers. SPAKE2 authenticates the exchange,
    which only has to hold now. The protocol version rises to 3, without a
    fallback to 2. The join request's proof is signed by both keys, which
    shows the guest holds the ML-DSA key it brings.
  - **TLS 1.3 between juist's own ends.** The relay's pinned and public
    configurations, the HTTPS-only client and `relay/forward` require TLS
    1.3 with X25519MLKEM768 alone. A proxy that terminates TLS without it
    can no longer carry an HTTPS-only device. ACME's challenge, the
    terminator, which browsers reach, and the TLS to an HTTPS proxy keep
    1.2.
  - **Sizes.** `MaxRecordSize` (4 MiB) and `MaxFrameSize` (8 MiB) stay. A
    records frame keeps 2 MiB beside its records, not 1: past the cut-over
    a frame's announcements, leases and pair message take up to 1.74 MiB,
    and a frame over the limit fails to encode every round. A lease may
    take 4 KiB, a catch-up message 8 KiB. A test encodes each at its caps.
  - **A member's name bytes.** From schema 17 a member's public names and
    published labels take at most 2048 bytes between them, so that a
    checkpoint at `MaxNodes`, names, published names and keys at their caps
    stays within `MaxRecordSize`. The upgrade to 17 is refused while a
    member holds more, naming it.
  - **Release signatures stay ssh-ed25519.** OpenSSH's `ssh-mldsa44-ed25519`
    ships beside the first once the OpenSSH that Debian stable and FreeBSD
    install verifies it; until then a second signature is one nobody can
    check.

- **Not changed:** the DHT's BEP 44 item key, which guards only who
  overwrites a sealed value (liveness, as the DHT is anyway); WireGuard's
  X25519 static keys, since an impostor without the pair's preshared key
  completes no handshake; the relay's self-signed ECDSA certificate and
  ACME's WebPKI ones, and the forward proof a host gives its relay, since a
  relay is trusted for liveness alone and SPAKE2 authenticates what passes
  through it; the proof juistd gives the CLI of a rotation, on the local
  socket; the APK signature, which Android's schemes keep to RSA and EC.

- **Exit criteria:** (1) past the cut-over, every verifier refuses each
  signed thing above when it carries an Ed25519 signature alone, and a test
  per kind shows it; (2) in `make interop`, a network of the previous
  release upgrades, its admin keys register theirs, and it cuts over
  without a gap in a ping; a member asleep across the cut-over catches up,
  which a daemon test shows, since the lab's two devices both sign it; (3)
  a recorded enrollment by code whose SPAKE2 key is handed to the attacker
  does not open the channel; (4) a juist-to-juist TLS
  connection offering TLS 1.2 alone, or no ML-KEM, is refused; (5) a
  record with every admin key's signature, a checkpoint at `MaxNodes` with
  names at their caps, and every frame at its caps stay within the limits
  above; (6) a branch below the cut-over is dropped by a device past it;
  (7) the Android app for the new schema is released.

## M18 — Schema 18 alone

**Done** on 2026-10-14, as below, reviewed (M18 reviews 1 to 4: an
adversarial review of M17 and M18 by six reviewers, signatures and the log,
gossip and discovery, enrollment and key exchange, TLS and the data plane,
the CLI, and the cryptographic design, its fixes attacked again three times),
validated by `make ci-vm` and `make test-freebsd` (12-validating.md). The
review's fixes raise the schema to 19 and want a new Android app. Core
10 845 lines, audit scope 32 340, measured after it (2026-10-14).

M17 left every rule of schemas 0 to 17 in place, and the way up from each
to 18: a cut-over record, a ratchet against branches below it, fork rules
around it, records verified by Ed25519 below it, and what gossip holds back
from builds that read less. Each is code to audit and a source of residual
risk (a removed admin key racing its removal with a cut-over, two cut-overs
from one head). The one network there is moves to 18 with M17's build; then
juist reads schema 18 and above alone.

- **Decided:**
  - **The move first.** The network is upgraded to 17, its admin keys
    register their signing keys, it cuts over to 18 and an admin writes a
    checkpoint (`juist log checkpoint`). A device whose log starts below 18
    then moves its anchor to that checkpoint and drops what lies below,
    once it has seen every live member hold the checkpoint, so that none
    still behind is left without a peer to catch up from; a peer asking from
    an anchor this device dropped is answered from its own. This lands
    before the network moves, in M17's build, and goes with the rest below.
  - **Nothing below 18.** A genesis, checkpoint or record below 18 is
    refused, and so is a log whose anchor is below it: such a device says to
    join again. The schemas' rules below 18 go, with the kinds only they
    wrote: `KindSetSigningKeys` and `KindSetAdminSigning`, whose numbers stay
    reserved; the steps up to 17 and 18 and their CLI (`juist admins
    receive` keeps setting the encryption key); the ratchet against branches
    below the cut-over, the copies-of-the-cut-over and cut-over fork rules
    and the dropped-records set; record verification by Ed25519; and what
    gossip holds back from older builds (relay names, epochs, schemas,
    signing claims, the second catch-up try for a sleeper from before 17).
    A network without a prefix of its own holds no address in 100.64/10,
    which members admitted before schema 4 kept. `KindSchemaUpgrade` stays,
    for 19 on, and so does telling a build that reads an older schema
    outdated.
  - **What the review of M17 and M18 found closes at schema 19.** An
    identity rotation names the new identity's signing key in what the
    quorum, the old key and the new one sign, and is refused below 19.
    Copies of one record, siblings with one `SigHash` and other signature
    sets, are that record: the lowest hash stands for them, and what hangs
    from any copy, the anchor's included, hangs from it; fork choice ties on
    the `SigHash`, and a key is a branch's signer only where the union of the
    copies' signatures needed it; a store keeps the two lowest copies, those
    bringing a key's signature no other carries, and those something hangs
    from. A hint says where to dial alone, never a key, relay pin, epoch or
    pair store. The enrollment words cover every key of the new device, its
    ML-DSA key included. The CLI makes every string juistd gives it
    printable text on no line of its own, and names juistd's device or relay
    name in a root command only where it is an interface or host name.
  - **Messages keep both signatures.** Announcements need Ed25519 as long as
    discovery carries them as hints; the others keep it too, since dropping
    it changes what builds at 18 send each other.
  - **Interop's previous release** is M17's, at 18: its network and this
    build's devices run together, and this build takes the device over.
  - **A chain below the epoch floor alarms.** Where fork choice over
    verified records moves the chain below the floor, a concurrent branch
    or a copy's late signature winning, the node holds the records and
    raises a rollback alarm naming the lost branch until the chain is back
    at the floor.

- **Open, for M19 to decide:** whether a switch fork choice demands is
  followed below the floor. The floor cannot tell it from a quorum-signed
  sibling withheld and released later, so nodes shown the same records in
  another order stay apart until an admin acts. Finality by a node's leases
  does not close it, since two nodes hold different leases and split
  again; one every node shares, such as the anchor a checkpoint sets, would.

- **Exit criteria:** (1) a genesis, checkpoint, record or anchor below 18 is
  refused, and no rule of a schema below 18 is left (no schema constant
  below 18 outside `types/schema.go`'s history); (2) a device whose log
  starts below 18 moves its anchor to a checkpoint past the cut-over once
  every member holds it, which a daemon test shows, and with the network
  past that the following build starts from there; (3) `make interop` runs
  M17's release beside this build; (4) the core is smaller by what goes.

## M19 — Log checkpoints

Only `juist log checkpoint` writes a checkpoint and nothing calls
`Authority.Compact`, so every log grows for good, and past
`MaxHashesPerFrame` records two nodes stop converging
([08-trust-layer-notes.md](08-trust-layer-notes.md), "The size constraint
that outlives the freeze"). Right after M17, which decided the record
sizes a checkpoint has to fit, and before the audit, so that M25 covers it.
Open, to decide in this order:

- **Proposing.** What prompts a checkpoint — a record count, a log size, an
  epoch bump — and which device drafts it, since it takes a quorum like any
  change and the admins must be asked to sign.
- **Compacting.** When a device compacts to a checkpoint it holds, and
  whether it keeps any history below the anchor for peers still behind it.
  A store that is not empty cannot yet move its anchor to a checkpoint it
  receives (`Bootstrap` takes an empty one), so a device behind a peer that
  compacted does not catch up. Every `Inform` also verifies the whole chain
  again, about a second at 4096 records. A keystore's pin (`cmd/juist/pin.go`) names the head it
  last verified, which compaction drops: the CLI then refuses juistd's log
  until the pin is deleted, as on every machine after the move to 18. A pin
  has to carry what lets a checkpoint stand in for its head, such as the
  admin keys it was verified under.
- **Joining.** Whether a device joining is handed the anchor instead of the
  whole chain.

- **Exit criteria:** (1) a network that has authored more than
  `MaxHashesPerFrame` records still converges on a new change, with no admin
  having asked for a checkpoint; (2) a device behind a peer that compacted
  catches up.

## M20 — Faster CI

`make ci-vm` takes 25 to 37 minutes, one step after the other, so a failure
late in the lab costs a whole run, and every review round of M24 and M25 waits on
it. It is to say where its time goes, stop at the first failure and do no
work twice, while the run that closes a milestone still passes or fails
wherever today's would.

Where the time goes today, from the code, not yet measured:

- the VM runs `make check` again, which the host passed before the push;
- `repro` builds juist and juistd from an empty build cache, tailscale and
  gvisor included;
- `make interop` builds the .deb and the FreeBSD package again, and the last
  done milestone's .deb from scratch;
- the lab decompresses and converts the FreeBSD image every run, boots
  Debian and FreeBSD under nested KVM, and fetches `pkg bootstrap`,
  docker.io, tcpdump and libndpi-bin from the mirrors every run;
- the race run lasts as long as its slowest packages: conn 142 s, daemon
  94 s, cmd/juist 74 s, trust/log 63 s, pairkey 57 s.

The plan, in order:

1. **Measure.** `ci/main.go` runs each make target as a step of its own and
   logs its time (`ci-vm: make check passed in 4m12s`), and the lab logs its
   phases: images, boot, setup, each subtest. The rest is ordered by what
   this shows.
2. **Stages, cheapest first.** A run stops at the first stage that fails:
   what only the VM shows (the host-network probes, the privileged tests),
   then the packages and the lab, then the cross builds, `govulncheck` and
   `repro`. `-from <stage>` resumes on the same tree after a fix.
3. **No work twice.** A tree that passed `make check` on the host, which a
   stamp with the tree's hash under `build/` records, runs in the VM only the
   tests that `JUIST_REQUIRE_HOST_NET` turns from a skip into a failure.
   `make interop` takes the packages `make ci` built. `deb-previous` is
   kept per milestone commit, and each lab image is kept converted, with a
   sum of its own.
4. **A provisioned lab.** Debian and FreeBSD boot from bases that are set up
   once, as the CI VM's are, keyed by the image's sum and the setup script;
   a run installs only juist, and needs no package mirror.
5. **The lab beside the VM.** `make interop` needs no root, so it can run on
   the host under KVM while the VM runs the privileged jobs: two at once,
   with no nested virtualization.
6. **The slow tests.** Fixed sleeps become waits on a condition, and tests
   that touch no shared state are made parallel, which shortens
   `make check` on every push as well.

Open decisions:

- **The closing run.** Which of these shortcuts the run that closes a
  milestone may take. Lead option: none of 3's; it runs every stage cold,
  `make check` and `repro` included.
- **The lab's host.** On the host it runs with the host's qemu and Chrome,
  not the pinned VM's. Whether the closing run accepts that, or keeps the
  lab nested.
- **The test cache.** Whether runs before the closing one drop `-count=1`
  for packages unchanged since a run that passed. Lead option: no, since
  Go's cache does not see every input a test reads, such as the host's
  network or root.
- **Stages in parallel.** The cross builds, `govulncheck` and the packages
  beside the lab, whose timed waits leave CPUs idle. Only if those waits do
  not start to flake.

- **Exit criteria:** (1) `build/ci`'s log gives each step's time; (2) a
  failure planted in each stage still fails the closing run, and a failing
  privileged test ends a run before the lab starts; (3) nothing in a run is
  built, converted or fetched twice; (4) the closing run passes in at most
  half of the 25 minutes recorded for it on the four-core host, and
  [12-validating.md](12-validating.md)'s table of gates carries the new
  times.

## M21 — Battery life on Android

A day with the app connected, the phone in neither battery nor data saver,
put juist at 65 % of the phone's battery use by the afternoon (2026-10-12):
too much to leave it on, which is what a VPN is for. The core runs on a
phone at a laptop's pace, and some of what it does costs more there. Before
the names on Android (M22), which are of little use on an app that cannot
stay on, and before the audit, so that M25 covers what changes.

Suspects, from the code, not yet measured:

- **A full node of the public DHT.** The core does not set `DisableDHT`,
  and the DHT runs not passive (BEP 43), so other nodes keep the phone in
  their routing tables and send it queries it answers, each one waking the
  radio and the CPU.
- **A multicast lock for as long as the VPN runs,** which has the Wi-Fi chip
  pass every multicast packet up, though only mDNS needs it.
- **Polls:** the service's watch loop every 5 s, the reconcile every 15 s,
  the tunnel check every 30 s, and magicsock's 3 s heartbeat, restarted for
  45 s by every probe.
- **No notion of the phone's state:** screen off, Doze and mobile data run
  at the pace of a laptop on mains.

The plan, in order:

1. **Measure.** In the emulator, an idle phone in a network of three: wakeups,
   alarms and packets per hour for the app's UID (`dumpsys batterystats`),
   and datagrams per minute by port, as the laptop's measurement takes them.
   A bug report from a real phone after a day, read with Battery Historian,
   says which of radio and CPU dominates. The result is the budget every
   step below is judged by, and the exit criterion's number.
2. **The DHT on a phone.** Passive, so that it asks and is never asked, or
   off where relays or members stand in, as on HTTPS alone.
3. **The multicast lock** only while mDNS is needed: an invite on the LAN,
   or a member last seen on the same Wi-Fi.
4. **Events instead of polls.** The watch loop, the reconcile and the host's
   DNS routing each become a timer on the next known deadline (a
   membership's expiry, a renumbering's) or a signal (a log change, netmon,
   resolved's `PropertiesChanged`), keeping a slow backstop: a missed event
   fails silently. Laptops gain it too.
5. **A keepalive that lets magicsock rest.** Without a relay every check
   still probes, since that holds the NAT mappings open, and each probe
   restarts magicsock's 3 s heartbeat for 45 s. A TSMP ping and a disco
   ping from the ping path both count as traffic; what keeps a mapping open
   without that is to be found in the pinned module.
6. **The phone's state.** With the screen off, in Doze and on mobile data,
   the quiet probe, the sync interval and the announcement stretch; the app
   says when they do. A tunnel in use keeps its pace.

- **Exit criteria:** (1) the measurement of step 1, before and after, is in
  [12-validating.md](12-validating.md); (2) an idle phone in the emulator
  stays within the budget step 1 sets, and a test fails when a change takes
  it past; (3) a phone with the screen off still reaches and is reached by
  a member within the stretched interval, and a phone woken by a packet
  answers it; (4) the app is released.

## M22 — Names on Android

The Android app resolves none of the network's names. With a DNS server set,
`VpnService` sends every lookup of the phone to it, so the core sets one only
for an exit node, which then answers them all (`mobile.errNoNames`). A name
for members alone (M16) is out of the phone's reach, and a published name
resolves to the ingress, not the tunnel. Taken from the full app (M28), and
before the audit, so that M25 covers a resolver that sees every lookup the
phone makes.

- **Lead options:**
  - **One resolver for all of the phone's lookups.** The core answers the
    network's names, its members' and its published ones, as juistd answers
    them for systemd-resolved (`ServeNames`), and forwards every other
    query: to the exit node where one is used, else to the DNS servers of
    the network beneath the VPN, which the app follows already for
    `setUnderlyingNetworks`, from a socket protected from the tunnel. With
    an exit node, the network's names are answered by the core too, not by
    the exit node's host.
  - **At an address of the overlay.** An app binds no port 53, and a packet
    to the phone's own address does not enter the tunnel, so the resolver
    answers at an address reserved in the network's ULA prefix, routed into
    the tunnel and taken by the core before the engine, as tailscaled's
    100.100.100.100 is. IPv6 alone, so it takes no address from the v4
    numbering.
  - **Failing fast.** A query the resolver cannot forward fails at once,
    not after Android's timeout, and stopping the VPN gives the phone its
    own DNS back.
  - **Status.** The app says, name by name as `juist status` does, where a
    name for members cannot be reached and why.

- **Open decisions:**
  - **Private DNS.** Which of Android's modes send lookups past the VPN's
    server, verified in the emulator; whether a host name set there leaves
    the network's names unresolved, and how the app says so. In the
    automatic mode Android tries DNS over TLS on 853 first, which the
    resolver refuses at once.
  - **The reserved address.** Which one, so that no member's address,
    derived from its identity, can take it.
  - **Short names.** Whether `addSearchDomain` gives the network's domain,
    so that a member's name resolves without it.

- **Exit criteria:** (1) in the emulator, with no exit node, the app
  resolves a member's name and a name for members alone to its overlay
  address and opens it through the tunnel, and every other name as without
  the VPN; (2) with an exit node, the network's names still resolve, and
  every other lookup goes to the exit node; (3) a lookup the resolver cannot
  forward fails within a second, and stopping the VPN restores the phone's
  DNS; (4) the resolver's input has a fuzz target; (5) the app says why a
  name cannot be reached where Private DNS passes the resolver by; (6) the
  app is released.

## M23 — Boundaries on a host

What one network's daemon, the LAN and a local user can reach on a host
running juist, closed before the audit, so that M25 covers it.

- **A user per juistd instance,** so that one network's compromised daemon
  on a host no longer holds the others' device keys (residual weakness 9 in
  [02-threat-model.md](02-threat-model.md)). An instance's home can then not
  sit in the default's 0700 one, each needs a runtime directory of its own,
  and the instance above has to be allowed to read the exact claims of the
  one below ([13-multi-network-notes.md](13-multi-network-notes.md)).
- **pf on FreeBSD** drops what reaches the overlay's addresses by another
  interface, as Linux does (residual weakness 8).
- **The FreeBSD helper's routes.** It refuses the host's links, loopback and
  multicast, but not a route over the host's own LAN, which a subnet route
  looks like; whether it checks the host's connected routes itself.
- **The read tier.** `ForReader` passes members' identities in `Reach` and
  their names in `Silent`, `TunnelsDown` and `PQ`, which the tier was
  narrowed to keep from any local user.

- **Exit criteria:** (1) with two networks on a host, installed as the
  package installs them, one network's juistd cannot read the other's
  device keys; (2) on FreeBSD, a packet from the LAN to a device's overlay
  address is dropped; (3) the helper refuses a route over the host's own
  LAN; (4) the read tier passes a local user no member's identity or name;
  (5) residual weaknesses 8 and 9 leave the threat model or say what
  remains of them.

## M24 — The internal security review

The review [15-security-review.md](15-security-review.md) plans, over the
audit scope as M17 to M23 leave it, so that the auditor's hours go to what a
reader cannot find. It starts from the fuzzing:

- **Fuzzing.** `waiting.Decode`, `types.DecodeLease`, the helper's protocol
  and the resolver's input, the Android app's included, have no target, and
  no `fuzz-long` run is recorded in [12-validating.md](12-validating.md).

- **Exit criteria:** (1) every parser of input from outside the membership
  has a fuzz target, and a `make fuzz-long` over each is recorded; (2) the
  review closed as its §6 says, its sizes, sessions and findings by
  severity recorded in [12-validating.md](12-validating.md); (3) every high
  and medium finding fixed with a test that fails without the fix, or
  accepted as a numbered residual weakness.

## M25 — External audit → v1

External security audit of the audit scope, in the tiers of
[06-verification.md](06-verification.md) §5, after M24's internal review:
the trust layer and enrollment at its core,
plus what M6, M8, M9, M9e, M10, M11, M12, M13, M14, M15, M16, M17, M19, M21, M22 and M23 add to it — route consumption and its forwarding helper, the
override record and the resolver, the published names, those for members alone, and the ingress, its QUIC Initial parser included, the
disable record, the preshared-key exchange, the ML-DSA cut-over and
enrollment's ML-KEM step, checkpoints and compaction, the Android app's key custody, in-process API, resolver and pacing, the ACL policy and its filter, the relay's DHT over HTTPS and its ACME certificate, a user per instance and FreeBSD's pf — fix findings, mature fuzz corpus (consider
OSS-Fuzz), implementation-vs-threat-model review, documentation of the
residual-weakness acceptances for operators, which the handbook's
trade-offs carry ([14-website.md](14-website.md)).

v1 is Linux and FreeBSD with M14's ACLs, and M10's minimal Android app;
packaging and the full app follow in M27 and M28.

- **Exit criteria:** (1) audit complete, all high/medium findings fixed and
  regression-tested; (2) the acceptances documented for operators; v1.0 tag.

## M26 — Multicast *(post-v1)*

Discovery multicast across the overlay: mDNS, SSDP, WS-Discovery, LAN games.
The overlay counts as one link for them. Multicast routing, streaming and
broadcast are out of scope; broadcast has no address to go to while every
overlay address is a host prefix.

Today nothing crosses: the pinned filter drops every multicast destination
before juist's rules, silently on the way out, and wireguard-go picks a peer
by destination address alone.

The plan, in order:

1. **Capture.** A multicast packet the host sends into `juist0`, IGMP and MLD
   excepted, is taken ahead of the filter, copied per peer, and the original
   dropped. The hook is `PreFilterPacketOutboundToWireGuardEngineIntercept`,
   which the engine already holds (`handleLocalPackets`), so juist chains in
   front of it, with a guard in
   [07-embedding-notes.md](07-embedding-notes.md#upgrading-the-pinned-tailscale).
2. **Transport.** Each copy goes IP-in-IP (protocol 4 or 41) from this
   device's overlay IPv4 address to the peer's, through `InjectOutbound`, so
   the outer address picks the peer and relays need nothing new. Every peer
   gets a copy: the receiving kernel drops groups nobody joined, and
   discovery traffic is small. Membership tracking waits until that proves
   too much.
3. **Delivery.** `PreFilterPacketInboundFromWireGuard`, also held by the
   engine, unwraps. The inner source must be the sending peer's own overlay
   address, as `AllowedIPs` requires of unicast, and the destination a
   multicast group in scope; the packet then enters through
   `InjectInboundCopy`. The receiver enforces a per-sender rate limit, since
   a sender's own limit binds only an honest one. The TTL is left as sent.
4. **Default-interface apps.** An app that joins and sends on the default
   route's interface never meets `juist0`. For groups an operator names,
   juistd routes the group into `juist0`, which takes the group off the LAN
   for that host. Whether common apps follow such a route is to be
   measured.
5. **avahi.** It skips point-to-point interfaces unless
   `allow-point-to-point=yes`, and a Linux TUN is one for good: the flag
   cannot be cleared. `juist status` hints at the setting where avahi runs.

Open decisions:

- **MTU.** A full-sized packet grows 20 bytes past the TUN MTU when wrapped.
  Sending it anyway is the lead option, pending a test over direct paths and
  relays.
- **IPv6.** Link-scope groups are sent from `fe80::` sources, which fail the
  source check and which `juist0` may not have. IPv4 comes first; IPv6 needs a
  per-member link-local address derived from its identity.
- **Default.** Multicast an app sends into `juist0` itself is forwarded by
  default, since the app chose the interface and every member already
  reaches every port; routed groups are opt-in.

Not planned: a TAP mode. Carrying Ethernet would need a virtual switch and
encapsulation, since wireguard-go carries only IP, and would lose the binding
of an overlay address to its member that the source check rests on.

- **Exit criteria:** (1) in the netns matrix, an mDNS query sent on `juist0`
  reaches the other members' listeners with the sender's overlay address as
  its source, directly and through a relay; (2) a wrapped packet whose inner
  source is not the sending peer's address is dropped; (3) a member whose
  daemon is patched to ignore the limit is cut at the receiver; (4) no packet
  from another LAN host, and no IGMP or MLD, crosses the overlay; (5) a
  listener joined on the default interface receives a routed group's packets
  from a member.

## M27 — Packaging *(post-v1)*

Distro repositories (apt, dnf, pkg) for the packages every release already
carries, and the readiness check that keeps an admin from stranding members
on an upgrade.

- **Exit criterion:** Linux/FreeBSD interop matrix green in CI via qemu;
  release artifacts reproducible byte-for-byte from two independent builders.

## M28 — The full Android app *(post-v1)*

The full Android app, on M10's: M6b's subnet routes through `VpnService`
routes, released as M27 releases the rest.

- **Exit criterion:** 3-platform interop matrix green in CI, Android by an
  emulator smoke test; the app's release artifact reproducible byte-for-byte
  from two independent builders.

## M29 — A store, and a messenger on it *(post-v1)*

Members leave each other data while the other is offline, with no server: a
key-value store replicated among the members' own devices, and a messenger on
it with groups, pictures and files, `juistmsg` on Linux and FreeBSD and a chat
in the app. It needs M10's app, not M28's. A device takes part if its owner
turns it on; nothing about it is the quorum's.

Not a DHT: every member holds the whole member list, so where a namespace
lives is rendezvous hashing over it, with no routing to attack. Not the
BitTorrent DHT either, whose items hold 1000 bytes, lapse within hours and
show strangers the traffic. Nothing here enters the trust layer: the store
can delay or lose data, never change membership.

1. **The store.** A Go package serving on the overlay, on Linux and FreeBSD
   as a daemon of its own (`juiststore`, its own user and unit), in the app
   inside its process. It holds none of juistd's keys and takes the members
   from juistd's read tier.
   - **Namespaces.** A namespace is an Ed25519 key, of two kinds: an
     *inbox*, which every member writes to and its owner alone lists, reads
     and deletes; and an *owned* namespace, which its owner alone writes and
     deletes and every member reads. The owner signs each request over a
     challenge of the holder's; a writer needs the public key alone. Values
     are sealed by their writer (HPKE to the reader, or under a key carried
     elsewhere), so a holder that ignores the rules learns nothing it holds.
   - **Entries.** In an inbox an entry's key is its hash, and the entries a
     set. In an owned namespace a key holds the value of the highest version
     the owner signed. Deleting is a signed tombstone, never a side effect
     of reading; every entry expires, after 30 days by default.
   - **Placement.** Three holders by rendezvous hashing over the members
     that announce a store, and the owner's own devices besides, so data for
     a device that is on reaches it at once. A holder coming back catches up
     from the others by anti-entropy, tombstones included.
   - **Limits.** Writes from current members alone; a removed member's
     namespaces are dropped. Quotas per holder, set by its operator, and per
     writer and namespace within it; values in chunks of 1 MiB.
   - **Announcement.** It gains a field of services, a name to a port and a
     key, which every member's decoder must take before any sends it: one
     schema bump, a new app with it, and no bump for a later service.
2. **Identities.** A chat identity is a key of its own that certifies the
   devices it speaks from; one device each at first. A person's phone and
   laptop are then one certificate more, linked by QR code between the two
   without the quorum, and every message goes to each device of an identity.
   Binding identities to device owners (the optional idea below) stays
   possible and is not needed.
3. **Messages.** Written to each recipient device's inbox, sealed to it and
   signed by the sender's identity; the recipient deletes what it has. Signed
   prekeys in the identity's owned namespace, rotated weekly, give forward
   secrecy across weeks, not per message; MLS may replace them.
4. **Groups.** A group's state (name, members, admins) is an owned namespace
   whose key its admins share, versioned like any value. A message is sealed
   once, its key wrapped to every member device, and written to each one's
   inbox. A device removed from the network leaves every group, and the next
   message is wrapped without it.
5. **Pictures and files.** Encrypted under a random key, in chunks in the
   sender's owned namespace; the message carries the key and the chunks'
   hashes. Above a cap, sent directly while both devices are on.
6. **`juistmsg`.** A TUI (Bubble Tea) on the local store: conversations,
   groups, sending and saving files, pictures inline where the terminal
   speaks the kitty or sixel protocol, `xdg-open` elsewhere. A binary and
   package of its own, depending on `juiststore`.
7. **The app.** A chat screen, notifications from the foreground service,
   the store on for its own namespaces; holding others' on unmetered Wi-Fi
   and mains power alone, by default.

Open decisions:

- **Beside juistd or in it.** Beside is the lead: a parser of members' data
  away from the device keys, and an optional package. It needs juistd to
  announce the store's port and key, and M14's filter to let members reach
  that port as juist's own traffic. In juistd it would reuse the gossip
  listener and announcement as they are.
- **A linked device's history:** none, from the other device, or from the
  store while it lasts.
- **Defaults:** the holder quota, the file cap for the store, the expiry.
- **The name** users see; `trust/store` is taken in the code.

A holder sees which namespace receives how much and when, and from which
member; it can delay, drop, or keep what it holds past a deletion until
expiry, but neither read nor forge it. That goes into
[02-threat-model.md](02-threat-model.md) as a residual weakness with the
code.

- **Exit criteria:** (1) in the netns matrix, A writes to B's inbox while B
  is off, B comes up after A has gone and reads it from a holder, and every
  holder drops it once B deletes; (2) a fetch or delete not signed by the
  owner, and a write by a removed member, are refused; (3) a group of three
  exchanges text and a picture, and a member removed from the network gets
  nothing written after; (4) in `make interop`, an emulator and `juistmsg`
  exchange messages and a file both ways; (5) a member writing past its
  quota is cut at a holder, and the others' writes still land.

## Later — The whole network's reach

Not scheduled. The status page, and `juist status`, show reach from the
device asked alone. Each member's own, live, direct or relayed per peer,
needs a field every member understands before any sends it, gated by a
schema, as the announcements' decoders are strict, as M15's epoch and pair
store were.
A summary in the announcement would re-sign and re-gossip it, and its copy
in the DHT, at every change of reach.

## Later — Battery life on laptops

Not scheduled. Done (M9): a quiet tunnel to a peer a relay can wake is
probed every 5 minutes rather than every 30 s, and mDNS slows from 2 s to a
minute while nothing changes; validated by unit tests alone. Events instead
of polls and a keepalive that lets magicsock rest are M21's. Open, in this
order:

1. **Measure.** Datagrams per minute on the underlay (magicsock's port, 5353,
   the relay's) and wakeups (`powertop`) of an idle laptop with three peers,
   with and without a relay, before and after M9. Every step below is
   judged by that number, so it is taken first.
2. **On battery.** Read the power source (Linux
   `/sys/class/power_supply/*/online` of a `Mains` supply, FreeBSD
   `hw.acpi.acline`) and, on battery, stop relaying though granted, and
   stretch the quiet probe and the sync interval. A relay that goes away moves
   its peers' home region, so the switch wants hysteresis, and the status
   says when it happened.

## Deferred (post-v1, schema must not preclude)

Kernel WireGuard fast path for public-endpoint nodes ·
hardware-backed admin keys (FIDO2/PIV signing, once tokens sign with ML-DSA) · sealing the node key, a 0600
file in v1 (TPM, kernel keyring; FreeBSD: geli) · update transparency log ·
macOS, which `make cross` keeps compiling, untested beyond that · Windows/iOS.

## Optional idea — Device owners and an identity provider

Not planned; SSO/OIDC stays a non-goal ([01-requirements.md](01-requirements.md)).
Recorded so M14's schema leaves room for it. The rule it rests on: adding a
member is the dangerous direction, removing one costs at most availability, so
an identity provider may remove alone but never add alone.

1. **Owners.** A device record names its owner, quorum-signed, in the same
   namespace as an admin key's `Holder`, so `alice` the admin and `alice` the
   owner are one person. It gives offboarding (remove every device of an
   owner), ACLs by person or group in M14, and `juist devices` showing whose
   device is whose. The quorum asserts the binding; nothing checks it against
   an IdP. A schema bump, like schema 3.
2. **Scoped admin keys.** A key whose votes count only for some kinds of
   change, today every vote counts for every change. A remove-only key lets a
   SCIM or webhook receiver remove a deprovisioned owner's devices at once; if
   it is compromised it can remove members, never add one.
3. **IdP-checked joins.** An enrollment service checks an OIDC login and signs
   a join naming the logged-in user as owner, with a vote the quorum policy
   keeps below the quorum, so a human admin co-signs. Giving it the full
   quorum is Tailscale's model, visible in the log as an operator's choice.

Rejected: ID tokens in log records that every member verifies. Members would
fetch the IdP's JWKS, which breaks LAN-only operation, tokens expire while
records do not, every member would hold every owner's address, and the IdP
would become trusted infrastructure. Admin keys are not bound to IdP accounts:
that makes the IdP vouch for the key and weakens it; where a key is kept is
custody, not protocol.

## Optional idea — A gateway between two networks

Not planned. A company keeps its people's devices in one network and its
servers in another, and a gateway, a member of both, routes the servers'
network into the clients'. A server then opens nothing to a client, the
servers' network holds no laptop, and a leaving person is removed from one
network alone.

Today, by reading the code rather than by a test: the gateway runs both as
instances (M5), a quorum of the clients' network grants it the servers'
ULA /48 as a subnet (M6b), which `ValidateRoute` takes, and the clients'
instance masquerades onto `juist1` as onto a LAN, so the servers see the
gateway's address alone. What is missing:

1. **IPv4.** The servers' /22 lies in 198.18/15, which no route may cover,
   since other overlays on a client's host may hold it. A grant naming
   another juist network's prefix would be taken by a client only where none
   of its own networks claims an overlapping range, as M5's claims decide.
2. **Names.** `DEVICE.servers.juist` resolves only on members of that
   network; the clients would send the zone to the gateway, as M6c sends DNS
   to an exit node.
3. **A test.** In the netns matrix: a client in A, the gateway in A and B, a
   server in B, both families, and a server that cannot open a connection to
   a client.

What it does not change: the servers see the gateway, not who used it, and
every client still holds the clients' network's whole log, so it knows every
other client's name, keys and overlay addresses, and reaches them unless the
access policy (M14) keeps them apart. Hiding
members from each other conflicts with full replication, which verifying the
chain rests on. An access VPN where clients know only a hub and access
follows an SSO login is a hub-and-spoke design with a central policy, not
this one; for owners and an identity provider see the previous section.

One network under an access policy (M14), clients reaching the servers and not
each other, is the direct way to the same end, IPv4 and names included; the
gateway is for keeping the servers out of the clients' log.

## Later — Networks of phones alone

Not scheduled; after M28, whose names it uses. A network whose every member is
an Android phone, created, invited to, governed and kept fresh from the app,
whose members reach each other without a VPS: a family's phones, and a
peer-to-peer chat between them. A relay member stays the answer that always
works; this plan makes it unnecessary where the networks the phones are on
allow it.

The case it has to serve: two phones, both behind NAT that punches nothing,
such as two carriers' mobile data, and nothing else of their own. Two such
NATs meet only through a third party both reach, so where IPv6 gives the pair
no path, that is the public DERP of step 4.4, and being in one place is the
only way to need none.

1. **Measure.** Which pairs punch directly today: Wi-Fi to Wi-Fi, Wi-Fi to
   mobile and mobile to mobile, across Telekom, Vodafone and O2, IPv4 and
   IPv6, and each carrier's NAT mapping and filtering. Step 4 is judged by that
   table, so it is taken first.
2. **Governing from the app.** Genesis on the phone, its admin key sealed by
   Keystore as `node.keys` is (M10), which M25's audit did not cover for
   admin keys, so it wants a review of its own. The app invites (the QR code
   on its screen, the code on the Wi-Fi, a link through the DHT's
   rendezvous), shows the words, votes, approves carried changes (M5b),
   removes a device and grants roles. Genesis asks for a second admin phone
   or M12's backup, since a lost phone holding the only admin key ends every
   further change.
3. **Freshness.** A phone may hold the `voucher` role and vouches while its
   service runs. As long as one voucher phone is on and reaches the others,
   no member falls back to vouchers only.
4. **Reach without a VPS**, cheapest first:
   1. **IPv6.** Carriers give phones global addresses, so between two of
      them only stateful filters stand, which a simultaneous open may pass;
      step 1 says how often.
   2. **Port mapping.** A phone on a home Wi-Fi maps a port on the router by
      UPnP, NAT-PMP or PCP, and one reachable side is enough for a pair. That
      is magicsock's portmapper, which juist does not link today
      (`tailscale.com/feature/portmapper`); Linux and FreeBSD members gain it
      too. It opens a port on someone's router, so `juist status` and the app
      say so, and it can be switched off.
   3. **A phone relays.** A member reachable by either of the above relays for
      those that are not, granted `relay` by the quorum as any relay is, and
      by default on unmetered Wi-Fi and mains power alone. Either M3b's DERP
      relay in the app's process, which wants a TCP port mapped too, or
      Tailscale's peer relays (UDP, `feature/relayserver`), whose candidates
      magicsock takes from the packet filter's `peercap.RelayTarget`, which
      juist would set from the role. Which, and whether a peer relay's
      allocation needs a DERP path, is read in the pinned module first.
   4. **A public DERP server**, last, where no member relay serves the pair.
      It is an untrusted public helper as the STUN servers and the DHT are
      ([01-requirements.md](01-requirements.md)): it carries WireGuard's
      ciphertext and can delay or drop it, nothing more, and it passes HTTPS
      on 443 where a school's or a guest Wi-Fi blocks UDP. It enters the data
      plane's map as a region with a home score below any member relay's, as
      the STUN-only regions do. Two devices meet only through a region both
      use, so whether and which is the network's choice, a quorum-signed
      setting in the log (a schema bump) rather than a device's flag; the app
      offers it at genesis, and Linux networks may choose it too. What its
      operator sees is weakness 5 in [02-threat-model.md](02-threat-model.md).
      Open: which servers the default names. Tailscale's are run for its
      customers, used by Headscale by default and tolerated, not promised; a
      DERP the juist project runs is central infrastructure, though nobody
      has to trust it.
   5. **Otherwise** the pair stays sought, as today, and the app says so.

   Rejected: public TURN servers, which magicsock does not speak.
5. **Joining without a relay.**
   1. **In one place.** By code on the same Wi-Fi, or on a hotspot the
      inviting phone opens, which needs nothing else; that the invite and
      mDNS listen on the hotspot's interface is tested.
   2. **From afar.** A link names the network's public DERP as it names a
      member's relay (M10). Forwarding at a member relay is juist's own HTTP
      endpoint (`relay/forward`), which a public DERP server does not have,
      so the host and the guest, under a key of its own, run the handshake as
      DERP packets in the region the link names; the server sees only what
      the link's secret seals. DERP drops packets when a queue fills, so the
      handshake carries its own retransmission.
6. **Reaching an app on a phone.** M10 tried a phone's connections out, not
   in. An app listening on the phone's overlay address takes a connection
   from another member through `VpnService`, tested. Without an access policy
   (M14) every member reaches every port a phone's apps open.

The chat is M29's, whose store holds a message for a phone that is off on
the members that are on.

- **Exit criteria:** (1) in `make interop`, three emulators and no other
  member: one creates the network, invites the others by QR code and by code,
  removes one, and the rest keep freshness through a voucher phone; (2) by
  hand, phones on two carriers' mobile data and one on a home Wi-Fi with UPnP
  reach each other, directly or through the phone at home, and each status
  says which; (3) an app on one emulator accepts a TCP connection from
  another; (4) in `make interop`, two emulators, each behind a NAT that
  picks a new port per destination, with nothing else but the harness's
  DHT and a DERP server standing for a public one: one creates the network
  and chooses that DERP, the other joins by link, both reach each other and
  keep freshness, and they are sought once the quorum withdraws it; (5) by
  hand, a phone joins by code on the inviting phone's hotspot.
