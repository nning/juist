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
epochs — and one that is not yet listed tries another peer. A refusal is
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
[02-threat-model.md](02-threat-model.md), and a user per instance is for M12.

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
rotating, removing or backing up (M11's `juist admins export`) the key of one
network touched the others.

What was built, in the plan's order:

1. **A new key for every network.** `juist create` creates one, named for the
   network as its break-glass file is (`admins/alex@home.key`), so that a
   rename (schema 6) moves nothing. In the log the admin is still "alex".
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
covers Linux; FreeBSD's side (pf) comes with M7, and Android's with M13. Split
in three, each shipped on its own: exit nodes first, as the feature asked for,
then subnet routers, then the exit node's DNS.

**Done** on 2026-09-28: M6a, M6b and M6c are built and validated as their
sections say, privileged and by hand against the packages. Untried: a
client below systemd 256, whose resolved polkit asks without the device.

**Before ACLs, unscoped.** Coarse ACLs come at M14, so until then using an exit
node is open to every member: the quorum grants the role per exit node, and each
client's owner chooses whether to use one, but no grant says *which* members may.
A subnet router's prefixes are likewise reachable from every member. The
trade is accepted in [02-threat-model.md](02-threat-model.md) item 7; M14 scopes it.

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
    comes with M13's. `make interop` is the lab, `interop/`: a Debian 12
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

Reproducible builds, for Linux and FreeBSD alike. The full Android app and the
rest of the release work — distro packages, signed releases — are M13, after
v1.0; a minimal Android app is M10.

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
    `--for` at most, one at a time per device. The terminator ends TLS for
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

An Android app that joins a network as a member and reaches the others, with
none of the roles. It comes before the audit, so that M12 covers the app's key
custody and its in-process API; the full app and its release are M13.

- **Joining.** The invite's link scanned as a QR code, which `juist invite`
  renders in the terminal beside the link; or the code typed or pasted, its
  words completed from enrollment's word list. Then the words to compare, in
  large type, and the wait for votes.
- **Status.** The network, this device and its addresses, freshness, and each
  member as reached: live, direct or through a relay, sought, absent. The
  alarms `juist status` reports are shown, and nothing `ipc.Status` does not
  carry.
- **Reaching members.** Ping and HTTP to a member's overlay address from the
  phone's own apps while the VPN is on, and a ping per member in the app.
- **Not in M10:** names, since with a DNS server set `VpnService` sends all
  the phone's DNS to it, so the resolver would have to forward everything
  else; exit nodes and subnets; inviting; admin keys; relaying; several
  networks.

What it builds on: the tree builds for `android/arm64` (`make cross`), and
router, exit and holdings are left out there by build tag.

- **The core** is the daemon's service in the app's process, bound with
  gomobile, its control protocol over an in-process pipe instead of the
  socket: the app's sandbox takes the place of `SO_PEERCRED` and the operator.
- **A `conn.Plumber` for `VpnService`.** `OpenTUN` is `Builder.establish()`;
  addresses, routes and DNS are the builder's, and a change establishes
  again. Serving and egress are refused.
- **The core's own sockets** — data plane, log sync, DHT, mDNS — stay out of
  the tunnel through `VpnService.protect`, by `netns.SetAndroidProtectFunc`;
  `netmon.RegisterInterfaceGetter` replaces the netlink enumeration Android
  refuses apps from API 30. Both are in the pinned Tailscale.
- **Lifecycle.** A foreground service keeps the mesh up in Doze, and a
  multicast lock lets mDNS find members on the Wi-Fi.

The app looks finished from M10 on, not from M13: Kotlin and Compose, with a
theme of its own (colour, type, shape, spacing and motion as tokens), light
and dark, and every state `ipc.Status` can report designed rather than left
to an error. A screenshot test renders every screen in both themes, at 200 %
font scale, and in German and English, so a review needs no device. The
colours are `design/tokens.json`, by Material 3 role, which the website shares,
so that a member's reach (direct, relay, sought, absent) and an alarm look the
same in both; the launcher icon is `design/logo/icon.svg`, monochrome
`icon-mono.svg` ([14-website.md](14-website.md)).

Open, to decide in this order:

- **Key custody.** The identity key is to be held by Keystore
  ([04-architecture.md](04-architecture.md)), but Go signs with it: either
  `node.keys` sealed by a Keystore AES key, or every signature a call
  through JNI into Keystore.
- **Dynamic colour.** Material You's colours, taken from the wallpaper,
  would replace the tokens, the status colours among them. Proposed: the
  app's own theme alone.
- **minSdk.** 31 is proposed: fewer cases to support, and Material You if
  dynamic colour is taken.

- **Exit criteria:** (1) in `make interop`, an Android emulator joins the
  network by the invite's QR code and by its typed code, pings a member and
  fetches a page from it over HTTP, directly and through a relay; (2) removed,
  it loses its tunnels as fast as a Linux member does, and past the freshness
  TTL keeps tunnels only to admin devices; (3) by hand, a phone on LTE joins
  and reaches a member behind NAT.

## M11 — Break-glass recovery and key backup

Genesis commits to break-glass secrets, `juist create` writes them to a file to
keep offline, and `State.ValidDisablement` verifies one; nothing consumes a
revealed secret yet. Until something does, an admin whose keys are all lost
leaves a network whose quorum needs them unchangeable, which `juist admins
quorum` and `juist admins require` warn about. The threat model's custody
property (02, item 2) rests on this record, so the audit has to see it.

Open, to decide in this order:

- **Scope.** What a revealed secret authorizes: replacing the admin set and
  quorum, only lowering the quorum, or disabling the network outright.
- **Use.** Whether a secret is spent by its record, and whether one secret
  suffices or several must be revealed together.
- **Veto.** Whether the record takes effect only after a delay in which a
  quorum of the remaining admins can cancel it; without one, a stolen secret
  is a takeover.
- **Devices.** How members surface an applied or pending recovery, and whether
  it raises the log's alarm.
- **CLI.** One command that reveals a secret from the file and submits the
  record.

The schema already carries the commitments, so existing networks gain
recovery without a flag day.

**Backing up the keystore.** Admin keys and break-glass secrets exist only in
`~/.config/juist`, and today the only backup is copying files in juist's own
format out of it. `juist admins export NAME` prints an admin key as one line
on stdout, made for a pipe into a password manager (`juist admins export
alice | bx create --name "juist alice" --password-stdin`), and `juist admins
import NAME` reads that line from stdin and writes the key file with the
keystore's modes — never through argv or a temporary file. The line carries a
version tag and a checksum, so a truncated paste fails at import and not at
the first signature. Import refuses to overwrite a key of that name and says
whether the log still gives the key a vote: a key removed since the backup is
worth knowing about when it is restored, not at the next change. The
break-glass file gets the same pair under M11's recovery command, and its
export says to keep it apart from the admin keys, since a vault holding both
is one secret that governs the network and recovers it too; likewise k admin
keys in one vault make the quorum one master password. Node keys are not
exported: they are the device, a copy restored elsewhere is a clone of a
member, and a lost device is removed and re-invited instead.

## M11a — Post-quantum WireGuard

Every pair of members mixes a preshared key into WireGuard's handshake that a
quantum computer cannot recover, so recorded tunnel traffic stays
confidential (harvest now, decrypt later). Authentication stays X25519 and
Ed25519; PQ authentication stays deferred, as it cannot be harvested now. It
is part of v1 and comes before the audit, so that M12 covers it.

What it builds on:

- **The keys.** Every `NodeRecord` carries an ML-KEM-768 public key, and the
  epoch's group secret is already sealed to it with hybrid HPKE; no new record
  field is needed ([08-trust-layer-notes.md](08-trust-layer-notes.md)).
- **The engine.** Since Tailscale 1.104, `wgcfg.PeerConfig.PresharedKey`
  reaches a peer created lazily through the config lookup, and
  `SyncDevicePeer` sets it in place on an active one, keeping its session
  ([07-embedding-notes.md](07-embedding-notes.md)). Setting a PSK is a few
  dozen lines in `conn`, with no patch to the pinned modules.
- **Not Rosenpass:** a daemon per link and no audit, where juist's own key
  distribution and stdlib `crypto/mlkem` do the same
  ([research/building-blocks.md](research/building-blocks.md)).

The engine is the small part. What makes this a milestone is agreeing on the
key: WireGuard holds one PSK per peer, the responder cannot tell a wrong one
from a lost packet, and a key held by one side alone fails every handshake.

Two stages, the first standing on its own:

1. **A PSK from the group secret.** `HKDF(epoch group secret, both WireGuard
   keys, epoch)`: no message to send, and it rotates with every epoch bump,
   that is every membership change. Outsiders who record traffic are held off,
   as the group secret reaches members only through the hybrid KEM. Every
   member can derive every pair's key, though, so a member, or one removed
   later, who recorded the traffic of others could read it with a quantum
   computer.
2. **A PSK per pair from ML-KEM.** Each side encapsulates once to the other's
   key; the PSK is HKDF over both secrets and the stage-1 key, so neither side
   picks it alone and no third member can derive it. The 1088-byte
   ciphertexts travel on the sealed DERP or disco sideband, or by gossip; not
   in the log.

Open, to decide in this order:

- **Catching up.** Gossip runs through the tunnel alone
  ([10-connectivity-notes.md](10-connectivity-notes.md)), so a member that
  missed an epoch bump cannot handshake with the key that would bring it the
  bump. Proposed: a pair uses the key of the lower of their two epochs, each
  learning the other's outside the tunnel, as DHT and mDNS records are
  published under the newest epoch and looked up under every one held; a
  member past `keyring.Depth` is invited again, as today (M4b).
- **No downgrade.** Falling back to no PSK at all would let an active
  attacker who blocks handshakes strip the protection. Towards a peer whose
  signed announcement says it uses PSKs, a member never handshakes without
  one; a fallback goes to an older epoch's key and nothing weaker.
- **Mixed versions.** A member that sets a PSK cannot reach one that does
  not, and the announcement's decoder refuses unknown fields
  (`types.StrictDecOptions`), so saying "I use PSKs" is a schema change every
  member must understand before any member sends it. Which schema gate, and
  whether a network can then require PSKs. The whole network's reach
  ("Later") waits for the same gate.
- **Switching keys.** On an epoch bump both sides change within the gossip's
  convergence, but a handshake in that window fails and is retried only after
  the 5 s `RekeyTimeout`. Whether the key changes at the next rekey (120 s)
  instead, and when a pair moves from stage 1 to stage 2 and back.
- **Status.** `juist status` names each tunnel that is not post-quantum, and
  says which stage the others are at.
- **The upgrade guard.** Both PSK paths get a row in 07's upgrade table and a
  test that reads the pinned engine.

Size: stage 1 is the derivation and the catch-up and downgrade rules; stage 2
adds a message with its own parser and fuzz target, and the derivation in
`trust/`, which `make tcb` counts. Together about as large as M9e and M9f.

- **Exit criteria:** (1) two members' handshakes carry a PSK, and a peer
  holding the right WireGuard key but the wrong PSK cannot complete one;
  (2) in `make interop`, an epoch bump changes the PSK while a ping across
  the tunnel loses nothing, and a member that slept through a bump reaches
  the others again without help; (3) blocking handshakes never makes two
  members that announce PSKs handshake without one; (4) a member of the
  previous release and one of this one still reach each other, and
  `juist status` says which tunnels are post-quantum; (5) with stage 2, a
  third member holding the group secret cannot derive a pair's PSK.

## M12 — Hardening → v1

External security audit of the trust layer + enrollment (the ≈7–9 k LOC TCB),
plus what M6, M8, M9, M9e, M10 and M11a add to it — route consumption and its forwarding helper, the
override record and the resolver, the published names and the ingress, the
preshared-key exchange, the Android
app's key custody and in-process API — fix findings, mature fuzz corpus (consider
OSS-Fuzz), implementation-vs-threat-model review, documentation of the
residual-weakness acceptances for operators. Before the audit, a user per
juistd instance, so that one network's compromised daemon on a host no longer
holds the others' device keys (M5's residual weakness 9 in
[02-threat-model.md](02-threat-model.md)).

Also before the audit, checkpoints put to use. Only `juist log checkpoint`
writes one and nothing calls `Authority.Compact`, so every log grows for good,
and past `MaxHashesPerFrame` records two nodes stop converging
([08-trust-layer-notes.md](08-trust-layer-notes.md), "The size constraint
that outlives the freeze"). Open, to decide in this order:

- **Proposing.** What prompts a checkpoint — a record count, a log size, an
  epoch bump — and which device drafts it, since it takes a quorum like any
  change and the admins must be asked to sign.
- **Compacting.** When a device compacts to a checkpoint it holds, and
  whether it keeps any history below the anchor for peers still behind it.
  A store that is not empty cannot yet move its anchor to a checkpoint it
  receives (`Bootstrap` takes an empty one), so a device behind a peer that
  compacted does not catch up. Every `Inform` also verifies the whole chain
  again, about a second at 4096 records.
- **Joining.** Whether a device joining is handed the anchor instead of the
  whole chain.

Also open before the audit:

- **The scope the gate measures.** `make tcb` counts `types` and `trust/`.
  The CLI's checks against a compromised juistd (`pin.go`, `rotate.go`,
  `changes.go`, `waiting.go`, `describe.go`, about 1 k lines), the filter
  and the resolver are audited too: they move into `trust/`, or the gate
  counts them against a budget that holds them.
- **Fuzzing.** `waiting.Decode`, `types.DecodeLease`, the helper's protocol
  and the resolver's input have no target, and no `fuzz-long` run is
  recorded in [12-validating.md](12-validating.md).
- **The read tier.** `ForReader` passes members' identities in `Reach` and
  their names in `Silent` and `TunnelsDown`, which the tier was narrowed to
  keep from any local user.
- **The FreeBSD helper's routes.** It refuses the host's links, loopback and
  multicast, but not a route over the host's own LAN, which a subnet route
  looks like; whether it checks the host's connected routes itself.
- **A checkpoint at the caps.** `MaxNodes` members, each holding their caps
  of names and published names, encode to about 5.5 MB, past
  `MaxRecordSize` (4 MiB), M8's names most of it: a state the quorum can
  reach cannot be checkpointed. A cap on a member's name bytes, or a record
  size of its own for checkpoints, with `TestRecordSizeAtMaxNodes` filling
  names to their caps.

v1 is Linux and FreeBSD, with M10's minimal Android app; the full app and the
release work follow in M13.

- **Exit criteria:** (1) audit complete, all high/medium findings fixed and
  regression-tested; (2) a network that has authored more than
  `MaxHashesPerFrame` records still converges on a new change, with no admin
  having asked for a checkpoint; v1.0 tag.

## M13 — Android & packaging *(post-v1)*

The full Android app, on M10's: M6's client side through `VpnService` routes
and `allowBypass`, and M8's names; distro packages, signed releases.

- **Exit criterion:** 3-platform interop matrix green in CI (Linux/FreeBSD via qemu,
  Android emulator smoke test); release artifacts, the Android app included,
  reproducible byte-for-byte from two independent builders.

## M14 — Coarse ACLs *(post-v1)*

Per-node allow-lists as quorum-signed log records; the netmap adapter renders them
into `wgengine`'s packet filter, replacing v1's allow-all-members rule, on sender
and receiver alike. They also scope M6: using an exit node, or a subnet router's
routes, becomes a grant (Tailscale's `autogroup:internet`) instead of open to every
member.

Two members the policy keeps apart both ways are no peers at all: neither
installs the other, so no handshake or disco passes between them, and the log
reaches each through the members it may reach. Discovery follows the policy
too: a member's announcement goes only to its peers, and its DHT record is
sealed for them, not under the group secret every member holds, which today
shows each member every other's public addresses; whether keys go per pair
or per group is open. Listings and `.juist` names show a member its peers
alone. The log stays whole on every member, names, keys and overlay addresses
included: hiding those conflicts with verifying the chain.

- **Exit criterion:** under a policy denying A→B, B drops A's packets even when A's
  daemon is patched to ignore its own outbound filter (receiver-side enforcement
  proven independently of sender cooperation); a node whose policy state is past the
  freshness TTL fails closed; a member without a grant for an exit node gets
  nothing forwarded by it, enforced at the exit node; two members kept apart
  both ways exchange no packet, and neither learns the other's endpoints.

## M15 — Multicast *(post-v1)*

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

## M16 — HTTP/3 for published names *(post-v1)*

QUIC on the published path: a handshake in one round trip, no head-of-line
blocking on lossy links, and a connection that survives the client's
address changing. Today the ingress passes TCP alone, by the SNI of the
ClientHello, and the terminator passes the bytes TLS carried; HTTP/2 rides
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

Open decisions:

- **The client's address** to the terminator: PROXY v2 has no per-flow form
  for UDP; a port per flow on the tunnel, or a header in the first datagram.
- **The TCP path as a proxy** for HTTP names, which `Alt-Svc` needs, or
  advertising by the DNS record alone.
- **Retry and amplification:** whether the ingress or the terminator sends
  QUIC Retry to an unvalidated address.

- **Exit criteria:** (1) headless Chrome in the lab fetches a published name
  over HTTP/3 through the ingress, and over HTTP/2 where 443/udp is blocked;
  (2) the Initial parser has a fuzz target that runs clean for 72 CPU-hours,
  and drops what does not parse without state kept; (3) the ingress sends
  an unvalidated address no more than three times what it received from it;
  (4) a name not published gets no datagram forwarded; (5) `make load-lab`
  over HTTP/3 loses no visitor at the rate HTTP/2 holds.

## Later — The whole network's reach

Not scheduled. The status page, and `juist status`, show reach from the
device asked alone. Each member's own, live, direct or relayed per peer,
needs a field every member understands before any sends it, gated by a
schema, as the announcements' decoders are strict: the gate M11a needs too.
A summary in the announcement would re-sign and re-gossip it, and its copy
in the DHT, at every change of reach.

## Later — Battery life on laptops

Not scheduled. Done (M9): a quiet tunnel to a peer a relay can wake is
probed every 5 minutes rather than every 30 s, and mDNS slows from 2 s to a
minute while nothing changes; validated by unit tests alone. Open, in this
order:

1. **Measure.** Datagrams per minute on the underlay (magicsock's port, 5353,
   the relay's) and wakeups (`powertop`) of an idle laptop with three peers,
   with and without a relay, before and after M9. Every step below is
   judged by that number, so it is taken first.
2. **Events instead of polls.** The service's watch loop every 5 s (rotation,
   overlay addresses, host conflicts, mesh retry), the reconcile every 15 s,
   and the host's DNS routing every 30 s. Each becomes a timer on the next
   known deadline (a membership's expiry, a renumbering's) or a signal
   (a log change, netmon, resolved's `PropertiesChanged`), keeping a slow
   backstop: a missed event fails silently.
3. **A keepalive that lets magicsock rest.** Without a relay every check still
   probes, since that holds the NAT mappings open, and each probe restarts
   magicsock's 3 s heartbeat for 45 s. A TSMP ping and a disco ping from the
   ping path both count as traffic; what keeps a mapping open without that
   is to be found in the pinned module.
4. **On battery.** Read the power source (Linux
   `/sys/class/power_supply/*/online` of a `Mains` supply, FreeBSD
   `hw.acpi.acline`) and, on battery, stop relaying though granted, and
   stretch the quiet probe and the sync interval. A relay that goes away moves
   its peers' home region, so the switch wants hysteresis, and the status
   says when it happened.

M10's app inherits the pacing: in Doze a foreground service keeps the mesh up,
and every timer above costs more on a phone than on a laptop.

## Deferred (post-v1, schema must not preclude)

Kernel WireGuard fast path for public-endpoint nodes ·
hardware-backed admin keys (FIDO2/PIV signing) · sealing the node key, a 0600
file in v1 (TPM, kernel keyring; FreeBSD: geli) · update transparency log ·
macOS/Windows/iOS · PQ authentication (ML-DSA checkpoint co-signatures).

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
other client's name, keys and addresses, and reaches them until M14. Hiding
members from each other conflicts with full replication, which verifying the
chain rests on. An access VPN where clients know only a hub and access
follows an SSO login is a hub-and-spoke design with a central policy, not
this one; for owners and an identity provider see the previous section.

One network under M14's policy, clients reaching the servers and not each
other, is the direct way to the same end, IPv4 and names included; the
gateway is for before M14, or for keeping the servers out of the clients' log.
