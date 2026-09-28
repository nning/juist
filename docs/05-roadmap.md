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
[02-threat-model.md](02-threat-model.md), and a user per instance is for M10.

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
rotating, removing or backing up (M9's `juist admins export`) the key of one
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
covers Linux; FreeBSD's side (pf) comes with M7, and Android's with M11. Split
in three, each shipped on its own: exit nodes first, as the feature asked for,
then subnet routers, then the exit node's DNS.

**Done** on 2026-09-28: M6a, M6b and M6c are built and validated as their
sections say, privileged and by hand against the packages. Untried: a
client below systemd 256, whose resolved polkit asks without the device.

**Before ACLs, unscoped.** Coarse ACLs come at M12, so until then using an exit
node is open to every member: the quorum grants the role per exit node, and each
client's owner chooses whether to use one, but no grant says *which* members may.
A subnet router's prefixes are likewise reachable from every member. The
trade is accepted in [02-threat-model.md](02-threat-model.md) item 7; M12 scopes it.

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
   for itself, and so do answers to connections from the internet to the
   device's own address. An nftables guard (`juist0guard`) drops whatever
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

`juist grant nas 192.168.1.0/24` lets every member reach the LAN behind nas
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
   one that fails the query; its announcement names the port. No capability is added: the port is
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
   programs ask their resolvers around resolved, and the CLI says so.
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

Next. The FreeBSD port: M3a's real device, router and privilege story on FreeBSD,
M6's forwarding, NAT and default-route capture with pf, and a port that
installs it. Two things M5 left to it: keeping instances apart, where
Tailscale's router routes in the host's one table (a FIB per instance, or the
IPv4 yield of [13-multi-network-notes.md](13-multi-network-notes.md) read
from that table), and sending from the old address during a renumbering,
which Linux's router pins and FreeBSD leaves to the OS.

Reproducible builds, for Linux and FreeBSD alike. Android and the rest of the
release work — distro packages, signed releases — are M11, after v1.0.

- **Exit criteria:** (1) Linux/FreeBSD interop matrix green in CI (FreeBSD via
  qemu); (2) build artifacts for both reproducible byte-for-byte from two
  independent builders.

## M8 — Names

A resolver in juistd for two things: members' names (`mailer.NETWORK`, the
MagicDNS equivalent), and **name overrides**, which point a public name at a
member so that members reach it through the tunnel instead of its public
address — `mx.example.net → mailer` puts every member's IMAP and submission
through the overlay, with the certificate still matching, since the name is
unchanged. Only members' lookups change; the rest of the internet still
resolves the public records.

Most of the mechanism is in the pinned Tailscale: `net/dns` configures
systemd-resolved over D-Bus — a DNS server and routing domains on `juist0`,
what `resolvectl dns` and `resolvectl domain` do by hand — and `dns.Config`
has the `Hosts` and `Routes` it needs. juist hands the engine an empty
`dns.Config` today (`conn/tsmanager.go`), per M3a.

The plan, in order:

1. **The record.** A quorum-signed record kind (a schema bump) mapping a name
   to a *member*, never to an address: an override follows renumbering by
   itself and cannot send a name outside the network. The validator refuses a
   name inside the network's own name space, a duplicate, and a member that
   does not exist; removing the member removes its overrides.
2. **The resolver.** juistd answers on its overlay address on `juist0`, only
   for member names and overrides. For an overridden name it answers every
   type: A and AAAA with the member's overlay addresses, HTTPS/SVCB (type 65)
   empty — their address hints would carry the public address — and the
   other types forwarded. Answering A alone would send clients to the public
   AAAA, around the tunnel. TTLs are short (30 s), so a withdrawn override
   leaves caches quickly. How juistd binds port 53 on the overlay address,
   and what capability that takes, is part of this step.
3. **Wiring it to the host** (built by M6c, if that comes first).
   resolved gets `~NETWORK` and one routing domain
   per override (`~mx.example.net`), so no other query reaches juistd, and the
   rest of `example.net` resolves as before. Without resolved nothing is
   configured and `juist status` says so; rewriting `/etc/resolv.conf` is not
   in scope.
4. **Opt-in and visibility.** A device applies overrides only after its owner
   agreed (`juist set --accept-names`, like Tailscale's `--accept-dns`);
   member names need no agreement, since they claim nothing outside the
   network. `juist status` lists the overrides in effect.
5. **Falling back to the public name.** juistd stops answering an override
   while the device is stale, or while the member it points at is not
   reachable: the connection then goes to the public address, as without
   juist, instead of into a tunnel that is down. A stale view therefore
   redirects nothing beyond the TTL, like every other authority change.

**The trade.** Whoever can set an override can point any public name at a
member of their choosing on every device that accepted overrides. Verified
TLS turns that into an error, since the member lacks the certificate; plain
HTTP, SMTP with unverified STARTTLS and much internal tooling are exposed.
Hence a quorum, not an admin device, the opt-in per device, and the listing.
The cost of the feature itself: in normal operation the overridden names
depend on juistd, and a broken juistd on a device that accepted them loses
them for up to a TTL.

- **Exit criteria:** (1) in the netns matrix, with resolved, an overridden
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

## M9 — Break-glass recovery and key backup

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
break-glass file gets the same pair under M9's recovery command, and its
export says to keep it apart from the admin keys, since a vault holding both
is one secret that governs the network and recovers it too; likewise k admin
keys in one vault make the quorum one master password. Node keys are not
exported: they are the device, a copy restored elsewhere is a clone of a
member, and a lost device is removed and re-invited instead.

## M10 — Hardening → v1

External security audit of the trust layer + enrollment (the ≈7–9 k LOC TCB),
plus what M6 and M8 add to it — route consumption and its forwarding helper, the
override record and the resolver — fix findings, mature fuzz corpus (consider
OSS-Fuzz), implementation-vs-threat-model review, documentation of the
residual-weakness acceptances for operators. Before the audit, a user per
juistd instance, so that one network's compromised daemon on a host no longer
holds the others' device keys (M5's residual weakness 9 in
[02-threat-model.md](02-threat-model.md)).

v1 is Linux and FreeBSD; Android and the release work follow in M11.

- **Exit criterion:** audit complete, all high/medium findings fixed and regression-
  tested; v1.0 tag.

## M11 — Android & packaging *(post-v1)*

Android app (gomobile + VpnService, Keystore-held identity), with M6's client
side through `VpnService` routes and `allowBypass`; distro packages, signed
releases.

- **Exit criterion:** 3-platform interop matrix green in CI (Linux/FreeBSD via qemu,
  Android emulator smoke test); release artifacts, the Android app included,
  reproducible byte-for-byte from two independent builders.

## M12 — Coarse ACLs *(post-v1)*

Per-node allow-lists as quorum-signed log records; the netmap adapter renders them
into `wgengine`'s packet filter, replacing v1's allow-all-members rule, on sender
and receiver alike. They also scope M6: using an exit node, or a subnet router's
routes, becomes a grant (Tailscale's `autogroup:internet`) instead of open to every
member.

- **Exit criterion:** under a policy denying A→B, B drops A's packets even when A's
  daemon is patched to ignore its own outbound filter (receiver-side enforcement
  proven independently of sender cooperation); a node whose policy state is past the
  freshness TTL fails closed; a member without a grant for an exit node gets
  nothing forwarded by it, enforced at the exit node.

## M13 — Multicast *(post-v1)*

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

## Deferred (post-v1, schema must not preclude)

Kernel WireGuard fast path for public-endpoint nodes ·
hardware-backed admin keys (FIDO2/PIV signing) · update transparency log ·
macOS/Windows/iOS · PQ authentication (ML-DSA checkpoint co-signatures).
