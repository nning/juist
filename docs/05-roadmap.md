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
CLI: `juist init / sign / verify / log show`. No networking.

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

Today a juistd holds one network, and `juist join` on a device that is in one
refuses to join another. The keystore already keeps its admin keys, anchors and
break-glass files per network, so a person can administer several networks;
what is missing is a host being a member of several. Running a second juistd by
hand, with its own `--home`, `--socket`, `--tun` and ports, works in part, but
three things break: every network numbers its devices from the start of the
same range (198.18.0.0/15 from schema 4, 100.64/10 before), so the two TUN
devices claim overlapping IPv4 routes; the Linux router's table and policy
rule priorities are fixed, so one instance stopping deletes the rules the
other routes by; and the packaged firewall rules and unit know one instance
with the fixed ports only. The overlay IPv6 prefix is derived from each
network's genesis and does not collide.

The plan, in order:

1. **An IPv4 prefix per network.** Schema 4 has `Snapshot.V4Prefix`, chosen
   at genesis with `juist init --ipv4` and moved by renumbering (6); without
   it a network uses all of 198.18/15, so two such networks collide on one
   host. What remains is the default: `juist init` should draw a random /22 inside 198.18/15 (1022
   devices, one of 128) rather than take the whole range.
2. **Instances.** A systemd template, `juistd@NETWORK.service`, with its home
   in `/var/lib/juist/NETWORK`, its socket in `/run/juist/NETWORK.sock`, and a
   TUN device named from the network (within IFNAMSIZ). The instance's name is
   chosen once, when the instance is created, and does not follow a rename (schema 6), which would
   otherwise move its home and socket under a running juistd. The first instance
   keeps the fixed ports; later ones take free ports, which the announcements
   already carry. Each instance also gets its own routing table and policy
   rule priorities, so that none removes what another routes by — the rule
   docs/07-embedding-notes.md sets for tailscaled holds between instances too.
   The unit for one network, `juistd.service`, remains the default instance.
3. **Refusing overlap on the host.** An instance does not start while another
   running here holds an overlapping IPv4 prefix, or the same network, and
   says which: two networks that drew one prefix cannot both route on one host,
   whatever either log says.
4. **The CLI.** `--network NAME` chooses the instance, and without it a
   command on a host with several asks which; `juist status` lists every
   network the host is in. `juist join` on a member device offers to join as a
   second network, creating the instance, instead of refusing.
5. **Packaging and firewall.** The firewalld and ufw definitions cover the
   instances' TUN devices and ports; `firewall.sh` allows and revokes per
   instance.
6. **Renumbering.** Schema 5 has it: `juist network renumber PREFIX` moves
   every member into another prefix, `juist network renumber DEVICE ADDR` one
   member to another address, and `--finish` retires the old addresses ahead
   of the deadline; the rules the log keeps are in
   [08-trust-layer-notes.md](08-trust-layer-notes.md#renumbering). What
   remains: exit criteria (5) and (6) in the netns matrix; preferring the old
   address as the source on platforms other than Linux, where the OS picks
   between the two; and the deadline counting from signing, so a record
   approved late leaves less of a transition. What juist cannot move is
   anything outside it that names the old addresses.

Security stays as it is per network: instances share no state, each home is
the juist user's alone, and a TUN device routes its own network's prefixes
only, so no packet crosses from one network into the other through juist.

- **Exit criteria:** (1) one host in two networks, in the netns matrix, pings
  members of both over IPv4 and IPv6, and no route of one prefix points into
  the other's device; (2) a second instance whose prefix overlaps a running
  one refuses to start with a message naming both; (3) removal from one
  network leaves the host's membership of the other untouched, across a
  restart of either instance, and stopping one leaves the other's routes and
  rules in place; (4) an existing network without `V4Prefix` keeps working as
  the default instance next to a new one; (5) a network renumbered while one
  member is offline keeps every pair of members reachable throughout, the
  offline one included once it returns; (6) a member renumbered on its own
  is reachable at both addresses until the deadline and at the new one
  only after it, and a record giving it an address another member holds, or
  one outside the network's range, is rejected by every node.

## M6 — Exit nodes and subnet routers

The `exit-node` role and route grants consumed from log state (schema and
validation landed in M1), widened `AllowedIPs` and filter destinations,
privileged-helper forwarding/NAT, client-side default-route capture with LAN bypass
and DNS handling. Design in
[04-architecture.md](04-architecture.md#exit-nodes-and-subnet-routes-m6). It
covers Linux; FreeBSD's side (pf) comes with M7, and Android's with M11.

**Before ACLs, unscoped.** Coarse ACLs come at M12, so until then using an exit
node is open to every member: the quorum grants the role per exit node, and each
client's owner chooses whether to use one, but no grant says *which* members may.
A subnet router's prefixes are likewise reachable from every member. The
trade is accepted in [02-threat-model.md](02-threat-model.md) item 7; M12 scopes it.

- **Exit criteria:** (1) a member that forwards traffic without a route grant is
  dropped by every peer; (2) a grant overlapping the overlay ULA or an overlay v4
  range is rejected by the log validator, so an exit node can never intercept
  member-to-member traffic; (3) with a full tunnel up, no DNS query and no non-LAN packet leaves the
  host outside the tunnel (asserted by capture on the physical interface) while LAN
  destinations still resolve and route locally; (4) withdrawing the `exit-node` role
  cuts egress within gossip convergence for reachable clients and at the TTL boundary
  for partitioned ones.

## M7 — FreeBSD

The FreeBSD port: M3a's real device, router and privilege story on FreeBSD,
M6's forwarding, NAT and default-route capture with pf, and a port that
installs it. Reproducible builds, for Linux and FreeBSD alike. Android and the
rest of the release work — distro packages, signed releases — are M11, after
v1.0.

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
3. **Wiring it to the host.** resolved gets `~NETWORK` and one routing domain
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

Genesis commits to break-glass secrets, `juist init` writes them to a file to
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
residual-weakness acceptances for operators.

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
