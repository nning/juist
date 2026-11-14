# 05 — Roadmap

Each milestone has a **security exit criterion**: it is not done until the
criterion passes, and the criteria are cumulative, since CI keeps enforcing
every earlier one; the tests that check what done milestones claim are in
[12-validating.md](12-validating.md), by what they check. *(demo-able)* marks
a milestone that closes a loop an outsider can be shown end to end. A done
milestone says what it delivered, what validated it and what of it still
binds; its plan and reviews are in git's history.

## M0 — Walking skeleton *(demo-able)*

**Done** on 2026-08-22. Two Linux nodes, statically configured, tunnel up
through the embedded Tailscale wgengine (wireguard-go and magicsock) without
`controlclient` or `tsnet`.

## M1 — Trust layer, offline

**Done** on 2026-08-22. The membership log as a pure library: genesis,
AddNode and RemoveNode, admin keys and vote weights, k-of-n quorum,
checkpoints, fork choice, epoch group secrets (HPKE fan-out), address
derivation and collision rules, and roles and route grants (`SetNodeRoutes`).

## M2 — Log-driven mesh on LAN *(demo-able)*

**Done** on 2026-08-23. The reconciler (log state ⇒ WireGuard config ⇒
netmap), gossip anti-entropy with log-head beacons, and blinded mDNS
discovery: two to five nodes on one LAN, no internet
([09-mesh-layer-notes.md](09-mesh-layer-notes.md)).

## M3 — Off the local segment

**Done** on 2026-09-05, in two slices: M3a makes the overlay carry traffic,
M3b makes it reach past the local segment. The record schema froze at the end
of M3: since then a new kind, role or field costs a quorum-signed
`SchemaUpgrade` record and an upgrade window, not a new network
([08-trust-layer-notes.md](08-trust-layer-notes.md)).

### M3a — OS plumbing: a real device, a real router

A real TUN device and `router.Router`, the peers' routes derived at every
reconfiguration, the daemon's privilege footprint, and the netns harness the
NAT matrix builds on; no DNS. The wiring's constraints are in
[07-embedding-notes.md](07-embedding-notes.md). Validated by the privileged
tests ([12-validating.md](12-validating.md#check-the-privilege-footprint)).

### M3b — NAT traversal, relays, DHT cold start

Full magicsock (disco, hole punching), member-run DERP relays that admit
members alone, BEP 44 announcements under blinded keys with AEAD payloads, a
persistent endpoint cache, and endpoints learned off the LAN from gossiped
announcements, which feed magicsock's own `CallMeMaybe`
([07-embedding-notes.md](07-embedding-notes.md),
[10-connectivity-notes.md](10-connectivity-notes.md)). The schema became
versioned, and the O(n) epoch fan-out was measured on a record at `MaxNodes`
(`TestRecordSizeAtMaxNodes`, kept as a guard) rather than argued; what that
decided is in [08-trust-layer-notes.md](08-trust-layer-notes.md).

## M4 — Enrollment + freshness + revocation UX *(demo-able — full product loop)*

**Done** on 2026-09-25, after 25 review rounds. Full-entropy invite links (the
payload a QR code carries) and wormhole-style typed codes (SPAKE2, single
use, one guess); `juist invite / join / remove / rotate`; freshness leases
from admin devices with fail-closed TTL enforcement, the startup gate
included; revocation in one tier, since every removal bumps the epoch
([11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md)).

## M4b — Coming back after many changes

**Done** on 2026-09-25. A member that slept through more epoch bumps than
`keyring.Depth` = 4 catches up by identity instead of by epoch: a catch-up
under the reserved epoch label 0, granted against the peer's current log
([09-mesh-layer-notes.md](09-mesh-layer-notes.md), "Epoch skew, and the
keyring"). A device every member refuses says in `juist status` that it was
most likely removed.

The keyring stays shallow: every epoch kept is one more change for which a
removed device is still answered. The DHT and mDNS stay keyed by epoch, so a
sleeper finds peers only through its endpoint cache or members that did not
move.

## M5 — Several networks on one host

**Done** on 2026-09-27; its privileged tests passed on real hardware, the
rest by `make check`.

A host is a member of several networks, one juistd instance each:
`juistd.service` is instance 0, `juistd@juist1` to `juistd@juist9` run beside
it, the number choosing the device, ports, routing table and rule
priorities. `juist create` draws a random /22 in 198.18/15 per network; an
instance whose IPv4 a lower one holds runs without IPv4 and says so. A
command about one network takes it first, and listings show every network.
Renumbering a network or a member keeps every pair reachable through a
transition. The rules a later change must keep are in
[13-multi-network-notes.md](13-multi-network-notes.md); since M24 each
instance runs as a user of its own.

## M5a — An admin key per network

**Done** on 2026-09-27, validated by `make check` (`cmd/juist/adminkeys_test.go`).
`juist create` makes a new admin key per network (`admins/alex@home.key`),
so a key lost or taken costs one network and does not show one person running
several. `--admin-key NAME` shares an existing key on purpose; `juist admins
new` makes a key before its network; `juist admins` lists each key with the
networks it governs. The CLI signs with every local key that has a part in a
record.

## M5b — Changes that wait for other admins, carried to them

**Done** on 2026-09-27, validated by `make check`
([12-validating.md](12-validating.md#what-checks-what)). A change that lacks
votes is carried by log sync to the network's admin devices, sealed to every
admin key's encryption key (schema 7, `AdminKey.Recipient`, which `juist admins
receive` sets), so the daemons carrying it cannot read it. `juist status` says
what waits for a vote, and `juist approve` asks about each one, shown from the
local log; the vote that completes the quorum applies it. A daemon holds at
most 64 changes and 32 MiB, 16 and 8 MiB per signing key, each for seven days
at most. An admission's copies wait five minutes at a time, renewed by the
running invite, which hands on each vote as it arrives, and are never carried
from a file. What a compromised admin
device or key gains is weakness 10 in [02-threat-model.md](02-threat-model.md).

## M5c — Moving one device without a transition

**Done** on 2026-09-27, validated by `make check`
([12-validating.md](12-validating.md#what-checks-what)). `juist network
renumber NETWORK DEVICE ADDRESS --finish` moves a device and retires its old
address at once, by the deadline `types.RetireAtOnce`, with no schema change.
The old address stays held against collisions until the next plain
`--finish` or the device's next move, from schema 25 until another device
takes it (M28, step 8); `juist network` lists what is held, and `juist
status` names the devices not told yet.

## M6 — Exit nodes and subnet routers

**Done** on 2026-09-28: M6a, M6b and M6c, validated privileged and by hand
against the packages. The design is in
[04-architecture.md](04-architecture.md#exit-nodes-and-subnet-routes-m6).
Open: a client below systemd 256, whose resolved polkit asks without the
device, is untried.

## M6a — Exit nodes

`juist grant vps exit` gives the role and the default routes; the exit node's
operator agrees with `juist exit serve`, and a client chooses one with `juist
exit use vps` (and `off`). A client routes *the internet* through it, public
IPv4 and `2000::/3` without the overlay and private or special-use space
(`conn.Internet`), so an exit node never intercepts member-to-member traffic
nor opens its own LAN. While the chosen exit node cannot be used, internet
traffic meets an unreachable route rather than leaving directly, and an
nftables guard drops what would leave by another device. juistd's own traffic,
by its user, goes by the host's routes, so it can always find its exit node
again; hence an exit node needs juistd running as a system user.

## M6b — Subnet routers

`juist subnet add nas 192.168.1.0/24` grants a prefix, which nas's operator
agrees to route with `juist subnet serve`. The log refuses a prefix that is
not masked, overlaps the overlay or another overlay a host may hold, or
another member's grant. Every member routes a router's prefixes into the
tunnel, less what the host reaches by routes of its own inside them, and
says so; a pushed route is not the host's own. `juist subnet off` turns them
off on a device. A Docker network cannot be routed to, which `juist subnet
serve` warns of.

## M6c — The exit node's DNS

While an exit node is in use, the device's DNS goes through it. The exit
node's juistd forwards DNS on its overlay addresses, port 41646 (redirected
from 53), bound to `juist0`, to the host's own resolvers; the client points
systemd-resolved at it over D-Bus on `juist0` with `~.`, which a packaged
polkit rule allows the `juist` user. A refused exit node keeps it, so lookups
go nowhere rather than to the LAN. Without resolved nothing is configured,
and `juist exit use` and `juist status` name the resolvers left outside.

## M7 — FreeBSD

**Done** on 2026-09-30, reviewed for security (M7 review 5), validated by
`make test-freebsd` on FreeBSD 14.5 in qemu, by hand between two such VMs
([Check a FreeBSD node](12-validating.md#check-a-freebsd-node)), by `make
repro-freebsd` and by `make interop`, which `make ci-vm` runs. Open: a
FreeBSD host outside qemu using an exit node is untried.

- **M7a — device, router and privileges.** juistd started as root keeps a
  root helper (`internal/plumber`) that creates juist's own TUN devices and
  sets their addresses and routes, and runs the daemon as `juist`, handed
  the device's descriptor. A route names its source address, as Linux's
  router pins it. An rc.d script runs the instances.
- **M7b — exit nodes, subnet routers and DNS.** pf, in anchors of juist's,
  keeps juistd's own traffic off the tunnel, guards what else would leave,
  and does the exit node's NAT and forwarding filter; DNS through the exit
  node goes through resolvconf(8).
- **M7c — the package, reproducible builds and the lab.** `make pkg-freebsd`
  builds the package to the same bytes on any system; `make repro-freebsd`
  compares the binaries and package from two builders; `make interop` runs a
  Debian 12 and a FreeBSD 14.5 VM in qemu without root, each the other's exit
  node, subnet router and DNS.

## M8 — Names

**Done** on 2026-10-02, reviewed (M8 reviews 1 and 2), validated by unit
tests, by hand on Debian 12 (systemd 252) as the package, and by `make
interop`.

juistd resolves members' names under `NETWORK.juist` (`mailer.home.juist`,
and `mailer` by the search domain) and **name overrides**, which point a
public name at a member so that members reach it through the tunnel with the
certificate still matching: schema 8's `SetNodeNames`, by quorum. The
resolver listens on the device's overlay address, port 41647, as resolved's
server for `juist0`, and forwards everything else. A device applies
overrides only once its owner agreed (`juist names on`), and stops answering
one while it is stale or the member is out of reach. Where no resolved runs,
juistd is the host's sole resolver and forwards the rest to the host's own:
on Linux the package's `resolv.sh` points `/etc/resolv.conf` at a file
juistd writes, and nftables take the host's queries on 53 to 41647; on
FreeBSD resolvconf names it exclusively, on 53, which the helper binds. A
resolv.conf tailscaled wrote stays its own, since tailscaled asks juistd back
(`07-embedding-notes.md`). Debian's dhclient writes the host's own beside
juistd's, by the package's enter hook, and programs AppArmor confines read
juistd's through the package's snippet in `abstractions/nameservice.d`, which
postinst has AppArmor reload once. Open: other DHCP clients follow the
link and write juistd's file, which the host then asks instead of juistd
until juistd writes it again, within five minutes. Open: what juistd forwards
without an exit node goes in plain DNS where resolved is configured for DNS
over TLS.

**The trade.** Whoever can set an override can point any public name at a
member on every device that accepted overrides; verified TLS turns that into
an error, plain protocols are exposed. Hence the quorum, the opt-in per device
and the listing.

## M9 — Publishing services

**Done** on 2026-10-03 and closed with M9e and M9f, reviewed (M9 reviews 1
to 6), validated privileged on Fedora too, by hand against the packages and
with a public ingress and Let's Encrypt, and by `make ci-vm` on 2026-10-04
(12-validating.md).

A member's service is reached from the internet by name through an
**ingress**, a member with a public address the quorum granted the role. TLS
ends at the service's side; the ingress reads the SNI and nothing else, and
public DNS needs one wildcard record per domain:

```
browser ──TLS──▶ vps (ingress, SNI only) ──overlay──▶ target (TLS ends) ──▶ 127.0.0.1:2283
```

- **M9a — the ingress and published names.** Schema 9: the role `ingress`,
  the network's domain (`juist network domain`), and published names
  (`juist publish add`), served once the target's operator agrees (`juist
  publish serve`). The ingress, `juistd --helper ingress`, splices TCP by SNI
  with optional PROXY protocol v2, and redirects port 80 to https.
- **M9b — TLS at the target, and the service member.** The terminator,
  `juistd --helper tls` as `juist-serve`, takes certificates by TLS-ALPN-01
  through the ingress and forwards to the local service; `juist publish`
  prints the CAA record that binds issuance to its ACME account. A **service
  member** (`juistd --serve NAME=ADDR`, role `service`, `make image`) runs on
  a network stack of its own, without TUN, root or capability; in Docker its
  service sits on an internal network in the isolated gateway mode, since an
  internal network otherwise leaves the host reachable at its gateway.
- **M9c — sharing at once.** The role `publish` lets a device publish under
  its own name without a vote each time: `juist share FILE|DIR` under a
  random 128-bit path, and `juist publish PORT`, announced for at most ten
  minutes ahead and renewed while they run.
- **M9d — the domain itself.** A member publishes the network's domain (the
  empty label), which members resolve through juistd whether names are on or
  not.

The ingress and the terminator hold no key of the network's, run as users of
their own, and may make one call each on juistd's socket (`published`,
`status page`), decoded with unknown fields ignored so that a juistd upgraded
first does not silence them. The log only says what may be published; the
operator decides what is served.

**Confined peers.** Tailscale's filter takes TCP without SYN, ICMP errors and
TSMP from any peer, so `conn` confines ingresses and service members by hooks
of its own, installed before `tundev.Start` and each calling the engine's own
after it: from a confined peer passes only the reverse of a flow this node
opened, or, from an ingress, TCP to a port this node publishes and serves or
to its gossip port.

Not planned: plain HTTP outward, which the ingress would have to parse; TLS
ending at the ingress; a domain run for every network, a central service
[01-requirements.md](01-requirements.md) excludes.

**The trade.** The ingress sees names, client addresses, timing and sizes,
logs a line per connection, and can drop. Whoever controls it can get a
certificate for a name by TLS-ALPN-01 and intercept public clients, not
members; CAA with `accounturi`, one entry per publishing device, closes
that. A PROXY header is believed from an ingress's addresses, so any process
on its host can name a client. A server published from a full member is one
compromise away from the network and the LAN, hence the service member.

## M9e — Renaming a device

**Done** on 2026-10-03, validated by unit tests, the in-process app and `make
interop`. Schema 10's `RenameNode`, signed by a quorum, and `juist rename
DEVICE NAME`: keys, addresses, roles, routes and published names stay with
the node, and its share label and `DEVICE.NETWORK.juist` follow the name. A
name that folds like another member's is refused, and so, for a holder of
`publish`, is one that gives no share label or another member's.

## M9f — The status page

**Done** on 2026-10-04, validated by unit tests and the page rendered in
headless Chrome. `juist publish status-page NAME` has the terminator serve
the network's status page in the website's look: devices, reach, published
names and shares, alarms and the log's newest changes. Members see all of it,
known by their overlay address; the public sees what `--public` says
(`none`, `services`, `network` or `all`). The terminator redirects port 80 of
the addresses it serves on to https, and the page sends HSTS.

## M10 — Android, minimal

**Done** on 2026-11-02, validated by `make check`, `make android-check`, the
automatic freshness tests, and by hand on an Android phone: QR and code joins,
ping and HTTP directly and through a relay; link joins over LTE through the
DHT and a member relay, including a NAT that changes ports by destination;
and an exit node carrying IPv4, IPv6 and DNS, failing closed when stopped or
withdrawn, and returning to direct traffic after `off`. Core 11 014 lines,
audit scope 36 069, measured after it with `make tcb`.

An Android app that joins a network as a member from anywhere, reaches the
others and sends its internet through an exit node, with none of the roles. It comes before the audit, so that M34 covers the app's key
custody and its in-process API; the full app is M26.

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
  (Linux exempts juistd's user for the same reason, M6a).
- **Lifecycle.** A foreground service keeps the mesh up in Doze, and a
  multicast lock lets mDNS find members on the Wi-Fi.

The app looks finished from M10 on, not from M26: Kotlin and Compose, with a
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
  hairpinning, kept from answering. On an Android phone, QR and code joins,
  ping and HTTP directly and through a relay, LTE joins through the DHT and a
  member relay behind NATs including one that changes ports by destination,
  and exit-node IPv4, IPv6 and DNS, fail-closed behavior, and return to direct
  traffic after `off` were also checked by hand. Freshness expiry is covered
  automatically by `trust/log.TestFreshnessEndsExactlyAtTheTTL`,
  `daemon.TestPartitionedVictimRefusesARevokedPeerAtTheTTL` and
  `daemon.TestStartupGate`.

- **Exit criteria:** (1) an Android device joins by QR code and typed code,
  pings a member and fetches a page over HTTP, directly and through a relay;
  (2) when removed, it loses its tunnels as fast as a Linux member does, and
  past the freshness TTL keeps tunnels only to admin devices; (3) a phone on
  LTE joins by link a network whose members are behind NAT, through the DHT
  and, with the invite's DHT off (`--no-dht`), through a member's relay, and
  reaches a member behind NAT; (4) the phone behind a NAT that picks a new
  port per destination joins by link through a member's relay; (5) through a
  Linux exit node, the phone's internet, IPv4, IPv6 and DNS leave by the exit
  node, none of the core's own sockets do, and with the exit node stopped or
  its role withdrawn nothing leaves directly; after `off` everything goes
  direct again.

## M11 — More than HTTPS through the ingress

M9's ingress passed TCP to 443 alone, by SNI. M11 widened what it carries, in
two parts shipped on their own, both done: a TCP service on a port of its own
(M11a), then HTTP/3 over 443/udp (M11b).

## M11a — Publishing a TCP port

**Done** on 2026-10-05, reviewed (M11 review 1), validated by `make interop`
and by hand on Fedora and Ubuntu (12-validating.md).

A service that speaks no TLS, such as a Minecraft server, is reached through
the ingress by port: schema 11 lets the quorum give a published name a public
TCP port (`juist publish add DEVICE NAME PORT --tcp[=PUBLIC]`), and every
ingress listens on it and splices to the target at once, with PROXY v2, the
bounds and the access log of 443. The log refuses a second name on a public
port, and 80, 443 and juist's own ports. `juist ingress serve` opens and
closes the ports in firewalld and ufw as the log changes
(`juist-ingress-ports.path`). Only the quorum publishes a TCP port; the
publish role shares on 443 alone. Not yet: UDP ports, which need flows at the
ingress as M11b's QUIC has.

**The trade.** For such a connection the ingress sees ports, addresses,
timing and sizes, and the plaintext of any protocol that does not encrypt
itself; CAA protects nothing there.

## M11b — HTTP/3 for published names

**Done** on 2026-10-06, reviewed (M11 reviews 2 to 4), validated by `make
interop`, `make load-lab`, 72 CPU-hours of fuzzing and by hand on Fedora and
Ubuntu (12-validating.md).

The ingress reads the SNI from a client's QUIC Initial packets on 443/udp
(`internal/quicinitial`) and forwards the flow, keyed by the client's address,
to the target, where the terminator ends QUIC and HTTP/3 (quic-go, pinned) for
names published with `--http3` and proxies each request to the service as
HTTP/1.1 or h2c, advertising `Alt-Svc` on the TCP path; `juist publish`
prints the DNS `HTTPS` record. Behind `--proxy`, the client's address comes
in a PROXY v2 datagram ahead of the flow. Until the terminator reports a client's handshake
complete, the ingress sends it no more than three times what it received;
0-RTT is off, since it can be replayed. Not done: a client's address changing
keeps no connection through the ingress, which would need connection IDs it
can route by (QUIC-LB); shares stay on TCP.

## M12 — Break-glass disablement and key backup

**Done** on 2026-10-07, reviewed (M12 reviews 1 to 5), validated by `make
ci-vm` and `make android-check` (12-validating.md).

Genesis commits to one break-glass secret, which `juist create` shows once as
a line to keep offline and writes nowhere. `juist network disable` reveals it
in a `KindDisable` record, unsigned and valid under every schema, which ends
the network on every device it reaches, wherever it hangs; it never recovers
a network, and nothing vetoes it, so a stolen secret costs availability,
never custody ([08-trust-layer-notes.md](08-trust-layer-notes.md), "Disable
records"). `juist admins export NAME` and `import NAME` move an admin key as
one checksummed line through stdout and stdin, and an import never replaces a
key. Node keys are not exported: a copy restored elsewhere is a clone of a
member, so a lost device is removed and invited again.

## M13 — HTTPS alone to the outside

**Done** on 2026-10-09, reviewed (M13 reviews 1 to 6, the last for security),
validated by `make ci-vm` and `make test-freebsd` (12-validating.md).

With `juist set --https-only` a device sends nothing but TLS over TCP to port
443 of member relays, and DNS for their names, so it works where a network
passes nothing else or sorts traffic by simple DPI; every packet then goes
through a relay. A relay-capable member serves its relay on 443 under a real
name (`juist set --relay-name`) with an ACME certificate, beside the
ingress where it is one; every member falls back to a named relay on 443 by
itself. The relays stand in for the DHT, a company's proxy is taken (`juist
set --proxy`), and links name relays by name. The rules are in
[10-connectivity-notes.md](10-connectivity-notes.md), "HTTPS alone, and relays
on 443". The Android app has its switch from M26 on.

It does not hide juist from a censor that probes servers or fingerprints
ClientHellos. Not done, each wanting more of the pinned Tailscale than it
gives at v1.104.0: ALPN or a browser's ClientHello on the DERP client (no hook
for its TLS config), HTTP/3 transport (no transport hook in magicsock), and a
proxy that ends TLS (DERP over WebSocket, built under a debug tag only and not
on FreeBSD; read the pinned module again first). A non-member's `Upgrade:
DERP` gets the server's key before admission refuses it, so a prober sees a
DERP server.

## M14 — Coarse ACLs

**Done** on 2026-10-09, reviewed (M14 reviews 1 to 3, two for security),
validated by `make ci-vm` and `make test-freebsd` (12-validating.md). Core
9 868 lines, audit scope 28 601, measured after it (2026-10-10).

One quorum-signed record, `KindSetPolicy` (schema 13), holds the whole access
policy, naming devices by identity; parsing, names and evaluation stay
outside the TCB, which checks shape and references alone. The language is
pf's filter subset: tables, services and `pass from … to …` lines, with
`internet [via …]` and subnet prefixes as destinations and `test` lines kept
in the record; no `block`, and order means nothing. `juist policy` prints the
canonical text and `edit`, `set`, `diff`, `check` and `fmt` work on it. Every
member enforces it where connections arrive, statefully, in the confiner, and
a sender drops what it may not open. It also scopes M6: using an exit node or
a subnet takes a rule, while roles and grants still say who may serve. Two
members kept apart both ways are no peers, and a member's addresses are
sealed for its peers alone. Relays and vouchers stay peers of every member
for juist's own traffic, and the log stays whole on every member
([02-threat-model.md](02-threat-model.md), weakness 11).

## M15 — Post-quantum WireGuard

**Done** on 2026-10-11, reviewed (M15 reviews 1 to 7, five of them security
reviews by fresh reviewers);
validated by `make ci-vm` and `make test-freebsd`, each throughput step
measured before and after (12-validating.md). Core 9 890 lines, audit scope
30 378, measured after it (2026-10-11).

Every pair of members mixes a preshared key from ML-KEM-768 into WireGuard's
handshake, so recorded tunnel traffic stays confidential; authentication in
the tunnel stays X25519. The engine's PSK path is in
[07-embedding-notes.md](07-embedding-notes.md); not Rosenpass, since juist's
own key distribution and stdlib `crypto/mlkem` do the same
([research/building-blocks.md](research/building-blocks.md)). Every change to
the device, a peer, egress, serving, a rotation or a renumbering, keeps
running connections, and the slow paths were tuned: the service member's
netstack, the confiner, UDP GRO forwarding and the proxies' splicing.

The rules of the exchange are in [07-embedding-notes.md](07-embedding-notes.md), "The preshared-key path".

What still restarts, and binds a later change: the settings of 443
(`--https-only`, `--proxy`, `--relay-name`) restart the mesh in-process; a
device that runs a relay restarts on a rotation, its certificate going with
the keys; `juist rotate identity` restarts, its IPv6 address moving; a
renumbering on the netstack restarts; an upgrade restarts the process. The
disco key stays drawn per process.

## M16 — Names for members alone

**Done** on 2026-10-11, reviewed (M16 reviews 1 to 8, six of them security
reviews by fresh reviewers), validated by `make ci-vm` and `make
test-freebsd` (12-validating.md), the Android app for schema 15 released. Core
9 954 lines, audit scope 30 633, measured after it (2026-10-11).

A published name marked `Members` (schema 15, `juist publish add …
--members`) holds a CA certificate like any other but is reached by the
members the access policy passes alone (`pass from <family> to name photos`),
at its device, through the tunnel. The ingress passes it to nobody but the
CA's TLS-ALPN-01 validation; the device ending its TLS takes it only from the
overlay addresses of the members the policy passes; and it is not served where
another name's or a share's bytes reach the same service as they are. A
member whose host does not route the domain to juistd reaches it not at all,
which `juist status` says. Out of scope: per-name access for a name passed by
TCP, and hiding that the name exists, which the CT logs show.

## M17 — Post-quantum signatures

**Done** on 2026-10-13, reviewed (M17 reviews 1 to 5, security and
performance reviews of the whole milestone by a fresh reviewer), validated by
`make ci-vm` and `make test-freebsd` (12-validating.md), the Android app for
schema 18 released. Core 10 998 lines, audit scope 32 389, measured after it
(2026-10-13).

Every signature that changes or carries state is ML-DSA-44, so a quantum
computer forges no change to the network; the networks moved by a one-time
cut-over to schema 18, which M18 removed again. Enrollment by code and
juist's own TLS became post-quantum too. What a quantum computer still forges
is weakness 13 in [02-threat-model.md](02-threat-model.md); the rules are in
[08-trust-layer-notes.md](08-trust-layer-notes.md), "Signatures".

## M18 — Schema 18 alone

**Done** on 2026-10-14, reviewed (M18 reviews 1 to 4: an adversarial review of
M17 and M18 by six reviewers, its fixes attacked again three times), validated
by `make ci-vm` and `make test-freebsd` (12-validating.md), the Android app
for schema 19 released. Core 10 845 lines, audit scope 32 340, measured after
it (2026-10-14).

juist reads schema 18 and above alone: a genesis, checkpoint, record or
anchor below 18 is refused, and such a device says to join again. Every rule
of the schemas below went, with the cut-over, record verification by Ed25519
and what gossip held back from older builds; the numbers of
`KindSetSigningKeys` and `KindSetAdminSigning` stay reserved, and
`KindSchemaUpgrade` stays. The review's fixes are schema 19: an identity
rotation names the new identity's signing key, and copies of one record are
that record ([08-trust-layer-notes.md](08-trust-layer-notes.md), "Fork
choice"). Announcements keep their Ed25519 signature as long as discovery
carries them as hints. A chain that fork choice moves below the epoch floor
is held under a rollback alarm until it is back at the floor.

## M19 — Log checkpoints

**Done** on 2026-10-14, reviewed (M19 reviews 1 to 7: an adversarial review
of the trust core, sync and compaction, and the CLI and its pin, each round's
fixes attacked again), validated by `make ci-vm` (12-validating.md). The
schema stays at 19. Core 10 933 lines, audit scope 32 805, measured after it
(2026-10-14).

Logs stay short and in sync without an admin asking. A hello lists the
records a device resolves from its anchor, those nothing hangs from first
past `MaxHashesPerFrame`, so two devices converge however long the log is
([09-mesh-layer-notes.md](09-mesh-layer-notes.md)). The admin's CLI that
applies a change drafts a checkpoint where the chain holds 256 records or
32 MiB since its newest checkpoint or anchor, submitted as any change; none
is drafted or asked for under an alarm, and one that loses fork choice raises
none. juistd compacts to the checkpoint before the newest once every live
member is heard past the newest; a device further behind than its peers keep
is invited again by a link naming its admin
([08-trust-layer-notes.md](08-trust-layer-notes.md), "The two ratchets"). The
CLI's pin survives compaction where a quorum of its keys signed the
checkpoint the log starts from. Open for M33: a record released below a
compaction is refused where devices compacted and taken where they did not,
with no alarm (weakness 14 in [02-threat-model.md](02-threat-model.md)).

## M20 — Faster CI

**Done** on 2026-10-17, reviewed (M20 reviews 1 and 2: the runner, the lab,
and the Makefile and docs, each round's fixes attacked again), validated by
`make ci-vm` (12-validating.md): the closing run in 16 to 19 minutes against
the 45 before it, the privileged tests in 2 against 6 on their own, the lab
in 14 to 16 against 27, and a failure planted in each stage ending the run in
that stage. Core 10 933 lines, audit scope 32 952, measured after it
(2026-10-17).

`make ci-vm` runs in stages from a snapshot of the working tree, a step for
each make target and its time in `build/ci`'s log, and the first step to fail
ends the run. What only a VM shows, the privileged tests, run in parallel,
every netns lab under a tag no other holds; `make check`'s steps follow in
the VM, and the RPM. The lab runs on the host from the start, on CPUs of its
own beside the VM's, and the cross builds and `govulncheck` run on them after
it. It boots two pairs of VMs at once from disks set up once, each kept with
a sum of its own: one pair on this build, its network past three epoch
bumps before the rest, and one upgraded from the previous release, whose
packages are built once per commit, which then carries the bumps' pings,
exit nodes, subnets, names and an ingress. Each lab test logs its
longest waits and commands; a ping across an epoch bump ends once a session
on the new key has carried data, which it now asserts. `make check` stamps the
tree it passed on, and `make ci-vm FAST=1` takes `make check` from the stamp
for the runs before the closing one; `STAGES` and `FROM` run some stages
alone.

What still binds:

- **The closing run** takes no stamp: it runs `make check` in the VM and
  `repro` from an empty build cache. It takes the lab's disks, which their
  sums check every run, and the previous release's packages, which the
  commit and the toolchain key, from their caches, and accepts the host's
  qemu and Chrome.
- **The CI VM shares no core with the lab.** A VM whose CPUs other guests
  take runs its race tests up to eight times slower and fails their timing;
  the lab's four guests on one CPU of four lose pings. Beside the lab, the
  VM and the lab take half the host's cores each.
- **The lab's parts depend on those before them** in `TestLinuxAndFreeBSD`,
  `domain itself` on `names`' resolver among them; a part moves to the
  other pair only with what it needs. What the single pair before it
  covered, both pairs together still do: the parts after the bumps on a
  network past them, and exit nodes, subnets, names and an ingress on
  upgraded packages as on fresh ones.
- **The test cache stays off** (`-count=1`): Go's cache does not see every
  input a test reads, such as the host's network or root.
- **The slow tests** run in parallel where they share nothing, `make
  test-race` in 8 minutes on the VM's two CPUs beside the lab's 14. What
  stays serial says why: a latency bounded, a window counted, every socket
  read. The long sleeps left are windows in which something must not
  happen, and stay. `cmd/juist` and `daemon` spend their time verifying
  ML-DSA signatures again on every resolve. In the lab,
  `access policy`'s hello for the name for members ended in a TLS internal
  error for two minutes in one run of four since the lab was split, its
  certificate not issued; the part now logs the terminator's journal and
  Pebble's where it fails, which is what the next one has to answer.

## M21 — Battery life on Android

A day with the app connected, the phone in neither battery nor data saver,
put juist at 65 % of the phone's battery use by the afternoon (2026-10-12):
too much to leave it on, which is what a VPN is for. The core runs on a
phone at a laptop's pace, and some of what it does costs more there. Before
the names on Android (M23), which are of little use on an app that cannot
stay on, and before the audit, so that M34 covers what changes.

**Done** on 2026-10-21, reviewed (M21 reviews 1 to 3, the second in
thirteen rounds, each round's fixes attacked again), validated by a real
phone's day before and after ([12-validating.md](12-validating.md), "A real
phone's day"): juist at 5 % of the battery in Android's own list against 32 %
the day before and 65 % before M21, 21 mAh an hour against 54, its radio
active 3 minutes an hour against 30, its own log sync through the tunnel
about 1 MB an hour each way against 5 to 20; by `make android-idle` beside
ten members; and by `make ci-vm` at 8799d87. Core 10 987 lines, audit scope
33 598, measured after it (2026-10-21).

Measured idle in the emulator, without a relay, before it: about 29,500
packets an hour, from magicsock's 3 s heartbeat on both ends of every
tunnel, restarted for 45 s by each 30 s probe; the engine asking STUN again
every few seconds, failing to reach a STUN server it took for its home; and
the notification posted every 30 s. What follows from it:

- A node that asks STUN servers and reaches no member relay is homeless,
  rather than homed at a STUN server it would try every few seconds, and
  asks STUN every 25 s only while its tunnels carry traffic and it does not
  save battery, on every platform; one whose relays went unreached asks
  again from 25 s to 10 minutes apart, saving or not, and homes at the
  first it reaches. The STUN servers share one region of the relay map, so
  that netcheck, which measures the three nearest regions, measures the
  relays beside them.
- The phone saves battery while its screen is off, it dozes or battery
  saver is on, and on a metered network while the app is not in front
  (`daemon.Pace`): tunnels are checked every 5 minutes, the log is synced
  every 30, and magicsock's heartbeat is off (silent disco), a path trusted
  while the peer's traffic arrives on it. The multicast lock is held, and
  LAN discovery announces, only while not saving or while joining, and the
  status poll, the notification included, pauses with the screen off. The
  status screen says when battery saver keeps it saving.
- **Peers let the phone rest,** from schema 20, whose announcements may say
  a device rests, as the phone's do. A peer that rests, or any while this
  device saves, is checked quietly: probed once in 30 minutes, its answer
  standing between, and where no relay could wake it pinged meanwhile by a
  disco ping sent with silent disco on, which starts no heartbeat on either
  end, every minute: more often would keep going a heartbeat the last
  packet started. A ping unanswered, a key changed since the answer, or a
  new announcement has it probed, and a handshake under the key since
  renews the answer, so that a pair costs one probe. The periodic sync
  leaves a member that rests to sync by itself, but for one every 30
  minutes where all do. A new address, where nothing else in the
  announcement changed and it is no relay's, is pushed to those that do not
  rest: one that rests learns it at its next sync, within 30 minutes, and
  from disco over its relay meanwhile; without a relay a direct path to it
  waits that long. A device that saves, homed at a relay, pushes a new
  address of its own at the next reconcile or when saving ends.
- **Log sync on a phone:** a real phone's day (2026-10-20) put juist at
  512 mAh of 2 385, 496 of them the radio, held up for 4 h 42 min by
  110 MB each way of juist's own log sync through the tunnel: every session
  carried every member's announcement and address key both ways, about
  70 KB a hello at 11 members, and every member pushed each change it heard
  on to eight others, the phone among them, which pushed it on in turn. A
  device that rests now passes on nothing it hears while a member awake
  does, and pushes its own news to two members awake; a member passes on
  others' announcements, address keys, waiting changes and leases to the
  members awake alone, and records and its own news to every member that
  rests besides `PushFanout` awake, so a phone hears others' news from its
  author, or at its own sync. From schema 21 a hello says what its sender
  holds of each node, its announcement's and address key's numbers and its
  newest lease, and the records frame answering it carries what the peer
  lacks, address keys among them. In the emulator beside ten members, one
  restarting every 3 minutes, the phone's traffic with the members fell
  from 30.5 MB an hour to 1.4, and its datagrams and segments from 53 000
  an hour to 8 400
  ([12-validating.md](12-validating.md), "An idle phone").
- **The DHT on a phone:** a device that rests takes part in the public DHT
  only once checked and while no member that does not rest answers it, and
  a member leaves its lookups to no peer that rests; relays are asked as
  before. A member answering it that runs without the DHT (`--no-dht`)
  stands in all the same, which no announcement says.
- **Events instead of polls:** the mesh reconciles at the next deadline it
  knows (a membership's expiry, a renumbering's, the view going stale, a
  lease to renew, a share's end, an exchange of pair keys put off, the
  routing of the host's DNS to renew) and otherwise every 2 minutes, 10
  while saving; the service looks for moved keys and addresses every
  minute, 10 while saving, which the mesh's calls on a change make a
  backstop, and every 5 s only while the mesh failed to start or a lower
  instance may conflict. systemd-resolved's restarts are watched over D-Bus
  (`NameOwnerChanged`), its routing renewed hourly then rather than every 5
  minutes, and the host's routing is read again when an interface changes.
  Laptops gain all of it.
- `make android-idle` measures an idle phone in the emulator beside ten
  members, one restarting every 3 minutes, with and without a relay, and
  fails past a budget: 15 065 datagrams an hour without a relay and 8 408
  with one ([12-validating.md](12-validating.md), "An idle phone").

Not taken up, from the review: a relay reached by TCP alone, its STUN port
blocked, is never measured while a public STUN server answers (netcheck
measures by HTTPS only where no UDP probe is answered), so it is no node's
home; and with no STUN server asked (`--no-stun`), a dead relay is dialled,
and measured, again every few seconds. Both are as before M21; `juist
health` could say the first, and M22 weighs measuring such a relay by HTTPS.

## M22 — Every member through one relay on 443

A device on a network that passes TCP to 443 alone reaches the relays named
on 443 and no other, and a member is sent to at the relay it is homed at, so
in a hotel's network a member homed at an unnamed relay is out of the
device's reach, with `--https-only` or without it, unless every relay is
named by hand. Both ends meet at the device's own relay instead: it sends
every peer whose home it cannot reach there, and members keep a connection
to it, so that one relay named on 443, the ingress's by itself, is enough.
Relays forwarding for one another is the alternative should that fall short.
Before the audit, so that M34 covers it, and not started before M21 is
validated and the refactoring
([temp/20261019-refactoring.md](temp/20261019-refactoring.md)) is done.

**Done** on 2026-10-23, reviewed (M22 reviews 1 to 3, the third's fixes
attacked again in three rounds), validated in the netns lab by hotel, a
device whose network passes TCP to 443 alone, beside lx homed at a relay
without a name (`interop/onerelay_test.go`): hotel reaches lx and is reached
through fb's relay, the ingress's, serving `relay.<domain>` with no name
set, with `--https-only` and without, and again after three minutes without
traffic; with lx stopped, hotel reaches it no longer and `juist health`
names it as not at fb's relay; and lx, started after hotel moved, reaches it
by what the relays hold alone. A member that rests keeps no connection and
is reached once it sends (`conn`: `TestWalledNodesMeetAtAHome`, `daemon`:
`TestAPeerWalledIsKeptAtItsHome`), and
[02-threat-model.md](02-threat-model.md), weaknesses 5 and 15, says what
changes. `make ci-vm` passed at M22, and in the nine lab runs since
M22 hotel met lx without `--https-only` within 21 s to 2m31s, mostly
under 40 s; `make android-idle` stays within its budgets
([12-validating.md](12-validating.md), "An idle phone beside ten members").
Core 10 987 lines, audit scope 34 049, measured after it (2026-10-23). The
rules, and what M22 leaves open, are in
[16-one-relay-on-443.md](16-one-relay-on-443.md).

## M23 — Names on Android

The Android app resolved none of the network's names: with a DNS server set,
`VpnService` sends every lookup of the phone to it, so the core set one only
for an exit node, which then answered them all. A name for members alone
(M16) was out of the phone's reach, and a published name resolved to the
ingress, not the tunnel. Taken from the full app (M26), and before the audit,
so that M34 covers a resolver that sees every lookup the phone makes.

**Done** on 2026-10-24, reviewed (M23 reviews 1 to 3, the third attacking
the fixes of the first two again), validated in the Android 16 emulator by
hand ([12-validating.md](12-validating.md), "Check names on Android") beside
members on a network stack and an exit node in docker-vm: exit criteria (1),
(2), (3) and (5) as below, the exit node refused failing lookups in 35 ms;
(4) by `FuzzAnswer` and `FuzzForwarded`, which found an OPT record among the
answers passing the TTL cap; by `make android-idle` within its budgets,
beside a relay 7 261 datagrams and segments an hour where 10 662 were before
a quiet peer that moved its addresses alone was spared a probe
([12-validating.md](12-validating.md), "An idle phone beside ten members");
by `make ci-vm` at M23; and (6) by the app built at the commit closing
it, a pre-release on juist-dev. Core 10 997 lines, audit scope 34 457,
measured after it (2026-10-24). What it built:

- **One resolver for all of the phone's lookups** (`daemon.Resolver`,
  `daemon.VPNDNS`): the core answers the network's names, its members' and
  those published under its domain, from the zone juistd answers
  systemd-resolved with, and forwards every other query: to the exit node in
  use, through the tunnel, else to the resolvers of the network beneath the
  VPN, which the app reports with each change of it, from a protected
  socket. The VPN searches the network's domain alone, so a member's name
  resolves without it, and a name without a dot it lacks is asked as it is:
  the underlay's domains would stay after the phone left its network, and
  following them would establish the VPN again, which ends every connection
  through it. The reverse names of the network's addresses are answered
  too, a member's by its name, so that no resolver outside learns them.
  Public names pointed at members followed on 2026-11-06: **Public
  names** in Details is the app's `juist names on`, off by default, and
  Details lists each name, its member and why it resolves publicly.
- **At an address of the overlay** (`types.ResolverAddr`): the network's
  prefix and ::53, routed into the tunnel and taken by `conn` from the
  device's own packets before the engine, into a network stack of its own
  in the core that answers UDP and TCP; a member's packets never reach it.
  The stack fragments nothing, so an answer longer than a datagram at the
  tunnel's MTU goes out truncated, for the phone to ask again over TCP.
  Answers from upstream keep their TTLs, which a cap would have the phone
  ask again for and wake the radio, but for the names the network may yet
  answer itself, under its public domain or pointed at a member.
  No member's address, derived from its identity, takes it but by finding an
  identity whose 80 derived bits are those. IPv6 alone.
- **Failing fast:** a query the resolver can ask no one of is answered
  SERVFAIL at once, as is one for a refused exit node, and one no resolver
  answered after the forwarder's 3 s; stopping the VPN gives the phone its
  own DNS back.
- **Private DNS:** off and automatic reach the resolver, which refuses DNS
  over TLS on 853 at once, so Android asks it in plain text; where automatic
  found the network's resolvers answering DNS over TLS, the core asks them
  over TLS too, unauthenticated as Android does, its sessions resumed, and in
  plain text where that fails, for 10 minutes. A provider's host name sends every lookup past the VPN, whose
  lookups then all failed, so the VPN takes none while one is set, and the
  app says the names are not resolved and why.
- **Status:** the phone's own name and each device's in DNS, and as alarms
  why the names are not resolved, Private DNS by its host, and each name for
  members alone then out of reach.
- **Carried from M21, the members' pings after news:** after a member's
  restart the phone synced, learned every member's addresses moved since,
  as STUN's answers do, and probed each of them, whose heartbeats then
  pinged it for 45 s; a peer checked quietly that moved its addresses alone
  is now left to its next check. `make android-idle` beside a relay fell
  from 10 662 datagrams and segments an hour to 6 871, and 7 261 in the run
  closing M23, below M21's 8 408.

Not taken up: DNS over TLS to the network's resolvers and their TTLs were not
tried by hand, as the emulator's resolver answers no TLS and every TTL as
30 s itself; a real phone's day on mobile data was taken in M26
(2026-11-03).

- **Exit criteria:** (1) in the emulator, with no exit node, the app
  resolves a member's name and a name for members alone to its overlay
  address and opens it through the tunnel, and every other name as without
  the VPN; (2) with an exit node, the network's names still resolve, and
  every other lookup goes to the exit node; (3) a lookup the resolver cannot
  forward fails within a second, and stopping the VPN restores the phone's
  DNS; (4) the resolver's input has a fuzz target; (5) the app says why a
  name cannot be reached where Private DNS passes the resolver by; (6) the
  app is released.

## M24 — Boundaries on a host

What one network's daemon, the LAN and a local user can reach on a host
running juist, closed before the audit, so that M34 covers it.

**Done** on 2026-10-31, reviewed (M24 reviews 1 and 2, the second
attacking the first's fix and the boundary between instances again),
validated by `make ci-vm` at M24, the lab on FreeBSD 15.1, in 36m8s:
exit criterion (1) by the lab's `a user per network` on Debian and FreeBSD
and its upgrade moving each instance's home; (2) by the lab's `tunnel`, lx
reaching fb's overlay address by the LAN no more, and
`TestAGuardSetsTheHostUpAndBack` on FreeBSD 15.1; (3) by
`TestTheHelperRoutesNothingOverTheHostsOwnLAN`; (4) by
`TestAReaderSeesNoMembersNames`; (5) by residual weaknesses 8 and 9 in
[02-threat-model.md](02-threat-model.md), which say what remains; (6) to
(10) as below. `make test-freebsd` passed all 54 packages on 15.1. Core
10 997 lines, audit scope 35 151, measured after it (2026-10-31). What
it built:

- **A user per juistd instance**, so that one network's compromised daemon
  on a host holds none of the others' device keys. Instance 0 stays the
  `juist` user, in `/var/lib/juist` and `/run/juist`; instance N runs as
  `juistN`, in `/var/lib/juistN` and `/run/juistN` (`/var/db/juistN`,
  `/var/run/juistN` on FreeBSD). The packages make `juist1` to `juist9` as
  they make `juist`, so `create` and `join` add no user. An upgrade moves an
  instance's home out of the default's once, as root, giving on only what
  was juist's and nothing that became a link or a file meanwhile. The
  instance above reads the claims of the one below over its socket, as any
  local user, coarsely. Polkit lets `juistN` point resolved at its own
  device alone.
- **pf on FreeBSD** keeps a device's overlay to its tunnel, as Linux's in
  table does: an anchor of its own, `juist/juistN_in`, drops what comes for
  the device's addresses by another device than it or the loopback, and
  members' sources by a device in no juist group. pf runs for it where it
  was off. Where the host's own rules call no juist anchor, the device runs
  unguarded and `juist health` says why.
- **The FreeBSD helper** plumbs its own daemon's device alone, and routes
  nothing that holds the host's own address or a gateway of its routes, so
  not the host's LAN whole. A part of a wider network the host is on stays
  a subnet's to take, as the daemon takes one inside a DHCP netmask too
  wide.
- **The read tier** names no other member: a local user who may not operate
  sees each by a pseudonym, `member 1` on, the same throughout one status,
  and no member's identity.

**Carried from M22**, what [16-one-relay-on-443.md](16-one-relay-on-443.md)
left open, before the user per instance; done, with exit criteria (6) to
(10) passed by `make ci-vm` at M24 and (6) by ten lab runs in a row
before it ([12-validating.md](12-validating.md)); the invite from a relay
on 443 by hand on Debian 13 VMs on laptop1 (`private/debian-vms.sh`, at
M24): a guest whose network passes TCP to 443 and DNS alone, on
`--https-only`, joined through the network's only relay, named on 443,
reached it both ways, and its package was removed cleanly:

- **The first meeting after a restart.** In two lab runs of nine, hotel
  reached lx 1m48s and 2m31s after leaving `--https-only`, where the others
  took 16 to 37 s. Caught in the fifteenth run of a loop: homed and not yet
  walled, hotel announced its addresses, so lx stopped keeping fb's relay
  open and heard the walls only at its next sync; a device homed without
  UDP now says it is walled until a report decides, and members keep a
  walled peer's home open 2 minutes past the last need, as a restarting
  peer is homeless first. The rest, caught in held lab runs: a device
  announced the home the engine picks by number where a report measured
  no relay, which lx sent to in vain; a home is now announced once
  measured, and a peer without one is sent to at its last for 2 minutes.
- **Homes reached by TCP alone.** Where public STUN servers answer and no
  relay's port does, netcheck measures no relay by HTTPS and the device is
  homeless: after two such reports it asks without the STUN servers, until
  its link changes.
- **A home pinged alone.** A juistd with the right to ping takes a relay
  that answered ICMP and not HTTPS for its home: such a relay counts as
  unmeasured, and the device is held at the nearest relay HTTPS reached.
- **The last name gone.** A device reaching no relay without UDP takes the
  ingress at `relay.<domain>`, its role's name in the log, once the name's
  server says it is the ingress: an announcement found unsigned names no
  relay, and a name once proven stays so until its server says otherwise.
- **Peers kept open for nothing.** A member keeps a connection at a walled
  peer's home only where its own home has no name on 443, which a walled
  peer reaches.
- **A walled phone is pinged.** The connection is kept by a write to the
  peer's home addressed to no client, which the relay drops, once per home,
  rather than by a ping to each walled peer.

- **Exit criteria:** (1) with two networks on a host, installed as the
  package installs them, one network's juistd cannot read the other's
  device keys; (2) on FreeBSD, a packet from the LAN to a device's overlay
  address is dropped; (3) the helper refuses a route over the host's own
  LAN; (4) the read tier passes a local user no member's identity or name;
  (5) residual weaknesses 8 and 9 leave the threat model or say what
  remains of them; (6) in the lab, hotel meets lx without `--https-only`
  within a minute in ten runs in a row; (7) hotel, its network passing a
  STUN server's port too, is homed at fb's relay and reaches lx; (8) a
  relay answering ICMP alone is never a home; (9) a walled device whose
  relay names all moved finds the members again at `relay.<domain>`; (10)
  a walled peer receives nothing from a member to keep the member's
  connection, and none from one whose home has a name.

## M25 — Multicast

Discovery multicast across the overlay: mDNS, SSDP, WS-Discovery, LLMNR,
LAN games. The overlay counts as one link for them. Multicast routing,
streaming and broadcast are out of scope; broadcast has no address to go to
while every overlay address is a host prefix. Before the audit, so that M34
covers the unwrapping, which parses what members send.

**Done** on 2026-10-31, reviewed (M25 reviews 1 to 5, the second and the
fourth attacking the fixes and the policy rule again, the fifth over the
whole milestone), validated by `make ci-vm` at M25, in 36m41s: exit
criteria (1) and (5) by the netns lab's `TestNetnsAGroupDatagram*` and
`TestNetnsARoutedGroupReachesTheDefaultInterface`; (2), (3) and (4) by
conn's tests through real tunnels; (6) by `FuzzUnwrapGroup` and
`FuzzUnwrapGroup6`; (7) by `TestAccessPassesGroupsAndTheirAnswersAlone`
and the policy's, log's and daemon's own; the lab's FreeBSD 15.1 and its
upgrade from M24 to schema 22 with multicast on; the app built at the
commit closing it is a pre-release on juist-dev. Core 11 014 lines, its
budget raised to 11 050 for the rule's field, check and schema, audit scope
35 738, measured after it (2026-10-31). What it built:

- **Capture** (`conn/multicast.go`): UDP to a multicast group that the host
  sends into the device from this node's own address, IPv6 only to groups
  of link or site scope, without IPv4 options or IPv6 extension headers, is
  taken ahead of the filter (`PreFilterPacketOutboundToWireGuardEngineIntercept`,
  chained in front of the engine's), and IGMP and MLD stay behind. This node
  holds itself to 100 datagrams a second in bursts of 200.
- **Transport:** a copy to each member without an access but one that
  rests, as the Android app does, which a copy would wake; IPv4 in IPv4
  between overlay IPv4 addresses, IPv6 in IPv6 between overlay IPv6
  addresses, as a member's IPv4 address is optional, injected by a goroutine
  of its own, since `InjectOutbound` from the hook blocks the goroutine that
  drains it. Every member gets a copy; membership tracking waits until that
  proves too much. A full-sized datagram goes 20 or 40 bytes past the MTU,
  which crosses a direct path and a relay in the lab, over an underlay of
  1500; a narrower one is untested.
- **Delivery:** a wrapped packet must be exactly what juistd makes, from a
  member without an access to this node's own address; the inner source
  the sender's overlay address, or over IPv6 its link-local one; at most
  100 a second in bursts of 200 from each sender; then `InjectInboundCopy`.
  The TTL is left as sent. A packet wrapped for this node never reaches
  the host, multicast on or off, so that a host's own IP-in-IP tunnels do
  not unwrap a member's.
- **A link-local address per member:** `fe80::/64` and the low 64 bits of
  its overlay IPv6 address, which follows from its identity. conn adds it
  to each member's addresses, so that AllowedIPs, the filter (by a
  `LinkLocalAllowHooks` hook), the confiner and the source check treat it as
  the member's own, and unicast answers (SSDP, legacy mDNS) come back. One
  two peers would share is neither's, one a peer shares with this node the
  peer's no longer. The device holds it alone: Linux's router sets
  addrgenmode none by netlink and deletes the kernel's, FreeBSD's helper
  sets `-auto_linklocal no_dad` and takes no link-local but one derived from
  an overlay address it is given. The overlay's guard and serving leave
  link-locals out.
- **Routed groups** (`juist set --groups`, IPv4, Linux): routed into the
  device in juist's table and joined on it, so that an app on the default
  interface sends to the members and receives theirs; the group leaves the
  LAN on that host. IPv6 groups are not routed: the kernel's local table
  sends `ff00::/8` by every device before juist's rules.
- **Under an access policy** none passes but what a rule passes, pair by
  pair: `pass multicast from <family> to <family> [port N]`. The keyword
  follows `pass`, as pf's `in` and `out` do, and is no `proto`: a group is a
  kind of destination; `port` needs no `proto`, since UDP alone crosses.
  `PolicyRule.Multicast` is a field older members' strict decoder refuses,
  so it needs schema 22 (`types.SchemaMulticast`), which the log enforces.
  The rule gives `conn.Access` its `GroupsTo` and `GroupsFrom` ports; the
  two members peer. The same rule passes unicast UDP to the port a group
  datagram left from, for ten seconds after it, both ways through the
  confiner, as netfilter's broadcast helper does: SSDP, WS-Discovery and
  mDNS's legacy and QU queries are answered so. The receiver looks the
  authenticated outer source up among the senders it takes before it
  parses anything.
- **juistd** carries multicast by default on a device of its own,
  `juist set --multicast=false` turns it off, both settings restart the
  mesh; `juist status` says `Multicast on`, `off` or the routed groups, and
  `juist health` warns where avahi runs and leaves the device out
  (`allow-point-to-point`, `allow-interfaces`, `deny-interfaces`). The
  Android app carries none, nor a service member on its network stack.

What a member gains is in [02-threat-model.md](02-threat-model.md),
residual weakness 17.

Not planned: a TAP mode. Carrying Ethernet would need a virtual switch and
encapsulation, since wireguard-go carries only IP, and would lose the binding
of an overlay address to its member that the source check rests on.

- **Exit criteria:** (1) in the netns matrix, an mDNS query sent on `juist0`
  reaches the other members' listeners with the sender's overlay address as
  its source, over IPv6 its link-local, directly and through a relay, and an
  SSDP answer goes back unicast; (2) a wrapped packet whose inner
  source is not the sending peer's address is dropped; (3) a member whose
  daemon is patched to ignore the limit is cut at the receiver; (4) no packet
  from another LAN host, and no IGMP or MLD, crosses the overlay; (5) a
  listener joined on the default interface receives a routed group's packets
  from a member; (6) the unwrapping has a fuzz target; (7) under a policy,
  a group datagram reaches only the members a `pass multicast` rule passes
  it to, an SSDP answer to one goes back, and a wrapped packet from a
  member no rule passes is dropped unparsed.

## Discovery copying after M25

Linux copies the host's own IPv4 UDP multicast and broadcasts into the
network alongside the LAN. The copy carries the sender's overlay address;
the original and its mark stay on the LAN. Limited and subnet broadcasts
are supported; subnet broadcasts arrive as limited broadcast. Only local,
unfragmented UDP without IP options, fitting 1280 bytes, is copied. DHCP
broadcasts are excluded; NetBIOS uses the ordinary UDP broadcast path,
without protocol-specific address or name handling. IPv6 still needs
native device support.

Without a policy, copying and multicast are enabled by default. Under a
policy they are off until a matching `pass multicast` rule permits them,
by peer, direction and port. Kernel copying needs an IPv4 peer with outgoing
UDP multicast access and follows policy changes even when routes stay the
same. `juist set --multicast=false` overrides every policy permission.

IPv4 groups are copied automatically. `--groups` restricts them to a list;
`--groups ""` disables group copies while leaving broadcast alone;
`--groups auto` restores the default. Explicit groups are also joined on
the device. A local unicast copy reaches Java sockets joined only on the
LAN, retaining the sender and requiring ordinary UDP permission too.
Bypass-marked sockets, including juist's own mDNS beacons, stay on the
underlay. Copying stops when the last eligible IPv4 peer goes away. Queued datagrams
expire with their policy snapshot; only traffic with an eligible recipient
spends the sending quota.

Core 11 014 lines, budget 11 050; audit scope 36 069, measured on
2026-11-01. `make check`, `make cross`, the website check, the Linux
privileged gate, the FreeBSD connection tests and the real Java discovery
probe passed. The Linux/FreeBSD lab passed at 66409ed (M25 review 9),
which recovers a pair key left unconfirmed when both ends restart.
[12-validating.md](12-validating.md#the-last-privileged-run)
identifies the tested snapshots and results. Residual weakness 18 in
[02-threat-model.md](02-threat-model.md) covers host-wide discovery exposure.

## M26 — The full Android app

**Done** on 2026-11-05: subnet routes through `VpnService` routes, less
those the network beneath the VPN reaches itself; the HTTPS-alone switch;
the Quick Settings tile; a member's services; the details screen with the
names switch; and the diagnosis copied with the log. Reviewed on
2026-11-02 (no finding that asked for a fix) and in M26 reviews 1 and 2
(2026-11-06: five lenses, 13 findings confirmed, one medium; the second,
on the first's fixes, found two gaps in their tests), validated by `make ci-vm`
at M26 ([12-validating.md](12-validating.md), "The last privileged
run"), the exit criterion by its lab's interop run and `make
android-smoke`, which joins the app in the emulator, resolves and pings a
member and is pinged by it. Subnets, the tile, the names switch and the
details checked by hand in an Android 13 emulator with Google APIs, HTTPS
alone on a phone against a relay on 443, and a phone's day on LTE
(2026-11-03) put juist at 16 % in Android's list, against 5 % on Wi-Fi at
M21. Family Link, and what the relay's keepalive costs on mobile data,
moved to M30. Core 11 014 lines, audit scope 36 432, measured after it
(2026-11-05).

Open from M26 review 1, all minor: the app's alarms on HTTPS alone lack
the CLI's "no relay on 443" and its wording for a relay's own device; a
subnet's reason in Details is the daemon's English; an interrupted first
`make install` leaves files neither it nor `make uninstall` takes, and on
a host with AppArmor it installs no nameservice snippet; `make
android-smoke`'s "is pinged" is a TSMP ping, answered before the phone's
filter, and no phone meets a FreeBSD member.

The full Android app, on M10's, once M10's exit criteria are met: M6b's
subnet routes through `VpnService` routes and M13's HTTPS alone, released
as the app is now. Before the audit, so that M34 covers the routes a phone
takes.

A real phone's day on mobile data, where M21's and M23's ran on Wi-Fi,
shows what a radio wake costs there, before it is released.

- **A Quick Settings tile** turns the VPN on and off as the app's switch
  does, and shows its state; a long press opens the app. Where Android has
  not yet granted the VPN, the tile opens the app to ask.
- **A member's services.** Its screen lists what the network publishes on
  it: names under the network's domain (M9), members-only among them (M16),
  and TCP ports through the ingress (M11a), each opened in the browser or
  copied. The in-process API gains them where `ipc.Status` lacks them.
- **Details.** The status screen gains what `juist status` and the status
  page (M9f) show where it applies to a phone: the network's schema and the
  app's, the log's head and when the phone last updated its view; the
  log's newest changes, as `juist log` lists them; relays (how many, which
  one this phone is homed at); the vouchers behind freshness; names and
  their DNS state; and each member's juist version beside its reach. Not
  what the phone cannot have (ports, serving, roles' settings, multicast).

- **Exit criteria:** 3-platform interop matrix green in CI, Android by an
  emulator smoke test.

## M27 — Several networks in the app

**Done** on 2026-11-06: up to four networks in the app, each in a slot of
its own in one core behind `conn.VPNHub`, which routes them together on one
device, hands each packet to the network its destination is in and the
internet to the exit node's, translates what Android sent from another
network's address, and lets nothing reach a network's addresses from
another network or from where another's routes lead; one resolver answers
every network's names; the M5 rules hold by slot; the app lists the
networks, joins another and leaves one. Decided: one Keystore key seals
every slot's keys, at most four networks, a network's alarm stays its own
([13-multi-network-notes.md](13-multi-network-notes.md#on-a-phone-slots-behind-one-vpn)).
Reviewed in three rounds (2026-11-05), each fix with a test that fails
without it; validated by `make ci-vm` at M26.1
([12-validating.md](12-validating.md), "The last privileged run"), exit
criteria (1), (3) and (4) by its `make android-smoke`, which joins the
emulator to two networks, reaches a member of each directly and one through
the other's relay alone, resolves both networks' names and leaves the
second while the first's tunnel stays up; (2) by the hub's tests, a
network's engine writing to the other's addresses or from them. An M26 app
in a network, updated in place to this one keeps the
network, its keys and addresses. Core 11 014 lines, audit scope 36 859,
measured after it (2026-11-06).

The app is a member of one network. On Linux each network is an instance of
its own (M5); a phone has one VPN at a time, and an app's `VpnService` one
interface, which `establish()` replaces.

- **Lead option:** one core in the app's process holding a service per
  network, all behind one TUN: a packet goes to the network whose prefix
  holds its destination, and the routes, the resolver (M23) and the exit
  node are the union of the networks'. An exit node is one network's at a
  time. Whether the pinned Tailscale runs several engines in one process,
  given what it keeps process-wide (`netmon`, `netns`'s protect function),
  is read in the module first.
- **The rules of M5** hold as on Linux: a network whose IPv4 another one
  holds runs without IPv4 and says so
  ([13-multi-network-notes.md](13-multi-network-notes.md)).
- **The app** lists the networks, joins and leaves one, and says for each
  what the status says now.

- **Exit criteria:** (1) in `make interop`, the emulator joins two
  networks and reaches a member of each, directly and through a relay; (2)
  a member of one network does not reach the other through the phone; (3)
  leaving one network keeps the other's tunnels; (4) both networks' names
  resolve.

## Publishing in one command

**Done** on 2026-11-07, released with M28. `juist publish` is one command
without subcommands: `NAME PORT|HOST:PORT` publishes here and has juist end
TLS, `NAME [PORT] --on DEVICE` is an admin's entry for another device,
`NAME status-page` the status page, `NAME` alone serves a name published
here, `PORT` shares under the device's own name, `--stop [NAME|PORT]` ends
one or, alone, all serving. `add`, `remove` and `serve` are gone. The
listing heads the domain's labels with the domain, spells out names of
their own, and says each name's state in a word (`serving`, `unserved`, `unpublished`, `failing`, `offline`); `juist
health` on a device names the admin's command for a name it sends somewhere
that is not published.

Who may publish stays as it was: the role `publish` shares under the
device's own name, every other name is an admin's change. Self-chosen names
for holders of the role were weighed and dropped: announced by gossip, a
label frees when its device is offline for ten minutes and another holder
gets a certificate for it; signed by the device into the log, it costs a
schema and a change kind admins did not approve. A later plan that wants
them has to answer both.

No schema: the log, IPC and juistd are as they were. `make ci-vm
STAGES=lab` passed at 4ebec19
([12-validating.md](12-validating.md#the-last-privileged-run)); reviewed
in M28's rounds 13 to 16 and its closing round.

## M28 — Governing from the phone, and networks of phones alone

**Done** on 2026-11-11: a phone founds a network and governs it with an
admin key sealed in Keystore behind the user's authentication, offers its
backup, invites by QR code, code and link, grants roles and removes
members; port mapping on Linux, FreeBSD and the app; Tailscale's public
DERP as the network's setting (schema 24); names of their own (schema
23); old addresses free once retired (schema 25); and publishing in one
command. Reviewed in 22 rounds, the closing one (18) over the whole diff
and four follow-ups on its fixes, the last confirming nothing above minor;
validated by `make ci-vm` and `make android-smoke` at M28
([12-validating.md](12-validating.md), "The last privileged run").
Exit criterion (1) holds in `mobile`'s tests and (4) passed by hand in the
emulator; (2) passed by hand on two phones and a computer on 2026-11-12
([12-validating.md](12-validating.md), "Govern a network from a phone"),
after the user published it; of (3), two phones on mobile data reached
each other directly the same day, and port mapping is open: the home router
offers no UPnP, NAT-PMP or PCP. Core 8 098 lines, audit scope 29 000, measured after it
(2026-11-11).

A network whose every member is an Android phone, created, invited to,
governed and kept fresh from the app, whose members reach each other without
a VPS: a family's phones, and a peer-to-peer chat between them. A relay
member stays the answer that always works; this plan makes it unnecessary
where the networks the phones are on allow it. Before the audit, so that M34
covers admin keys on a phone. A phone as exit node or as relay is not
planned.

The case it has to serve: two phones, both behind NAT that punches nothing,
such as two carriers' mobile data, and nothing else of their own. Two such
NATs meet only through a third party both reach, so where IPv6 gives the pair
no path, that is the public DERP of step 3.3, and being in one place is the
only way to need none.

1. **Governing from the app.** Genesis on the phone, its admin key sealed by
   Keystore as `node.keys` is (M10), under a key that requires the user's
   authentication: every change using it — genesis, invite, approve, remove,
   grant or revoke a role — asks for the phone's biometric first, the device
   credential as the fallback, and none signs while the phone is locked. The
   app invites (the QR code on its screen, the code on the Wi-Fi, a link
   through the DHT's rendezvous), shows the words, votes, approves carried
   changes (M5b), removes a device and grants roles. Exporting the admin key,
   as M12's line or as the app's password-encrypted file to a cloud folder the
   user picks, asks for that authentication too. Genesis offers such a
   backup and never forces one (decided 2026-11-07): a phone lost with the
   only admin key ends every further change, but every copy is one more place
   the key can be taken from. In place: genesis, the backup (the line or the
   sealed file, which `juist admins import` reads), invites by QR code, code
   and link, roles and removal; a change the key alone does not authorize is
   carried. Votes on carried changes, a second admin phone and the joining
   name in the words moved to
   [Later — Phones without a relay](#later--phones-without-a-relay).
2. **Freshness.** A network of phones alone takes no voucher: phones rest, so
   a voucher there would check nothing at M = 1 and cost availability, and
   freshness stays unchecked (`juist status` says so), removals still
   spreading by gossip, the epoch bump and the rotated group secret. In a
   mixed network a phone may hold the `voucher` role and vouch while its
   service runs. In place: a network the app founds gives the phone no
   role, and the app grants `voucher` to a member.
3. **Reach without a VPS**, cheapest first:
   1. **IPv6.** Carriers give phones global addresses, so between two of
      them only stateful filters stand, which a simultaneous open may pass.
   2. **Port mapping.** A phone on a home Wi-Fi maps a port on the router by
      UPnP, NAT-PMP or PCP, and one reachable side is enough for a pair. That
      is magicsock's portmapper, linked through conn's own hook, on Linux and
      FreeBSD members too; it opens a port on someone's router, so `juist
      status` and the app say so, and `juist set --port-mapping=false` and
      the app's switch turn it off. In place; what is left is exit
      criterion (3) by hand.
   3. **A public DERP server**, last, where no member relay serves the pair.
      It is an untrusted public helper as the STUN servers and the DHT are
      ([01-requirements.md](01-requirements.md)): it carries WireGuard's
      ciphertext and can delay or drop it, nothing more, and it passes HTTPS
      on 443 where a school's or a guest Wi-Fi blocks UDP. It enters the data
      plane's map as a region with a home score below any member relay's, as
      the STUN-only regions do. Two devices meet only through a region both
      use, so whether and which is the network's choice, a quorum-signed
      setting in the log (a schema bump) rather than a device's flag. Its
      default follows where the network is created: on at genesis in the app,
      off at `juist create`, so a network of laptops and servers uses none
      unless its admins choose one, and either can change it later. A laptop
      in a network that has one uses it too, as phones' last way to it. What its
      operator sees is weakness 5 in [02-threat-model.md](02-threat-model.md).
      Decided (2026-11-07, revising 2026-11-06): the default is
      Tailscale's public regions, as the build embeds them
      (`net/dnsfallback`), run for its customers and tolerated, not
      promised; no server of the project's own. In place: the setting is
      `types.KindSetPublicDERP` (schema 24), `juist network derp
      on|off`, on at genesis in the app; its regions are numbered
      apart from member relays' and scored as homes below them. A member
      relay netcheck does not measure still loses to them, which the
      handbook says; its fix is [Later](#later--phones-without-a-relay)'s.
   4. **Otherwise** the pair stays sought, as today, and the app says so.

   Rejected: public TURN servers, which magicsock does not speak.
4. **Joining without a relay in one place:** by code or QR code on the same
   Wi-Fi, which mDNS finds on every interface (M10). Joining on the inviting
   phone's hotspot and from afar through the public DERP moved to
   [Later](#later--phones-without-a-relay).
5. **Reaching an app on a phone.** M10 tried a phone's connections out, not
   in. An app listening on the phone's overlay address takes a connection
   from another member through `VpnService`, tested. Without an access policy
   (M14) every member reaches every port a phone's apps open.

6. **Names of their own** (schema 23, `types.SchemaOwnNames`, done
   2026-11-06). A member publishes a host name outside the network's
   domain, such as `photos.example.net`, whose DNS its owner points at the
   ingresses: `juist publish photos.example.net --on nas`. Stored as the
   published name's label, whole, which earlier builds refuse; the ingress,
   the terminator and members' resolution take it as a name under the
   domain. Never for members alone, as the policy
   names labels. One member's alone, and no name an override points at
   another; the domain cannot move over it. The trade: a quorum points any
   name at a member for every member without each device's word, as it
   does the domain; an approval says so.

7. **Old addresses free once retired** (schema 25,
   `types.SchemaTakeRetired`, done 2026-11-07). An old address retired at
   its deadline or by `--finish` no longer waits for a plain `--finish`:
   another device's move takes it, and a subnet route over an old range
   takes the range, each ending the retirement of what it takes in the same
   record. The log stays time-free, so the CLI refuses either before the
   deadline; devices not yet told still send there, which the CLI warns of
   and an approval says.

The chat is M36's, whose store holds a message for a phone that is off on
the members that are on.

- **Exit criteria:** (1) in `mobile`'s tests, a phone's core founds a
  network in which it holds no role, invites with its admin key and admits
  only once the words are confirmed, grants and revokes `voucher`, and
  removes a member; (2) by hand, a phone creates a network in the app, keeps
  the backup, invites a second phone by QR code and a computer by code on one
  Wi-Fi, and removes the computer, which the other phone learns, both
  statuses saying freshness is unchecked; (3) by hand, two phones on mobile
  data reach each other, through Tailscale's DERP where not directly, and
  each status says which; one on a home Wi-Fi with UPnP maps a port, which
  status says; (4) in the emulator, a listener on the phone's overlay
  address takes a TCP connection from another member.
  (4) passed by hand on 2026-11-08 ([12-validating.md](12-validating.md),
  "Reach an app on a phone"); (1) holds in `mobile`'s tests.


## M29 — macOS

**Done** on 2026-11-14: juistd and `juist` on a Mac, macOS 13 or later,
Apple silicon and Intel: a root helper and the daemon as `_juist` on
`utun100`, names through `/etc/resolver`, a LaunchDaemon and `setup.sh`
behind `install.sh`, each peer's handshake and bytes in the status, the
guard and exit nodes in pf under `com.apple`, DNS through an exit node by
scutil, and another network as an instance of its own. Reviewed in 12
rounds: 10 with commits of their own, the closing one (9) over the whole
diff, and the follow-ups on review 10 and on the macOS checksum fix
confirming nothing above minor; validated by `make ci-vm` at M29 and
by `macos.yml` at M29 ([12-validating.md](12-validating.md), "The last
privileged run"). Exit criterion (1) passed on a macOS runner from a kit
built there, `install.sh`'s Darwin path waiting for a release with the
macOS tarballs; (2) passed in five minutes of `FuzzServe` on darwin, twice;
(3), the hand test on a Mac, had not run when the user published it. Core
8 098 lines, audit scope 29 394, measured after it (2026-11-14).

juistd and `juist` on a Mac (macOS 13 or later, Apple silicon and Intel), as
on FreeBSD. No Mac is at hand: `make cross` builds and vets darwin, and the
tests that need one run on GitHub's macOS runners, by hand and at low
priority; they gate this milestone's end, not its work. A Mac user's run
counts as the hand test.

- **Device and privileges.** macOS has no capability for TUN devices and
  routes, so juistd splits as in M7a: started as root, it keeps
  `internal/plumber`'s helper as root and runs the daemon as `_juist`. The
  device is a utun, whose name the kernel gives by unit: instance N's is
  `utun10N`, which the helper alone accepts, holding a lock per name as on
  FreeBSD; its descriptor carries each packet behind the same four-byte
  address family as FreeBSD's. Addresses by ifconfig(8), routes by the route
  socket, both shared with FreeBSD where the kernels agree.
- **Names.** The network's names resolve through `/etc/resolver`, one file
  per domain the daemon serves, naming its resolver on the device; the
  helper writes only files it marks as its own and removes them with the
  device.
- **The service.** A LaunchDaemon, `io.nning.juist.juistd`, runs juistd at
  boot; the binaries and the plist are root's, outside any directory a
  user may write (Homebrew's `/usr/local` on Intel is one). The control
  socket is `/var/run/juist/juistd.sock`, the state `/var/db/juist`.
- **The install.** The release carries a tarball per architecture, and
  `install.sh` on a Mac installs it, makes `_juist` with dscl(8) and loads
  the daemon; `/Library/juist/setup.sh remove` removes all of it, the keys
  in `/var/db/juist` and their user left unless asked. Go signs darwin/arm64 binaries ad hoc,
  and a download by curl carries no quarantine, so neither needs an Apple
  developer ID; a signed and notarized `.pkg` waits for one.
- **The status per peer.** The status gives each peer's last handshake,
  and to operators the bytes its tunnel carried, read when asked, as the
  menu bar apps beside juist want them.
- **Guard and exit nodes.** pf, which the helper turns on by a token and
  gives back, keeps the overlay to the device and does the egress of an exit
  node as on FreeBSD, in anchors under `com.apple/juist.*`, which macOS's own
  `/etc/pf.conf` calls; macOS has no interface groups and no sloppy state.
  juistd's own sockets are bound to the uplink by Tailscale's netns. DNS
  through the exit node is the host's default resolver, a key of the
  device's in SystemConfiguration's dynamic store, set by scutil(8).
- **Several networks.** Instance N is a LaunchDaemon of its own,
  `io.nning.juist.juistd.juistN`, its user `_juistN` and device `utun10N`,
  which `setup.sh instance start|stop` makes and stops for juist.
- **Not on a Mac yet:** serving an exit node or a subnet, a relay, and
  multicast and broadcast (the device's link-local address waits for a run
  on a Mac).

- **Exit criteria:** (1) on a GitHub macOS runner, `install.sh` installs,
  juistd comes up under launchd as `_juist` with the helper as root, joins
  a network whose other member is a netstack juistd on the same runner, and
  a ping and a lookup of its name go through the device; `setup.sh
  remove --keys` leaves no file of juist's, user or device behind; (2) a compromised daemon
  cannot ask the helper for another device than `utun100`–`utun109`, an
  address or route the plumber's rules refuse, or a resolver file outside
  its domains, by the plumber's fuzz test on darwin's rules, five minutes
  of it on the runner; (3) by hand on
  a Mac: the install from a release, a reboot, the tunnel to a Linux
  member, an exit node of one, and removal.

## M30 — Family Link, and a phone on mobile data

What the app does on two phones as they are used, beside M26's features:
one Google's Family Link supervises, and one on mobile data all day.

- **Family Link.** On a phone Google's Family Link supervises, what a
  parent sends while juist runs does not arrive (more screen time, playing
  a sound to find it), without an exit node too; it comes as a push
  through Google's FCM, whose connection to `mtalk.google.com:5228` leaves
  beside the VPN without an exit node, while its lookup goes through
  juist's resolver. The first
  fix (M25.3, the VPN no more metered than the network beneath it, since
  Android held back Google's jobs for an unmetered network) is in 0.25.6
  and the dev builds from 2026-11-01. With a dev build of 2026-11-04 a
  sound arrived on the supervised phone, juist and its names on, shortly
  after the VPN came on; the rest of step 1 is not tried. Each step is
  judged by the one before it:
  1. **Confirm** on the supervised phone with an app at or after M25.3:
     a sound sent and more screen time granted arrive within a minute,
     on Wi-Fi and mobile data, the screen on and off.
  2. **If not, look at FCM** with the VPN on and off (`adb shell dumpsys
     activity service com.google.android.gms/.gcm.GcmService`): whether
     the connection stands, how often it reconnects, and whether a new
     device from `establish()` drops it; with Private DNS off, automatic
     and named; and against another VPN that routes only its own
     prefixes (Tailscale), which would point at Android rather than juist.
  3. **Suspects then:** the resolver every lookup goes to since M23,
     failing or slow for `mtalk.google.com`; an IPv6 address on the VPN
     where the network beneath has none, so that AAAA answers are tried
     first; Family Link's lock at a time limit or bedtime, reported to stop
     VPNs that then stay off, where the service has to come back as after a
     reboot.
- **The relay's keepalive.** A phone's day on LTE (2026-11-03) put juist
  at 16 % in Android's list, against 5 % on Wi-Fi at M21. Its floor is the
  relay's keepalive: the pinned derpserver sends every client one every 60
  to 65 s, a resting phone too, which on LTE wakes the radio about 60 times
  an hour whatever the phone's pace. Sparing a resting phone it is safe
  only where the carrier's NAT keeps an idle connection open longer than
  the phone's own traffic leaves it idle; else the relay no longer reaches
  the phone.

- **Exit criteria:** (1) on a phone Family Link supervises, with juist on,
  directly and through an exit node, on Wi-Fi and mobile data, the screen
  on and off after the phone slept, a sound and more screen time a parent
  sends arrive within a minute, as with juist off; after Family Link locks
  and unlocks the phone, juist is on again; (2) how long the carrier of the
  phone's day keeps an idle connection is measured, and from it decided
  whether a relay spares a resting phone its keepalive; where it does, a
  phone's day on LTE puts juist below 16 % and a member reaches the
  resting phone within a minute.

## M31 — A desktop app on Linux

An icon in the desktop's status bar, as Tailscale's on Linux (`tailscale
systray`): the state at a glance, and what a laptop's user changes on the
move without a terminal. Before the audit, so that M34 covers what it asks
of the control socket.

- **The icon** shows connected, an exit node in use, or a warning of `juist
  health`, and its tooltip the status's first lines.
- **The menu:** the device's name and addresses (copied by a click), the
  members and whether each is reached, the exit node chosen from those
  granted or none, and a notification for a new warning or an alarm. With several networks (M5), one submenu each.
- **Built on** the control socket as `juist` uses it, nothing of its own in
  juistd: the operator gets the menu whole; any other user what the read
  tier passes (M24), the state without members, and no switches. It holds
  no keys, and governing (invite, approve, remove) stays the command
  line's.
- **How:** StatusNotifierItem over D-Bus, which KDE, Xfce, Cinnamon and
  sway's bars show, and GNOME only with the AppIndicator extension, which
  `juist health` does not judge; the app says where no host is found.
  `fyne.io/systray`, which Tailscale's pinned module uses
  (`client/systray`), is the lead, so no cgo and no GTK. A binary of its
  own, `juist-tray`, started by an XDG autostart entry the package installs,
  so that a server's install can leave it out.
- **Open decisions:** whether it is a package of its own; a window beyond
  the menu (the status page, M9f, opens in the browser meanwhile); FreeBSD's
  desktops, which take the same binary.

- **Exit criteria:** (1) on a desktop session in the CI VM (sway, headless),
  the item appears on D-Bus, its menu lists the granted exit nodes, choosing
  one routes through it and the icon says so; (2) a user who is not the
  operator gets the menu without the switches; (3) stopping juistd turns the
  icon to off and starting it brings the state back, without restarting the
  app; (4) by hand on GNOME with the extension and on KDE, Debian and Fedora,
  the package installed and removed cleanly.

## M32 — Formal models of what juist designed itself

Machine-checked models of the protocols and rules juist composed from
standard primitives, before the review and the audit: a flaw in a design is
found before a reader judges its code, and the audit checks the models
with it. The primitives and WireGuard are not modelled; the preshared key
joins WireGuard's published models (Tamarin, CryptoVerif).

- **Enrollment** (`trust/enroll`) in ProVerif: the code stays a weak secret
  against offline guessing, and online costs the invite its one guess, a
  password-built element included; the channel key stays secret while
  SPAKE2 or ML-KEM-768 holds; guest and host agree on the transcript, and
  the key admitted is the one the admin saw; no side's message reflects
  back as the other's.
- **The pair key** (`internal/pairkey`) in ProVerif or Tamarin: a third
  member holding the group secret learns no pair's key; both ends agree on
  key and epoch before either mixes it in; forward secrecy as a lemma that
  fails, as weakness 12 says, and whether an ephemeral ML-KEM share makes
  it hold.
- **The log** (`trust/log`) in TLA+: honest validators converge on one
  state or one alarm in any order of delivery, no trusted state falls below
  the epoch floor, every membership change has its quorum, a removed key
  undoes no revocation, compaction included, and a member cut off from a
  removal refuses the removed one at the TTL under bounded clock skew. The
  three fork-choice findings M33 lists are decided against it.
- **Model and code:** traces the log's model generates are replayed against
  `trust/log`'s validator; each protocol model names the labels and
  transcript fields it stands for, and a test fails where the code's differ.
- **Left out:** `aead` and `addrkey`, standard constructions M33 reads line
  by line; the computational strength of the SPAKE2 and ML-KEM combiner,
  which a symbolic model takes as given; code-level proof (Gobra).
- **Open decisions:** ProVerif or Tamarin for the pair key; TLA+ checked by
  TLC or Apalache, or Quint; whether the models run in `make ci-vm` or by
  hand, as `make fuzz-long` does.

- **Exit criteria:** (1) every model's lemmas proved, or a failed one fixed
  in the code with a test that fails without the fix, or accepted as a
  numbered residual weakness; (2) each model's attacker written beside it
  against [02-threat-model.md](02-threat-model.md)'s adversaries; (3) the
  log's traces replay against the validator without a divergence; (4) the
  run, its tool versions and what did not run recorded in
  [12-validating.md](12-validating.md).

## M33 — The internal security review

The review [15-security-review.md](15-security-review.md) plans, over the
audit scope as M17 to M32 leave it, so that M34's audit goes to what a
reader cannot find, and M32's models beside the code they stand for. It
starts from the fuzzing:

- **Fuzzing.** No `fuzz-long` run over every target is recorded in
  [12-validating.md](12-validating.md).
- **A settled orphan that alarms later,** found in M19's review: a change
  that lost fork choice and was redone is probed against the head as it is
  now, so once a later change removes its subject it reads as a conflict,
  and every device that holds it alarms for good, a compaction included,
  which an alarm refuses. To decide: what an orphan is probed against, so
  that a later change settles nothing it already settled, while two changes
  made at once that disagree still alarm
  (`TestConflictingConcurrentRecordsAlarm`).
- **A record released below a compaction,** found in M19's review: refused
  where devices compacted, taken by fork choice where they did not, with no
  alarm on either side. To decide: how the split is made known on both
  sides without giving a key that lost its quorum a way to raise it at will;
  no rule of fork choice may rank a count of checkpoints above a revocation
  (`TestMintedCheckpointsDoNotUndoARevocation`).
- **A raise undone by a ground revocation,** found in M19's review: of two
  revocations at one parent the lower `SigHash` wins, so the keys a raised
  quorum or a holder's fewer votes stripped can sign a removal beside the
  raise, redraw its epoch secret until it sorts lower, and undo the raise
  and what followed it; only a removed key's own signatures are ruled out
  ("A removed key cannot undo its removal"). A removed key can also sign a
  revocation beside its removal, which loses yet is named to be redone and
  holds compaction back until an admin does.

- **Exit criteria:** (1) every parser of input from outside the membership
  has a fuzz target, and a `make fuzz-long` over each is recorded; (2) the
  review closed as its §6 says, its sizes, sessions and findings by
  severity recorded in [12-validating.md](12-validating.md); (3) every high
  and medium finding fixed with a test that fails without the fix, or
  accepted as a numbered residual weakness.

## M34 — An audit by a second model → v1

Security audit of the audit scope by a model other than the one juist is
developed with, from the code and the threat model rather than M33's notes;
no human audit is planned. In the tiers of
[06-verification.md](06-verification.md) §5, after M33's internal review:
the trust layer and enrollment at its core, M32's models with them,
plus what M6, M8, M9, M9e, M10, M11, M12, M13, M14, M15, M16, M17, M19, M21, M22, M23, M24, M25, M26, M27, M28, M29, M30 and M31 add to it — route consumption and its forwarding helper, the
override record and the resolver, the published names, those for members alone, and the ingress, its QUIC Initial parser included, the
disable record, the preshared-key exchange, the ML-DSA cut-over and
enrollment's ML-KEM step, checkpoints and compaction, the Android app's key custody, in-process API, resolver and pacing, the ACL policy and its filter, the relay's DHT over HTTPS and its ACME certificate, the meeting at a relay on 443, a user per instance and FreeBSD's pf, macOS's root helper and resolver files, discovery's unwrapping and local delivery, the phone's subnet routes, several networks in one app, admin keys on a phone and the desktop app's use of the control socket — fix findings, mature fuzz corpus (consider
OSS-Fuzz), implementation-vs-threat-model review, documentation of the
residual-weakness acceptances for operators, which the handbook's
trade-offs carry ([14-website.md](14-website.md)). Open decision: which
model.

v1 is Linux and FreeBSD with M14's ACLs and M25's multicast, macOS as
M29 leaves it, Linux's desktop app (M31), and the Android app as M26 to
M28 and M30 leave it; packaging follows in M35.

- **Exit criteria:** (1) audit complete, all high/medium findings fixed and
  regression-tested; (2) the acceptances documented for operators; v1.0 tag.

## M35 — Packaging *(post-v1)*

Distro repositories (apt, dnf, pkg) and a port in FreeBSD's ports tree, which
fetches a release, for the packages every release already carries, and the readiness check that keeps an admin from stranding members
on an upgrade. The app's APK becomes reproducible here too, which gomobile's
cgo build with the NDK, Gradle and R8 make harder than the Go binaries; until
then its signature alone vouches for it.

Arch Linux, Gentoo and Nix join the distributions the package repository
serves, each in its own form and built by the same builder as the deb, the
rpm and FreeBSD's pkg, in a stable and a dev channel:

- **Arch Linux:** a pacman repository, `arch/$arch` beside `deb/` and `rpm/`:
  a `PKGBUILD` that packages the release's binaries with the deb's units,
  `sysusers.d` and scripts, `makepkg` in an `archlinux:base-devel` container,
  `repo-add` for the database, packages and database signed with the
  repository's key (`SigLevel = Required`). An AUR `PKGBUILD` that builds
  from the release's sources may follow; it is maintained in the AUR, not
  here.
- **Gentoo:** an ebuild repository (overlay) in git, added with
  `eselect repository`, its commits signed and verified by Portage
  (`sync-git-verify-commit-signature`). `net-vpn/juist-bin` installs the
  release's binaries, its `Manifest` holding their checksums, and the users
  come from `acct-user`/`acct-group` ebuilds, one per user the packages make.
  A source ebuild needs the Go modules as a tarball of its own and is left
  out unless asked for.
- **Nix:** a flake in the repository, `buildGoModule` with a pinned
  `vendorHash`, for `nix run` and `nix profile install`, and a NixOS module,
  `services.juist`, that makes the users, the units, their capabilities and
  the firewall's openings, as the packages do elsewhere. A binary cache is
  optional: Go builds quickly from source. nixpkgs itself is a later
  question, its review being outside this project.
- **What each needs:** `install.sh` learns pacman and, where it can, Portage;
  the handbook's install and updating pages, English and German, and
  `features.yaml` name each; `make check` builds each package's files as it
  builds the deb's.
- **Open decisions:** OpenRC, which much of Gentoo runs: an init script of
  juist's own, or the ebuild depending on systemd at first; whether the
  NixOS module covers instances 1 to 9 and the ingress or the default
  instance alone at first.

- **Exit criterion:** Linux/FreeBSD interop matrix green in CI via qemu;
  release artifacts, the app's APK among them, reproducible byte-for-byte
  from two independent builders; on Arch, on Gentoo with systemd and on
  NixOS, juist installs from the repository, joins a network, upgrades from
  the previous release in place and removes cleanly, saying what it leaves.

## M36 — A store, and a messenger on it *(post-v1)*

Members leave each other data while the other is offline, with no server: a
key-value store replicated among the members' own devices, and a messenger on
it with groups, pictures and files, `juistmsg` on Linux and FreeBSD and a chat
in the app. It needs M10's app, not M26's. A device takes part if its owner
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

## M37 — OpenBSD *(post-v1)*

juistd on OpenBSD as M7 has it on FreeBSD: a root helper, the daemon as
`juist`, DNS, exit nodes and subnet routers, an rc.d script and a package.

Today `GOOS=openbsd` compiles for amd64 and arm64, though `make cross` does
not build it, and every platform file takes its fallback: no helper, so a
device means root throughout; no peer credentials, so the IPC socket's mode
alone; no host DNS; no serving. The pinned Tailscale's own router
(`osrouter/router_openbsd.go`, ifconfig and route) would set addresses and
routes, an exit node's default route included; juist's helper replaces it,
as on FreeBSD.

The plan, in order:

1. **Build.** `openbsd/amd64` and `openbsd/arm64` join `CROSS_PLATFORMS`, so
   that nothing breaks unseen meanwhile.
2. **Helper and privileges.** `internal/plumber` gains an OpenBSD host beside
   FreeBSD's: the helper opens `/dev/tunN`, sets addresses and routes with
   ifconfig and route, each route naming its source address, and hands the
   descriptor to the daemon running as `juist`. Code where the two agree is
   shared, what differs is build-tagged. pledge(2) and unveil(2) narrow the
   helper and the daemon to what each uses.
3. **Peer credentials.** `daemon/peercred` reads `SO_PEERCRED`
   (`struct sockpeercred`), so the IPC socket checks its callers as on Linux
   and FreeBSD.
4. **DNS.** resolvd(8) takes the helper's proposal of juistd's resolver per
   device (`route nameserver <dev> <addr>`, withdrawn by the same without an
   address). Unlike `resolvconf -x` it keeps the other servers behind, and
   takes no search domains. While unwind(8) runs, resolvd comments
   proposals out; `juist health` then warns unless `unwind.conf` forces
   juist's names to `autoconf`.
5. **Exit nodes and subnet routers.** Forwarding through
   `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding`, held and restored
   as on FreeBSD; the NAT, forwarding filter and egress guard in pf anchors of
   juist's. OpenBSD's pf has `anchor` alone, no `nat-anchor` or `rdr-anchor`,
   and writes NAT as `match out … nat-to`, so the rules are OpenBSD's own and
   only the anchors' life cycle is FreeBSD's.
6. **Service and package.** An rc.d script (`rc.subr`, `rcctl`), the
   commands in `cmd/juist` that start and enable instances beside systemd's
   and FreeBSD's, manual pages and `--help` naming rc.d, and `make
   pkg-openbsd` by `pkg_create`, reproducible as `make repro-freebsd` checks.
7. **Tests and lab.** `make test-openbsd` runs every test on an OpenBSD VM in
   qemu as root, as `make test-freebsd` does; `make interop` gains it beside
   Debian and FreeBSD.

Constraints:

- **DNS through an exit node** must not fall back to the LAN's servers that
  resolvd keeps behind juistd's: the egress guard blocks DNS to anyone but
  juistd while names go through the exit node.
- **Network changes** are noticed by Tailscale's 10 s poll on OpenBSD
  (`net/netmon/netmon_polling.go`), not by events as devd(8) gives them on
  FreeBSD: roaming is slower until a routing-socket monitor is added there.

Open decisions:

- **juistd's own traffic beside an exit node:** off the tunnel by pf's `user`
  match, as on FreeBSD, or by an rtable of its own, as Tailscale's router
  does. pf is the lead, being one mechanism for both.
- **Signing the package:** `pkg_add` checks signify(1) signatures against the
  keys in `/etc/signify`, so either a key of juist's that the user installs
  once, or unsigned packages until a port in the ports tree, as M35 plans for
  FreeBSD.
- **Which releases:** the current one alone, or both that OpenBSD supports.

- **Exit criteria:** (1) `make test-openbsd` passes; (2) in `make interop`,
  OpenBSD, Debian and FreeBSD each use the others as exit node, subnet router
  and DNS; (3) on OpenBSD the helper alone runs as root, and a caller of
  another user is refused at the IPC socket; (4) with an exit node and
  juistd's resolver stopped, no DNS query leaves the host outside the tunnel;
  (5) the package installs and removes cleanly, and builds to the same bytes
  on two builders.

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
minute while nothing changes; validated by unit tests alone. M21 reconciles
at deadlines rather than every 15 s and has a quiet ping, which starts no
heartbeat, check a phone and a peer while saving. Open, in this order:

1. **Measure.** Datagrams per minute on the underlay (magicsock's port, 5353,
   the relay's) and wakeups (`powertop`) of an idle laptop with three peers,
   with and without a relay, before and after M9. Every step below is
   judged by that number, so it is taken first.
2. **On battery.** Read the power source (Linux
   `/sys/class/power_supply/*/online` of a `Mains` supply, FreeBSD
   `hw.acpi.acline`) and, on battery, stop relaying though granted, and
   save as a phone does (`daemon.Pace`), its peers' tunnels checked
   quietly. A relay that goes away moves its peers' home region, so the
   switch wants hysteresis, and the status says when it happened.

## Later — Kernel WireGuard

Not scheduled. A fast path in the kernel (Linux netlink, FreeBSD `if_wg`) for
pairs that reach each other directly at a public endpoint; magicsock's
traversal, disco and DERP stay in user space, so a peer moves between two
data planes. Taken only if a measurement asks for it: on real hardware,
kernel WireGuard against `make throughput`'s tunnel (3.5 Gbit/s in the CI
VM) and UDP through an exit node (300 Mbit/s), throughput and CPU both.

What it would have to keep: M14's policy, enforced in the confiner today,
which kernel traffic passes by, so in nftables or pf; M15's preshared keys
and their renewal, through `wgctrl`; and a port of its own beside
magicsock's.

## Later — Phones without a relay

Not scheduled; moved out of M28 on 2026-11-08. M34's audit covers admin keys
on a phone without what is here.

1. **Governing from the app, the rest:** votes on changes carried to the
   phone, a second admin phone, and binding the name a joining device asks
   for into the words, which today cover its keys alone, on the command line
   too.
2. **Member relays measured apart from netcheck.** A member relay netcheck
   does not measure loses the home to Tailscale's regions: one whose UDP port
   is closed while STUN passes (Tailscale's STUN keeps netcheck off HTTPS),
   or one far away (netcheck stops once three regions answered). Quieting
   Tailscale's STUN (M28 review 8) and benching its regions in netcheck until
   no member relay is reached (review 9) each left devices without any home
   in other cases (reviews 9, 10), and were taken back.
3. **Joining on a hotspot,** the inviting phone's, tested: that the invite
   and mDNS listen on its interface.
4. **Joining from afar through the public DERP.** A link names the network's
   public DERP as it names a member's relay (M10). Forwarding at a member
   relay is juist's own HTTP endpoint (`relay/forward`), which a public DERP
   server does not have, so the host and the guest, under a key of its own,
   run the handshake as DERP packets in the region the link names; the
   server sees only what the link's secret seals. DERP drops packets when a
   queue fills, so the handshake carries its own retransmission.
5. **Phones in the lab:** in `make interop`, three emulators and no other
   member, one governing the others; and two emulators, each behind a NAT
   that picks a new port per destination, with nothing else but the
   harness's DHT and a DERP server standing for a public one, joining by link
   and keeping freshness until the quorum withdraws it. Not on a 4-core host.

## Deferred (post-v1, schema must not preclude)

A default exit node
an admin sets, quorum-signed per device, below the device's own choice ·
hardware-backed admin keys (FIDO2/PIV signing, once tokens sign with ML-DSA) · sealing the node key, a 0600
file in v1 (TPM, kernel keyring; FreeBSD: geli) · update transparency log ·
Windows/iOS · desktop apps on macOS and Windows.

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
