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
[13-multi-network-notes.md](13-multi-network-notes.md); instances share the
`juist` user until M24.

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
`--finish` or the device's next move; `juist network` lists what is held, and
`juist status` names the devices not told yet.

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

**Under way:** the app and its core are built, and by hand in an emulator it
joins by link, shows the network and pings a member; the exit criteria are
not met yet (below). Joining from another network and using an exit node,
added on 2026-10-04, are built; on a phone a Linux exit node carried its
internet, and is yet to across the VPN turned off and on and the phone
changing networks.

An Android app that joins a network as a member from anywhere, reaches the
others and sends its internet through an exit node, with none of the roles. It comes before the audit, so that M26 covers the app's key
custody and its in-process API; the full app is M29, after v1.

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

The app looks finished from M10 on, not from M29: Kotlin and Compose, with a
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
on 443". The Android app has no switch for it yet (M29).

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
checkpoint the log starts from. Open for M25: a record released below a
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
stay on, and before the audit, so that M26 covers what changes.

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
Before the audit, so that M26 covers it, and not started before M21 is
validated and the refactoring
([temp/20261019-refactoring.md](temp/20261019-refactoring.md)) is done. The
rules, the open decisions and what changes in the threat model are in
[16-one-relay-on-443.md](16-one-relay-on-443.md).

- **Exit criteria:** (1) in the netns lab, a device whose network passes TCP
  to 443 alone, homed at the one named relay, reaches a member homed at an
  unnamed relay and is reached by it, with `--https-only` and without, and
  the member reaching it no longer once it stops keeping the connection;
  (2) after three minutes without traffic, the device still reaches the
  member first; (3) a member that learns the device's new home from the
  relays alone, with no tunnel to it, reaches it; (4) a member that rests
  keeps no connection, and is reached once it syncs; (5) an ingress's relay
  is named `relay.<domain>` without `--relay-name`, and the device of (1)
  needs no setting of 443 to reach every member; (6) `juist health` names a
  peer the device's relay says is not there; (7)
  [02-threat-model.md](02-threat-model.md) says what changes, and `make
  ci-vm` passes with the lab.

## M23 — Names on Android

The Android app resolves none of the network's names. With a DNS server set,
`VpnService` sends every lookup of the phone to it, so the core sets one only
for an exit node, which then answers them all (`mobile.errNoNames`). A name
for members alone (M16) is out of the phone's reach, and a published name
resolves to the ingress, not the tunnel. Taken from the full app (M29), and
before the audit, so that M26 covers a resolver that sees every lookup the
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
  - **Carried from M21: the members' pings after news.** What is left of
    an idle phone's traffic beside ten members comes in a burst a few
    seconds after each member's restart, mostly disco pings from the other
    members to the phone, a radio wake each time: find which check or push
    starts them, and spare a phone that rests those that wake it for
    nothing. The day that closed M21 ran on Wi-Fi; a day on mobile data
    shows what a radio wake costs there.

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

## M24 — Boundaries on a host

What one network's daemon, the LAN and a local user can reach on a host
running juist, closed before the audit, so that M26 covers it.

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

## M25 — The internal security review

The review [15-security-review.md](15-security-review.md) plans, over the
audit scope as M17 to M24 leave it, so that the auditor's hours go to what a
reader cannot find. It starts from the fuzzing:

- **Fuzzing.** `waiting.Decode`, `types.DecodeLease`, the helper's protocol
  and the resolver's input, the Android app's included, have no target, and
  no `fuzz-long` run is recorded in [12-validating.md](12-validating.md).
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

## M26 — External audit → v1

External security audit of the audit scope, in the tiers of
[06-verification.md](06-verification.md) §5, after M25's internal review:
the trust layer and enrollment at its core,
plus what M6, M8, M9, M9e, M10, M11, M12, M13, M14, M15, M16, M17, M19, M21, M22, M23 and M24 add to it — route consumption and its forwarding helper, the
override record and the resolver, the published names, those for members alone, and the ingress, its QUIC Initial parser included, the
disable record, the preshared-key exchange, the ML-DSA cut-over and
enrollment's ML-KEM step, checkpoints and compaction, the Android app's key custody, in-process API, resolver and pacing, the ACL policy and its filter, the relay's DHT over HTTPS and its ACME certificate, the meeting at a relay on 443, a user per instance and FreeBSD's pf — fix findings, mature fuzz corpus (consider
OSS-Fuzz), implementation-vs-threat-model review, documentation of the
residual-weakness acceptances for operators, which the handbook's
trade-offs carry ([14-website.md](14-website.md)).

v1 is Linux and FreeBSD with M14's ACLs, and M10's minimal Android app;
packaging and the full app follow in M28 and M29.

- **Exit criteria:** (1) audit complete, all high/medium findings fixed and
  regression-tested; (2) the acceptances documented for operators; v1.0 tag.

## M27 — Multicast *(post-v1)*

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

## M28 — Packaging *(post-v1)*

Distro repositories (apt, dnf, pkg) and a port in FreeBSD's ports tree, which
fetches a release, for the packages every release already carries, and the readiness check that keeps an admin from stranding members
on an upgrade.

- **Exit criterion:** Linux/FreeBSD interop matrix green in CI via qemu;
  release artifacts reproducible byte-for-byte from two independent builders.

## M29 — The full Android app *(post-v1)*

The full Android app, on M10's: M6b's subnet routes through `VpnService`
routes and M13's HTTPS alone, released as M28 releases the rest.

- **Exit criterion:** 3-platform interop matrix green in CI, Android by an
  emulator smoke test; the app's release artifact reproducible byte-for-byte
  from two independent builders.

## M30 — A store, and a messenger on it *(post-v1)*

Members leave each other data while the other is offline, with no server: a
key-value store replicated among the members' own devices, and a messenger on
it with groups, pictures and files, `juistmsg` on Linux and FreeBSD and a chat
in the app. It needs M10's app, not M29's. A device takes part if its owner
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

## Deferred (post-v1, schema must not preclude)

Kernel WireGuard fast path for public-endpoint nodes · a default exit node
an admin sets, quorum-signed per device, below the device's own choice ·
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

Not scheduled; after M29, whose names it uses. A network whose every member is
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
   Keystore as `node.keys` is (M10), which M26's audit did not cover for
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

The chat is M30's, whose store holds a message for a phone that is off on
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
