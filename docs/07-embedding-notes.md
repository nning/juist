# 07 — Embedding Tailscale's connectivity stack

Findings from embedding it in `conn/`, against the pinned **tailscale.com v1.104.0**
and its wireguard-go fork `v0.0.0-20260928213032`. Anything here
may change at upgrade time, which is the cost
[04-architecture.md](04-architecture.md) already accepted.

## Verdict: the reuse decision holds

`wgengine.NewUserspaceEngine` + `magicsock` instantiate with **no
`controlclient`, `tsnet`, or `ipn`** anywhere in the path. `wgengine.Config` has no
control-plane field at all, and the `Engine` interface is almost entirely
callback-injection — `SetPeerConfigFunc`, `SetPeerByIPPacketFunc`,
`SetPeerForIPFunc`, `SetSelfNode`, `SetFilter`. Everything `LocalBackend` supplies in
Tailscale, we supply from log state instead. Two nodes reach a direct WireGuard
tunnel and exchange overlay ICMP with no coordination server and no relay.

Option (b) — a from-scratch disco-style manager — stays behind `conn.Manager`, but
nothing found here argues for taking it.

## The adapter is smaller than planned

**No synthetic `netmap.NetworkMap` is needed.** magicsock's entry point is

```go
func (c *Conn) SetNetworkMap(self tailcfg.NodeView, peers []tailcfg.NodeView)
```

plus `UpsertPeer(tailcfg.NodeView)` / `RemovePeer(tailcfg.NodeID)` for O(1)
incremental changes — a good match for a reconciler applying single log records.
`netmap.NetworkMap` never appears. The adapter builds `tailcfg.Node` values and
nothing more; the module map's "log state ⇒ synthetic netmap" is really "log state ⇒
`[]tailcfg.NodeView`".

**Peers are no longer part of the WireGuard config.** `wgcfg.Config` is now just
`{PrivateKey, Addresses}`. The device learns its peer set from a live lookup:

```go
eng.SetPeerConfigFunc(func(key.NodePublic) (allowedIPs []netip.Prefix, ok bool))
```

This is a *better* fit for the design than the roadmap's "log state ⇒ WG config"
phrasing. Default-deny becomes one function answering from log state, so there is no
window in which the device holds a peer the log does not — the reconciler updates its
map first, and `ok=false` for an unknown key means wireguard-go refuses to create the
peer at all.

**Default-deny is enforced twice, independently.** Beyond the peer lookup, a nil
packet filter drops *every* inbound packet (`tstun`:
`if filt == nil { return filter.Drop }`). The filter must be built explicitly. Both
gates are worth keeping: M2's exit criterion is satisfied by either alone.

## The preshared-key path

M15's preshared keys ([05-roadmap.md](05-roadmap.md)) go to the engine as
`conn.Peer.PSK`. Against `tailscale.com v1.104.0` and
`tailscale/wireguard-go v0.0.0-20260928213032` it carries them with no patch,
and the design respects what it does:

- **Both peer states have a path, and need one.** Peers are created lazily, so
  a PSK reaches a new peer through the config lookup (`wgcfg.PeerConfig.PresharedKey`,
  passed on by `wgcfg.NewPeerLookupFunc`, `wgcfg/device.go:60`) and an active one
  through `SyncDevicePeer` (`wgengine/userspace.go:714`), which `SetPeers`
  calls for every kept peer. One without the other leaves a gap.
- **A change keeps the session.** `Peer.SetPresharedKey` (`device/peer.go:197`)
  writes under the handshake mutex: the session runs on its derived keys and the
  next handshake mixes in the new value. A session made without a key would
  so carry traffic for minutes after one is given, which is why `SetPeers`
  resets a peer newly given one, and, as `LookupPeer` reads the config and
  creates the peer with no lock between, keeps it passing nothing and resets
  it again 2 s later.
- **Each role reads the key at its own moment.** The responder mixes it into
  the response it creates, the initiator when it consumes the response
  (`device/noise-protocol.go`), and a mismatch fails the initiator's
  decryption, retried after `RekeyTimeout`, 5 s. A handshake that completed
  says little of which key it used, as the key may change between the two
  moments and the session outlives it; juist confirms keys by message.
- **Rotation is bounded by the rekey window.** `RekeyAfterTime` is 120 s and
  `RejectAfterTime` 180 s (`device/constants.go`), and a peer holds one PSK, so
  both ends need the new key before the next handshake or it fails, while
  the old session still carries traffic.
- **The ciphertext does not travel in the log.** ML-KEM is a KEM, so a
  per-pair secret means a ciphertext sent in log sync; the public keys it is
  built from are already in `NodeRecord.MLKEM`
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)).

## Wiring requirements that nothing documents

Each fails silently or confusingly.

- **`tstun.Wrapper.Start()` must be called by us.** `ipnlocal` does it in Tailscale.
  Without it every TUN read blocks forever, with only a once-per-second
  `tstun: awaiting Wrapper.Start call` line to say so. Call it after the lookups,
  the filter and the first `Reconfig` are installed.
- **`SetSelfNode` and `SetPeerForIPFunc` gate diagnostics.** `Engine.Ping` resolves
  its target through the first and its source through the second; without both it
  reports "no matching peer" for a peer that is fully up.
- **Loopback endpoints do not work.** Tailscale's `netns` binds UDP sockets to the
  default interface, so a datagram to `127.0.0.1` leaves via that interface and is
  never delivered. Multi-node tests on one host must use the host's real address.
- **Resetting dead WireGuard sessions on disco-key rotation is the embedder's job.**
  `ipnlocal` calls `Engine.ResetDevicePeer` for every peer whose disco key changed
  after `SetNetworkMap`; nothing below it does. Miss it and a *restarted* peer's dead
  session keys stay in the device, blackholing traffic for minutes with nothing
  logged.
- **A real TUN device alone plumbs nothing into the OS.** `wgengine.Config.Router`
  defaults to `router.NewFake`, which silently discards the `router.Config` passed to
  `Reconfig`. OS plumbing needs a real `router.Router` wired at engine construction.
  `router.New` wants the device and the engine wants the router, so the order is
  fixed: netmon, TUN, router, engine. Share one `netmon.Monitor` through
  `Config.NetMon`; the engine will not close one it was handed.
- **`wgengine.Config.ListenPort` is a preference, not a requirement.**
  `magicsock.bindSocket`'s candidate list ends in `0`, so a port it cannot bind
  becomes an OS-assigned one after a single log line. Tailscale repairs that
  reflexively; we cannot, because endpoints come from an interface scan. `conn.New`
  compares `magicsock.LocalPort()` against a non-zero requested port and refuses to
  start on a mismatch. `LocalPort` reports the v4 socket only, which is also what the
  announcements are built from, so the two agree by construction.
- **The TUN MTU must come from `tstun.DefaultTUNMTU()`.** It is 1280 — exactly the
  IPv6 minimum. The kernel removes `/proc/sys/net/ipv6/conf/<iface>/` from an
  interface below that, and the router reads exactly that path to decide whether to
  program IPv6 at all. A "conservative" lower literal therefore deletes the v6 half
  of the overlay silently, which costs us more than upstream: our ULA is the primary
  family.
- **Closing a router the engine never brought up panics.** `linuxRouter.Close`
  dereferences `r.nfr`, which only `router.Up()` populates. `Config.Router` is not in
  the engine's `closeOnErrorPool`, so a failed `NewUserspaceEngine` leaves the router
  with us — and `magicsock.NewConn` and `wgdev.Up` both fail before `router.Up` runs.
  Do not close it on that path. Nothing leaks: `bus.Close` releases its event client,
  and any `ip` rules survive only until the next `router.Up`, which deletes before it
  adds.
- **Device names go straight to `TUNSETIFF`.** Over `IFNAMSIZ-1` (15 bytes) that is a
  bare `EINVAL`; containing `%` it is a kernel *template*, so `juist%d` creates
  `juist0` and the device is not the one the caller named. Validate before creating.
- **Peer routes do not land in the main routing table.** `linuxRouter.routeTable()`
  returns table 52 whenever policy routing is available, falling back to main only
  when it is not. `ip route show dev juist0` therefore shows nothing; use
  `ip route show table all dev juist0`.
- **IPv6 is programmed conditionally and silently.** `addRoute` and `addAddress` both
  open with `if !r.getV6Available() && cidr.Addr().Is6() { return nil }`, so on a host
  with IPv6 off the v6 half of the config is skipped with no error. Assertions must
  allow for it. `getV6Available` is not only a kernel check: it asks the router's
  *netfilter* runner, which we otherwise never use, since `NetfilterOff` means we
  install no rules. The runner reports IPv6 only where `disable_ipv6` and
  `disable_policy` are 0 and IPv6 policy routing works — and, in its iptables mode,
  only where the `ip6tables` binary exists. A host missing `ip6tables` therefore
  loses the overlay's *primary* family with nothing but a log line. Packaging (M19)
  must declare that dependency, and an operator report of "no v6 on the overlay"
  should start here.
- **`router.CleanUp` is not worth calling here**, though `tailscaled` calls it at
  startup. It clears netfilter chains and orphaned addresses; we run `NetfilterOff`
  so there are no chains, and a wireguard-go TUN is not persistent, so a crashed
  daemon's device and everything on it is already gone. The `ip` rules that do
  outlive a crash are reconciled by `addIPRules`, which begins with `delIPRules`.
- **magicsock keeps its first home relay without a control plane.**
  `maybeSetNearestDERP` changes the home region only while
  `health.Tracker.GetInPollNetMap()` is true, since Tailscale tells peers of a new
  home through control. Nothing sets that here, so the region picked at start is
  kept for good: a node started before any member relayed homes on a STUN-only
  region and never connects to a relay granted later. `conn` marks its tracker
  as in a map poll, because announcements carry the home region to peers. The
  flag is read nowhere else we link (v1.104.0).
- **One node key under two node IDs is refused.** `magicsock.updateNodes` meets a key
  it already holds under another `NodeID` with `devPanicf`: a panic under test, and
  in production an endpoint silently not created until a later `SetNetworkMap`. An
  identity rotation keeps the WireGuard key, so the daemon's local peer ID follows
  the key, not the identity.
- **Over DERP, WireGuard needs no disco key.** A DERP packet from a node key in the
  peer map goes to wireguard-go whatever disco key that peer last announced, and the
  reply takes the region it came from. It is what lets a device whose juistd
  restarted, announcing its new disco key under an epoch its peers no longer hold,
  reach them through a shared relay for a catch-up.
- **A router config that failed is never handed to the router again.**
  `Reconfig` records it as the last one before calling `router.Set`, so asking
  again returns `ErrNoChanges`. `conn` retries a failed one on the OS router
  itself, which redoes only what failed (v1.104.0, `userspace.go:855`).
- **A new private key goes through `Reconfig`.** A changed `PrivateKey` is set
  on magicsock, which redials its relays under it, and on the device, which
  expires every peer's session. The disco key and the device stay, so a
  rotation needs no new engine (v1.104.0, `userspace.go:886`).
- **A first handshake sent on no path costs five seconds.** With no relay and
  no path disco has proven yet, magicsock fails the send ("no UDP or DERP
  addr"), and wireguard-go sends no other initiation within `RekeyTimeout`,
  failed or not. `conn` holds what is sent to a peer installed without a relay
  until disco's first pong, for at most two seconds.
- **A real device joins LAN discovery unless told not to.** A Linux TUN carries
  `IFF_MULTICAST`, so anything enumerating multicast-capable interfaces picks it up
  and starts sending into the tunnel. Discovery is an underlay function; the overlay
  is not one of the networks it should look on.

## Upgrading the pinned Tailscale

An upgrade is done when `make check` passes and each assumption below still
holds. Every one is guarded by a test that fails if upstream changes it; a
guard that fails names a workaround to revisit, not a test to relax. A new
dependency on upstream behaviour gets a guard here before it merges. The
`conn/upstream_test.go` guards read the pinned module's source or drive its
code directly, so they fail on the upgrade itself rather than in the field.

| Assumption | Where it is relied on | Guard |
|---|---|---|
| `SetSubsystem` hands over the `*magicsock.Conn` and the `*tstun.Wrapper` | `conn.New`, which refuses to start without both | every test that starts a manager, e.g. `TestTwoNodeOverlayPing` |
| An unknown key gets no peer, and a nil filter drops everything | default-deny | `TestNonMemberIsDenied`, `TestFilterRejectsNonMembers` |
| `ListenPort` is a preference magicsock may silently give up | `conn.New`'s port check, `ErrPortTaken` | `TestListenPortInUse` |
| The engine records a router config before programming it, so it never retries one that failed | the forced retry in `reconfig` | `TestUpstreamEngineSkipsARouterItFailedToProgram`, `TestReconfigReprogramsAFailedRouterOnTheRealEngine` |
| magicsock changes its home relay only while `GetInPollNetMap` is true, a check it skips under test | `GotStreamedMapResponse` in `conn.New` | `TestUpstreamHomeRelayWaitsForAMapPoll`, `TestTheHomeRelayMayChange` |
| util/backoff logs `%s: [v1] backoff: %d msec` under `derp-<region>`, and derphttp says `no non-STUNOnly nodes` for a STUN-only region | `withoutSTUNHomeNoise` | `TestUpstreamBackoffLineIsTheOneFiltered`, `TestUpstreamSTUNOnlyRegionErrorIsTheOneFiltered` |
| Nothing below `ipnlocal` resets a peer's sessions when its disco key changes, and `SyncDevicePeer` removes a peer whose lookup fails | the eviction in `SetPeers` | `TestARestartedPeerIsReachedAtOnce` |
| derpserver asks its admission URL through `http.DefaultClient`, failing closed, with the context `Accept` was given | relay admission, `relay/admit.go`, `serveDERP` | `TestNonMemberCannotUseTheRelay`, `TestMembersRelayThroughAMember` |
| magicsock reaches no relay and no STUN server without a DERP map | direct-only operation | `TestNoThirdPartyEgress` |
| With `SetOnlyTCP443`, magicsock and netcheck send no UDP, take a peer's UDP path only from a pong or a peer relay, and the self node's only-TCP-443 capability turns peer relays off | HTTPS alone | `TestUpstreamOnlyTCP443SendsNoUDP`, `TestHTTPSOnlySendsNoUDP` |
| derphttp dials a node's `DERPPort` at its host name in DNS where an address is empty, verifies a node without `CertName` by WebPKI, and asks `feature.HookProxyFromEnvironment` for each dial; no port mapper or captive-portal probe is linked | relays on 443, the proxy | `TestUpstreamANamedNodeIsDialledByNameThroughTheProxy`, `TestUpstreamNoPortMapperOrCaptivePortalIsLinked`, `TestMembersRelayThroughThePublicName` |
| A preshared key reaches a peer created on first contact through the config lookup and an active one in place through `SyncDevicePeer`, which keeps its session; a peer holding another completes no handshake | `conn.Peer.PSK`, M15, and the resets of a peer newly keyed | `TestHandshakesCarryThePresharedKey`, `TestAKeyWhereThereWasNoneEndsTheSession`, `TestAPeerCreatedWithTheKeyItHadPassesNothing` |
| The router, device and MTU behave as the wiring requirements above say | the real-device path | `make test-os-plumbing` (root, not on CI's unprivileged job) |

## Answers leave the way they came (Linux)

Using an exit node, answers to connections that came in by another device
leave by it. The conntrack mark is bit 0x20000000, apart from Tailscale's
0xff0000; software that saves or clears the whole mark, as Calico's default
mask does, breaks the answers, not the guard. A connection is marked only
where it was sent to an address of the device it came by, and where the
host's routes, as answers take them, lead back by that device: this keeps
what a LAN sends to the overlay's addresses, and what comes by another VPN,
out. A UDP server bound to the wildcard address without `IP_PKTINFO` picks
its answer's source by the routes, the exit node's, so its answers are no
answers to conntrack and go through the tunnel.

## Sharing a host with tailscaled

juist must hold nothing tailscaled also holds, since both run on one host:

- **Not its address range.** tailscaled's `ts-input` chain drops every packet
  from 100.64.0.0/10 that arrives on an interface other than `tailscale0`, local
  ones included. Overlay IPv4 therefore comes from 198.18.0.0/15 from schema 4 on.
- **Not its routing table or rule priorities.** Tailscale's Linux router hard-codes
  table 52 and rules at 5210–5270, and deletes those rules when it closes. juist
  programs its own table and priorities (`conn/router_linux.go`), below
  Tailscale's so an exit node's default route in table 52 cannot capture overlay
  traffic.

- **Not its resolver.** An exit node asks nothing of tailscaled's
  100.100.100.100 or fd7a:115c:a1e0::53 for a member, whose answer would come
  from the host's tailnet: where tailscaled wrote resolv.conf, it asks the
  resolvers in `/etc/resolv.pre-tailscale-backup.conf`.

The same holds between juist's own instances, one per network on a host (M5):
instance n routes in table 0x6a75+n behind rules at 5110+n, 5130+n, 5150+n and
5170+n, so every instance's bypass rule comes before any instance's table, each
deletes and restores only its own rules, and where two tables claim an address
the lowest instance's wins. That is why the higher of two instances whose
networks claim one address runs without IPv4 (`daemon/host.go`): its routes
would never win.

An instance using an exit node (M6a) adds two rules after every instance's
table and before Tailscale's: juistd's own user to main at 5180+n, and its
exit table, 0x6a75+0x100+n, at 5200+n, which throws special space back to
later rules. Bypass-marked packets, tailscaled's as well as magicsock's, have
left for main at 5110 by then, and the exit rule skips them anyway, as it
must where an instance refuses without a mesh, and so without a bypass rule; tailscaled's tailnet (100.64.0.0/10,
fd7a:115c:a1e0::/48) is special space, which reaches its table 52; its
guard, the nftables tables `juistNguard`, lets bypass-marked packets and
special space past. The first exit table takes every address it is asked
about: of two instances using an exit node the lower one's routes, the
higher routing nothing of its own, and an instance serves nothing beside one
that uses an exit node (`conn.ErrEgressTaken`).

## FreeBSD

What the pinned Tailscale and wireguard-go do on FreeBSD, and what juist does
instead (M7a):

- **Tailscale's BSD router is not used.** It runs `ifconfig` and `route`,
  which need root, and its `Close` leaves routes behind. juist's router asks
  its helper instead (`conn/plumbed_freebsd.go`).
- **wireguard-go's FreeBSD device is not used by the daemon.** Built from a
  descriptor it sets the MTU itself, `SIOCSIFMTU`, which only root may, even
  to the MTU the device has. The helper creates the device with it; the
  daemon reads and writes the descriptor behind the four-byte family header
  `TUNSIFHEAD` asks for.
- **`route add … -iface DEV -ifa SRC` does not pin the source** of what the
  host sends; the route shares its next hop with one without `-ifa`. Naming
  the source as the gateway, `route add P SRC -ifp DEV`, does.
- **netmon hears devd's IFNET events alone**, and polls every ten seconds
  without devd: a route change alone is not heard.
- **Nothing keeps Tailscale's own traffic off the tunnel** on FreeBSD: no
  mark, no FIB, no binding. juist's pf anchor sends it back to the host's
  gateway by its user (M7b).
- **pf, as juist uses it:** a stateful `pass` takes a TCP connection by its
  SYN alone, so the guard passes without state, or it drops what answers a
  connection that came in, sshd's included. A NAT's state, taken on the
  uplink, does not pass an answer out of the tunnel, so the exit node keeps
  state as peers' traffic comes in. `LOCAL_PEERCRED` on a socket pair names
  its creator, the helper, not the daemon holding the other end.
- **A host that runs pf itself** must call `nat-anchor "juist/*"`,
  `rdr-anchor "juist/*"` and `anchor "juist/*"` in `/etc/pf.conf` before any
  rule that passes quick, which would pass what the guard drops; juist
  refuses otherwise, and says so. Without pf running, juist runs it with
  those lines alone, and turns it off again while nobody changed them and
  rc.conf does not start pf. Answers to what comes in keep leaving the way
  it came only with that ruleset of juist's: pf decides by the last rule
  that matches, so a pass of juist's would override a host's `block in all`
  before the anchor, and `match` takes no `reply-to` in 14.5; beside the
  host's own rules theirs decide, and the status says so.
- **Routes to one prefix do not stand side by side** on 14.5, even with
  `net.route.multipath=1`, whatever their gateways: juist deletes a route
  by its gateway all the same, so as never to take another's.
- **IPv6 on the device** takes the address as `inet6 A prefixlen 128`;
  Tailscale's `/48` workaround for FreeBSD bug 218508 concerns the
  point-to-point form, which juist does not use.

## Constraints on the test harness

- **`RespondToPing` is IPv4-only.** `wgengine.echoRespondToAll` calls `ICMP4Header()`
  on anything `IsEchoRequest()` matches, so an ICMPv6 echo **panics the engine**. This
  is Tailscale's test scaffolding and no product code depends on it — but it is
  arguably an upstream bug worth reporting. Since our addressing makes the v6 ULA
  primary, the harness sidesteps the scaffolding instead of relying on it: a
  ~100-line fake `tun.Device` that echoes ICMP for both families
  (`conn/echotun_test.go`) asserts v4 *and* v6 reachability today, and exercises the
  full TUN round trip (decrypt → filter → Wrapper.Write → Wrapper.Read → encrypt)
  rather than RespondToPing's engine-internal shortcut. The real devices M3a adds
  do not replace it: a fake device keeps the two-node assertions runnable in one
  namespace by an unprivileged CI job, where the netns harness needs root.
- **The M0 egress criterion is met without privileges** by scanning this process's own
  sockets (`/proc/self/fd` → `/proc/net/{tcp,tcp6,udp,udp6}`) and asserting no remote
  address outside the host, plus `magicsock.Conn.DERPs() == 0`. The detector is
  self-checked against a UDP socket connected to an external address (`connect(2)`
  sends nothing) so it cannot pass vacuously, and the test kicks `magicsock.ReSTUN`
  before looking, so the lazy netcheck path runs inside the observation window
  rather than on its own timer. One blind spot is structural: STUN would leave via
  magicsock's main *unconnected* UDP socket, which `/proc/net` shows with a zero
  remote address, so STUN egress is covered only by the `DERPs()`/netcheck side.
  The netns harness closes that from outside the process: an `AF_PACKET` tap on the
  node's only link fails the test on any destination outside the lab's LAN. Two
  details decide whether that tap can see anything at all, and both look like
  passes when they are wrong. The namespace's default route must go through a
  **next hop that already resolves** — the lab routes via a `.254` nobody holds and
  gives each namespace a permanent neighbour entry for it — because an on-link
  default route makes the kernel ARP for the third party itself and the IP packet
  is never put on the wire. (An address on the bridge would do the same job and
  give the *host* a second route for the lab's prefix, which is a poor trade for a
  test.) And the tap counts **ARP and neighbour-solicitation targets** as
  destinations, not only IP headers, so a resolution attempt that goes unanswered
  still fails the test rather than passing as silence. The lab's underlay
  is IPv4 only, so v6 egress is not so much asserted as unreachable: a node there
  has no v6 route to a third party to take.
- **A node needs its own namespace and its own process.** A network namespace is a
  property of a *thread*, so a single Go process cannot hold two of them without
  pinning every goroutine that might touch an engine. The harness re-executes the
  test binary under `ip netns exec`, which sets the namespace before `exec`, and
  drives each child over a one-line stdin/stdout protocol. That is also why the
  privileged gate must stay a `go test` invocation: the child is the test binary.
- **Traffic assertions use the host's own tools.** `ping` inside the namespace, and
  an ordinary Go TCP client that knows nothing about juist, rather than
  `Manager.Ping` — the criterion is that the *host stack* reaches the overlay, and
  the engine's internal ICMP answers without a device being involved at all.

## Endpoints without a control plane

**magicsock will not report its own local endpoints without a DERP map.**
`Conn.setEndpoints` returns early with neither a STUN result nor a DERP map. Since
the design gossips signed endpoint records, `daemon.underlayEndpoints` reads the
host's interface addresses directly instead — the option that needs no third party,
which is what "LAN-only operation with zero internet" requires. Reflexive addresses
from disco and member relays arrive at M3b and are *added* to that set, never
substituted for it.

A second cost of the same gap: with no fallback path the first WireGuard handshake
to a new peer is dropped while disco is still working, and WireGuard's five-second
retry then dominates. `conn.warmPaths` starts discovery when a peer appears.

## What tailcat confirms — and what M3b takes from it

Tailscale published [tailcat](https://github.com/tailscale/tailcat) on 2026-08-31:
a netcat-like tool that runs, in its own words, "the open-source Tailscale data
plane (WireGuard® + NAT traversal + DERP) without the Tailscale control plane".
BSD-3, Go, about two thousand lines of library code. It is the embedding this
document describes, done by the people who own the code, and it is worth reading
for that reason alone.

It is not a competitor to juist and does not touch the thesis. tailcat is one
point-to-point tunnel between a server and the clients holding its `ConnBlob`
token; it has no membership, no log, no quorum, no identity, no policy, and its
README does not mention revocation at all. Access control is a `--allow` list of
client public keys, keys are ephemeral per run by default, and the TCP/IP stack
is netstack rather than a real TUN. Tailscale draws the line themselves: "Use
Tailscale when you need a governable network. Use tailcat when you need a quick
connection." tailcat ends roughly where M0 ended and M1 begins.

### It reduces the upgrade-churn risk this document accepted

[04-architecture.md](04-architecture.md) accepted that pinning an unversioned
internal API means every Tailscale upgrade carries breakage risk. tailcat uses
the same entry points `conn/` does — `SetPeerConfigFunc`, `SetPeerByIPPacketFunc`,
`SetPeerForIPFunc`, `SetSelfNode`, `SetFilter`, `magicsock.Conn.SetNetworkMap` —
and it is now a public, tested, release-engineered artifact inside Tailscale's own
repository set. That does not make the surface stable (tailcat itself promises no
API stability), but it does mean the control-plane-free path through `wgengine`
now has an upstream consumer, which is a much better position than being the only
one.

### The technique worth taking: endpoint exchange as a hand-sealed disco frame

The open item this document recorded — magicsock will not distribute endpoints
without a control plane, and never attempts a direct path to a peer whose
endpoints it does not know — is the same problem tailcat has, and tailcat solves
it in a way M3b should copy. It seals a `disco.CallMeMaybe` itself and ships it as
a DERP packet, so the *stock* magicsock on the far side processes it natively:

```go
pkt = append(pkt, disco.Magic...)
pkt = b.discoPublic().AppendTo(pkt)
pkt = append(pkt, discoPriv.Shared(p.DiscoKey()).Seal(payload)...)
mc.SendDERPPacketTo(p.Key(), regionID, pkt)
```

The receiving magicsock disco-pings the advertised endpoints, which both teaches
it a direct path to the sender and teaches the sender the receiver's address from
the pings coming back. **M3b did not need to hand-seal anything** — with a DERP
map installed magicsock sends `CallMeMaybe` itself, but only for a peer it
already holds one candidate address for, which is what the signed announcement
supplies. See [10-connectivity-notes.md](10-connectivity-notes.md); the
technique stays the right shape for a sideband over a relay, and nothing wants
one yet. The prerequisite is knowing one's *own* disco private key,
which magicsock otherwise generates internally and never reveals; that is what
`wgengine.Config.ForceDiscoKey` is for, and `conn/tsmanager.go` already sets it
from `Self.DiscoKey`. The precondition is in place.

Endpoints to advertise come from `Engine.SetStatusCallback`: `wgengine.Status`
carries `LocalAddrs []tailcfg.Endpoint`, the set magicsock has learned from STUN
and from local interfaces. That does not replace `daemon.underlayEndpoints` for
M2 — with no DERP map, `Conn.setEndpoints` returns early and the callback has
nothing to report, which is exactly the finding above. It becomes available at M3b
alongside the member-relay DERP map, and it is the path by which reflexive
addresses join the directly-read interface addresses rather than replacing them.

### Also worth taking: DERP as an arbitrary authenticated sideband

`magicsock.Conn.SendDERPPacketTo(dstKey, regionID, pkt)` sends an arbitrary
packet to a node key through a relay, creating the relay connection on demand,
and `wgengine.Config.OnDERPRecv` receives every non-disco DERP packet before the
peer-map lookup, returning `handled` to swallow it. Together they are a general
message channel over a relay that sees only node keys and ciphertext — which is
the shape M3b's "member-volunteered, E2E-blind relays" needs. tailcat's own
rendezvous ("meow") rides that channel as raw framed packets with a four-byte
magic chosen to be distinguishable from WireGuard message types 1–4 and from
disco's `TS💬`. juist's equivalent carries the same framing discipline but is
sealed under the epoch group secret, because unlike tailcat we have a group
secret and a membership to bind it to.

**All three APIs — `ForceDiscoKey`, `SendDERPPacketTo`, `OnDERPRecv` — are
present in the pinned tailscale.com v1.104.0**, verified against the module cache.
tailcat pins a v1.103.0-pre, but adopting these techniques needs no upgrade.

### What tailcat does not solve

The preshared key. `grep -rn preshared` over tailcat returns nothing: it runs the
same PSK-less Noise IKpsk2 as stock Tailscale, so M15 had no prior art to take.

### Where ours differs on purpose

tailcat derives its overlay address from the node key into Tailscale's fixed ULA
`fd7a:115c:a1e0::/48`. juist derives the /48 itself from the genesis hash
(`types/addr.go`), so two juist networks — or a juist network and a Tailscale
tailnet — do not collide on one host. And tailcat bootstraps through
Tailscale-operated public DERP relays with a DERP map fetched from `tailcat.dev`,
which is precisely the trusted third party the architecture rejects. The
mechanism transfers to M3b; the bootstrap does not.
