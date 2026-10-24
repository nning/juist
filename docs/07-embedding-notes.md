# 07 — Embedding Tailscale's connectivity stack

What `conn/` relies on in the pinned **tailscale.com v1.104.0** and its
wireguard-go fork `v0.0.0-20260928213032`. Any of it may change at an
upgrade, the cost [04-architecture.md](04-architecture.md) accepted.

## The shape of the embedding

`wgengine.NewUserspaceEngine` and `magicsock` run with **no `controlclient`,
`tsnet` or `ipn`** in the path. `wgengine.Config` has no control-plane field,
and the `Engine` is driven by callbacks — `SetPeerConfigFunc`,
`SetPeerByIPPacketFunc`, `SetPeerForIPFunc`, `SetSelfNode`, `SetFilter` — which
juist answers from log state where Tailscale's `LocalBackend` would.

- **No `netmap.NetworkMap`.** magicsock takes
  `SetNetworkMap(self tailcfg.NodeView, peers []tailcfg.NodeView)`; the adapter
  builds `tailcfg.Node` values and nothing more.
- **Peers are not in the WireGuard config.** `wgcfg.Config` is
  `{PrivateKey, Addresses}`; the device asks
  `SetPeerConfigFunc(func(key.NodePublic) (allowedIPs, ok))` for each peer, and
  `ok=false` means wireguard-go never creates it. `SetPeers` stores the new
  snapshot before it resyncs the device, so no peer outlives its removal.
- **Default-deny is enforced twice.** Beside the lookup, a nil packet filter
  drops every inbound packet (`tstun`: `if filt == nil { return filter.Drop }`),
  so the filter must be built explicitly. Keep both.

## The preshared-key path

Every pair of members mixes a preshared key from ML-KEM-768 into WireGuard's
handshake. It reaches the engine as `conn.Peer.PSK`, with no patch:

- **Both peer states need their path.** A peer created lazily gets its key
  through the config lookup (`wgcfg.PeerConfig.PresharedKey`, passed on by
  `wgcfg.NewPeerLookupFunc`, `wgcfg/device.go:60`), an active one through
  `SyncDevicePeer` (`wgengine/userspace.go:698`), which `SetPeers` calls for
  every kept peer.
- **A change keeps the session.** `Peer.SetPresharedKey` (`device/peer.go:197`)
  takes effect at the next handshake, so a session made without a key would
  carry traffic for minutes after one is given. `SetPeers` therefore resets a
  peer newly given a key, keeps it passing nothing, and resets it again 2 s
  later, since `LookupPeer` may have created it from the older config.
- **Each role reads the key at its own moment.** The responder mixes it into
  the response, the initiator when it consumes it (`device/noise-protocol.go`);
  a mismatch fails the initiator's decryption and is retried after
  `RekeyTimeout`, 5 s. A completed handshake does not say which key it used;
  juist confirms keys by message.
- **Rotation is bounded by the rekey window.** `RekeyAfterTime` is 120 s and
  `RejectAfterTime` 180 s (`device/constants.go`), and a peer holds one key, so
  both ends need the new key before the next handshake.
- **The ML-KEM ciphertext travels in gossip frames** (`frame.Pair`), never in
  the log; the encapsulation keys are `NodeRecord.MLKEM`
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)).

The exchange (`internal/pairkey`, `daemon/pairkeys.go`) keeps these rules:

- **Announced first.** Every member sets a preshared key towards every peer
  and announces the newest epoch it holds and its store of pair keys
  (`Endpoint.Epoch`, `Endpoint.PairStore`). Towards a peer announcing neither
  it sets none and keeps the peer to juist's own traffic, so no user traffic
  crosses a tunnel without a preshared key.
- **A group key first.** A pair's first key is `HKDF(seed, epoch, both
  WireGuard keys)`, the seed from the group secret of the lower of the two
  epochs the pair announce, so a member behind is reached without a message.
  Seeds for the last 64 epochs (`pairkey.SeedDepth`) are kept apart from the
  keyring, since a seed answers no gossip or discovery.
- **A pair key next.** In log sync the member with the lower WireGuard key
  leads four signed messages, each naming both members, their WireGuard keys
  and both stores: it encapsulates to the follower's ML-KEM key, the follower
  encapsulates back and confirms, the leader commits with its own
  confirmation. The key is HKDF over both ML-KEM secrets, salted with the
  group key of the leader's epoch and bound to the network, both WireGuard
  keys and both ciphertexts, so no third member derives it, the group secret
  included. Every rise of the pair's epoch starts a new generation.
- **Bound to WireGuard keys.** A pair key holds while both WireGuard keys and
  the peer's store are those it was made with. An identity rotation keeps it,
  so a member that slept through one reaches the rotated device. No
  generation number is used twice in a store.
- **No downgrade.** The follower uses the last key it took up and moves only
  on the leader's confirmed commit; the leader uses the committed key and
  tries the one before only while the tunnel is down. Every key either side
  may use is a pair key or the group key, so blocking handshakes never takes a
  pair to none.
- **Kept before told.** Pair keys and seeds live in `pairs.secret`, sealed as
  the keys are, and a change is written and synced before any message shows
  it. A store lost starts over under a new ID, which peers read as their pair
  keys given up.
- **Paced.** A pair starts or answers one generation per 5 s (`pairkey.Pace`).
- **Addresses too.** An address key's wrap for a peer mixes in the pair key
  once the pair has one, so M14's sealed addresses are as post-quantum as the
  tunnels.

## Wiring requirements that nothing documents

Each fails silently or confusingly.

- **`tstun.Wrapper.Start()` must be called by us.** Without it every TUN read
  blocks, with only a once-a-second `tstun: awaiting Wrapper.Start call`. Call
  it after the lookups, the filter and the first `Reconfig`.
- **`SetSelfNode` and `SetPeerForIPFunc` gate diagnostics.** `Engine.Ping`
  resolves its target through the first and its source through the second;
  without both it reports "no matching peer" for a peer that is up.
- **Loopback endpoints do not work.** Tailscale's `netns` binds UDP sockets to
  the default interface, so a datagram to `127.0.0.1` is never delivered.
  Multi-node tests on one host use the host's real address.
- **Resetting a restarted peer's sessions is the embedder's job.** Nothing in
  the engine drops a peer's sessions when its disco key changes; `SetPeers`
  evicts it with a `SyncDevicePeer` whose lookup fails. Without that, dead
  session keys blackhole traffic for minutes with nothing logged.
- **A real TUN device alone plumbs nothing into the OS.**
  `wgengine.Config.Router` defaults to a fake that discards every
  `router.Config`. juist hands its own router on Linux (`conn/router_linux.go`),
  the helper's on FreeBSD, and Tailscale's `router.New` elsewhere. The router
  wants the device and the engine the router, so the order is netmon, TUN,
  router, engine; one `netmon.Monitor` is shared through `Config.NetMon`, and
  the engine never closes a monitor it was handed.
- **Tailscale's routers may panic when closed before `Up`,** and a failed
  `NewUserspaceEngine` leaves `Config.Router` with the caller.
  `closeUnstartedRouter` closes juist's Linux router on that path and leaves
  Tailscale's alone.
- **`wgengine.Config.ListenPort` is a preference.** `magicsock.bindSocket`'s
  candidate list ends in `0`, so a port it cannot bind becomes an OS-assigned
  one after a log line. `conn.New` compares `magicsock.LocalPort()` with a
  non-zero requested port and refuses to start on a mismatch (`ErrPortTaken`).
- **The TUN MTU must come from `tstun.DefaultTUNMTU()`,** 1280, the IPv6
  minimum. Below it the kernel removes `/proc/sys/net/ipv6/conf/<iface>/`, and
  the router reads that directory to decide whether to program IPv6 at all.
- **Device names go straight to `TUNSETIFF`.** Over `IFNAMSIZ-1` (15 bytes) is
  a bare `EINVAL`, and a `%` makes the name a kernel template; `checkTunName`
  refuses both.
- **Peer routes are not in the main table.** Instance n routes in table
  0x6a75+n, so `ip route show dev juist0` shows nothing; use
  `ip route show table all dev juist0`.
- **IPv6 is programmed conditionally.** The router skips every IPv6 address
  and route where the device's `disable_ipv6` is set or its conf directory is
  absent, logging it once, and the IPv6 rules where the kernel has no IPv6
  policy routing. The overlay's primary family is then gone with nothing but a
  log line; assertions must allow for it, and a report of "no v6 on the
  overlay" starts here.
- **Tailscale's `router.CleanUp` is not called.** juist runs `NetfilterOff`, a
  wireguard-go TUN dies with its process, and juist's router adds its rules
  idempotently and deletes them by priority.
- **magicsock keeps its first home relay without a control plane.**
  `maybeSetNearestDERP` changes the home region only while
  `health.Tracker.GetInPollNetMap()` is true. `conn` marks its tracker as in a
  map poll (`GotStreamedMapResponse`), since announcements tell peers of a new
  home; otherwise a relay granted after start is never used. Besides magicsock,
  only the tracker's own warnings read the flag.
- **One node key under two node IDs is refused.** `magicsock.updateNodes`
  meets it with `devPanicf`: a panic under test, a missing endpoint in
  production. An identity rotation keeps the WireGuard key, so the local peer
  ID follows the key, not the identity.
- **Over DERP, WireGuard needs no disco key.** A DERP packet from a node key in
  the peer map reaches wireguard-go whatever disco key the peer last
  announced. That lets a restarted device, whose new disco key its peers do
  not hold yet, reach them through a shared relay for a catch-up.
- **A router config that failed is never handed to the router again.**
  `Reconfig` records it before calling `router.Set` and then answers
  `ErrNoChanges`, so `conn` retries a failed one on the OS router itself
  (`userspace.go:855`).
- **A new private key goes through `Reconfig`.** magicsock redials its relays
  under it and the device expires every session; the disco key and the device
  stay, so a rotation needs no new engine (`userspace.go:886`).
- **A first handshake sent on no path costs five seconds.** With no relay and
  no path disco has proven, magicsock fails the send ("no UDP or DERP addr")
  and wireguard-go waits `RekeyTimeout` before the next initiation. `warmPaths`
  pings a new peer at 0, 250 ms, 1 s and 3 s — repeated because a ping reaching
  a peer that has not installed us yet is discarded, and only a pong adopts a
  path — and `conn` holds what is sent to a peer with addresses but no relay
  until the first pong, at most until the last of those pings.
- **A real device joins LAN discovery unless told not to.** A Linux TUN
  carries `IFF_MULTICAST`; discovery skips the host's juist devices
  (`mdns.Options.SkipInterface`).

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
| netcheck measures the three nearest regions and the home, stops once three answered, measures by HTTPS only where no UDP probe was answered, and picks the nearest region it measured for a home, a STUN-only one where no relay answered, which magicsock then fails to connect to and measures again every few seconds, the connection made even where it was told meanwhile that it has no home; a homeless magicsock takes no home, keeps no relay connection and asks STUN only when told to, yet says at each netcheck that its home moves to the nearest region; NetInfo leaves out latencies measured by HTTPS, one that differs in latencies alone is not passed on, and each is passed on in a goroutine of its own, so an older one may come after a newer | one STUN region in `derpMap`, `followReport`, `followHome`, `stunWhileHomeless`, `watchEngine` | `TestAHomeIsARelayReachedOrNone`, `TestAConnectionToTheSTUNRegionIsDropped`, `TestARelayIsMeasuredBesideThreeSTUNServers`, `TestARelayReachedByHTTPSAloneIsAHome`, `TestAReportMeasuringNothingKeepsTheHome`, `TestAHomeTakenOutOfOrderIsSetRight`, `TestASavingNodeHomesAgainWhenItsRelayReturns`, `TestAnIdleNodeWithoutARelayStopsAskingSTUN`, `TestAHomelessNodeSaysNoHomeItDoesNotTake` |
| magicsock pings a peer every 3 s until 45 s after the last packet sent to it, starting on a WireGuard packet or a disco ping through `Engine.Ping` unless silent disco is on as it is sent; such a ping still counts as the last packet | `ProbeQuietly`, `quietPingGap` | `TestAQuietProbeStartsNoHeartbeat`, `TestARestingPeerIsCheckedQuietly` |
| Nothing in the engine resets a peer's sessions when its disco key changes, and `SyncDevicePeer` removes a peer whose lookup fails | the eviction in `SetPeers` | `TestARestartedPeerIsReachedAtOnce` |
| derpserver asks its admission URL through `http.DefaultClient`, failing closed, with the context `Accept` was given | relay admission, `relay/admit.go`, `serveDERP` | `TestNonMemberCannotUseTheRelay`, `TestMembersRelayThroughAMember` |
| magicsock reaches no relay and no STUN server without a DERP map | direct-only operation | `TestNoThirdPartyEgress` |
| With `SetOnlyTCP443`, magicsock and netcheck send no UDP, take a peer's UDP path only from a pong or a peer relay, and the self node's only-TCP-443 capability turns peer relays off | HTTPS alone | `TestUpstreamOnlyTCP443SendsNoUDP`, `TestHTTPSOnlySendsNoUDP` |
| derphttp dials a node's `DERPPort` at its host name in DNS where an address is empty, verifies a node without `CertName` by WebPKI, and asks `feature.HookProxyFromEnvironment` for each dial; no port mapper or captive-portal probe is linked | relays on 443, the proxy | `TestUpstreamANamedNodeIsDialledByNameThroughTheProxy`, `TestUpstreamNoPortMapperOrCaptivePortalIsLinked`, `TestMembersRelayThroughThePublicName` |
| A preshared key reaches a peer created on first contact through the config lookup and an active one in place through `SyncDevicePeer`, which keeps its session; a peer holding another completes no handshake | `conn.Peer.PSK` and the resets of a peer newly keyed | `TestHandshakesCarryThePresharedKey`, `TestAKeyWhereThereWasNoneEndsTheSession`, `TestAPeerCreatedWithTheKeyItHadPassesNothing` |
| The wrapper hands each packet the device sends to `PreFilterPacketOutboundToWireGuardNetstackIntercept` before the engine's own hook and the filter, a hook nothing but Tailscale's netstack sets, and `InjectInboundCopy` writes to the device past the inbound filter | `conn.Options.Local`, the phone's resolver | `TestALocalAddressIsAnsweredInTheProcess` |
| The device, MTU and engine wiring behave as the requirements above say | the real-device path | `make test-os-plumbing` (root; `make ci-vm` runs it) |

## Answers leave the way they came (Linux)

Using an exit node, answers to connections that came in by another device
leave by it, through a rule at 5160+n that sends packets carrying conntrack
mark bit 0x20000000 to the main table. The bit is apart from Tailscale's
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
  from 100.64.0.0/10 that arrives on an interface other than `tailscale0`,
  local ones included. Overlay IPv4 therefore comes from 198.18.0.0/15.
- **Not its routing table or rule priorities.** Tailscale's Linux router
  hard-codes table 52 and rules at 5210–5270, and deletes those rules when it
  closes. juist programs its own table and priorities (`conn/router_linux.go`),
  below Tailscale's so an exit node's default route in table 52 cannot capture
  overlay traffic.
- **Not its resolver.** An exit node asks nothing of tailscaled's
  100.100.100.100 or fd7a:115c:a1e0::53 for a member, whose answer would come
  from the host's tailnet: where tailscaled wrote resolv.conf, it asks the
  resolvers in `/etc/resolv.pre-tailscale-backup.conf`.
- **Not resolv.conf, without resolved.** tailscaled without resolved writes
  `/etc/resolv.conf` itself, puts it back when another program does and then
  asks what it found there, juistd's resolver included. So `resolv.sh` leaves
  tailscaled's alone, juistd never asks tailscaled's resolvers where the host
  asks juistd alone, and juist's names say tailscaled writes resolv.conf. On
  FreeBSD tailscaled names itself to resolvconf exclusively and asks every
  other interface's resolvers, juist0's too.

The same holds between juist's own instances, one per network on a host:
instance n routes in table 0x6a75+n behind rules at 5110+n, 5130+n, 5150+n and
5170+n, so every instance's bypass rule comes before any instance's table, each
deletes and restores only its own rules, and where two tables claim an address
the lowest instance's wins. That is why the higher of two instances whose
networks claim one address runs without IPv4 (`daemon/host.go`): its routes
would never win.

An instance using an exit node adds two rules after every instance's table
and before Tailscale's: juistd's own user to main at 5180+n, and its exit
table, 0x6a75+0x100+n, at 5200+n, which throws special space back to later
rules. Bypass-marked packets, tailscaled's as well as magicsock's, have left
for main at 5110 by then, and the exit rule skips them anyway, as it must
where an instance refuses without a mesh, and so without a bypass rule.
tailscaled's tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48) is special space,
which reaches its table 52; its guard, the nftables tables `juistNguard`,
lets bypass-marked packets and special space past. The first exit table
takes every address it is asked about: of two instances using an exit node
the lower one's routes, the higher routing nothing of its own, and an
instance serves nothing beside one that uses an exit node
(`conn.ErrEgressTaken`).

## FreeBSD

What the pinned Tailscale and wireguard-go do on FreeBSD, and what juist does
instead:

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
  gateway by its user.
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

- **`RespondToPing` is IPv4-only.** `wgengine.echoRespondToAll` calls
  `ICMP4Header()` on any echo request, so an ICMPv6 echo panics the engine.
  The harness uses a fake `tun.Device` that echoes both families
  (`conn/echotun_test.go`) instead, which also drives the full TUN round trip
  and keeps two-node tests runnable unprivileged in one namespace.
- **Egress is asserted from inside and outside the process.** Unprivileged,
  the test reads this process's sockets (`/proc/self/fd` →
  `/proc/net/{tcp,tcp6,udp,udp6}`) for a remote address outside the host,
  self-checked against a socket connected outward, and asserts
  `magicsock.Conn.DERPs() == 0` after kicking `ReSTUN`; STUN would leave by
  magicsock's unconnected socket, which `/proc/net` cannot show. The netns
  harness closes that gap with an `AF_PACKET` tap on the node's only link that
  fails on any destination outside the lab's LAN, counting ARP and
  neighbour-solicitation targets as destinations. The namespace's default
  route goes through a `.254` held by a permanent neighbour entry, since an
  on-link default route would have the kernel ARP for the third party and
  never put the packet on the wire. The lab's underlay is IPv4 only.
- **A node needs its own namespace and its own process.** A network namespace
  is a property of a thread, so the harness re-executes the test binary under
  `ip netns exec` and drives each child over a one-line stdin/stdout protocol;
  the privileged gate must therefore stay a `go test` invocation.
- **Traffic assertions use the host's own tools** — `ping` and an ordinary Go
  TCP client inside the namespace — rather than `Manager.Ping`, whose ICMP the
  engine answers without a device.

## Endpoints without a control plane

magicsock reports no local endpoints without a STUN result or a DERP map
(`Conn.setEndpoints` returns early), so the announcement is built from an
interface scan (`daemon.underlayEndpoints`), which needs no third party. Once a
DERP map is installed, `Engine.SetStatusCallback` reports
`wgengine.Status.LocalAddrs`, and its reflexive addresses are added to the scan,
never substituted for it.

## tailcat

Tailscale's [tailcat](https://github.com/tailscale/tailcat) (BSD-3) runs the
same data plane without a control plane through the same entry points `conn/`
uses, so this path has an upstream consumer, though no API promise. It is a
point-to-point tunnel with no membership, log or revocation. Two differences
are on purpose: juist derives its ULA /48 from the genesis hash
(`types/addr.go`) rather than using Tailscale's `fd7a:115c:a1e0::/48`, and it
bootstraps through no Tailscale-operated relay.

tailcat distributes endpoints by sealing a `disco.CallMeMaybe` by hand and
sending it with `magicsock.Conn.SendDERPPacketTo`, which the peer's stock
magicsock processes. juist does not need it: an announcement gives magicsock a
candidate address, after which it sends `CallMeMaybe` itself
([10-connectivity-notes.md](10-connectivity-notes.md)). `SendDERPPacketTo` and
`wgengine.Config.OnDERPRecv` (which sees every non-disco DERP packet first) are
the shape of an authenticated sideband over a relay, and nothing uses them yet;
`wgengine.Config.ForceDiscoKey`, which such a frame needs, is already set from
`Self.DiscoKey`. All three are in v1.104.0.
