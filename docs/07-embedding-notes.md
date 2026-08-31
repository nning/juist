# 07 — Embedding Tailscale's connectivity stack

Findings from the M0 spike (`conn/`), against **tailscale.com v1.102.2** and its
wireguard-go fork `v0.0.0-20260715223240`. These are pinned versions; anything here
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

## Problem: no preshared-key path

The per-pair ML-KEM-768 PSK hedge in [04-architecture.md](04-architecture.md) has
**no route through the current API**:

- `wgcfg.Config` has no PSK field.
- `device.NewPeerConfig` — what the peer-lookup func returns, and the only way a
  lazily-created peer is configured — carries `AllowedIPs` and `Endpoint`, nothing else.
- `grep -rn preshared wgengine/` returns nothing: Tailscale's engine layer never sets
  a PSK.

The fork itself *does* implement PSK — `handshake.presharedKey` in the Noise
handshake, settable per peer via the `preshared_key` UAPI key, all of it upstream
WireGuard's standard, battle-tested support. Only the layer above omits it. And
`wgengine`'s `wgdev` is private: it is not in the `Engine` interface and
`SetSubsystem` never surfaces it, so **the UAPI route is not reachable from outside
the package either**. That leaves two real options:

1. **Patch the vendored code** — add a `PresharedKey` field to `NewPeerConfig`, thread
   it through `wgcfg.NewPeerLookupFunc`, and expose *some* in-place update path for
   rotation. The crypto is upstream and untouched; the patch is plumbing. The cost is
   that the pinned dependency becomes a *modified* one: every Tailscale upgrade needs
   the patch rebased, and the diff is in the audit path even though it is not
   cryptographic.
2. **Defer the PQ hedge to post-v1**, alongside the ML-DSA checkpoint co-signatures
   already deferred.

Note also that [04-architecture.md](04-architecture.md) states PSKs are rotated on
epoch bump with tunnels staying up. Peers are configured only at *creation* through
`NewPeerConfig`, so without an in-place update path a rotation means recreating the
peer — which drops the tunnel and forces a re-handshake. Either the patch supplies
that path, or the documented rotation behaviour changes.

**Reserve the field in M1, decide before the M3 freeze.** `AddNode` should carry the
ML-KEM public key regardless — reserving it costs nothing and keeps (1) and (2) open.
But the record schema freezes at M3, and the choice determines whether v1 can claim
the PQ property at all, so it cannot be left open past that point.

*Done in M1:* `types.NodeRecord` carries `MLKEM` (an ML-KEM-768 encapsulation key)
alongside `X25519`. Both are consumed now as the two halves of the hybrid HPKE KEM
that seals epoch group secrets, which gives the discovery layer the PQ hedge
immediately; the data-plane PSK use is still the open decision above. See
[08-trust-layer-notes.md](08-trust-layer-notes.md).

## Wiring requirements that nothing documents

Each of these fails silently or confusingly; all three cost time in the spike.

- **`tstun.Wrapper.Start()` must be called by us.** `ipnlocal` does it in Tailscale.
  Without it, every TUN read blocks forever and the only symptom is a once-per-second
  `tstun: awaiting Wrapper.Start call` log line — a breadcrumb upstream left
  deliberately. Call it after all lookups, the filter, and the first `Reconfig` are
  installed.
- **`SetSelfNode` and `SetPeerForIPFunc` gate diagnostics.** `Engine.Ping` resolves
  its target through `SetPeerForIPFunc` and its source through `SetSelfNode`; without
  both it reports "no matching peer" for a peer that is otherwise fully up.
- **Loopback endpoints do not work.** Tailscale's `netns` binds UDP sockets to the
  default interface, so a datagram addressed to `127.0.0.1` leaves via that interface
  and is never delivered. Disco reports `sent ping` and then times out, with the
  receiving node logging nothing at all. Multi-node tests on one host must use the
  host's real address — and M2's netns-per-node harness sidesteps this anyway.
- **Resetting dead WireGuard sessions on disco-key rotation is the embedder's
  job.** `ipnlocal` calls `Engine.ResetDevicePeer` for every peer whose disco key
  changed after `SetNetworkMap`; nothing below it does. An adapter that only resets
  departed peers leaves a *restarted* peer's old session keys in the device, and
  traffic to it blackholes until WireGuard's own rekey timers give up — tens of
  seconds to minutes, with nothing logged. `SetPeers` diffs disco keys against the
  previous set and resets exactly those peers.
- **A real TUN device alone plumbs nothing into the OS.** `wgengine.Config.Router`
  defaults to `router.NewFake` when left nil, so the `router.Config{LocalAddrs}`
  passed to `Reconfig` is silently ignored: the interface gets no address and no
  routes, and nothing points at the cause. Actual OS plumbing needs a real
  `router.Router` wired at engine construction — M3a territory (see below); `conn`
  deliberately does not pass one yet.
- **`wgengine.Config.ListenPort` is a preference, not a requirement.**
  `magicsock.bindSocket` builds a candidate port list that always ends in `0`, so a
  port it cannot bind produces one `unable to bind udp4 port N: address already in
  use` line and an OS-assigned port instead. For Tailscale that is right: endpoints
  are discovered reflexively, so a moved port repairs itself. Here nothing repairs
  it — `daemon.underlayEndpoints` announces what a local interface scan finds, and
  the operator who passed the port has usually opened it in a firewall or forwarded
  it at a NAT. Found on a real laptop, where the requested 41641 was already held by
  the host's own `tailscaled` (that is its default port) and the daemon came up on
  40463 with only a banner line to say so. `conn.New` now compares
  `magicsock.LocalPort()` against a non-zero requested port and refuses to start on a
  mismatch. Note `LocalPort` reports the *v4* socket only, which is also the port the
  announcements are built from, so the check and the announcement agree by
  construction.

## Constraints on the test harness

- **`RespondToPing` is IPv4-only.** `wgengine.echoRespondToAll` calls `ICMP4Header()`
  on anything `IsEchoRequest()` matches, so an ICMPv6 echo **panics the engine**. This
  is Tailscale's test scaffolding and no product code depends on it — but it is
  arguably an upstream bug worth reporting. Since our addressing makes the v6 ULA
  primary, the harness sidesteps the scaffolding instead of relying on it: a
  ~100-line fake `tun.Device` that echoes ICMP for both families
  (`conn/echotun_test.go`) asserts v4 *and* v6 reachability today, and exercises the
  full TUN round trip (decrypt → filter → Wrapper.Write → Wrapper.Read → encrypt)
  rather than RespondToPing's engine-internal shortcut. Real TUN devices arrive
  with M3a, and do not replace this: a fake device keeps the two-node assertions
  runnable in one namespace by an unprivileged CI job.
- **The M0 egress criterion is met without privileges** by scanning this process's own
  sockets (`/proc/self/fd` → `/proc/net/{tcp,tcp6,udp,udp6}`) and asserting no remote
  address outside the host, plus `magicsock.Conn.DERPs() == 0`. The detector is
  self-checked against a UDP socket connected to an external address (`connect(2)`
  sends nothing) so it cannot pass vacuously, and the test kicks `magicsock.ReSTUN`
  before looking, so the lazy netcheck path runs inside the observation window
  rather than on its own timer. One blind spot is structural: STUN would leave via
  magicsock's main *unconnected* UDP socket, which `/proc/net` shows with a zero
  remote address, so STUN egress is covered only by the `DERPs()`/netcheck side
  until a packet capture exists. That capture is still the stronger form of the
  whole assertion and lands with M3a's netns harness, which is the first point
  there is an interface to capture on.

## Open item for M2 — *settled*

**magicsock will not report its own local endpoints without a DERP map.**
`Conn.setEndpoints` returns early when there is no STUN result *and* no DERP map
("ignoring pre-DERP map, STUN-less endpoint update"). Our design gossips signed
endpoint records, so something must be able to read local endpoints — and M2 is
LAN-only with no relays, so no DERP map exists yet. Either read interface state
directly for the LAN case, or install a DERP map built from member relay roles
as soon as there is one.

*Decided in M2:* read the host's interface addresses directly
(`daemon.underlayEndpoints`), because that is the option that needs no third
party at all, which is what M2's "LAN-only operation with zero internet works"
asks for. Reflexive addresses from disco and member relays arrive at M3b and are
added to that set rather than replacing it. See
[09-mesh-layer-notes.md](09-mesh-layer-notes.md).

M2 also found a second thing the reuse decision costs, in the same area:
without a DERP map there is no fallback path, so the *first* WireGuard handshake
to a new peer is dropped while disco is still establishing one, and WireGuard's
own five-second retry then dominates — ten seconds to first packet on a LAN.
`conn.warmPaths` starts discovery when a peer appears, which brings it to about
seven milliseconds.

## What M3a has to wire

The OS plumbing slice ([05-roadmap.md](05-roadmap.md), M3a). M2 left the data plane
deliberately unplumbed — `conn` passes neither a TUN device nor a router, so the
engine substitutes `tstun.NewFake()` and `router.NewFake()` — and these are the
pieces that removes. Two of them the code is already shaped for; one is missing
outright, and one is not a code change at all.

- **The missing field is `Router`, not `Tun`.** `conn.Options` already carries a
  `Tun tun.Device` for the test harness, and `wgengine.Config` takes
  `Router router.Router` beside it, falling back to `router.NewFake(logf)` when nil.
  Construction order follows `ipnlocal`'s, because `router.New` wants the device and
  the engine wants the router: `netmon.New`, then
  `tun.CreateTUN(name, int(tstun.DefaultTUNMTU()))`, then
  `router.New(logf, tundev, netMon, health, bus)`, then the engine with
  `Config{Tun, Router, NetMon, HealthTracker}`. Share one `netmon.Monitor` rather
  than letting the engine create its own — `Config.NetMon` exists for exactly that —
  and take the MTU from `tstun.DefaultTUNMTU()` rather than picking a number.

- **`reconfig` already runs at the right moments, and is missing `Routes`.**
  `tsManager.reconfig` is called from `New` and from *every* `SetPeers`, and it
  already passes `&router.Config{LocalAddrs: m.self.Addrs}` — a line that has been
  written and dead since M0, because the fake router discards it. A real router makes
  it live and immediately insufficient: `LocalAddrs` puts this node's overlay
  addresses on the interface, but with no `Routes` the host has no reason to send a
  *peer's* address into the tunnel. The route set is the peers' prefixes, read from
  the same `m.state.Load()` snapshot `filter()` already walks, so it costs a loop in
  a function that has the data and runs at the right time. Worth stating because the
  failure mode is quiet and asymmetric: the interface comes up, pings to your own
  overlay address work, and only peer traffic goes nowhere.

- **The DNS configurator stays fake, on purpose.** Naming is deferred post-v1, so
  `Config.DNS` stays nil and `reconfig` keeps passing an empty `dns.Config{}`. This
  is called out because "plumb the overlay into the OS" reads like it includes DNS,
  and wiring `resolved` here would give the daemon a host-wide side effect the
  project has not decided to have.

- **This is where the daemon stops being unprivileged, and that is a property being
  spent.** Everything through M2 runs as an ordinary user; the fake device needs
  nothing, which is why the M0 egress criterion could be met by reading
  `/proc/self/fd`. Creating a TUN needs access to `/dev/net/tun`, and creating it and
  programming addresses and routes both need `CAP_NET_ADMIN`. What widens is the
  daemon's reach over the *host*, not over the *network*: a compromised `juistd`
  still holds no admin keys and still cannot authorize a membership change
  ([04-architecture.md](04-architecture.md), key custody). The smallest form is an
  ambient capability on a dedicated user, not root, and
  [02-threat-model.md](02-threat-model.md) should gain a line naming which of the two
  it assumes.

- **Two real devices do not fit in one namespace.** M2's manual test runs two daemons
  side by side on one host, which works precisely because neither owns an interface.
  With real devices they collide — both want a device, both want the same overlay
  routes — and that, not NAT simulation, is why the netns harness belongs to M3a. It
  starts as the minimum for two nodes on one machine; M3b extends the same harness
  into the NAT matrix. Whether it can run unprivileged in CI via user namespaces
  (`unshare -Ur`, which grants `CAP_NET_ADMIN` inside the new namespace) is worth
  establishing early: if yes the M3a exit criterion is an ordinary CI gate, if no it
  is a manual gate like `fuzz-long`, and that answer shapes how the tests are
  written.

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
the pings coming back. The prerequisite is knowing one's *own* disco private key,
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
present in the pinned tailscale.com v1.102.2**, verified against the module cache.
tailcat pins a v1.103.0-pre, but adopting these techniques needs no upgrade.

### What tailcat does not solve

The preshared key. `grep -rn preshared` over tailcat returns nothing: it runs the
same PSK-less Noise IKpsk2 as stock Tailscale. The open decision above — patch
the vendored engine or defer the PQ data-plane hedge past v1 — is untouched, and
tailcat is evidence that upstream is not about to open that path on its own.

### Where ours differs on purpose

tailcat derives its overlay address from the node key into Tailscale's fixed ULA
`fd7a:115c:a1e0::/48`. juist derives the /48 itself from the genesis hash
(`types/addr.go`), so two juist networks — or a juist network and a Tailscale
tailnet — do not collide on one host. And tailcat bootstraps through
Tailscale-operated public DERP relays with a DERP map fetched from `tailcat.dev`,
which is precisely the trusted third party the architecture rejects. The
mechanism transfers to M3b; the bootstrap does not.
