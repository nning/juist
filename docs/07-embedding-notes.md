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
  `router.Router` wired at engine construction — M2 netns-harness territory; `conn`
  deliberately does not pass one yet.

## Constraints on the test harness

- **`RespondToPing` is IPv4-only.** `wgengine.echoRespondToAll` calls `ICMP4Header()`
  on anything `IsEchoRequest()` matches, so an ICMPv6 echo **panics the engine**. This
  is Tailscale's test scaffolding and no product code depends on it — but it is
  arguably an upstream bug worth reporting. Since our addressing makes the v6 ULA
  primary, the harness sidesteps the scaffolding instead of relying on it: a
  ~100-line fake `tun.Device` that echoes ICMP for both families
  (`conn/echotun_test.go`) asserts v4 *and* v6 reachability today, and exercises the
  full TUN round trip (decrypt → filter → Wrapper.Write → Wrapper.Read → encrypt)
  rather than RespondToPing's engine-internal shortcut. Real TUN devices still
  arrive with the M2 netns harness.
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
  whole assertion and lands with the netns harness.

## Open item for M2

**magicsock will not report its own local endpoints without a DERP map.**
`Conn.setEndpoints` returns early when there is no STUN result *and* no DERP map
("ignoring pre-DERP map, STUN-less endpoint update"). Our design gossips signed
endpoint records, so `conn` must be able to read local endpoints — and M2 is
LAN-only with no relays, so no DERP map exists yet. Either read `netmon` interface
state directly for the LAN case, or install a DERP map built from member relay roles
as soon as there is one. Resolves itself at M3; needs a decision at M2.
