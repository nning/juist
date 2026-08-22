# 04 — Architecture

Daemon: `wgp2pd`. CLI: `wgp2p`. (Working names.)

## Layering — what is trusted for what

```
┌────────────────────────────────────────────────────────────┐
│ TRUST LAYER (the TCB — small, new, audited)                │
│   membership log (TKA-adapted) · quorum multi-sig ·        │
│   epoch group secret · freshness leases · enrollment       │
├────────────────────────────────────────────────────────────┤
│ SYNC LAYER (self-certifying data, untrusted transports)    │
│   gossip anti-entropy · log-head beacons · DHT · mDNS      │
├────────────────────────────────────────────────────────────┤
│ CONNECTIVITY LAYER (reused, not trust-critical)            │
│   magicsock/disco · member relays (DERP) · netmap adapter  │
├────────────────────────────────────────────────────────────┤
│ DATA PLANE (reused, authenticates everything above nothing)│
│   wireguard-go (Tailscale fork) · cryptokey routing        │
└────────────────────────────────────────────────────────────┘
```

Rule: layers below the trust layer can delay or deny connectivity; they can never
change who is a member or read/alter traffic. WireGuard's cryptokey routing enforces
this at the bottom — a peer not configured from log state cannot exchange a single
data packet, and an overlay IP is bound to a 256-bit key, not to anything the
connectivity layer says.

## Decision: reuse Tailscale's magicsock/wgengine (synthetic netmap)

The fork in the road was (a) drive Tailscale's `wgengine`/`magicsock` with a synthetic
`netmap.NetworkMap` built from our log state, vs. (b) write a minimal disco-style
connection manager over plain wireguard-go / kernel WireGuard.

**Chosen: (a).** Rationale:

- **NAT-traversal quality is where ease-of-use lives** (priority 2), and
  magicsock/disco is the best-tested traversal stack in existence (~90 %+ direct
  connections, birthday-search against hard NAT, DERP fallback, active upgrade).
  Reimplementing it is years of subtle failure modes.
- **It does not grow the trust TCB.** Disco/relay bugs cost availability or metadata,
  never membership integrity or traffic confidentiality (WireGuard authenticates
  end-to-end below it). Reused, production-fuzzed parsing code is *safer* than new
  parsing code of our own.
- The coupling to Tailscale types is manageable: `magicsock` consumes a
  `NetworkMap`/DERP-map and disco keys; `wgengine` takes WG configs. We write an
  **adapter** (`conn/netmapper`) that renders our log state into those types. We do
  **not** use `tsnet`/`controlclient`/`ipn` (those assume a coordination server).
- **Consequences accepted:** (1) we pin/vendor a Tailscale release and absorb internal
  API churn at upgrade time — the adapter is the only file that touches their types;
  (2) magicsock is a userspace UDP bind, so the data plane is **wireguard-go on all
  platforms in v1** (Android requires it anyway). Kernel WireGuard (Linux netlink,
  FreeBSD if_wg) becomes a **post-v1 optimization** for nodes with static public
  endpoints, where no traversal is needed. Performance is priority 3; Tailscale's
  wireguard-go fork with batching is more than adequate for 25–100 nodes.
- The adapter is built behind a narrow internal interface (`conn.Manager`) so a
  from-scratch minimal manager remains a swap-in option if the fork burden ever
  outweighs the benefit.

## Module map

| Package | Responsibility | Reuses | New trust-critical code |
|---|---|---|---|
| `types` | Node identity (Ed25519), record schemas, deterministic CBOR wire encoding | — | ~500 LOC (schema validation) |
| `trust/log` | Membership log: AUM chain, k-of-n quorum verification, checkpoints, fork choice, address-collision validation | `tailscale.com/tka` (adapted/vendored) | ~2–3 k LOC (P2P additions: fork choice, freshness, validation rules) |
| `trust/secrets` | Epoch group secret: HPKE fan-out, derivations (blinded topic IDs, discovery AEAD keys, ML-KEM per-pair PSKs) | stdlib `crypto/ecdh`, `crypto/mlkem`, HPKE lib | ~1 k LOC |
| `trust/store` | Persisted log, highest-seen epoch (rollback protection), key material | — | ~1 k LOC |
| `enroll` | Invite issue/redeem: QR full-entropy token path; wormhole-code + SPAKE2 path; join state machine → AddNode AUM | SPAKE2 impl (minimal, vetted) | ~1.5 k LOC |
| `gossip` | Anti-entropy AUM/endpoint-record sync; log-head beacons; fork alarm | — | ~1–2 k LOC (records self-certifying; transport untrusted) |
| `discovery/dht` | BEP 44 publish/lookup, blinded topics, AEAD payloads | `anacrolix/dht` | ~800 LOC, **not** TCB (trust-free) |
| `discovery/mdns` | Blinded LAN beacons | stdlib/mdns lib | ~300 LOC, not TCB |
| `conn` | Log state → synthetic netmap → magicsock/wgengine; DERP map from member relay roles | `magicsock`, `wgengine`, `netcheck`, `portmapper` (vendored Tailscale) | glue ~1–2 k LOC, not TCB |
| `relay` | Embedded DERP server on relay-capable members, **membership-authenticated** (client keys checked against log) | `derp`/`derphttp` server | ~500 LOC glue |
| `daemon` | Reconciliation loop (log state ⇒ WG config ⇒ netmap), lifecycle, IPC server | — | reconciler is TCB-adjacent (~800 LOC) |
| `cli` | `init`, `invite`, `join`, `ls`, `revoke`, `rotate`, `heartbeat`, `status` | — | thin |

New trust-critical code target: **≈ 7–9 k LOC** — a realistic external-audit scope.
Everything else is glue around production-tested imports.

## Log schema (extends TKA's AUM set)

Record types, all hash-chained, all carrying signer IDs + signatures:

- `Genesis` — network name, ULA /48 (derived from genesis hash), initial admin keys +
  vote weights, quorum policy k, disablement-secret hashes, initial epoch secret
  (HPKE-wrapped).
- `AddNode` / `RemoveNode` — node identity key, WG pubkey, ML-KEM pubkey, derived v6
  (validated collision-free), optional explicit v4, roles (`relay-capable`, `admin`,
  `exit-node`), advertised routes, expiry. RemoveNode **must** carry an epoch bump
  (new HPKE-wrapped group secret for survivors).
- `SetNodeRoutes` — grants or withdraws a node's `exit-node` role and the set of
  prefixes it may forward for. Quorum-signed like any other authority change: a node
  can never self-assert a route, and route state is read only from the log, never from
  anything a peer advertises over the wire. Validation is enforced from M1 even though
  nothing consumes routes until M7:
  - advertised prefixes **must not overlap** the network's own overlay space (the
    genesis-derived ULA /48, or the 100.64/10 v4 range) — otherwise a route grant
    could hijack overlay destinations and intercept member-to-member traffic;
  - `0.0.0.0/0` and `::/0` are legal only in combination with the `exit-node` role,
    which exists to make a full-tunnel grant explicit and separately revocable;
  - overlapping advertisements from several nodes are legal (failover); the reconciler
    picks one, and that choice is local, not consensus.
- `RotateNodeKey` — new WG/ML-KEM key, signed by the node's identity key **and**
  admin policy; `RotateIdentity` requires quorum.
- `AddAdminKey` / `RemoveAdminKey` / `Checkpoint` — as in TKA; checkpoints are
  quorum-signed compactions that also settle ordering.
- `FreshnessLease` — quorum-signed (or delegated-signer) statement "head H at time T";
  not chained into the log (high frequency), but references the head. TTL default
  48 h; acceptors fail closed.

Fork choice: between checkpoints, concurrent non-conflicting AUMs order by ascending
AUM hash; **conflicting records never auto-resolve except revocations, where
"revoked wins"** (safety bias); any true fork (two heads, neither an ancestor, with
conflicting membership) raises a persistent alarm requiring admin action. Nodes never
accept a chain that lowers their persisted epoch or drops a checkpoint they hold.

## Gossip & sync

- **Beacons:** every disco keepalive/pong and every gossip message carries
  `(epoch, truncated log-head hash)`. Mismatch ⇒ pull sync: exchange heads, walk back
  to common ancestor, transfer missing AUMs (bounded batch). AUMs are self-certifying,
  so they may arrive over *any* transport — WG tunnels (normal case), the enrollment
  channel, even DHT-published head pointers.
- **Schedule:** push new locally-authored AUMs to all reachable members immediately;
  periodic anti-entropy with a random member every 2–5 min; full sync on daemon start.
- **Offline catch-up:** a node returning after a week contacts cached endpoints + DHT,
  syncs before the reconciler will bring tunnels up if its state is past TTL
  (fail-closed startup gate).
- **Convergence math:** at n ≤ 100, epidemic push/pull converges in seconds while any
  path of fresh members exists; revocation latency is gossip convergence for reachable
  nodes and ≤ TTL for partitioned ones.

## Connectivity

- Every member gets a disco key; the netmap adapter renders members ⇒ netmap peers.
- **DERP map = members with `relay-capable` role** (from the log), each running the
  embedded, membership-authenticated derper. Warn at <2 relay-capable members. Public
  untrusted STUN may supplement reflexive-address discovery; member disco reflection
  is primary.
- Endpoint records (current reflexive addrs) are signed by the node's identity key,
  gossiped, and cached persistently for cold start.

## Exit nodes and subnet routes (v1.1 — schema reserved in v1)

Not in v1. The connectivity and data-plane pieces come almost free from the `wgengine`
reuse decision; the new work is policy plumbing and the privileged helper.

**Must not ship before coarse ACLs.** Who may *use* an exit node is an access-control
question (Tailscale expresses it as `autogroup:internet`). With no policy layer, the
`exit-node` role would mean "every member may route all their internet traffic through
this member's uplink" — an all-or-nothing grant with no way to scope it. Hence the
ordering in [05-roadmap.md](05-roadmap.md): coarse ACLs, then exit nodes.

What changes, layer by layer:

- **Trust layer.** `exit-node` role plus advertised prefixes, granted only by quorum
  (`SetNodeRoutes`) with the no-overlay-overlap rule above. Withdrawal is an ordinary
  log record, so it converges at gossip speed for reachable clients and at the
  freshness TTL for partitioned ones — not instantly, and no single admin can pull an
  exit node offline unilaterally. Same trade-off as every other authority change here.
- **Netmap adapter (`conn`).** The adapter currently derives a peer's `AllowedIPs` and
  the filter's destination set from that peer's own overlay addresses. Both widen to
  include the peer's log-granted routes — and only those.
- **Packet filter.** The exit node must accept packets destined *off* the overlay,
  which the present allow-nothing-outside-local-nets shape rejects by construction. A
  member *without* a grant must keep rejecting them, so this stays a two-sided rule
  like all filtering here: the receiver's filter is the one carrying the security
  weight, since a compromised sender can always ignore its own.
- **Privileged helper.** New duties on the exit node: enable forwarding, install
  NAT/masquerade for overlay sources. On the client: default-route capture (or a
  policy-routing table), LAN and link-local bypass so the local printer keeps working,
  and DNS handling so queries do not leak to the local resolver while the full tunnel
  is up. This is the bulk of the work and it is per-platform (Linux nftables + ip
  rules, FreeBSD pf, Android `VpnService` route/`allowBypass` config).
- **CLI.** `wgp2p exit-node list / use <node> / off` for members; admin-side
  `wgp2p route grant|revoke`, which emits a quorum-signed `SetNodeRoutes`.

Excluded even in v1.1: automatic exit-node selection, per-destination split tunneling
beyond the LAN bypass, and exit-node chaining.

## Local security architecture

Both surveyed local-API CVEs in this space (Tailscale CVE-2022-41924: DNS rebinding →
localhost TCP LocalAPI → RCE; NetBird GHSA-qcpp-8vwj-hhwr: 0666 unix socket → root)
are the same lesson: **the local API is the most-exploited surface.** Rules:

- **No TCP listener, ever.** IPC is a unix socket, mode 0600, owner root or a
  dedicated group, in `/run/wgp2p/`; peer identity verified via `SO_PEERCRED`
  (Linux) / `LOCAL_PEERCRED` (FreeBSD). Admin operations additionally require the
  CLI to hold the admin key — the daemon never holds admin signing keys.
- **Privilege separation:** TUN creation + route/config in a small privileged helper
  (or granted via `CAP_NET_ADMIN` on the service); the daemon body (parsers, gossip,
  DHT — the code facing attacker input) runs unprivileged. Android: VpnService
  sandbox, in-process API only. Exit-node support (v1.1) widens this helper to
  forwarding, NAT and policy routing, so its input must stay a validated route set
  derived from log state — never free-form rules passed down by the daemon.
- **Key custody:** node identity key sealed at rest (Linux: kernel keyring/TPM2 where
  present; Android: Keystore for the identity key — WG keys must live in app memory
  for wireguard-go; FreeBSD: 0600 state file, document geli). Admin keys live in the
  admin's CLI keystore (or hardware key, roadmap), *never* in the daemon.
- **State integrity:** log + highest-epoch persisted with fsync before any action
  depends on them; state file corruption ⇒ refuse to start with recovery instructions,
  never silently re-genesis.
- **Parser hygiene:** every externally-supplied input (AUM bytes, gossip frames, DHT
  payloads, invite strings) has a fuzz target from the milestone it is introduced.

## Data plane details

- wireguard-go (Tailscale fork) on all platforms in v1; kernel WG post-v1 for
  public-endpoint nodes.
- Per-pair PSK: `HKDF(ML-KEM-768 encap between the pair's log-recorded static PQ keys,
  epoch)` — post-quantum harvest-now-decrypt-later hedge using stdlib `crypto/mlkem`.
  Rotated on epoch bump via WG reconfig (next handshake picks it up; tunnels stay up).
- Addressing: v6 ULA `fd<40 bits from genesis hash>::/48`, host bits =
  `truncate(SHA-256(identity pubkey))`; v4 100.64/10 assigned explicitly in AddNode.
  The log validator rejects collisions deterministically on every node.
