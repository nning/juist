# 04 — Architecture

Daemon: `juistd`. CLI: `juist`.

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
  **adapter** (`conn`, chiefly `tsmanager.go`) that renders our log state into those types. We do
  **not** use `tsnet`/`controlclient`/`ipn` (those assume a coordination server).
- **Consequences accepted:** (1) we pin/vendor a Tailscale release and absorb internal
  API churn at upgrade time — `conn` is the only package that touches their types,
  besides the relay's derper and STUN;
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
| `trust/log` | Membership log: AUM chain, k-of-n quorum verification, checkpoints, fork choice, address-collision validation | TKA's *design*, not its code — see [08-trust-layer-notes.md](08-trust-layer-notes.md) | ~2–3 k LOC (P2P additions: fork choice, freshness, validation rules) |
| `trust/secrets` | Epoch group secret: HPKE fan-out, derivations (blinded topic IDs, discovery AEAD keys, ML-KEM per-pair PSKs) | stdlib `crypto/ecdh`, `crypto/mlkem`, HPKE lib | ~1 k LOC |
| `trust/store` | Persisted log, highest-seen epoch (rollback protection), key material | — | ~1 k LOC |
| `trust/enroll` | Invite issue/redeem: full-entropy link and wormhole-style code, both over SPAKE2 (RFC 9382); join protocol → AddNode AUM; see [11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md) | `filippo.io/edwards25519` | ~0.9 k LOC |
| `gossip` | Anti-entropy AUM/endpoint-record sync; log-head beacons; fork alarm | — | ~1–2 k LOC (records self-certifying; transport untrusted) |
| `discovery/dht` | BEP 44 publish/lookup, blinded topics, AEAD payloads | `anacrolix/dht` | ~800 LOC, **not** TCB (trust-free) |
| `discovery/mdns` | Blinded LAN beacons | stdlib/mdns lib | ~300 LOC, not TCB |
| `conn` | Log state → synthetic netmap → magicsock/wgengine; DERP map from member relay roles | `magicsock`, `wgengine`, `netcheck`, `portmapper` (vendored Tailscale) | glue ~1–2 k LOC, not TCB |
| `relay` | Embedded DERP server on relay-capable members, **membership-authenticated** (client keys checked against log) | `derp`/`derphttp` server | ~500 LOC glue |
| `daemon` | Reconciliation loop (log state ⇒ WG config ⇒ netmap), lifecycle, IPC server | — | reconciler is TCB-adjacent (~800 LOC) |
| `internal/host` | The inviting half of an enrollment: listener, LAN answers, DHT rendezvous, serial sessions; asks an admitter (the CLI) for every signature | — | not TCB (holds no key) |
| `cli` | `create`, `invite`, `join`, `status`, `devices`, `remove`, `rotate`; for admins `grant`, `revoke`, `approve`, `apply`, `admins`, `log`. Holds the admin keys and a per-network anchor; signs only what it rebuilt from its own verified log | — | thin |

New trust-critical code target: **≈ 7–9 k LOC** — a realistic external-audit scope.
Everything else is glue around production-tested imports.

## Log schema (extends TKA's AUM set)

Record types, all hash-chained, all carrying signer IDs + signatures:

- `Genesis` — network name, ULA /48 (derived from genesis hash), initial admin keys +
  vote weights, quorum policy k, disablement-secret hashes, initial epoch secret
  (HPKE-wrapped).
- `AddNode` / `RemoveNode` — node identity key, WG pubkey, X25519 + ML-KEM pubkeys,
  derived v6 (validated collision-free), optional explicit v4, roles
  (`relay-capable`, `admin`, `exit`), advertised routes, expiry. **Every**
  record that changes the member set or a member's keys carries an epoch bump whose
  wrap set covers exactly the resulting member set — stricter than "RemoveNode must",
  and what makes a quiet lockout or a leak to a non-member detectable
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)).
- `SetNodeRoutes` — grants or withdraws a node's `exit` role and the set of
  prefixes it may forward for. Quorum-signed like any other authority change: a node
  can never self-assert a route, and route state is read only from the log, never from
  anything a peer advertises over the wire. Validation is enforced from M1 even though
  nothing consumes routes until M6:
  - advertised prefixes **must not overlap** the network's own overlay space (the
    genesis-derived ULA /48, or the overlay v4 ranges of the network's schema) — otherwise a route grant
    could hijack overlay destinations and intercept member-to-member traffic;
  - `0.0.0.0/0` and `::/0` are legal only in combination with the `exit` role,
    which exists to make a full-tunnel grant explicit and separately revocable;
  - overlapping advertisements from several nodes are legal (failover); the reconciler
    picks one, and that choice is local, not consensus.
- `RotateNodeKey` — new WG/X25519/ML-KEM keys, signed by the node's identity key
  **and** admin policy; `RotateIdentity` requires quorum plus a signature by the new
  key (proof some device holds it).
- `AddAdminKey` / `RemoveAdminKey` / `SetQuorum` / `Checkpoint` — admin key ops as in
  TKA, plus a policy change TKA has no equivalent for; checkpoints are quorum-signed
  compactions that also settle ordering, and a checkpoint whose ancestry is known
  must equal the state that ancestry produces.
- `EpochBump` — rotates the group secret with no membership change: the routine tier
  of the two-tier revocation response.
- `RenumberNetwork` / `RenumberNode` / `RetireAddresses` (schema 5) — move the
  network to another v4 prefix with every member to an address in it, or one member
  to another address in the prefix. The address a member leaves stays its own until
  the record's deadline, and the ranges the network leaves with such addresses in
  them stay reserved until a `RetireAddresses` or the next network renumbering: see
  [08-trust-layer-notes.md](08-trust-layer-notes.md#renumbering).
- `RenameNetwork` (schema 6) — gives the network another name. The name is a label;
  the genesis hash is what identifies the network, so nothing else changes.
- `Lease` — an admin device's signed statement "head H at time T", the delegated
  signer being a member the quorum grants the `admin` role; not chained into the
  log (hourly), but references the head. TTL default 48 h, set by the acceptor,
  which fails closed.

Fork choice: between checkpoints, concurrent non-conflicting AUMs order by ascending
AUM hash; **conflicting records never auto-resolve except revocations, where
"revoked wins"** (safety bias); any true fork (two heads, neither an ancestor, with
conflicting membership) raises a persistent alarm requiring admin action. Nodes never
accept a chain that lowers their persisted epoch or drops a checkpoint they hold.

Implemented in `trust/log`; see [08-trust-layer-notes.md](08-trust-layer-notes.md)
for how "conflicting" is decided (an orphaned branch is replayed against the winning
head; a revocation on a losing branch always alarms), and for the two node-local
ratchets — the anchor and the epoch floor — that carry the last sentence.

## Gossip & sync

- **Beacons:** every gossip frame carries `(epoch, log head, anchor)`. Disco
  keepalives do not: magicsock's frames are not ours to extend, and a beacon there
  would ride a channel the sync layer cannot answer on anyway. What M2 built in place
  of walking back to a common ancestor is simpler — each side sends the hash set it
  holds and answers from the *peer's* anchor, which is what keeps sync alive across
  compaction asymmetry (see [09-mesh-layer-notes.md](09-mesh-layer-notes.md)). At a
  few kilobytes of hashes it costs less than the bookkeeping a walk needs;
  `MaxHashesPerFrame` is where that stops being true. AUMs are self-certifying, so
  they may arrive over *any* transport — the underlay at M2, WG tunnels once M3a
  gives them somewhere to run, the enrollment channel, even DHT-published head
  pointers.
- **Schedule:** push new locally-authored AUMs to all reachable members immediately;
  periodic anti-entropy with a random member every 2–5 min; full sync on daemon start.
- **Offline catch-up:** a node returning after a week contacts cached endpoints + DHT,
  syncs before the reconciler will bring tunnels up if its state is past TTL
  (fail-closed startup gate). One that holds no epoch its peers still speak asks for
  a catch-up, granted by identity against the peer's current log
  ([09-mesh-layer-notes.md](09-mesh-layer-notes.md)).
- **Convergence math:** at n ≤ 100, epidemic push/pull converges in seconds while any
  path of fresh members exists; revocation latency is gossip convergence for reachable
  nodes and ≤ TTL for partitioned ones.

## Connectivity

- Every member gets a disco key; the netmap adapter renders members ⇒ netmap peers.
- **DERP map = members with `relay-capable` role** (from the log), each running the
  embedded, membership-authenticated derper. Warn at <2 relay-capable members —
  a floor, not a capacity model: relay demand tracks the number of unpunchable
  *pairs*, so above the 25–100 target the threshold has to become a function of
  member count. Public untrusted STUN may supplement reflexive-address discovery;
  member disco reflection is primary.
- Endpoint records (current reflexive addrs) are signed by the node's identity key,
  gossiped, and cached persistently for cold start.

## Exit nodes and subnet routes (M6)

Planned as M6, with the schema reserved from M1, and built in three steps:
exit nodes (M6a), subnet routers (M6b) and the exit node's DNS (M6c). The connectivity and data-plane
pieces come almost free from the `wgengine` reuse decision; the new work is policy
plumbing and the privileged helper.

**Ships before coarse ACLs, unscoped.** Who may *use* an exit node is an
access-control question (Tailscale expresses it as `autogroup:internet`), and coarse
ACLs come later, at M14 in [05-roadmap.md](05-roadmap.md). Until then the
`exit` role means "every member may route all their internet traffic through
this member's uplink" — an all-or-nothing grant the quorum makes per exit node,
with no way to scope it to some members. Accepted in
[02-threat-model.md](02-threat-model.md) item 7; M14 scopes it.

What changes, layer by layer:

- **Trust layer.** `exit` role plus advertised prefixes, granted only by quorum
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
- **Privileged helper.** New duties on the exit node: forwarding, set once as
  root by a packaged script, since juistd writes no sysctl; masquerade for
  overlay sources, in an nftables table of juistd's own. On the client: a
  policy-routing table behind the host's routes without their default, so the
  LAN and link-local stay direct, and a rule keeping juistd's own traffic
  outside the tunnel; DNS, pointed at the exit node's resolver through
  systemd-resolved over D-Bus, which a polkit rule allows the `juist` user on
  juist's own devices. This is the bulk of the work and it is per-platform (Linux nftables +
  ip rules, FreeBSD pf, Android `VpnService` route/`allowBypass` config).
- **CLI.** `juist exit`, `use NODE`, `off` for members, `serve` for an
  exit node's operator; admin-side `juist grant DEVICE exit`, which emits
  a quorum-signed `SetNodeRoutes` with the role and the default routes, and
  `juist subnet add DEVICE PREFIX` for a subnet, which `juist subnet serve` agrees
  to route.

Excluded at M6: automatic exit node selection, per-destination split tunneling
beyond the LAN bypass, and exit node chaining.

## Local security architecture

Both surveyed local-API CVEs in this space (Tailscale CVE-2022-41924: DNS rebinding →
localhost TCP LocalAPI → RCE; NetBird GHSA-qcpp-8vwj-hhwr: 0666 unix socket → root)
are the same lesson: **the local API is the most-exploited surface.** Rules:

- **No TCP listener, ever.** IPC is a unix socket, and every call is attributed to a
  uid by `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (FreeBSD). The packaged socket lives
  in `/run/juist/`, apart from the state, so reaching it is not reading `node.keys`;
  it is 0666 where the kernel reports callers and 0600 where it cannot. Any local user
  may ask for status; root, the daemon's own user and the one appointed **operator**
  may do everything else; only root and the daemon's own user may appoint. That is
  Tailscale's read/write split (`ipnserver.actor.Permissions`, verified against the
  pinned module) with the read tier narrowed to status, since the member list is an
  asset here. Admin operations additionally require the CLI to hold the admin key —
  the daemon never holds admin signing keys, and in the packaged layout cannot read
  them either: they are in the operator's own keystore.
- **Privilege separation:** TUN creation + route/config in a small privileged helper
  (or granted via `CAP_NET_ADMIN` on the service); the daemon body (parsers, gossip,
  DHT — the code facing attacker input) runs unprivileged. Android: VpnService
  sandbox, in-process API only. Exit-node support (M6) widens this helper to
  forwarding, NAT and policy routing, so its input must stay a validated route set
  derived from log state — never free-form rules passed down by the daemon.
  FreeBSD, which grants no capability for the network alone, has the helper
  (M7a): juistd started as root keeps a process as root that creates, addresses,
  routes and destroys juist's own devices, and runs the daemon as `juist` with
  the device's descriptor (`internal/plumber`).
- **Key custody:** node identity key a 0600 file on Linux and FreeBSD (sealing
  it in the kernel keyring or a TPM is post-v1; FreeBSD: document geli);
  Android: Keystore for the identity key — WG keys must live in app memory for
  wireguard-go. Admin keys live in the admin's CLI keystore (or hardware key,
  roadmap), *never* in the daemon.
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
  The key is in the schema from M1 and consumed for the epoch HPKE fan-out; the
  data plane takes it in M11a ([05-roadmap.md](05-roadmap.md)), the engine's PSK
  path in [07-embedding-notes.md](07-embedding-notes.md).
- Addressing: v6 ULA `fd<40 bits from genesis hash>::/48`, host bits =
  `truncate(SHA-256(identity pubkey))`; v4 assigned explicitly in AddNode, from the prefix
  the network chose at genesis or last renumbered to. `juist create` draws a random
  /22 in 198.18/15 unless told one, so two networks on one host rarely collide; a
  network without a prefix of its own, founded before that, uses all of 198.18/15
  (100.64/10 before schema 4) and numbers from its start, which the draw leaves out.
  No address is handed out twice, so a /22 serves 1022 admissions over the
  network's life; renumbering into a larger prefix makes room. The log validator rejects collisions deterministically on every node,
  counting the addresses renumberings leave. While one is live a member has two v4
  addresses, in its AllowedIPs and on its device, and sends from the old one, which
  every member still accepts; the Linux router pins that as each route's source.
