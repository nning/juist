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

- **NAT-traversal quality is where ease of use lives** (priority 2), and
  magicsock/disco is the best-tested traversal stack there is (~90 %+ direct
  connections, birthday search against hard NAT, DERP fallback, active upgrade).
- **It does not grow the trust TCB.** Disco/relay bugs cost availability or metadata,
  never membership integrity or traffic confidentiality (WireGuard authenticates
  end-to-end below it).
- We do **not** use `tsnet`/`controlclient`/`ipn` (those assume a coordination
  server). The adapter (`conn`, chiefly `tsmanager.go`) renders log state into
  magicsock's netmap and DERP map and wgengine's WireGuard config.
- **Consequences accepted:** (1) we pin a Tailscale release and absorb internal
  API churn at upgrade time ([07-embedding-notes.md](07-embedding-notes.md)); `conn`
  alone drives the engine, the relay runs its derper, and other packages use only
  its utilities (netmon, netns, stun, key types); (2) magicsock is a userspace UDP
  bind, so the data plane is **wireguard-go on all platforms in v1**. Kernel
  WireGuard (Linux netlink, FreeBSD if_wg) is a **post-v1 optimization** for nodes
  with static public endpoints.
- The adapter sits behind a narrow interface (`conn.Manager`), so a minimal manager
  of our own remains a swap-in option.

## Module map

The main packages; [`audit-scope`](../audit-scope) places every package in or out
of the audit, and the Audit column is its placement.

| Package | Responsibility | Reuses | Audit |
|---|---|---|---|
| `types` | Identities (Ed25519 identity, ML-DSA-44 signing key), record schemas, deterministic CBOR, addressing | — | core |
| `trust/log` | Membership log: chain, quorum, checkpoints and compaction, fork choice, alarms, validation | TKA's *design*, not its code — see [08-trust-layer-notes.md](08-trust-layer-notes.md) | core |
| `trust/secrets` | Epoch group secret: hybrid HPKE fan-out, derivations (discovery keys, the seed of the group's preshared keys) | stdlib `crypto/hpke`, `crypto/mlkem` | core |
| `trust/store` | Persisted log, epoch floor, key material | — | core |
| `trust/enroll` | Invites: full-entropy link and typed code, SPAKE2 (RFC 9382) with ML-KEM-768; join → `AddNode`; see [11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md) | `filippo.io/edwards25519` | core |
| `gossip` | Anti-entropy sync of records, announcements, leases and waiting changes; log-head beacons; catch-up | — | in |
| `discovery/dht` | BEP 44 publish/lookup under blinded keys, sealed items | `anacrolix/dht` | out (trust-free) |
| `discovery/mdns` | Blinded LAN beacons | `x/net/dns/dnsmessage` | out (trust-free) |
| `conn` | Log state → synthetic netmap → magicsock/wgengine; DERP map from relay roles; host plumbing | `magicsock`, `wgengine`, `netcheck`, `portmapper` | `confine.go` |
| `relay` | Embedded DERP server on relay-capable members, **membership-authenticated** (client keys checked against the log) | `derp`, `derpserver` | admission, certificate, HTTPS |
| `daemon` | Reconciliation loop (log state ⇒ WireGuard config ⇒ netmap), compaction, lifecycle, IPC server | — | reconciler, compaction, IPC, peercred |
| `internal/host` | The inviting half of an enrollment; asks the CLI for every signature | — | out (holds no key) |
| `cmd/juist` | The CLI, commands in its table in `main.go`. Holds the admin keys and a per-network pin; signs only what it rebuilt from its own verified log | — | changes, pin, rotation, waiting |

The core (`types`, `trust/`) is held to **11 k lines** by `make tcb`; the audit
scope around it is measured ([06-verification.md](06-verification.md) §5).

## Log schema (extends TKA's AUM set)

Record types, all hash-chained, all carrying signer IDs + ML-DSA signatures
(`types/aum.go` has every kind):

- `Genesis` — network name, admin keys + vote weights, quorum k,
  disablement-secret hashes, initial epoch secret (HPKE-wrapped). Its hash names
  the network and derives the ULA /48.
- `AddNode` / `RemoveNode` — node identity key, ML-DSA signing key, WireGuard key,
  X25519 + ML-KEM keys, a v4 address (the v6 one derives from the identity), roles
  (`relay-capable`, `admin`, `exit`, `ingress`, `service`, `publish`), routes,
  expiry. **Every** record that changes the member set or a member's keys carries
  an epoch bump whose wrap set covers exactly the resulting member set, which makes
  a quiet lockout or a leak to a non-member detectable
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)).
- `SetNodeRoutes` — grants or withdraws a node's roles and the prefixes it may
  forward for. Quorum-signed like any other authority change: a node can never
  self-assert a route, and route state is read only from the log, never from
  anything a peer advertises over the wire.
  - advertised prefixes **must not overlap** the network's own overlay space (the
    ULA /48 and its v4 prefix), or a grant could intercept member-to-member traffic;
  - `0.0.0.0/0` and `::/0` are legal only with the `exit` role, which makes a
    full-tunnel grant explicit and separately revocable;
  - overlapping advertisements from several nodes are legal (failover); the
    reconciler picks one, locally.
- `RotateNodeKey` — new WireGuard/X25519/ML-KEM keys, signed by the node **and** the
  quorum; `RotateIdentity` requires quorum plus signatures by the old key and the
  new one.
- `AddAdminKey` / `RemoveAdminKey` / `SetQuorum` / `SetHolder` /
  `SetAdminRecipient` — admin keys, their weights and holders, and the quorum.
- `Checkpoint` — the whole state at a point of the chain, quorum-signed; one whose
  ancestry is known must equal the state that ancestry produces. The admin's CLI
  drafts one every 256 records or 32 MiB, and juistd compacts to them.
- `EpochBump` — rotates the group secret with no membership change: the routine
  tier of the two-tier revocation response.
- `SchemaUpgrade` — raises the schema the network is written under.
- `SetVouchers` — how many admin devices must vouch for a view within the TTL.
- `RenumberNetwork` / `RenumberNode` / `RetireAddresses` — move the network to
  another v4 prefix, or one member to another address in it; see
  [08-trust-layer-notes.md](08-trust-layer-notes.md#renumbering).
- `RenameNetwork` / `RenameNode`, `SetNodeNames` / `SetDomain` / `SetPublished`
  (names and published services), `SetPolicy` (the access policy).
- `Disable` — reveals a break-glass secret the genesis committed to and ends the
  network for good; unsigned, and in effect wherever it hangs.

Not chained: a **lease**, an admin device's signed "head H at time T", hourly; the
TTL (48 h default) is set by the acceptor, which fails closed.

Fork choice between siblings: a branch loses to one that removes an admin key that
signed on it; then a revocation beats a non-revocation; then the lower `SigHash`
wins. An orphan whose substance the winning head no longer admits raises a
persistent alarm requiring admin action; a lost checkpoint raises none. Two
node-local ratchets bound it: resolution never walks past the anchor, and a chain
below the epoch floor is held under a rollback alarm. Implemented in `trust/log`;
[08-trust-layer-notes.md](08-trust-layer-notes.md) has the rules.

## Gossip & sync

- **Beacons:** every gossip frame carries `(epoch, log head, anchor)`; disco
  keepalives do not, since magicsock's frames are not ours to extend.
- **Hellos:** a hello lists the records its sender resolves from its anchor, past
  `MaxHashesPerFrame` the ones nothing hangs from first, and from such a cut-short
  list a peer is taken to hold the ancestors of what it lists. Each side answers from the *peer's* anchor, so
  sync converges whatever the log's size and across compaction
  ([09-mesh-layer-notes.md](09-mesh-layer-notes.md)). From schema 21 a hello
  says what its sender holds of each node's announcement, address key and
  lease, and the answer carries what is newer.
- **Transports:** records are self-certifying, so they may arrive over any
  transport: log sync through the tunnel, an enrollment, a catch-up.
- **Schedule:** a change to the log is pushed at once to `PushFanout`
  members that do not rest and to every one that does, by its author and by
  each member that hears it; another's announcement, address key or lease is
  passed on to those that do not rest alone; a device that rests passes on
  nothing and pushes its own news to two; anti-entropy with a random member
  every 2 min; full sync on daemon start.
- **Compaction:** juistd moves its anchor to the checkpoint before the newest once
  every live member has been heard past the newest, or one has compacted that far,
  and keeps the chain from its previous anchor for those behind
  ([02-threat-model.md](02-threat-model.md) residual weakness 14).
- **Offline catch-up:** a node whose state is past the TTL syncs before the
  reconciler brings tunnels up (fail-closed startup gate). One that holds no epoch
  its peers still speak asks for a catch-up, granted by identity against the
  peer's current log; one further behind than its peers keep is invited again.
- **Convergence:** at n ≤ 100, push/pull converges in seconds while any path of
  fresh members exists; revocation latency is gossip convergence for reachable
  nodes and ≤ TTL for partitioned ones.

## Connectivity

- Every member gets a disco key; the netmap adapter renders members ⇒ netmap peers.
- **DERP map = members with the `relay-capable` role** (from the log), each running
  the embedded, membership-authenticated derper. `juist status` warns where none may
  relay in a network of more than two; a floor, not a capacity model: relay demand
  tracks the number of unpunchable *pairs*, so above the 25–100 target it has to
  become a function of member count. Member disco reflection is primary; public STUN supplements it
  (Google's and Cloudflare's by default).
- Announcements (current reflexive addresses, disco key, relay) are signed by the
  node's ML-DSA key, gossiped, and cached for cold start; discovery carries hints
  signed by its Ed25519 identity alone
  ([02-threat-model.md](02-threat-model.md) residual weakness 13).

## Exit nodes and subnet routes (M6)

Exit nodes (M6a), subnet routers (M6b) and the exit node's DNS (M6c).

**Who may use one is the access policy's.** The `exit` role and a route grant say
who may serve; who may *use* an exit node or a subnet router's prefixes is the
access policy's (M14): `pass from … to internet via …` and `pass from … to PREFIX`,
enforced by the exit node or router, and followed by the client, which routes
nothing through one the policy does not pass. A network without a policy lets every
member use every exit node and subnet
([02-threat-model.md](02-threat-model.md) item 7).

Layer by layer:

- **Trust layer.** `exit` role plus prefixes, granted only by quorum
  (`SetNodeRoutes`) with the no-overlap rule above. Withdrawal is an ordinary log
  record: gossip speed for reachable clients, the freshness TTL for partitioned
  ones, and no single admin can pull an exit node offline.
- **Netmap adapter (`conn`).** A peer's `AllowedIPs` and the filter's destinations
  are its overlay addresses plus its log-granted routes, and only those.
- **Packet filter.** Two-sided like all filtering here: a member without a grant
  rejects packets destined off the overlay, and the receiver's filter carries the
  security weight, since a compromised sender can ignore its own.
- **Host plumbing.** On the exit node: forwarding, set once as root by
  `packaging/exit-node.sh`, since juistd writes no sysctl; masquerade for overlay
  sources, in an nftables table of juistd's own. On the client: a policy-routing
  table behind the host's routes without their default, so the LAN and link-local
  stay direct, and a rule keeping juistd's own traffic outside the tunnel; DNS
  pointed at the exit node through systemd-resolved over D-Bus, which a polkit rule
  allows the `juist` user. Per platform: Linux nftables + ip rules, FreeBSD pf
  through the root helper, Android `VpnService`.
- **CLI.** `juist exit use DEVICE`, `off`, and `serve` for an exit node's operator;
  `juist grant DEVICE exit` for admins; `juist subnet add DEVICE PREFIX`, which
  `juist subnet serve` agrees to route.

Excluded: automatic exit node selection, per-destination split tunneling beyond the
LAN bypass, and exit node chaining.

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
  Tailscale's read/write split (`ipnserver.actor.Permissions`) with the read tier
  narrowed to status, since the member list is an asset here. Admin operations
  require the CLI to hold the admin key — the daemon never holds admin signing keys,
  and in the packaged layout cannot read them: they are in the operator's own
  keystore.
- **Privilege separation:** on Linux the daemon runs as `juist` with
  `CAP_NET_ADMIN` alone, and `CAP_NET_BIND_SERVICE` beside it on a relay named on
  443 (M13), by a drop-in root's `juist set --relay-name` writes through
  `packaging/relay.sh`. FreeBSD, which grants no
  capability for the network alone, keeps a root helper (`internal/plumber`) that
  creates, addresses, routes and destroys juist's own devices, writes its pf
  anchors and binds 443, and runs the daemon as `juist` with the device's
  descriptor. The helper's input is a validated route set derived from log state,
  never free-form rules from the daemon. Android: VpnService sandbox, in-process
  API only. [02-threat-model.md](02-threat-model.md) says what a compromised daemon
  can still do.
- **Key custody:** node keys in a 0600 file on Linux and FreeBSD (kernel keyring or
  TPM is post-v1; FreeBSD: document geli); on Android sealed under an AES key
  Android Keystore holds, in StrongBox where there is one. Admin keys live in the
  admin's CLI keystore, *never* in the daemon.
- **State integrity:** log + epoch floor persisted with fsync before any action
  depends on them; state file corruption ⇒ refuse to start, never silently
  re-genesis.
- **Parser hygiene:** every externally supplied input has a fuzz target; M25 adds
  those still missing ([06-verification.md](06-verification.md) §2).

## Data plane details

- wireguard-go (Tailscale fork) on all platforms in v1; kernel WireGuard post-v1 for
  public-endpoint nodes.
- Per-pair PSK (M15, `internal/pairkey`): first a group key from the group
  secret of the lower of the pair's two epochs, then a key of the pair's own,
  HKDF over an ML-KEM-768 encapsulation each way to the pair's log-recorded
  keys, salted with the group key — the harvest-now-decrypt-later hedge. Renewed at
  every rise of the pair's epoch through log sync; the next handshake picks it up
  and tunnels stay up. The exchange's rules and the engine's PSK path are in
  [07-embedding-notes.md](07-embedding-notes.md).
- Addressing: v6 ULA `fd<40 bits from genesis hash>::/48`, host bits =
  `truncate(SHA-256(identity pubkey))`; v4 assigned explicitly in `AddNode`, from the
  prefix the network chose at genesis or last renumbered to. `juist create` draws a
  random /22 in 198.18/15 unless told one; a network without a prefix of its own
  uses all of 198.18/15. No address is handed out twice, so a /22 serves 1022
  admissions over the network's life; renumbering into a larger prefix makes room.
  The log validator rejects collisions deterministically on every node, counting
  the addresses renumberings leave. While one is live a member has two v4
  addresses, in its AllowedIPs and on its device, and sends from the old one, which
  every member still accepts; the Linux router pins that as each route's source.
