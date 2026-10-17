# Research appendix — Building blocks for a fully-P2P WireGuard control plane

*Compiled Aug 2026; maturity/status claims verified against live sources at that time.
Structure: per block — what it provides / security properties & caveats / maturity /
Rust & Go libraries.*

**Since decided otherwise** (the recommendations below stay as researched):

- tka is followed as a design, not imported
  ([08-trust-layer-notes.md](../08-trust-layer-notes.md)).
- Every signature is ML-DSA-44 since M17/M18, not Ed25519 with PQ cosigning
  later ([02-threat-model.md](../02-threat-model.md), residual weakness 13).
- Freshness leases are signed by admin devices, M of them required
  (`juist admins vouchers`), not by the quorum; the TTL defaults to 48 h.
- The log head rides gossip frames, not disco keepalives
  ([04-architecture.md](../04-architecture.md)).
- The DHT blinds the item's key, not a topic ID
  ([10-connectivity-notes.md](../10-connectivity-notes.md)).
- IPv4 is assigned in the log from the network's prefix, by default a /22 in
  198.18/15, not from 100.64/10.
- wireguard-go on every platform in v1, kernel WireGuard after it; a pair's PSK is
  first a group key, then a key of the pair's own from ML-KEM-768 encapsulations
  (M15), so the group secret seeds a pair's first PSK, though the WireGuard
  handshake holds without it.
- The residual weaknesses juist accepts are those of
  [02-threat-model.md](../02-threat-model.md).

## 1. Signed append-only membership logs

### Tailscale tailnet lock (TKA) — the deployed prior art

- **Design**: Each participating node holds a *tailnet lock key* (TLK, Ed25519); node
  keys are only trusted if signed by a TLK. State lives in the **Tailnet Key
  Authority**: a hash-chained log of **AUMs (Authority Update Messages)** — `AddKey`,
  `RemoveKey`, `Checkpoint`, `DisableNL`, `NoOp`. Each AUM references the hash of its
  parent, so the log is an append-only chain; clients verify the chain independently,
  and the (untrusted) coordination server is demoted to a dumb transport that cannot
  inject nodes. Keys carry **vote weights**; destructive operations (key removal,
  disablement) require signatures summing to a majority of votes — i.e., **plain
  multi-signature with policy checked at verification time, no threshold crypto**.
- **Disablement/recovery**: at initialization, hashes of ~10 random "disablement
  secrets" are committed into the authority; revealing any one preimage authorizes
  turning the lock off (`DisableNL`). Lose all secrets → "the tailnet cannot be
  recovered" (their words). This is the honest answer to "how do you recover a quorum
  system": pre-committed break-glass preimages. GA as of late 2025, requires ≥1.46.1,
  max 20 signing nodes. Verified: https://tailscale.com/kb/1226/tailnet-lock
- **Caveats**: TKA still assumes the coordination server for *ordering and
  distribution* of AUMs — it prevents forgery, not split-view (the server could show
  different chains to different nodes until they gossip). In a fully-P2P design you
  must supply ordering/anti-fork yourself. Forks from concurrent AUMs need a resolution
  rule (TKA uses server ordering; you'd need deterministic fork choice + quorum
  checkpoints).
- **Library**: the `tka` package inside `github.com/tailscale/tailscale` (BSD-3) is
  importable Go and battle-tested in production — arguably the single most valuable
  off-the-shelf artifact for this whole project. No Rust equivalent; the design is
  small enough to reimplement (~2-3k LOC) but reimplementation is where security bugs
  live.

### Key transparency (CONIKS, SEEMless, Google/Apple KT, WhatsApp AKD)

- **What it solves**: auditing an *untrusted directory operator* serving millions of
  users who each see only their own slice — VRF-privatized sparse Merkle trees, epochs,
  third-party auditors, append-only proofs (CONIKS USENIX Sec'15; SEEMless CCS'19;
  Parakeet NDSS'23).
- **Does it matter for a small closed network? Mostly no.** If every member replicates
  and fully validates the entire signed log, every member *is* the auditor; the
  Merkle/VRF machinery buys nothing. The one property to *borrow* from KT is
  **split-view / fork-consistency detection**: gossip log heads between members over
  independent paths (and embed the current head hash in your discovery/disco messages)
  so no one can be held on a stale or forked chain silently. That's a few lines, not a
  KT system.
- **Library note**: if you did want SEEMless-style machinery, Meta's `akd` crate (Rust,
  ECVRF RFC 9381 + sparse Merkle, NCC-audited Aug 2023, production in WhatsApp) exists:
  https://github.com/facebook/akd. Overkill here.

## 2. Threshold admin keys: FROST vs. plain multi-sig

### FROST (RFC 9591, published July 2024)

- **Provides**: k-of-n Schnorr/Ed25519 signing where the output is a *single ordinary
  signature*; RFC 9591 FROST(Ed25519,SHA-512) signatures verify under standard
  Ed25519 — verifiers need zero new code.
- **Caveats (significant)**:
  - RFC 9591 covers **signing only; DKG is out of scope**. You need trusted-dealer
    keygen (single point of compromise at ceremony) or PedPoP-style DKG (interactive,
    more protocol surface).
  - Two-round interactive signing needs a coordinator/broadcast; nonce (commitment)
    misuse or share leakage is catastrophic, as with all Schnorr.
  - **Accountability loss**: a threshold signature hides *which* k admins signed. For a
    security-first audit log this is an anti-feature — you want attributable
    signatures.
  - Share revocation/rotation of an individual admin requires a resharing protocol,
    vs. just removing a key from the log.
- **Maturity**: Rust: `ZcashFoundation/frost` (frost-ed25519 etc.) — NCC Group audited
  v0.6.0 (core + all main ciphersuites; DKG per FROST20 included, "partially audited",
  SemVer-stable): https://github.com/ZcashFoundation/frost, https://frost.zfnd.org/.
  Go: `bytemare/frost` (RFC 9591, multiple groups, no known third-party audit) and
  `taurushq-io/frost-ed25519` (Taurus, pre-RFC, decent quality):
  https://github.com/bytemare/frost, https://github.com/taurushq-io/frost-ed25519.

### Plain n-of-m multi-signature in the log

Each admin has an independent Ed25519 key listed (with weight) in the log; a
membership-change record is valid iff it carries ≥k distinct valid signatures. No DKG,
no interaction, no resharing; individually revocable, fully attributable; cost is
k×64 bytes per record (irrelevant at this scale). This is what TKA ships.

**Verdict: plain multi-sig is the prudent choice.** FROST's only real advantages —
constant-size signatures and hiding the signer set — are worthless or harmful here, and
it adds an interactive protocol, DKG, and a young library to the TCB. Use FROST only if
some *external* verifier must see a single Ed25519 key (not our situation).

## 3. Group membership / key agreement: is MLS the tool?

- **MLS (RFC 9420)** gives continuous group key agreement with forward secrecy and
  post-compromise security, O(log n) rekey via TreeKEM, epochs with defined add/remove
  semantics — on paper a perfect match for "network-wide rekey after revocation."
- **Why it's overkill/misfit here**:
  - MLS assumes a **Delivery Service** that provides ordered broadcast of handshake
    messages; concurrent commits fork the group. In a fully-P2P setting you must build
    consensus/ordering anyway — at which point you already have the signed log, and MLS
    is a second, much larger state machine (~130-page RFC) layered on top.
  - The heavy properties (per-message FS/PCS) protect *message content*. The content
    plane is WireGuard, which already has its own handshake, FS, and rekeying. The
    group secret in this design only gates **discovery/rendezvous and gossip
    confidentiality** — a far weaker requirement.
  - Go ecosystem is effectively empty (cisco/go-mls is pre-RFC and unmaintained); Rust
    is fine but adds a big dependency.
- **Cheap replacement, adequate for tens-to-hundreds of nodes**: an **epoch-numbered
  group secret** distributed by encrypting it pairwise to each member's static key
  (HPKE, RFC 9180) as part of a signed log record. Revocation ⇒ bump epoch, re-encrypt
  to survivors, revoked node can no longer decrypt discovery traffic. O(n) per rekey —
  trivial at this scale. PCS is obtained by rotating member static keys via the log.
- **Maturity if you do want MLS**: Rust `openmls` — third-party audit by SRLabs
  (sponsored by Sovereign Tech Agency; 8 findings, 1 high, fixed in 0.7.3/0.8.1):
  https://blog.phnx.im/openmls-independent-security-audit/,
  https://github.com/openmls/openmls. AWS `mls-rs` — 100% RFC-conformant, explicitly
  **not** third-party audited: https://github.com/awslabs/mls-rs.

**Verdict: skip MLS.** Signed log + epoch group secret via HPKE fan-out is smaller,
auditable, and sufficient. Revisit MLS only if an E2E group-messaging channel between
admins is added.

## 4. PAKE-based enrollment / pairing

- **The Magic Wormhole pattern is the state of the art for human-typed invites**: a
  short single-use code (`7-crossover-clockwork`: channel id + ~16 bits of word
  entropy) bootstraps **SPAKE2**; a wrong guess kills the code, so an online attacker
  gets exactly one guess per issued invite and failure is *detectable* (fail-loud).
  Security does not rest on code entropy being high — only on single-use +
  one-guess-per-run. Ideal flow: admin issues invite code → new device runs PAKE with
  any member over the rendezvous layer → inside the PAKE-protected channel the device
  submits its WG pubkey + node metadata → admins sign an AddNode record into the log.
- **Protocol choices (verified status)**:
  - **SPAKE2**: RFC 9382 (informational, 2023). Fine, widely copied from Magic
    Wormhole.
  - **CPace**: CFRG's *recommended* balanced PAKE, but **still an Internet-Draft**
    (draft-irtf-cfrg-cpace-21, expires Oct 2026, not yet an RFC):
    https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/. Cleaner than SPAKE2; draft
    status is a paperwork caveat, not a security one.
  - **OPAQUE**: now **RFC 9807 (July 2025)** — but it's an *augmented* client-server
    PAKE for password databases; wrong shape for symmetric device pairing. Don't use it
    here. https://datatracker.ietf.org/doc/rfc9807/
- **QR enrollment**: if a camera/screen is available you don't need a PAKE at all — the
  QR can carry a full-entropy value (the new device's pubkey + a 256-bit invite token +
  rendezvous hints). PAKE exists to compensate for *low-entropy human channels*; use QR
  (full entropy, no PAKE) when possible, wormhole-style codes as fallback. This is what
  modern pairing (e.g., mobile device setup flows) converged on.
- **Libraries**: Rust `magic-wormhole` 0.8.1 (May 2026, actively maintained, EUPL):
  https://github.com/magic-wormhole/magic-wormhole.rs; Rust `spake2` (warner;
  unaudited), `opaque-ke` (Meta, NCC-audited 2021 for WhatsApp, tracks RFC 9807):
  https://github.com/facebook/opaque-ke; jedisct1's small `cpace` crate. Go:
  `psanford/wormhole-william` (wormhole-compatible), `bytemare/opaque`;
  `schollz/pake` (used by croc) has a patchy security history — avoid. Rust is clearly
  stronger here. Caveat applying to all: PAKE-level libs other than
  opaque-ke/magic-wormhole are mostly unaudited — keep the PAKE's job minimal
  (bootstrap one channel, then hand off to signed-log verification).

## 5. The revocation problem in decentralized systems

- **Fundamental limit (cannot be engineered away)**: a node partitioned from all
  honest, up-to-date members *cannot learn* of a revocation. Its only sound options are
  (a) keep trusting stale state (fail-open) or (b) stop trusting state older than TTL
  (fail-closed, i.e., self-DoS under partition). This is CAP applied to trust; every
  design picks a point on that line. Rivest formalized the principle in "Can We
  Eliminate Certificate Revocation Lists?" (1998): recency requirements are set by the
  *acceptor*; the modern Web-PKI trend to ever-shorter cert lifetimes (Let's Encrypt
  6-day certs) is the same idea deployed at scale.
- **Standard mitigation stack (use all of them)**:
  1. **Monotonic epoch counter** on network state; nodes never accept a lower epoch,
     and record the highest seen (persisted) — kills rollback.
  2. **Freshness leases**: quorum (or any designated set) periodically co-signs a
     "state head as of time T" heartbeat; peers refuse to *initiate/accept new tunnels*
     against state older than TTL (e.g., 24-72 h). Tunable knob: TTL = max revocation
     latency = max survivable partition.
  3. **Anti-entropy gossip**: revocation records are self-certifying (signed), so
     accept them from *any* transport, even untrusted; epidemic push/pull converges in
     O(log n) rounds. Piggyback the current log head hash on every disco/keepalive so
     any contact with any fresh node propagates revocation.
  4. **Rekey on revoke**: bump group epoch (block #3) so a revoked node also loses
     *discovery* — it can't even find members to exploit stale trust; and actually
     remove the peer from WireGuard configs (revocation must reach the data plane, not
     just the trust database).
  5. **Two-tier response**: routine removal (lazy, gossip-converged) vs. key-compromise
     emergency (epoch bump + all-node re-verify + optionally forced re-handshake of all
     tunnels).
- **Prior art done well**: TKA (above); **KERI** (Key Event Receipt Infrastructure —
  per-identity append-only key-event logs with witness receipts; academically
  interesting, ecosystem immature/ID-community-flavored); SPKI/SDSI (delegation certs
  with validity windows); CRLite/OCSP-must-staple (push proofs of freshness to the
  verifier); Nebula (CA-signed certs + distributed blocklists, but relies on
  out-of-band blocklist distribution, i.e., same gossip problem). Nothing beats
  TTL+gossip+epoch in practice; academia agrees the partition limit is fundamental.

## 6. Rendezvous / discovery without trusted servers

- **BitTorrent mainline DHT** (BEP 5, ~8-10M nodes): no operator, hard to kill.
  **BEP 44** stores signed mutable data (Ed25519, monotonic `seq`, ≤1000 bytes) —
  enough to publish an encrypted endpoint hint or even the current log-head hash.
  Caveats: no admission control ⇒ **Sybil/eclipse of a specific target ID is cheap**
  (documented since Wang & Kangasharju 2012, "Real-world Sybil attacks in BitTorrent
  mainline DHT"; similar results for IPFS: "Total Eclipse of the Heart" USENIX
  Sec'22). S/Kademlia hardening (crypto puzzles for node IDs, disjoint lookup paths) is
  implemented *partially* in libp2p but doesn't change the economics on an open DHT.
- **Design consequence — make the DHT trust-free**: never derive *trust* from the DHT;
  all authenticity comes from the signed log + WG handshake keys. Then a successful
  eclipse is only a **DoS of cold-start discovery**, which is an acceptable residual
  (nodes also cache last-known endpoints and gossip).
- **Privacy of announcements**: default DHT announcements let anyone enumerate "who
  participates in topic X" (crawler literature is extensive). Hardening that works:
  - **Rotating blinded topic IDs**: `topic_t = HMAC(group_secret, floor(time/T) ||
    salt)` — outsiders can't recognize, join, or enumerate the network; revoked members
    lose it at the next epoch (interacts nicely with the epoch group secret).
  - **Encrypted announcement payloads** (AEAD under group secret): DHT storage nodes
    see random bytes at a random-looking key. Residual leak: the announcing node's IP
    is still visible to DHT neighbors as "stores *something*" — full unobservability is
    not achievable on a public DHT.
  - **Private DHT is pointless at small n**: for ≤ a few hundred nodes, a full gossip
    mesh (every member knows every member — the log is replicated anyway) replaces the
    DHT entirely; the public DHT is needed only for **cold start /
    all-endpoints-changed recovery**.
- **mDNS/DNS-SD** for same-LAN discovery: cheap, works when the internet path fails;
  broadcast the *blinded* ID, not a recognizable service name, or you leak network
  membership to every coffee-shop LAN.
- **Libraries**: Go: `anacrolix/dht` (mainline + BEP44, mature, powers
  anacrolix/torrent); `libp2p/go-libp2p` Kad-DHT (runs IPFS Amino at ~10⁴-10⁵ node
  scale, mature); `hashicorp/memberlist`/`serf` for SWIM-style gossip. Rust:
  `rust-libp2p` (active through Aug 2026: https://github.com/libp2p/rust-libp2p);
  `mainline` crate (Rust mainline DHT w/ BEP44, used by pkarr — smaller community).
  Also note **pkarr** (public-key-addressable records over mainline DHT) as
  directly-relevant prior art for "publish signed node records on the public DHT".

## 7. NAT traversal without company-run infra

- **Techniques**: classic ICE/STUN/TURN vs. Tailscale's **disco** (in-band pings via
  relay carrying observed endpoints, birthday-paradox port search against hard NAT —
  see their NAT traversal series). Functionally equivalent; disco's insight is that
  *any reachable peer can act as your STUN server* because the encrypted ping response
  can carry your reflexive address.
- **Verified success-rate data (2024-2026)**:
  - Tailscale: direct-connection success "well north of 90%" in typical conditions;
    every connection starts on DERP and upgrades
    (https://tailscale.com/blog/nat-traversal-improvements-pt-1).
  - iroh: ~90% hole-punch success (~95% by production data); 95-99% of *data volume*
    direct depending on deployment; relay fallback covers the rest
    (https://www.iroh.computer/blog/comparing-iroh-and-libp2p; iroh 1.0 shipped
    2026-06-15: https://www.iroh.computer/blog/v1).
  - libp2p DCUtR measured around ~70% (large-scale measurement papers, arxiv
    2024-2025) — a fair baseline for "hole punching without a coordinated dual stack".
  - **Planning number: 5-15% of node pairs will need a relay**, dominated by
    CGNAT↔CGNAT (endpoint-dependent mapping both sides) and UDP-blocked corporate/hotel
    networks. UDP fully blocked ⇒ need a TCP/443-capable relay path.
- **Members as infrastructure (validated pattern)**:
  - *STUN role*: any member with a public/EIM-NAT address reflects observed endpoints —
    disco-style, or via **QUIC Address Discovery** (standards-track,
    draft-ietf-quic-address-discovery, active 2026:
    https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/). iroh
    *replaced STUN entirely with QAD* since v0.90
    (https://www.iroh.computer/blog/qad) — strong evidence this is production-ready.
  - *Relay role*: **Tailscale peer relays** (v1.86+, docs:
    https://tailscale.com/docs/features/peer-relay) are exactly "member nodes as relays
    before falling back to DERP" — direct validation that this works in production.
    Relays are untrusted for confidentiality/integrity (traffic is WG-encrypted
    end-to-end); they cost you availability and see traffic metadata only. DERP itself
    is open-source and self-hostable (`derper`), as is `iroh-relay`; **MASQUE
    CONNECT-UDP (RFC 9298)** is the standards-based alternative for member-run relays.
  - *Bootstrap caveat*: pure P2P needs ≥1 reachable member (or the public DHT) for
    first contact — a network where *every* node is behind hard NAT and no relay
    volunteer exists cannot form. Make "relay-capable" a visible, log-recorded role and
    warn when <2 exist.

## 8. Crypto-derived IP addressing vs. coordinated assignment

- **Prior art**: cjdns: addr = double-SHA-512(pubkey) constrained to `fc00::/8`
  (grinding gives ~8 bits of implicit PoW). Yggdrasil: `200::/7`, address = truncated
  SHA-512 of the key with a leading-ones-count byte
  (https://yggdrasil-network.github.io/2018/07/28/addressing.html). Their own tracker
  acknowledges 128-bit addresses (and especially /64 prefixes) are "too short really to
  be immune to collisions" in an *open* network where the address is the *only*
  identity (https://github.com/yggdrasil-network/yggdrasil-go/issues/33).
- **Key insight for a closed WG network**: the threat model is completely different
  from Yggdrasil's. WireGuard's **cryptokey routing** binds each overlay IP to a full
  256-bit pubkey via AllowedIPs; packets only flow inside authenticated tunnels. So
  **spoofing is impossible regardless of how the IP was chosen** — the hash-derived
  address is merely a *coordination-free allocation scheme*, not a security boundary.
  Second-preimage grinding against a member's address buys an attacker nothing unless
  they also get their key admitted to the log.
- **Collision math**: IPv6 ULA `fdxx:…/48` leaves ~80 bits per host ⇒ accidental
  collision negligible below ~2^40 nodes. IPv4 CGNAT `100.64.0.0/10` has only 22 bits ⇒
  birthday collision ~50% around ~2400 nodes and plausible at hundreds —
  **hash-derived v4 addresses need a collision-resolution rule**.
- **Recommendation**: derive v6 from `truncate(SHA-256(pubkey))` into a per-network ULA
  /48 (network id itself derived from the genesis log hash — RFC 4193-compatible); the
  log validator **rejects an AddNode whose derived address collides** (deterministic,
  converges identically everywhere). For v4, either assign explicitly in the log record
  (the log is already the consensus mechanism; conflict = invalid record) or
  derive-then-linear-probe with the probe result recorded in the log. Hybrid "derive by
  default, record in log, log is authoritative" gets both partition-safe allocation and
  clean collision handling.

## 9. WireGuard integration options

- **Kernel WG via netlink (Linux)** — fastest, smallest attack surface (in-kernel,
  formally analyzed Noise IKpsk2). Go: `golang.zx2c4.com/wireguard/wgctrl`
  (semi-official, mature, also drives userspace impls via UAPI). Rust:
  `defguard_wireguard_rs` (kernel netlink + userspace + Windows), `wireguard-control`
  (from tonari's innernet — low-activity; reference prior art, not a dependency).
- **wireguard-go** — official userspace, cross-platform, the engine inside Tailscale's
  client (their fork adds batching etc.). The safe default off Linux.
- **boringtun** — Cloudflare's Rust userspace WG: maintenance chronically spotty;
  **Mullvad forked it as GotaTun (announced Dec 2025)** for active stewardship
  (https://www.phoronix.com/news/GotaTun-Rust-WireGuard-OSS). For Rust userspace in
  2026, watch GotaTun; don't bet on upstream boringtun.
- **Key rotation ergonomics**: WG has no built-in identity rotation — node-key rotation
  is a control-plane operation: publish new pubkey (signed by old key + admin quorum)
  in the log, peers atomically swap AllowedIPs/peer entry. Design the log schema for
  this from day one (node identity ≠ current WG key; identity is the log record, keys
  are rotatable attributes). Per-pair **PSKs** rotate cheaply via `wg set` without
  breaking tunnels (next handshake picks them up).
- **Post-quantum**:
  - The **PSK slot is the sanctioned PQ hedge**: mix a PQ-derived secret into each
    pair's PSK and Noise IKpsk2 confidentiality survives a CRQC
    (harvest-now-decrypt-later defense).
  - **Rosenpass** (Classic McEliece + Kyber via liboqs, ProVerif-verified protocol,
    feeds WG PSK): technically the right idea, but **maturity in 2026 is weak — latest
    tagged release still v0.2.3 (Aug 2024); no published third-party audit**
    (https://github.com/rosenpass/rosenpass/releases, https://rosenpass.eu/). A
    separate long-running daemon per link is also real attack surface. Verdict: not
    yet.
  - **Simpler DIY hybrid with audited primitives**: the control plane already
    distributes keys — give each node a static **ML-KEM-768** keypair (recorded in the
    log), derive per-pair PSKs via encapsulation + HKDF, rotate per epoch. Rust:
    `ml-kem` (RustCrypto) / `liboqs`; Go: `cloudflare/circl` or the stdlib's ML-KEM
    (`crypto/mlkem`, Go ≥1.24). Smaller TCB than Rosenpass, same hedge. Sign the log
    with Ed25519 now; PQ *authentication* (ML-DSA cosigning of checkpoints) can be
    added later — authentication is not harvest-now-decrypt-later-exposed.

## Synthesis: recommended minimal-TCB stack

**Trust layer (the actual TCB):**

1. **TKA-style hash-chained AUM log** — Ed25519, monotonic epochs, deterministic
   validation; **plain k-of-n multi-signature** for membership changes (admin keys with
   vote weights); pre-committed **disablement/recovery preimages** for break-glass. No
   FROST, no MLS, no KT machinery. In Go, import/adapt Tailscale's `tka` package rather
   than reimplementing.
2. **Epoch group secret**: HPKE (RFC 9180) fan-out of a per-epoch secret inside signed
   log records; bumped on every revocation. Gates discovery only — never data-plane
   security.
3. **Fail-closed freshness**: quorum-signed heartbeat head; peers refuse state older
   than TTL (24-72 h, configurable). Log-head hash piggybacked on all keepalive/disco
   traffic for anti-entropy + split-view detection.

**Enrollment:** QR with full-entropy token when a camera exists;
**Magic-Wormhole-style single-use code + SPAKE2/CPace** for typed codes; both terminate
in an admin-quorum-signed AddNode record.

**Discovery:** full-mesh gossip among members (the log is replicated anyway) as
primary; **BitTorrent mainline DHT + BEP44** with **HMAC-rotated blinded topic IDs and
AEAD-encrypted payloads** for cold start; mDNS with blinded names on LAN. DHT is
trust-free by construction — eclipse ⇒ DoS only.

**Connectivity:** disco-style endpoint reflection between members (or QUIC Address
Discovery); hole-punch with birthday-search fallback; **member-volunteered relays**
(Tailscale peer-relay pattern; MASQUE RFC 9298 or self-hosted derper as protocol) for
the residual 5-15% of pairs; relays are membership-authenticated but untrusted.

**Data plane:** kernel WG on Linux via netlink, wireguard-go elsewhere; per-pair
**PSK = HKDF(ML-KEM-768 encap between log-recorded static PQ keys, epoch)** as the PQ
hedge (skip Rosenpass until it has a release cadence and an audit); **v6 ULA addresses
hash-derived from pubkey, recorded and uniqueness-checked in the log**; explicit log
assignment for any v4 range.

**Language note:** Rust has the broadest audited-crypto coverage (ZF frost, opaque-ke,
openmls, akd, ml-kem, iroh, magic-wormhole); Go has the decisive shortcut of
importable, production-proven `tka` + `wgctrl` + `wireguard-go` + anacrolix/dht. A Go
control plane over kernel/wireguard-go is the fastest path to a small, reviewable TCB;
Rust is the better base only if leaning on iroh as a transport substrate.

## Residual weaknesses that cannot be engineered away

1. **Revocation under partition**: a node cut off from all fresh members either trusts
   a revoked peer (fail-open) or bricks itself after TTL (fail-closed). Only the TTL
   knob moves; the dilemma doesn't.
2. **Quorum loss = network death**: lose k-of-n admin keys *and* all disablement
   secrets and the network is unrecoverable by design — that unrecoverability *is* the
   security property (Tailscale documents the same).
3. **Split-view window**: without global consensus, a quorum of *malicious admins* can
   briefly show divergent chains to disjoint node sets; gossip detects forks after the
   fact but cannot prevent them in real time. (Against non-quorum attackers the chain
   rule prevents this; against a bad quorum nothing does — quorum compromise is game
   over in any design.)
4. **Cold-start availability**: first contact needs the public DHT or one reachable
   member; a network that is 100% hard-NAT with zero relay volunteers cannot bootstrap.
   Public-DHT eclipse can delay (not corrupt) recovery.
5. **Metadata leakage**: DHT storage nodes see *that* some IP stored an opaque record;
   relays see traffic timing/volume between member IPs; LAN observers see blinded but
   present announcements. Full unobservability requires Tor-class machinery, out of
   scope.
6. **Enrollment is a trusted ceremony**: one-guess-PAKE and QR reduce but never
   eliminate the window where a mis-issued invite or a compromised admin device admits
   an attacker — membership security bottoms out at admin-device security.
7. **Endpoint compromise**: nothing in the control plane survives compromise of a
   member's device before revocation is noticed; PCS via key rotation only helps
   *after* detection.

## Key sources

https://tailscale.com/kb/1226/tailnet-lock ·
https://datatracker.ietf.org/doc/rfc9591/ ·
https://github.com/ZcashFoundation/frost ·
https://github.com/bytemare/frost ·
https://blog.phnx.im/openmls-independent-security-audit/ ·
https://github.com/awslabs/mls-rs ·
https://datatracker.ietf.org/doc/rfc9807/ ·
https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/ ·
https://github.com/magic-wormhole/magic-wormhole.rs ·
https://github.com/facebook/opaque-ke ·
https://github.com/facebook/akd ·
https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/ ·
https://www.iroh.computer/blog/qad ·
https://www.iroh.computer/blog/v1 ·
https://tailscale.com/blog/nat-traversal-improvements-pt-1 ·
https://tailscale.com/docs/features/peer-relay ·
https://github.com/rosenpass/rosenpass/releases ·
https://www.phoronix.com/news/GotaTun-Rust-WireGuard-OSS ·
https://yggdrasil-network.github.io/2018/07/28/addressing.html ·
https://github.com/yggdrasil-network/yggdrasil-go/issues/33 ·
https://github.com/libp2p/rust-libp2p
