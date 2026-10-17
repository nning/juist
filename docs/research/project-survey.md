# Research appendix — Decentralized / P2P VPN control-plane survey

*Compiled Aug 2026, extended Oct 2026; project status claims verified against live sources at those times.*

Where this names `tailscale.com/tka` as reusable, juist took its design and none of
its code ([08-trust-layer-notes.md](../08-trust-layer-notes.md)); its v1 runs
wireguard-go, not kernel WireGuard ([04-architecture.md](../04-architecture.md)).

## Tailscale

1. **Control plane:** Central proprietary SaaS coordination server holds membership
   truth. **Tailnet Lock (TKA)** overlays this with client-side verification: an
   append-only log of signed **AUMs (Authority Update Messages)** defines a set of
   trusted signing keys; every node's WireGuard key must carry a signature chained to
   that authority or peers reject it — so the control plane becomes an *untrusted
   transport* that cannot inject nodes
   ([whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper),
   [docs](https://tailscale.com/docs/features/tailnet-lock)). Limits: max 20 signing
   nodes, key rotation recommended ≤1/yr (log growth). "Disablement secrets" allow
   turning lock off. Still active in 2026 (`tailscale lock status -json` stabilized
   March 2026, [changelog](https://tailscale.com/changelog)).
2. **Trust roots:** OIDC identity at login; node keys distributed by control server;
   TKA adds user-held `tlpub` signing keys as an independent root.
3. **Revocation:** Node removal is still a control-plane operation pushed via netmap
   (fast, seconds, but requires the central server). TKA prevents *additions*, and
   supports signed key removal/rotation via AUMs, but eviction latency/availability
   depends on Tailscale infra.
4. **NAT traversal:** `disco` protocol + **DERP** relays (Tailscale-run global fleet;
   DERP embeds STUN; custom DERPs self-hostable). Best-in-class hole punching.
5. **Security:** Strongest documented design of the group; notable CVE-2022-41924
   (Windows RCE via DNS-rebinding of cleartext LocalAPI, fixed 1.32.3,
   [advisory](https://github.com/tailscale/tailscale/security/advisories/GHSA-vqp6-rc3h-83cp));
   TKA design is essentially key-transparency-for-membership.
6. **Practical:** Go. Open source (BSD-3): full daemon/CLI, Linux+Android clients,
   **DERP server**, magicsock/disco, `tsnet`, and crucially the **`tailscale.com/tka`
   package** ([pkg.go.dev](https://pkg.go.dev/tailscale.com/tka)); proprietary:
   coordination server, macOS/Windows GUIs
   ([tailscale.com/opensource](https://tailscale.com/opensource)). A third-party Rust
   reimplementation effort (`tailscale-rs`) is replaying TKA
   ([issue](https://github.com/GeiserX/tailscale-rs/issues/7)).
   **Reusable: tka, DERP, magicsock/netcheck/portmapper.**

## Headscale

1–3. Faithful reimplementation of the coordination server: a single self-hosted Go
server (BSD-3) is the membership truth; revocation = server-side node expiry/delete
pushed on netmap. **Tailnet Lock is NOT supported** (open feature gap,
[issue #1307](https://github.com/juanfont/headscale/issues/1307)) — so a Headscale
tailnet has *no* client-side membership verification at all.
4. Uses Tailscale's disco; can embed a DERP server or use Tailscale's.
5–6. Active community project, v0.27.x in 2026
([headscale.net](https://headscale.net/stable/about/releases/),
[repo](https://github.com/juanfont/headscale)). Distance from P2P: data plane is P2P;
control is a classic central server you run — a SPOF you administer, not a
decentralized design.

## NetBird

1. Central self-hostable stack: management server (accounts/peers/ACLs = membership
   truth) + signal server + relay/TURN + STUN. v0.62 (Jan 2026) removed the
   external-IdP requirement; v0.72+ by mid-2026
   ([vpnsmith](https://www.vpnsmith.com/en/blog/netbird-self-host-2026)).
2. Trust root = management server; enrollment via setup keys / SSO (OIDC); server
   distributes WireGuard pubkeys.
3. Revocation: management push to online peers; requires server availability.
4. Signal server + STUN/TURN + NetBird relay; company runs hosted infra, all
   self-hostable.
5. GHSA-qcpp-8vwj-hhwr / fixed v0.76.0 (2026-07-29): unauthenticated local gRPC IPC
   (0666 unix socket, loopback TCP on Windows) → local privesc to root via embedded SSH
   toggles ([advisory](https://github.com/netbirdio/netbird/security/advisories/GHSA-qcpp-8vwj-hhwr)).
6. Go, BSD-3, VC-funded, very active. Reusable: signal/relay/ICE code, but architecture
   is Tailscale-with-your-own-server, not P2P.

## Netmaker

1–3. Most server-centric: central Go server (API + broker) is membership truth; clients
poll/subscribe; revocation = server push. Open-core: Apache-2.0 with proprietary `pro/`
dir ([repo](https://github.com/gravitl/netmaker)).
4. STUN/TURN (pro features for advanced NAT cases); historically assumed reachable
servers.
5. History of severe control-plane bugs (2023 hardcoded-key/JWT vulnerability allowing
admin takeover, fixed 0.17.1/0.18.6). Kernel WireGuard = good data-plane perf.
6. Active commercial project; low reuse value for a P2P design. Oct 2026: v1.7.0;
   netclient on Linux, FreeBSD, Windows, macOS, mobile app; UDP hole punching with
   relays, failover relays and IdP sign-in in the paid edition.

## Nebula (closest serverless-CA prior art)

1. **Control plane: offline CA.** Membership truth = a certificate signed by a CA whose
   cert is in each host's config, encoding overlay IP(s), groups, expiry. No online
   coordinator; **cert v2** (v1.10+, 2025) adds multiple IPv4/IPv6 addrs, dual-CA
   migration ([upgrade guide](https://nebula.defined.net/docs/guides/upgrade-to-cert-v2-and-ipv6/)).
2. Trust roots: CA cert(s) shipped in every host's config; multiple CAs supported for
   rotation. Key distribution is your problem (config management).
3. **Revocation is the weak point:** per-host `pki.blocklist` of cert fingerprints must
   be pushed out-of-band to *every* host; otherwise you wait for cert expiry. No
   built-in CRL/gossip. Defined Networking's managed product papers over this with 60s
   polling ([blog](https://www.defined.net/blog/blocklisting/)). **CVE-2026-25793**
   (HIGH, 1.7.0–1.10.2, fixed 1.10.3): ECDSA P256 signature malleability (high-S/low-S)
   yields alternate fingerprints that bypass the blocklist
   ([SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-25793/)) —
   a concrete demonstration that fingerprint-blocklist revocation is fragile. (Note:
   CVE-2026-61699/53602 are against an unrelated `forgekeep/nebula-mesh` package, not
   slackhq/nebula.)
4. NAT traversal: user-run **lighthouses** (any node with a public IP) for endpoint
   discovery + UDP hole punching; peer relays since v1.6. Zero vendor infrastructure.
5. Noise IX_PSK0, Curve25519 default (P256 optional), AES-GCM/ChaCha20-Poly1305; paid
   vulnerability assessment + bug bounty per Slack
   ([slack.engineering](https://slack.engineering/introducing-nebula-the-open-source-global-overlay-network-from-slack/));
   proven at Slack scale.
6. Go, MIT, active (v1.9.x/1.10.x maintained through 2026,
   [releases](https://github.com/slackhq/nebula/releases)). Reusable: cert
   format/library, lighthouse+punching code, config-driven trust model.

## Innernet

Central Rust server (SQLite) = membership truth; CIDR-based ACLs; invitation files for
enrollment; revocation via server. MIT, explicitly "experimental, no security audit"
([repo](https://github.com/tonarino/innernet)); maintained but slow-moving. Nice UX
ideas (invitations, CIDR ACL model), still a central coordinator.

## wesher

Go; HashiCorp memberlist **gossip** cluster keyed by one shared symmetric key — *anyone
with the key joins*; WireGuard pubkeys exchanged over gossip; membership truth = live
gossip state ([repo](https://github.com/costela/wesher)). Revocation = rotate the
cluster key everywhere (bad). No NAT traversal (assumes reachable nodes, cloud use
case). Dormant-ish since ~2022. Lesson: symmetric admission ≠ security-first.

## vpncloud

Rust, GPL-3; static bootstrap peer list + peer-exchange gossip; shared-secret or
key-based crypto; some hole punching but no rendezvous infra. Last release v2.3.0
Dec 2021 — **dormant** ([releases](https://github.com/dswd/vpncloud/releases)).

## Tinc

C, GPL-2; manual host-file key exchange, transitive trust via meta-connection graph
(any member introduces others); TCP meta-relaying doubles as NAT fallback. 1.1 stuck at
pre18 since 2021, 1.0.x legacy — effectively **dormant**
([repo](https://github.com/gsliepen/tinc)); legacy protocol had authentication/MITM
CVEs in 2018 (fixed by SPTPS in 1.1). Historical interest only.

## ZeroTier

1. Two-layer: **VL1 roots** (rendezvous/relay; ZeroTier-run "planet"; user "moons" now
   **deprecated/unsupported** — [docs](https://docs.zerotier.com/roots/)) and **VL2
   network controllers** = membership truth, issuing certificates of membership.
   Controller code ships in every node and is self-hostable, but…
2. Trust roots: controller identity per network; node identity = 40-bit address from
   pubkey hash (small namespace, collision-griefing considerations).
3. Revocation: controller-issued credential revocations propagate peer-to-peer with
   anti-backdating clocks — better-than-average design, but still
   controller-dependent.
4. Roots do rendezvous + limited relaying; hole punching mature. ZeroTier 2.0
   (configurable root lists replacing planet/moons) still unshipped after years
   ([2.0 status](https://www.zerotier.com/news/zerotier-2-0-status/)).
5. Custom protocol/crypto (Salsa20/Poly1305 legacy, AES-GMAC-SIV); no public
   third-party audit; no major recent CVEs.
6. C++, **BSL 1.1** (GPL→BSL in 2019; controller-as-a-service and some commercial use
   require paid license; community reports license friction,
   [issue #2206](https://github.com/zerotier/ZeroTierOne/issues/2206)); v1.16.2
   May 2026. License makes it a poor foundation. Oct 2026: since 1.16.0 the agent is
   MPL-2.0 and the controller sits in `nonfree/` under a source-available licence that
   bars commercial use without a paid licence; free hosted plan 10 devices; SSO only in
   paid plans; moons deprecated.

## Yggdrasil

1. **No membership** — one global open network; control plane is the routing algorithm
   itself (v0.5 dropped the DHT for spanning-tree routing + key→coordinate lookups).
2. Trust root = your own key: IPv6 in `0200::/7` **derived from Ed25519 pubkey**
   (unspoofable but truncated hash → sub-128-bit effective strength).
3. Revocation: N/A; you must firewall the overlay interface — any global node can send
   you packets.
4. Manual/public peer lists + LAN multicast; no hole punching to speak of (relies on
   peering links).
5. Self-described experimental; no audit; authenticated peering handshakes since 0.5.
6. Go, LGPL-3, active (v0.5.13 Feb 2026,
   [releases](https://github.com/yggdrasil-network/yggdrasil-go/releases)). Reusable
   idea: **crypto-derived addressing** kills IP-spoofing and address allocation
   problems at once.

## cjdns

Same family: `fc00::/8` address from double-SHA-512 of pubkey; DHT pathfinder +
source-routed labels; manual password peering. C/Rust, GPL-3; maintenance mode, tied to
PKT ecosystem (repo touched Dec 2025, [repo](https://github.com/cjdelisle/cjdns)).
Custom CryptoAuth, never audited. Historical prior art for crypto-addressing, not a
foundation.

## Veilid

Not a VPN — a P2P app framework (cDc): DHT with owner-signed records, onion-like
private routing, pluggable "crypto kinds" (Ed25519/X25519/ChaCha20/BLAKE3). Rust,
MPL-2.0, active (veilid-core 0.5.3 Mar 2026,
[docs.rs](https://docs.rs/crate/veilid-core/latest); [veilid.com](https://veilid.com/)).
No audit known. Relevant as a reference for signed-DHT-record membership storage and
metadata privacy, not for packet-plane performance.

## iroh (n0-computer) — key building block

1. Connectivity library, not a VPN: dial an **EndpointId (Ed25519 key)**, get a QUIC
   connection. Membership is the application's problem — which is exactly what you want
   for a custom control plane.
2. Discovery = signed records via **pkarr/DNS** (n0 runs `dns.iroh.link`;
   `iroh-dns-server` open source) and optionally the **BitTorrent mainline DHT**
   (serverless), plus mDNS locally.
3. Revocation: N/A at this layer (app-defined).
4. **iroh 1.0 shipped 2026-06-15** ([blog](https://www.iroh.computer/blog/v1)): stable
   wire protocol, multipath QUIC + IETF QUIC NAT-traversal draft, ~90 %
   direct-connection rate, fallback to stateless encrypted relays; n0's public relay
   fleet served 200M+ endpoints/30d; **relay server is open source and self-hostable**
   (`iroh-relay`).
5. TLS-over-QUIC with raw-key identity; no published third-party audit found in repo
   docs — a real gap for a security-first project.
6. Rust, MIT/Apache-2.0, very active; Python/Node/Swift/Kotlin bindings
   ([repo](https://github.com/n0-computer/iroh)). Caveat: application-level tunnel,
   not a TUN/WireGuard device — see rayfish.

### rayfish (mesh VPN on iroh — closest thing to the target design that exists)

Rust daemon + TUN device tunneling IP over iroh QUIC. **No server, no account:** a
network is a keypair; membership = a **signed network record published on a public
DHT**; virtual IPs (100.64.0.0/10) derived from device identity; admission via
single-use invites, reusable fleet keys, or live approval, gated by **coordinator
peers** (the creator initially); `ray kick` = mesh-wide removal; invite revocation
propagates ([repo](https://github.com/rayfish/rayfish)). MPL-2.0, explicitly
**experimental, pre-1.0, unaudited**, wire format unstable. Weakness: coordinator
liveness = admission/eviction availability; DHT record is a single-writer-ish trust
point; not WireGuard (no kernel path). Oct 2026 (v0.5.7, source read): the record goes
to n0's pkarr relay `dns.iroh.link` by default and relays are iroh's N0 preset, both
overridable; co-coordinators (`ray admin add`) receive **the same network key**, so
multi-admin means a shared key, not a quorum; per-device firewall with
coordinator-suggested rules carried in the signed record; Linux, macOS, Windows,
Android, FreeBSD, no iOS.

### Other serverless signed-roster meshes (Oct 2026)

- **nostr-vpn** ([repo](https://github.com/mmalmi/nostr-vpn)): Rust, MIT, since Mar
  2026, v4.1, ~1.2k★. Devices accept a roster only if a configured admin signed it;
  several admins, any one suffices. Data plane is its own FIPS overlay, not WireGuard;
  Nostr relays carry discovery only. All five desktop/mobile platforms, no FreeBSD.
  How a removal reaches devices the admin cannot reach is not documented.
- **Tunnet** ([repo](https://github.com/tunnetio/Tunnet)): open-core (AGPL control
  plane), mainly a self-hostable Tailscale-like product; its *Direct* mode keeps a
  signed genesis, epoch, member records and revocations in an iroh-docs document the
  devices replicate, with a coordinator as the single signer. Pre-1.0.
- **meshguard**: Zig, MIT, serverless WireGuard over SWIM gossip with org-signed
  identities and revocation, FreeBSD support; ~20★, too small to compare against.

None of these, nor any other project found, requires k-of-n admin signatures.

## libp2p-based VPNs

- **hyprspace:** Go, IPFS/libp2p; membership = mutually-configured peer ID lists
  (manual truth); rendezvous via public IPFS DHT + DCUtR hole punching + public relays.
  Original archived Feb 2024, community fork alive with light activity
  ([fork](https://github.com/hyprspace/hyprspace)).
- **EdgeVPN (mudler):** Go; shared token seeds a libp2p pubsub room + symmetric
  encryption of a gossiped ledger mapping IP↔peerID — *anyone with the token is a
  member* (wesher-class trust). Uses public libp2p bootstrap/DHT/relays. Active (deps
  updated through late 2025; powers LocalAI P2P)
  ([repo](https://github.com/mudler/edgevpn)). Userspace perf is modest.
- **weron (pojntfx):** Go, WebRTC data channels; needs a signaling server + STUN/TURN;
  community-name+password admission; README states unaudited; modest activity
  ([repo](https://github.com/pojntfx/weron)). Interesting only for
  censorship-resistance (WebRTC blends in).

## Newer/other entrants (brief)

- **EasyTier:** Rust, LGPL-3.0, very active, popular in homelab circles
  ([repo](https://github.com/EasyTier/EasyTier)). "Decentralized" = no server/client
  distinction: any reachable node (incl. community-run **public shared nodes**)
  introduces you; admission = network name + secret (symmetric); WireGuard-compatible +
  AES-GCM. No audit; symmetric-secret trust model again.
- **wgmesh (wgmesh.dev):** new project, WireGuard + DHT peer discovery, decentralized
  or centralized modes ([site](https://wgmesh.dev/),
  [repo](https://github.com/atvirokodosprendimai/wgmesh)). Unaudited newcomer;
  validates the concept, not yet a foundation.
- **WireHub (gawen, 2019):** WireGuard + authenticated Kademlia DHT + PoW anti-spam —
  conceptually the most direct ancestor of the target design; **abandoned at alpha**
  ([repo](https://github.com/gawen/WireHub)).
- **n2n → n3n fork (2023):** C, GPL-3; user-run supernodes + shared community key;
  n3n 3.3.x maintained ([n3n](https://github.com/n42n/n3n)). Legacy crypto, weak
  admission model.
- **Nym dVPN:** decentralizes *transit* (mixnet + WireGuard) via a token-incentivized
  node network, not private-network membership
  ([blog](https://nym.com/blog/building-decentralized-wireguard-vpn)) — different
  problem.

---

# Synthesis

**Best prior art / foundations (3):**

1. **Tailscale's TKA (`tailscale.com/tka`, BSD-3)** — the only production-grade
   *signed, append-only membership log with client-side verification* in this space.
   It is exactly the "membership truth without a trusted server" primitive, already
   open source in Go, and deliberately designed so the transport (currently Tailscale's
   server) is untrusted. The build path: keep the AUM/checkpoint state machine, replace
   the central AUM distribution with gossip/DHT sync among peers.
2. **iroh (MIT/Apache, 1.0 stable June 2026)** — production-grade serverless
   rendezvous: dial-by-key, self-hostable open-source relays, pkarr/DNS/mainline-DHT
   **signed discovery records**, best-measured hole-punching outside Tailscale itself.
   Rayfish proves a coordinator-less mesh VPN can be built on it; but iroh is unaudited
   and application-level (you'd either tunnel WireGuard/TUN frames over it like
   rayfish, or reuse only its discovery/relay/punching layers alongside kernel
   WireGuard).
3. **Nebula (MIT)** — the proven "trust = offline CA cert in config, infra = any node
   with a public IP" deployment model at real scale, with WireGuard-class Noise crypto.
   Its documented failure mode is the one to solve: revocation (out-of-band blocklists,
   CVE-2026-25793 fingerprint-malleability bypass, expiry-as-backstop).

**The gap nobody fills:** no project combines (a) kernel-WireGuard data plane, (b) a
*multi-writer, verifiable membership log* (TKA-style) as the sole membership truth,
(c) serverless rendezvous (DHT/pkarr signed records + self-hostable relays), and above
all (d) **fast, reliable, decentralized revocation**. Every surveyed system evicts a
compromised device either by central push (Tailscale/Headscale/NetBird/Netmaker/
ZeroTier/Defined-managed-Nebula), by out-of-band config distribution + cert expiry
(Nebula, tinc), by rotating a shared secret (wesher/EdgeVPN/EasyTier/n2n), or by
depending on a coordinator peer's liveness (rayfish). A security-first fully-P2P design
has to make eviction a first-class signed log event whose propagation doesn't depend on
any single node — e.g., short-lived membership credentials continuously re-attested via
the gossiped log (freshness horizon = max eviction latency), plus quorum signing for
authority changes so a stolen admin laptop isn't game over. Secondary unfilled gaps:
membership *transparency*/anti-equivocation for the log outside Tailscale's
server-mediated model, and independent audits — of everything here only Tailscale and
Nebula have any professional assessment; iroh, Veilid, and every DHT-based VPN are
unaudited.
