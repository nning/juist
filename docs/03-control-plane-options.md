# 03 — Control-plane options evaluated

The control plane answers one question: **who holds membership truth?** Five
architectures were evaluated security-first, against a survey of ~25 projects
(see [research/project-survey.md](research/project-survey.md), verified Aug 2026).
This is the record of that choice; where the project later decided otherwise, it
says so.

## A. Self-hosted coordinator — rejected

*Headscale, NetBird, Netmaker.* The server you run is the membership truth and a
fully-trusted single point of failure; compromise of it is compromise of the network.
Headscale notably does **not** support tailnet lock, so its clients have zero
independent verification of what the server tells them. NetBird (GHSA-qcpp-8vwj-hhwr,
local privesc via unauthenticated IPC, fixed v0.76.0) and Netmaker (2023 admin-takeover
via hardcoded keys/JWT) illustrate the class. Fails the "zero trusted infrastructure"
requirement by definition.

## B. Shared-secret admission — rejected

*wesher, EdgeVPN, EasyTier, n2n/n3n.* Anyone holding one symmetric secret is a member.
No per-device identity, no attributable admission, and revocation means rotating the
secret on every remaining device. This is the most common "P2P VPN" design and the
least secure.

## C. Offline CA + certificates — rejected as core; deployment model adopted

*Nebula.* Serverless and proven at Slack scale: trust is a CA cert in every host's
config; any public-IP member can serve as a "lighthouse". But revocation is its
documented weak point — per-host blocklists distributed out-of-band, cert expiry as the
backstop — and CVE-2026-25793 (ECDSA signature malleability yields alternate
fingerprints that bypass the blocklist) demonstrated how fragile fingerprint-blocklist
revocation is. Dynamic membership requires a config-management system, which becomes
the de-facto trusted control plane. We **adopt** its validated deployment pattern
(member-run lighthouses/relays, zero vendor infra) while replacing static certs with a
dynamic log.

## D. Open DHT-routed networks — rejected as core; addressing idea adopted

*Yggdrasil, cjdns.* No membership at all: one global network, identity = key,
address = hash(key), and you firewall your own node. The opposite trust model from a
private team network. We **adopt** crypto-derived addressing (it solves allocation
without coordination, and WireGuard's cryptokey routing makes address spoofing
impossible regardless).

## E. Signed replicated membership log — **selected**

*Tailscale tailnet lock (TKA), generalized to serverless.* An append-only hash chain of
admin-signed records (AUMs: add key, remove key, checkpoint), fully replicated and
independently verified by every node; membership changes require signatures from a
k-of-n admin quorum (vote weights); the transport that moves records is untrusted **by
construction** — Tailscale built TKA precisely so its *own* coordination server would
not need to be trusted, and ships it as an importable, production-tested, BSD-3 Go
package (`tailscale.com/tka`). Superseded in part: juist follows tka's design and
imports none of its code ([08-trust-layer-notes.md](08-trust-layer-notes.md)).

What TKA lacks for a fully-P2P deployment is ordering and distribution of AUMs (it
leans on the coordination server for both). Those are addressable with well-understood
machinery — deterministic fork choice, periodic quorum-signed checkpoints, gossip
anti-entropy, and split-view detection via cross-gossiped log heads — which is exactly
the new security-critical code this project must write and get audited (see
[04-architecture.md](04-architecture.md)).

Why it wins on the priorities:

- **Security:** no trusted party anywhere; forgery prevented by the chain; rollback by
  monotonic epochs; sub-quorum admin compromise is survivable and attributable.
  Revocation becomes a first-class signed event rather than an out-of-band afterthought
  (the gap every surveyed project has).
- **Ease of use:** members never touch configuration; admins run explicit, auditable
  operations; enrollment reduces to "scan this QR / type this code".
- **Performance:** at 25–100 nodes, full replication and O(n) rekey fan-out are
  negligible.

### Ruled out without full evaluation

**Blockchain / smart-contract membership.** Buys global ordering — which quorum
checkpoints give us for free — at the cost of privacy leakage (membership on a public
chain), an external consensus dependency, fee/latency coupling, and enormous TCB
growth.

## Decision record: go-libp2p as connectivity substrate — rejected

Considered because it bundles peer identity, secure channels, Kademlia DHT, gossipsub,
circuit relays, and DCUtR hole punching. Rejected because:

1. **It never overlaps the hard part.** The membership log, quorum signing, freshness,
   revocation, and enrollment are ours to build regardless; libp2p only replaces the
   connectivity layer.
2. **On that layer it is measurably worse:** DCUtR direct-connection success is ~70 %
   in published measurements vs ~90 %+ for Tailscale's disco stack, which we get
   production-tested from the same codebase we already import. (iroh began on libp2p
   and moved off it for this reason.)
3. **Trust-model mismatch:** open-network assumptions (public bootstrap, enumerable
   IPFS DHT, its own peer-ID identity layer) would add a third identity system to
   reconcile with log keys and WireGuard keys. Surveyed libp2p-based VPNs (hyprspace,
   EdgeVPN) are the cautionary prior art.
4. **TCB size:** a large framework in the audit path, against "boring auditable Go".

For cold-start rendezvous, `anacrolix/dht` (BitTorrent mainline, BEP 44 signed mutable
records) is leaner and rides an existing 8–10 M-node network with no bootstrap
infrastructure of ours — used strictly trust-free. Revisit libp2p only if the
Tailscale-parts decision changes.

## Survey synthesis

No existing project combines: (a) kernel-WireGuard data plane, (b) a multi-writer
verifiable membership log as sole truth, (c) serverless rendezvous, and (d) first-class
decentralized revocation; juist meets (b) to (d), on wireguard-go in v1
([04-architecture.md](04-architecture.md)). The closest attempt is **rayfish** (Rust mesh VPN on iroh,
DHT-published network records) — experimental, unaudited, dependent on coordinator-peer
liveness, and not WireGuard. Every other surveyed system evicts devices via central
push, out-of-band config distribution, or shared-secret rotation. That gap is this
project.
