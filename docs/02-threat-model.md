# 02 — Threat model

## Assets

1. **Membership truth** — who is in the network, with which keys and addresses.
2. **Admin authority** — the ability to add/remove members and change policy.
3. **Data-plane confidentiality/integrity** — traffic between members.
4. **Network metadata** — existence of the network, member IPs, traffic patterns.
5. **Availability** — members can reach each other; admins can manage.

## Adversaries in scope

| Adversary | Capability assumed | Primary defense |
|---|---|---|
| Network observer (on-path) | Read/inject/drop packets anywhere between members | WireGuard (Noise IKpsk2); all control traffic signed and/or inside tunnels |
| Malicious rendezvous infra | Controls public DHT nodes / STUN servers we query | Trust-free construction: DHT/STUN can delay discovery (DoS), never alter membership; announcements AEAD-encrypted, topics blinded |
| Evicted member | Was a member; retains all old keys and state | Signed revocation records + epoch bump (loses group secret → loses discovery) + WG peer removal + fail-closed freshness TTL |
| Stolen/lost device | Full key material of one member | Same as evicted member, after detection; per-device keys mean no shared secrets to rotate |
| Compromised admin, below quorum | One admin key (or few, < k) | k-of-n quorum for membership changes; attributable multi-signatures make the malicious signer identifiable in the log |
| Member holding an exit-node / route grant (v1.1) | Full plaintext view of everything routed through it, plus drop/redirect | Grant is a quorum-signed log record separate from membership and separately revocable; routes may never overlap the overlay space; route state read only from the log, never from peer advertisements; use gated by ACLs (which is why M7a precedes M7b) |
| Log-transport attacker | Controls how AUMs reach some nodes | Hash chain prevents forgery/reorder; monotonic epochs prevent rollback; log-head cross-gossip detects split views |
| Supply chain (our updates) | Compromise of release pipeline | Signed releases; reproducible builds; update transparency (roadmap item, not v1) |

## Out of scope / consciously accepted

- **Full admin quorum compromised** — game over in any design; mitigated only by key
  custody practices (hardware-backed keys, geographic separation of admins).
- **Endpoint compromise of a valid member** — the VPN admits the device; host security
  is not our layer. Post-compromise security exists only *after* detection + revocation.
- **Global passive adversary / traffic analysis** — relays and DHT interactions leak
  timing, volume, and IP metadata. Full unobservability is a non-goal (see residual
  weaknesses).

## Residual weaknesses — fundamental, tunable, not removable

These were identified in research and confirmed against deployed prior art. Anyone
adopting this system must accept them explicitly.

1. **Revocation is eventually-consistent.** A revoked device keeps access to any peer
   it can still reach until that peer learns of the revocation. Mitigation stack:
   monotonic epochs (no rollback), gossip anti-entropy with log-head piggybacking on
   every keepalive (convergence in O(log n) rounds), rekey-on-revoke (revoked node
   loses the discovery layer), and **fail-closed freshness leases**: quorum-signed
   heartbeats over the log head; peers refuse tunnels against state older than a TTL
   (24–72 h). The TTL is the single knob: max revocation latency = max survivable
   partition. Instantaneous global revocation in a partitioned P2P system is a
   CAP-style impossibility. (Same principle as Rivest 1998 and the Web PKI's move to
   ever-shorter cert lifetimes.)
2. **Admin-quorum custody is the crown jewel.** Lose k-of-n admin keys *and* all
   pre-committed break-glass disablement secrets → the network is unrecoverable **by
   design**; that unrecoverability is the security property (Tailscale documents the
   same for tailnet lock). Compromise of a full quorum is game over — true of every
   design, centralized or not.
3. **Split-view window under a malicious quorum.** A colluding quorum can briefly show
   divergent logs to disjoint node sets. Cross-gossiped log heads (fork detection)
   expose this after the fact; nothing prevents it in real time short of global
   consensus. Against sub-quorum attackers the hash chain prevents split views
   entirely.
4. **Cold-start availability.** First contact requires the public DHT or one reachable
   member. A network that is 100 % hard-NAT with zero relay-capable members cannot
   form. DHT eclipse/Sybil attacks can *delay* cold start; they can never corrupt
   membership. Mitigation: cache last-known endpoints, advertise "relay-capable" as a
   first-class role, warn when fewer than two exist.
5. **Metadata leakage.** Public DHT storage nodes observe that some IP stored an opaque
   record; member relays observe timing/volume between member IPs; LAN observers see
   blinded-but-present mDNS announcements. Full unobservability requires Tor-class
   machinery — out of scope. Two consequences of the rendezvous design are worth
   naming, since neither is removable at this layer. Running the DHT at all tells a
   passive observer that this host speaks the BitTorrent DHT, which is the
   internet-scale twin of the mDNS leak above — `juistd -no-dht` is the answer for a
   deployment that would rather not, at the cost of off-LAN cold start. And a node's
   *queries* are visible to whichever storage node answers them: each names one
   opaque address, so no query says who is being looked for, but a node that asked
   after all of its missing peers at once would turn that into a count. Lookups are
   therefore capped per round and shuffled, and only members this node holds no
   address for are asked after at all.
6. **Enrollment bottoms out at admin-device security.** One-guess PAKE invites and
   full-entropy QR tokens shrink but cannot eliminate the window in which a mis-issued
   invite or a compromised admin device admits an attacker.
7. **Exit nodes concentrate trust in one member (v1.1 feature).** Traffic leaving the
   overlay through an exit node is plaintext on that member's host — a deliberate MITM
   position for everything routed through it, exactly as with Tailscale or any
   commercial VPN. Two P2P-specific sharpenings: *withdrawing* the grant is
   eventually-consistent (weakness 1 applies to the role itself, bounded by the
   freshness TTL), and no single admin can revoke it unilaterally — it takes a quorum,
   so "turn that exit node off right now" is not an available operation. Bounded by:
   the role is separate from membership and separately revocable; advertised routes may
   never overlap the overlay space, so an exit node cannot intercept member-to-member
   traffic; and using one is an ACL grant rather than a network-wide default.
8. **A real device puts the overlay addresses on the host, where the LAN can reach
   them.** Linux's weak host model makes an address on `juist0` reachable through
   *any* interface, so a LAN-adjacent attacker can send plain IP packets to a node's
   overlay address and can forge the source as another member's. Both default-deny
   gates sit downstream of WireGuard decryption and never see these packets. It is no
   way in to membership, but **a source in `100.64.0.0/10` is not evidence that a
   packet came through the tunnel**, and services bound only to an overlay address
   are LAN-reachable. The v6 ULA has the same shape, guessable only from the genesis
   hash. Tailscale closes the source half with a netfilter rule; juist runs
   `NetfilterOff` so the daemon touches neither the host firewall nor any sysctl,
   which is also what lets its unit file set `ProtectKernelTunables`. Accepted for
   v1: the overlay is a transport, and anything on top authenticates its own peers.
   Operators wanting the stronger boundary add the host rule themselves. Revisit at
   M7b, which needs netfilter management anyway.

## Security design rules derived from the above

- No component outside the member set is ever trusted for *integrity* of membership —
  only, at worst, for *liveness* of discovery.
- Every message that changes state is signed and chained; every message that carries
  state advertises the log head.
- Freshness is enforced by the *acceptor* (fail closed), never assumed from the sender.
- Prefer attributable signatures (audit trail) over threshold/aggregated ones.
- The data plane never depends on the group secret; discovery privacy never gates
  data-plane security.
- The daemon runs with the narrowest host privilege that lets it own a TUN device:
  `CAP_NET_ADMIN` as an ambient capability on a dedicated unprivileged user, never
  as root (M3a; see `packaging/systemd/juistd.service`). This widens what a
  compromised `juistd` can do to the *host* — create interfaces, set routes and the
  reverse-path sysctls — not to the *network*: it still holds no admin keys and
  still cannot authorize a membership change. Attacker-facing parsers (gossip, IPC,
  later the DHT) get no privilege from this.
