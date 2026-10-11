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
| Network observer (on-path) | Read/inject/drop packets anywhere between members, and record them for a quantum computer later | WireGuard (Noise IKpsk2) with a preshared key from ML-KEM-768 (M15); all control traffic signed and/or inside tunnels |
| Malicious rendezvous infra | Controls public DHT nodes / STUN servers we query | Trust-free construction: DHT/STUN can delay discovery (DoS), never alter membership; announcements AEAD-encrypted, topics blinded |
| Evicted member | Was a member; retains all old keys and state | Signed revocation records + epoch bump (loses group secret → loses discovery) + WG peer removal + fail-closed freshness TTL |
| Stolen/lost device | Full key material of one member | Same as evicted member, after detection; per-device keys mean no shared secrets to rotate |
| Compromised admin, below quorum | One admin key (or few, < k) | k-of-n quorum for membership changes; attributable multi-signatures make the malicious signer identifiable in the log |
| Member holding an exit / route grant (M6) | Full plaintext view of everything routed through it, plus drop/redirect | Grant is a quorum-signed log record separate from membership and separately revocable; routes may never overlap the overlay space; route state read only from the log, never from peer advertisements, which can only withhold a grant (an operator's consent); a subnet reaches clients without asking them, but never over what a client reaches by routes of its own inside it (which a hostile LAN can claim by numbering itself so, or by DHCP routes a client does not mark as pushed), and a grant of public space says so; once the network has an access policy (M14), only members it passes use one, enforced at the exit node or router |
| Log-transport attacker | Controls how AUMs reach some nodes | Hash chain prevents forgery/reorder; monotonic epochs prevent rollback; log-head cross-gossip detects split views |
| Supply chain (our updates) | Compromise of release pipeline | Reproducible builds (M7); each release's SHA256SUMS signed by a key `packaging/release-signers` names, and its APKs by the certificate `packaging/android-release.sha256` names; distro repositories (M19, after v1.0); update transparency (roadmap item, not v1) |

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
   loses the discovery layer), and **fail-closed freshness leases**: admin devices —
   members the quorum grants the `admin` role — sign "my head was H at T" every hour;
   a node whose newest lease naming its own chain is older than the TTL (48 h default)
   keeps tunnels only to admin devices. The TTL and the vouching threshold M
   (`juist admins vouchers`, one by default; a new network has no admin device, so
   freshness is unchecked until one is granted) are the knobs: max revocation latency =
   max survivable partition *without M admin devices in it*. A signer inside the
   partition vouches for what it holds, and a lying or revoked admin device can vouch
   for a head from before every removal, so with M = 1 freshness assumes every admin
   device is honest, and with M it takes M dishonest ones to defeat it
   ([11-enrollment-and-freshness-notes.md](11-enrollment-and-freshness-notes.md)). Instantaneous global revocation in a partitioned P2P system is a
   CAP-style impossibility. (Same principle as Rivest 1998 and the Web PKI's move to
   ever-shorter cert lifetimes.)
2. **Admin-quorum custody is the crown jewel.** Lose k-of-n admin keys → the network
   can never be changed again **by design**; that is the security property (Tailscale
   documents the same for tailnet lock). A pre-committed break-glass secret then only
   ends it for good (M12): it disables, it never recovers, so a stolen secret costs
   availability and never custody. Compromise of a full quorum is game over — true of
   every design, centralized or not.
3. **Split-view window under a malicious quorum.** A colluding quorum can briefly show
   divergent logs to disjoint node sets. Cross-gossiped log heads (fork detection)
   expose this after the fact; nothing prevents it in real time short of global
   consensus. Against sub-quorum attackers the hash chain prevents split views
   entirely.
4. **Cold-start availability.** First contact requires the public DHT or one reachable
   member. A network that is 100 % hard-NAT with zero relay-capable members cannot
   form, unless it chooses a public DERP server (planned, see
   [05-roadmap.md](05-roadmap.md), "Networks of phones alone"). DHT eclipse/Sybil
   attacks can *delay* cold start; they can never corrupt membership. Mitigation:
   cache last-known endpoints, advertise "relay-capable" as a first-class role, warn
   when fewer than two exist.
5. **Metadata leakage.** Public DHT storage nodes observe that some IP stored an opaque
   record; member relays observe timing/volume between member IPs; LAN observers see
   blinded-but-present mDNS announcements. Full unobservability requires Tor-class
   machinery — out of scope. Two consequences of the rendezvous design are worth
   naming, since neither is removable at this layer. Running the DHT at all tells a
   passive observer that this host speaks the BitTorrent DHT, which is the
   internet-scale twin of the mDNS leak above — `juistd --no-dht` is the answer for a
   deployment that would rather not, at the cost of off-LAN cold start. And a node's
   *queries* are visible to whichever storage node answers them: each names one
   opaque address, so no query says who is being looked for, but a node that asked
   after all of its missing peers at once would turn that into a count. Lookups are
   therefore capped per round and shuffled, and only members this node holds no
   address for are asked after at all. Public STUN servers (Google's and
   Cloudflare's by default, `juistd --stun`/`--no-stun`) see every node's public
   address and how often it asks, which is what lets two nodes behind NAT find a
   direct path without a relay member. An invite whose link does not reach
   meets the same way: both ends leave a sealed item at a key derived from the
   link's secret, so a storage node learns that two addresses met through one
   opaque key within minutes of each other — who invited whom, to what, stays
   inside the seal. `juist invite --no-dht` and `juistd --no-dht` keep invites off
   the DHT. A public DERP server a network chooses (planned) sees more than
   either: every client's public address and node key, which keys exchange
   packets with which, when and how much, for as long as the pair has no
   other path. A relay on 443 is verified by WebPKI, not by the hash its
   announcement pins: a certificate any CA the device trusts issued for the
   name, forged or a company's that intercepts TLS, puts its holder in the
   relay's position, which is the one above, though a member cannot take
   another relay's name: members ask the server at the name whose it is. A
   device on HTTPS alone asks the relays for the announcements it lacks, so
   they learn which members it looks for, and it puts every packet through
   them.
6. **Enrollment bottoms out at admin-device security.** One-guess PAKE invites and
   full-entropy QR tokens shrink but cannot eliminate the window in which a mis-issued
   invite or a compromised admin device admits an attacker.
7. **Exit nodes concentrate trust in one member (M6).** Traffic leaving the
   overlay through an exit node is plaintext on that member's host — a deliberate MITM
   position for everything routed through it, exactly as with Tailscale or any
   commercial VPN. Two P2P-specific sharpenings: *withdrawing* the grant is
   eventually-consistent (weakness 1 applies to the role itself, bounded by the
   freshness TTL), and no single admin can revoke it unilaterally — it takes a quorum,
   so "turn that exit node off right now" is not an available operation. Bounded by:
   the role is separate from membership and separately revocable; advertised routes may
   never overlap the overlay space, so an exit node cannot intercept member-to-member
   traffic; an exit node carries public addresses alone, so it reaches neither its
   own LAN nor a client's; and a client uses one only when its owner chooses it
   and its operator agreed to serve. Without an access policy (M14) the grant is
   network-wide: every member may use every exit node, so the quorum that grants
   the role decides for all members at once; a policy scopes it, enforced by the
   exit node itself. The exit node answers its clients' DNS
   too, where systemd-resolved runs on them, and so sees their lookups as it sees
   their traffic; names in the LAN's own domain are still asked of the LAN, and a
   hostile DHCP server can claim a wide one, `com` say, as its own domain. While no
   mesh runs, as on a device the network removed, the host's own resolvers answer,
   though its traffic stays refused. A clean restart of the client's juistd lets
   its traffic out directly for the moment in between. Answers to connections
   that came in from the internet leave directly, from the address they were
   sent to, which the one who connected knows already. So a program on the
   host can talk around the exit node with a party it tells its address, where
   the host's firewall lets that party's packets in first, and so can a socket
   bound to the host's own address with a sender who forges the first packet
   from where it will send; a client that must
   send nothing outside the tunnel, not even answers, chooses the exit node
   with `--isolate`.
8. **A real device puts the overlay addresses on the host, where the LAN could
   reach them.** Linux's weak host model makes an address on `juist0` reachable
   through *any* interface, and both default-deny gates sit downstream of WireGuard
   decryption. On Linux juistd therefore drops, in an nftables table of its own
   (`juistNin`, prerouting at raw priority), what comes for this node's overlay
   addresses by another device than its tunnel or loopback, and what comes from a
   member's overlay address by a device that is no juist device. Tailscale drops
   only the second. What this costs: a container or VM on a bridge of the host no
   longer reaches the host's own overlay address, and a LAN host no longer reaches
   a subnet router's. **FreeBSD is still open**: it takes an address by any
   interface too, and pf, which juist runs only to serve or use an exit node, is
   where the same two rules belong. There a service bound only to an overlay
   address stays LAN-reachable, and an overlay source is no evidence that a packet
   came through the tunnel. The package's installer, not the
   daemon, does touch the host firewall once, in the other direction: where
   firewalld or ufw runs it lets everything in on `juist0`, as Tailscale's own
   rules do for `tailscale0`, because a host firewall that drops the overlay
   silently breaks gossip — and with it removals. So without an access policy
   (M14) **every member can reach every port the host listens on through the
   tunnel**; with one, what it passes; the host firewall still guards every
   other interface, and
   `/usr/lib/juist/firewall.sh revoke` takes the rule back.
9. **A host's networks trust one another's juistd (M5).** A host in several
   networks runs one juistd per network, all as the `juist` user. An attacker
   who takes over one of them, through a parser bug a member of that network
   reaches, can read the other instances' device keys and operate them over
   their sockets. That makes the attacker this device in every network the
   host is in. It gains no admin key and no vote in any of them. Each
   instance already holds `CAP_NET_ADMIN` and could redirect the host's
   traffic anyway, so the step from one network to all of them on that host
   is the device keys. Bounded by: a device is still removed from each network
   by that network's quorum. A user per instance, which would close it, needs
   the packaging and each instance's view of the one below reworked, and is
   left for the hardening before the audit (M17).
10. **Admin devices see what waits for the admins (M5b).** A change waiting
   for votes is sealed to the admin keys, but the juistd of every admin device
   that carries it sees its outside: which admin key handed it on, when it
   expires, how large it is, and which devices it is about. A compromised
   admin device can tell a device that its removal waits. A compromised admin
   key can put changes in front of the other admins, within the bounds of 16
   changes and 8 MiB per signing key. Neither makes a change
   count: that still takes the quorum's signatures, each given where its
   admin was shown the change from their own log.
11. **An access policy scopes traffic, not what members know (M14).** Every
   member keeps the whole log, the policy in it: which members exist, their
   names, keys, overlay addresses and roles, and who may open what on whom.
   What a member does not learn of one the policy keeps apart from it is its
   underlay addresses, sealed for its peers under a pair key that mixes in
   the pair's preshared key once it has one (M15); mDNS still shows the LAN a
   beacon's source address.
   Relays and vouchers peer every member, so each learns every member's
   addresses, as a relay already sees its clients' from DERP; in a network
   with neither, every two members keep a tunnel for log sync, and so learn
   each other's addresses. A policy change is eventually consistent as a
   role is (weakness 1): a member that has not heard of a narrowing still
   passes what it passed, until its view is stale past the TTL, when it
   keeps its vouchers for juist's own traffic alone. A narrowing stops what
   may be opened next at once; a connection the receiving member itself
   opened before goes on until it ends, and a peer set the data plane
   refuses leaves the one before it in place, as with a removal. Each member
   enforces what it receives: a member that ignores its own policy reaches
   nothing the receiver does not pass, and a member that ignores the
   receiving side lets in what it chooses, its own risk. Past the target
   scale, address keys beyond a hello's 2 MiB travel in their owners' own
   hellos alone.

12. **A tunnel is post-quantum against outsiders at once, against members
   once its pair has a key (M15).** A pair's first preshared key comes from
   the group secret, so a member holding that epoch's secret, one removed
   since included, and a quantum computer could read what the pair sent on
   it: until the pair's first exchange, one log sync after its tunnel comes
   up, and while one of the two is behind. Every member keeps the seeds of
   64 epochs, so a device stolen later gives those epochs' group keys. A
   pair's own key is held by the two alone, and a device stolen later gives
   its pair keys and, recorded, what was sealed under them: no forward
   secrecy beyond WireGuard's own, which a quantum computer breaks. A
   member's announcement says whether it sets preshared keys; one that says
   not, an older build or one behind the upgrade, is kept to juist's own
   traffic, which seals itself. A pairs file restored from an older copy can
   leave its device on a key its peer has moved past, cutting that tunnel
   until the file is removed and the device starts a store of its own.

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
  as root (M3a; see `packaging/systemd/juistd.service`). `CAP_NET_BIND_SERVICE`
  joins it on a relay named on 443 alone, by a drop-in root's
  `juist set --relay-name` writes and takes back; on FreeBSD the root helper
  binds 443 alone, while root's grant is in place and nothing answers there.
  This widens what a
  compromised `juistd` can do to the *host*, not to the *network*: it still holds
  no admin keys and still cannot authorize a membership change. On the host,
  `CAP_NET_ADMIN` over netlink is broad. `ProtectKernelTunables` keeps it from
  setting sysctls, but it can create and rename interfaces (a `juist0` of its
  own choosing inherits the trusted firewall zone), set routes, flush the
  host's nftables rules, and mirror traffic from other interfaces with `tc`.
  Treat a compromised `juistd` as one that controls the host's network
  configuration. Attacker-facing parsers (gossip, IPC,
  later the DHT) get no privilege from this. FreeBSD has no such capability, so
  there juistd splits (M7a): a helper stays root and does four things, for
  devices named `juist0`–`juist9` it made itself and holds a lock on —
  create, address with single hosts, route, destroy — and the daemon runs as
  `juist`. A compromised daemon can route any prefix but a default into its
  own device, and so take the host's traffic, as on Linux; it reaches no other
  interface, firewall or sysctl. The helper parses one CBOR request at a time
  from the daemon alone, and a compromised helper is root. Serving and using
  an exit node (M7b) add sysctl forwarding, pf anchors under `juist/`, and
  resolvconf(8) for the device's resolvers; the pf rules are the helper's
  own text around the daemon's prefixes and addresses, never text the
  daemon wrote, and juistd's uid in them is the one the helper started it
  as.
