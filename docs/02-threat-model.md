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
| Network observer (on-path) | Read/inject/drop packets anywhere between members, and record them for a quantum computer later | WireGuard (Noise IKpsk2) with a preshared key from ML-KEM-768 (M15); control traffic signed by ML-DSA-44 and/or inside tunnels; enrollment SPAKE2 with ML-KEM-768 (residual weaknesses 12, 13) |
| Malicious rendezvous infra | Controls public DHT nodes / STUN servers we query | Trust-free construction: DHT/STUN can delay discovery (DoS), never alter membership; announcements AEAD-encrypted, topics blinded |
| Evicted member | Was a member; retains all old keys and state | Signed revocation records + epoch bump (loses group secret → loses discovery) + WG peer removal + fail-closed freshness TTL |
| Stolen/lost device | Full key material of one member | Same as evicted member, after detection; per-device keys mean no shared secrets to rotate |
| Compromised admin, below quorum | One admin key (or few, < k) | k-of-n quorum for membership changes; attributable multi-signatures make the malicious signer identifiable in the log |
| Member holding an exit / route grant (M6) | Full plaintext view of everything routed through it, plus drop/redirect | Grant is a quorum-signed log record separate from membership and separately revocable; routes may never overlap the overlay space; route state read only from the log, never from peer advertisements, which can only withhold a grant (an operator's consent); a subnet reaches clients without asking them, but never over what a client reaches by routes of its own inside it (which a hostile LAN can claim by numbering itself so, or by DHCP routes a client does not mark as pushed), and a grant of public space says so; once the network has an access policy (M14), only members it passes use one, enforced at the exit node or router |
| Log-transport attacker | Controls how AUMs reach some nodes | Hash chain prevents forgery/reorder; monotonic epochs prevent rollback; log-head cross-gossip detects split views |
| Supply chain (our updates) | Compromise of release pipeline | Reproducible builds (M7); each release's SHA256SUMS signed by a key `packaging/release-signers` names, and its APKs by the certificate `packaging/android-release.sha256` names; distro repositories (M33, after v1.0); update transparency (roadmap item, not v1) |

## Out of scope / consciously accepted

- **Full admin quorum compromised** — game over in any design; mitigated only by key
  custody practices (hardware-backed keys, geographic separation of admins).
- **Endpoint compromise of a valid member** — the VPN admits the device; host security
  is not our layer. Post-compromise security exists only *after* detection + revocation.
- **Global passive adversary / traffic analysis** — relays and DHT interactions leak
  timing, volume, and IP metadata. Full unobservability is a non-goal (see residual
  weaknesses).

## Residual weaknesses — fundamental, tunable, not removable

Bounded, not removable: anyone adopting juist accepts them. Other documents cite
them by number.

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
   consensus. Against sub-quorum attackers the hash chain prevents split views,
   except the one compaction leaves (weakness 14).
4. **Cold-start availability.** First contact requires the public DHT or one reachable
   member. A network that is 100 % hard-NAT with zero relay-capable members cannot
   form, unless it chooses a public DERP server (planned, see
   [05-roadmap.md](05-roadmap.md), "Networks of phones alone"). DHT eclipse/Sybil
   attacks can *delay* cold start; they can never corrupt membership. Mitigation:
   cache last-known endpoints, advertise "relay-capable" as a first-class role, warn
   when none exists.
5. **Metadata leakage.** Public DHT storage nodes observe that some IP stored an opaque
   record; member relays observe timing/volume between member IPs; LAN observers see
   blinded-but-present mDNS announcements. Full unobservability requires Tor-class
   machinery — out of scope. Two consequences of the rendezvous design are worth
   naming, since neither is removable at this layer. Running the DHT at all tells a
   passive observer that this host speaks the BitTorrent DHT, which is the
   internet-scale twin of the mDNS leak above — `juistd --no-dht` is the answer for a
   deployment that would rather not, at the cost of off-LAN cold start. And the
   DHT **links members' addresses**: an item's address is one member's for an
   hour, and the storage nodes closest to it, among which anyone can place
   nodes of their own, see the address that puts it and every address that
   asks for it, and so learn that these are in one network, though not which
   network or who. A member is asked after while it is unheard, while its
   tunnel does not answer (every 30 s at first, backing off to an hour), and
   by a stale node, so what a storage node gathers is cold starts, moves and
   broken paths, never a mesh that works. The member relays are asked first,
   as members they learn nothing new from it, and the DHT only by a device
   that reaches no member, is stale, or holds the lowest identity among
   those it reaches: what it finds, gossip hands the others, so a storage
   node links the members sought to one address of a group, not to each.
   Asking after every missing peer at
   once would add a count, so lookups are capped at four a round and
   shuffled. Whoever sees a query on its way can fetch the item for the rest
   of the hour, and learns from it what a storage node does, less the
   address that put it. Without an item's address the DHT tells a stranger
   nothing: it keeps no index to ask. An item shows neither the epoch it is
   sealed under nor its author's length
   ([10-connectivity-notes.md](10-connectivity-notes.md)). Public STUN servers (Google's and
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
   them. A walled device, one that reaches some relays by TCP alone (M22),
   does so without `--https-only` too, and meets every member at its own
   home: that one relay sees the timing and volume of all its pairs and can
   stop all of them, where they were spread over the peers' homes, and as
   every member homed at a relay without a name keeps a connection to it
   while the device is walled, it sees which of those run then. A relay is given no right over another, and sees
   node keys and WireGuard ciphertext alone, as before.
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
   too, and so sees their lookups as it sees their traffic; where
   systemd-resolved runs, names in the LAN's own domain are still asked of the
   LAN, and a hostile DHCP server can claim a wide one, `com` say, as its own domain. While no
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
   reach them.** Linux and FreeBSD deliver to an address on `juist0` by *any*
   interface (the weak host model), and both default-deny gates sit downstream
   of WireGuard decryption. juistd therefore drops what comes for this node's
   overlay addresses by another device than its tunnel or loopback, and what
   comes from a member's overlay address by a device that is no juist device:
   on Linux in an nftables table of its own (`juistNin`, prerouting at raw
   priority), on FreeBSD in a pf anchor of its own (`juist/juistN_in`), pf run
   for it where it was off (M24). Tailscale drops only the second. What this
   costs: a container or VM on a bridge of the host no longer reaches the
   host's own overlay address, and a LAN host no longer reaches a subnet
   router's. What remains: on FreeBSD, where the host loads pf rules of its
   own that do not call juist's anchors first, the guard cannot load; the
   device runs without it, as refusing would cost every member's tunnel, and
   `juist health` says so. The package's installer, not the
   daemon, does touch the host firewall once, in the other direction: where
   firewalld or ufw runs it lets everything in on `juist0`, as Tailscale's own
   rules do for `tailscale0`, because a host firewall that drops the overlay
   silently breaks gossip — and with it removals. So without an access policy
   (M14) **every member can reach every port the host listens on through the
   tunnel**; with one, what it passes; the host firewall still guards every
   other interface, and
   `/usr/lib/juist/firewall.sh revoke` takes the rule back.
9. **A host's networks share the host (M5, M24).** A host in several networks
   runs one juistd per network, each as a user of its own (`juist`, then
   `juist1` to `juist9`), in a home only that user reads. An attacker who
   takes over one of them, through a parser bug a member of that network
   reaches, reads no other instance's device keys and may only read the
   others' status, as any local user may: no member's name or identity.
   What remains is what the network capability gives every instance: it can
   route what the host sends to another network's overlay addresses into its
   own device, as overlay space may overlap, and read what the host sends
   there; not what members send each other, and no key. On FreeBSD the
   daemon has no such capability, but its helper routes into its device
   what the daemon asks, the host's own address and gateways excepted, so the
   same holds. Bounded by: the attacker is still this device in its own
   network alone, which that network's quorum removes it from. Once, on the
   upgrade to M24, root moves each instance's home out of the default's, a
   directory the `juist` user held, and gives on only what was that user's;
   a taken-over default daemon holding a directory of it open could still
   swap a name for a hard link to another's file while that runs, on
   FreeBSD, where any user may make one (Linux's `fs.protected_hardlinks`
   forbids it).
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
   scale, address keys beyond a frame's 2 MiB travel from their owners
   alone.
12. **A tunnel is post-quantum against outsiders at once, against members
   once its pair has a key (M15).** A pair's first preshared key comes from
   the group secret, so a member holding that epoch's secret, one removed
   since included, and a quantum computer could read what the pair sent on
   it: until the pair's first exchange, one log sync after its tunnel comes
   up, and while one of the two is behind. A device stolen later opens
   every epoch secret sealed to the keys it still holds, in its log or
   recorded off the wire, until `juist rotate` replaces them, and with them
   those epochs' group keys. A pair's own key is held by the two alone,
   derived from both sides' static ML-KEM-768 keys with no ephemeral part,
   and a device stolen later gives its pair keys and, recorded, what was
   sealed under them: no forward secrecy beyond WireGuard's own, which a
   quantum computer breaks. A pair moving from one preshared key to another
   keeps its running WireGuard session until the next handshake, at most
   two minutes. A
   member's announcement says whether it sets preshared keys; one that says
   not, an older build or one behind the upgrade, is kept to juist's own
   traffic, which seals itself. A pairs file restored from an older copy can
   leave its device on a key its peer has moved past, cutting that tunnel
   until the file is removed and the device starts a store of its own.

13. **What a quantum computer still forges.** Every record, announcement,
   address key, lease, waiting change, pair-key and catch-up message and
   admission is signed by ML-DSA-44 and verified by it; a log, genesis or
   checkpoint below schema 18 is not read. ML-DSA signs a labelled SHA-256
   digest of the canonical encoding, deterministically, so that one key
   signing one record twice makes one record. Three things are still taken
   on Ed25519 alone, which a quantum computer forges. Hints, the DHT's, a
   relay's rendezvous's and the LAN's copies of announcements, sealed under
   the epoch's key: a member, or a device removed within the last four
   epochs, points another member's dialing elsewhere (its addresses, gossip
   port and home relay), and where no announcement of that member is held,
   or this device reaches it by no tunnel, names its disco key too, which
   costs that member's dials alone: a member's disco key is new each run,
   and log sync runs through the tunnel, so after a restart hints alone
   bring it. The gossip port it names is the port this device may open to
   that member under a restricted access policy. A hint naming another
   disco key has its member probed at once, two probes missed in a row
   finding it down; it changes the disco key of no tunnel that answers,
   nor an announcement's relay, epoch or pair store, makes no member
   rest and be checked quietly, adds no
   relay, relay name, route or consent, and a disco key it shares with an
   announcement leaves the hint's member out, not the announcement's. A
   device known by a hint alone exchanges no pair key, its preshared key is
   this device's newest group key or the pair key held, whatever the hint
   names, and the WireGuard handshake is keyed by the log. A catch-up
   answer from a device the asker's log does not name yet, which hands over
   only records the asker verifies by ML-DSA. A host's proof to its relay,
   and a relay's ECDSA certificate, a relay being trusted for liveness
   alone. Enrollment adds ML-KEM-768 to SPAKE2, so a recorded one opens to
   nobody, and its words cover every key of the new device, its ML-DSA key
   included. juist's TLS between its own ends is 1.3 with X25519MLKEM768
   alone, except the relay client of the embedded Tailscale stack, which
   takes what a relay offers: an honest relay offers X25519MLKEM768 alone,
   and whoever ends TLS as the relay learns nothing a relay does not. A
   release is signed by ssh-ed25519 alone until the OpenSSH that Debian
   stable and FreeBSD install verifies ML-DSA.
14. **A member can have devices compact early (M19).** juistd compacts its log
   to the checkpoint before the newest once every live member has been heard
   with a head past the newest, or one has compacted that far, and a hello's
   head and anchor are not signed: a member, or a device removed within the
   keyring's window, that lies about the others makes devices drop what lies
   below that checkpoint before a member behind has it. That member catches
   up from the chain each compaction keeps, and one further behind is invited
   again. A change made below the anchor, as a removal of the liar from an
   admin device that slept through two checkpoints, is refused where devices
   compacted and taken by fork choice where they did not: the two hold
   different members, and neither alarms. A lying member that has devices on
   both sides of a long partition compact on their own side splits them for
   good, each refusing the other's records. No record is ever accepted on
   that word.

15. **Strangers can still crowd a member out of a relay (audit 2026-10-19).**
   A relay holds the connections nothing admitted yet by site (an IPv4 /24,
   an IPv6 /48), group (an IPv4 address, an IPv6 /56) and host, and a
   newcomer past a bound closes the oldest of the largest. Who churns
   connections faster than a member's TLS and DERP handshake completes still
   pushes the member out where it shares the member's group, holds about
   256/m groups of the member's site while the member's group holds m, or
   holds as many sites as the 1024 in all (for IPv6 one /38). Behind NAT64
   every IPv4 client is one host. A rendezvous stream whose peer is never
   heard at the address it first heard follows the first other source after
   three quiet keepalives, a stranger's on the path among them. A walled
   device's every pair runs through its home, so a member crowded out there
   is cut off from it, though it reaches the member's own home.

16. **Strangers can delay a member's log sync that waits on a round trip
   (refactoring 2026-10-19).** A node holds eight connections that have
   said nothing yet, past which it closes the oldest of the host holding
   the most in the group (an IPv6 /56) and site (an IPv4 /24, an IPv6 /48)
   holding the most; who opens about eight a round trip from seven sites,
   from fewer against several silent members of one site (a household, a
   CGNAT pool), or from the member's own host, still closes a member's
   before it authenticates where that takes a round trip, as a catch-up
   does. A member whose hello comes at once is rarely held up.
17. **Members are on one link for discovery (M25).** A member's UDP to a
   multicast group, mDNS, SSDP and LLMNR among it, and its pings to an IPv6
   group, reach every other member's host, as a LAN neighbour's would:
   it can answer for any name or service those protocols ask about, as a
   printer or a media server, and a host that trusts a discovered service
   trusts the member. Each datagram carries its sender's own address, so
   the answer names who gave it; nothing but the sender's own address
   passes, at most 100 datagrams a second from each. Under an access
   policy only what a `pass multicast` rule passes crosses, with the
   unicast answers to it for ten seconds. On Linux, echo replies to a
   member's link-local address on its device go untracked, since conntrack
   takes an answer to a group ping for invalid and firewalld drops those.

## Security design rules derived from the above

- No component outside the member set is ever trusted for *integrity* of membership —
  only, at worst, for *liveness* of discovery.
- Every message that changes state is signed and chained; every message that carries
  state advertises the log head.
- Freshness is enforced by the *acceptor* (fail closed), never assumed from the sender.
- juistd forwards a name only where the host's systemd-resolved would send it, else
  refuses it, and refuses one resolved would ask over DNS over TLS only where the
  plaintext would cross the device's own local network (its resolver, no exit node
  in use), not for members, whose queries leave at the exit node's site.
- On a phone, juistd's resolver (M23) answers the phone's own packets alone,
  taken before the engine, never a member's, and the reverse names of the
  network's addresses itself, as every resolver of juistd's that the host
  asks alone does; it asks the network beneath the
  VPN what it does not answer as Android would, over unauthenticated TLS where
  Android's automatic Private DNS found the resolvers answering it and in plain
  text otherwise, and leaves the phone's DNS alone where Private DNS names a
  host, which then sees every lookup as it did before juist.
- Prefer attributable signatures (audit trail) over threshold/aggregated ones.
- The data plane never depends on the group secret alone: WireGuard's handshake
  holds without it, and a pair key replaces it as the preshared key; discovery
  privacy never gates data-plane security.
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
  the DHT) get no privilege from this. FreeBSD has no such capability, so
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
