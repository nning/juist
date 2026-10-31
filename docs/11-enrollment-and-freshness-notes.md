# 11 — Enrollment and freshness notes

The choices behind enrollment and freshness that a reader of the code would
otherwise have to reverse-engineer, the rules a later change must keep, and
what is still open.

Packages: `trust/enroll` (SPAKE2, invite codes, the enrollment protocol — in the
audit scope), `types.Lease` and `trust/log/lease.go` (freshness), `daemon/fresh.go`
(issuing, holding and enforcing leases), `discovery/mdns/invite.go` (finding an
invite on the LAN), `internal/guest` (the joining side), and the CLI in
`cmd/juist`.

## The command line is the product loop

`create`, `invite`, `join`, `status`, `devices`, `remove`, `rotate` are what a
person uses; `grant`, `approve`, `apply`, `admins` and `log` are what an admin
of a multi-admin network uses. Every command that changes the network goes
through one path (`cmd/juist/changes.go`): sign with every local key that has
a part in the record, apply it if that authorizes it, and otherwise write it to
the working directory and carry it to the admin devices for the other admins.
Pending is an outcome, not an error: with a quorum above one no machine can
finish a change.

Defaults a user does not have to choose: `create` names the network with two
random words of the PGP word list, the device after its host and the admin key
after the user; the network numbers from a random /22 in 198.18/15; the first
device gets its first address and the admin role, and every admitted device the
next free address. A name another member uses gets a numeric suffix, because
devices are removed by name.

## The daemon owns the device; the person owns the keys

juistd runs from installation, in no network, and holds everything that is the
device's: its keys, its log, its hints. It creates a network from a genesis the
CLI signed, and redeems an invite itself. The CLI holds everything that is the
person's: admin keys in `~/.config/juist`.

Where the two meet, the daemon is the less trusted side: it runs the parsers an
attacker reaches first. The CLI verifies the daemon's chain in memory and
against the keystore's own pin (`networks/`: the head it last verified, that
head's `SigHash`, and the admins and threshold that governed it), signs against
that, and hands back only signed records. It signs nothing the daemon built
without rebuilding it: a rotation record must be the one the CLI's own log
produces for the staged keys, and come with proof by the device's current
identity key, since which device it is is the daemon's word too. A later log
must hold the pinned head or a copy of it; failing that, either this side's
own fork choice over the chain and the daemon's orphans rejects the head, or a
checkpoint a quorum of the pinned admins signed, descending from the head,
stands in for it once compacted away. A truncated log passes neither. A daemon
that turns up holding another network is refused until the person deletes the
pin naming the old one.

**The inviting half runs in the daemon too.** `juist invite` asks juistd to
offer the invite (`CmdInvite`, `internal/host`): listener, LAN answers, DHT and
sessions run there, apart from the admin keys. When a guest proves it knows the
invite, the daemon asks the CLI to admit it on the same connection. The CLI
builds the AddNode from its own verified log, signs it, waits for the other
admins if it must, and answers with an *admission*: the admin key's signed
statement that this guest is a member as of a head. The link names that admin
key, and a guest holding one stores nothing unless the admission verifies,
names it, and names a head on the chain it was sent. So a compromised juistd on
the inviting device can refuse or stall a guest, but not enroll it into a
network of its own. The typed code carries no admin key, so for it the device
that answers is trusted, which is one reason it stays LAN-only.

Who may call the daemon is decided per call from the kernel-reported uid (see
[04-architecture.md](04-architecture.md)): status for everyone, the rest for
root, the daemon's user and the operator. `sudo juist join` appoints whoever
ran sudo, and a user who is not the operator is offered `sudo juist set
--operator` instead of retrying as root, which would put their admin keys in
root's keystore and is refused.

Without a daemon — a developer's `--home`, a test, an air-gapped signing
machine — the CLI does the same work on a state directory itself.

## Invites

**One protocol, two secrets.** A typed code (`42-drumbeat-tolerance-glucose`: a
nameplate from 1 to 999 and three words of the PGP word list, 24 bits) and a
link (`juist:` plus 128 random bits and the host's addresses) both run SPAKE2
(RFC 9382, the edwards25519/SHA-256/HKDF/HMAC suite) with the secret as the
password; one handshake to audit. `TestSPAKE2Constants` regenerates M and N
from the RFC's seeds, and `TestKeyScheduleMatchesRFC` checks the transcript and
key schedule against the RFC's P-256 vectors, which is why the schedule takes
encoded elements. `w` is SHA-512 of the password reduced mod ℓ, without a
memory-hard function: `w` is never stored, and without the transcript's `K`
there is nothing to test a password against offline.

**Exactly one guess, and only a guess spends it.** The guest confirms first. A
wrong code voids the code, and the link still works
(`TestAWrongCodeVoidsTheInvite`), so nobody on the LAN can end the whole
invite with one connection. A wrong link voids nothing: 128 bits are not
guessed online. The code is taken only from the LAN
(`TestTheCodeIsTakenFromTheLinkAlone`), never through the DHT or from a routed
address, and 32 hellos for other nameplates retire it
(`TestNameplateMissesRetireTheCode`). Anything that tells a guest whether its
guess was right spends the invite, including an element built from the code
itself (`TestAnElementBuiltFromTheCodeIsItsOneGuess`). A session that ends
before the guest's confirmation leaves the invite open, so a port scan does not
kill it. Sessions are serial. A nameplate the host does not hold is refused
before any key exchange. A host that answers without knowing the code cannot
produce the host's confirmation, and the guest reports an impersonator.

**Finding the host.** A code is found by asking the LAN over mDNS who answers
for its nameplate; the answer carries the TCP port and an instance id, so one
host on two interfaces is one host. Two hosts answering for one nameplate are
refused rather than guessed between, since the wrong one would spend the
invite. The link carries the host's addresses. The invite listens on TCP 41642
unless that is taken, so a firewall can be opened for it once.

**Two devices behind NAT.** A link whose addresses the guest cannot reach is
met through the public DHT (`internal/rendezvous`). The link's secret derives,
through HKDF, two DHT keys and a sealing key. Each side leaves its STUN-learned,
LAN and IPv6 addresses sealed at its key, and both send UDP toward the other's
until one gets through. The path carries a small reliable stream, and the
enrollment runs over it unchanged: nothing on the path is trusted, and an
injected packet can end a session but not spend a guess. The link's own
addresses get a two-second head start. It fails where both NATs pick a new port
per destination, and the join says so. The DHT nodes are clients (BEP 43), so
a stranger cannot have them store puts. The typed code stays LAN-only: 24 bits
hold against one online guess, not against a DHT key anyone can compute
offline.

**Through a member's relay.** Without the DHT, and where both NATs defeat
punching, the link reaches the host through a relay of the network's own. The
inviting daemon keeps connections waiting at each relay-capable member's relay,
its own last, over TLS pinned to the certificate that member announces,
registered under the link's forward id (HKDF of the secret, one way) and a
signature by its identity key over the relay's certificate hash, the id and a
relay nonce. The relay checks the signer is a live member. The link names the
relays (`r=`), the host's own too, which is all a guest on HTTPS alone reaches
where no other relay serves a name; the guest asks one for the id and the
relay joins the two connections, so it learns the id, the addresses and the
traffic's size, and cannot answer for the host. It bounds what it holds (`relay/forward.go`). The host counts a forwarded
guest by the address the relay reports, and takes no code hello through it.

**Firewalls.** The packages install firewalld services and ufw profiles for
the fixed ports — `juist` for 41643/udp, `juist-relay` for 41645/tcp+udp,
`juist-invite` for 41642/tcp — and let `juist0` in where either firewall runs,
which log sync needs, since it runs inside the tunnel (residual weakness 8 in
[02-threat-model.md](02-threat-model.md)). The guest hands the host its signed
announcement with its confirmation, so a host behind NAT learns where a guest
with a public address is without the DHT. Default ports another program holds
fall back to OS-chosen ones; explicit ones do not. `juist invite` prints the
command that opens its port if the firewall is closed to it, and `juist status`
warns when firewalld keeps log sync out of `juist0`.

**What travels.** Inside the channel: the guest's public keys, a signature by
its identity key over the channel binding (so the request cannot be replayed
into another session), then the log from the host's anchor, member
announcements and leases. The guest stores the log only if it admits this
device under exactly these keys and the group secret opens. Hints are signed by
their authors and grant nothing.

**One invite admits one device, and a person compares it.** The CLI answers
one admission per invite. Through a daemon, it shows the joining device as four
words, which `juist join` shows on the device, and asks before it signs. The
words hash the identity, every key, a salt the admin draws and a nonce the
guest draws; builds hashing a different set show different words, so a join
between them is refused. The join request commits to the nonce, the admin
draws the salt after it, and the guest reveals the nonce only after accepting
one salt, so a daemon in the middle gets one try at 32 bits on either screen,
not a search over salts.

**More than one admin.** The invite submits the admission for the others to
approve, tells the guest how many votes it has, and waits until the device
appears in its log, applied here or gossiped from another admin's device. The
invite's expiry covers the wait.

**Rejoining.** A removed device is never told it was removed, and its own log
still lists it. So `join` accepts a device that holds a log and takes the new
records into it, keeping its ratchets (`guest.Extend`). Where the invite's chain
no longer continues that log — the device fell behind the chain its peers kept
— the log is replaced (`Authority.Rebase`) only on an admin's admission, so only
by link, and only by a chain whose anchor a quorum of the log's admins signed,
at a later epoch. A join refuses an invite for another network.

## Freshness

A node's view of the network may be missing a removal it has not heard of. A
**lease** is an admin device's signed statement "my head was H at time T"; a node
holding one that names a record on its own active chain knows it has at least
what the signer had at T. With not enough such leases younger than the TTL (48 h
by default, `juistd --freshness-ttl`, set by the acceptor), the node is
**stale** and keeps tunnels only to admin devices, dropping every other peer in
both directions: the fail-closed half of residual weakness 1 in
[02-threat-model.md](02-threat-model.md). Leases are gossiped in every records
frame and persisted, so a restarted node knows its freshness before it hears
from anyone.

**Who signs: admin devices, not admin keys.** A quorum-signed lease would need
k admins online daily, and a key-signed one would put an admin key in the
daemon. So the signer is a member the log grants the `admin` role, whose daemon
signs with its identity key. The grant is quorum-signed and revocable; an admin
device can vouch for freshness and change nothing about membership. The CLI
calls these devices *vouchers* (`juist grant vps voucher`); the log keeps the
value `admin`, which the CLI still accepts. These notes say "admin device".

**Why stale keeps admin devices.** Two members behind NAT sync only through
their tunnel, and the leases that would make the node fresh come from exactly
those devices.

**How many must vouch.** A lease names a head and the anchor is on every
chain, so one lying admin device can keep any node it reaches fresh on a view
from before every removal. The log therefore holds a threshold
(`KindSetVouchers`, `juist admins vouchers M`): a node is fresh while M distinct
admin devices have vouched within the TTL, from the M-th newest of their
leases. The threshold cannot exceed the admin devices there are. With M = 1 the
rule is "every admin device is honest"; with M, it takes M of them.

**What the design admits.** Admin devices inside the victim's partition keep
the partition fresh. A revoked admin device can keep vouching for the head
before its removal to anyone who has not seen it, which is why the threshold
exists. A network with no admin device does not enforce freshness, and
`juist status` says so. Too few admin devices online for longer than the TTL
take every other member down to admin-only tunnels. A node that cannot see past
a schema upgrade vouches for nothing, since its view ends before every removal
after it.

**No voucher by default.** Fail-closed freshness costs availability unless
vouchers are always on, and with every device a voucher at M = 1 it checks
nothing, since a voucher vouches for itself. So `juist create` makes the founder
a voucher only with `--voucher`, a network with none says `unchecked: no
voucher`, and removals still spread by gossip, the epoch bump and the rotated
group secret. Where vouchers are used:

- they are hosts that are always on and fail apart: two of three at M = 2, not
  two machines in one cloud account;
- a relay is not the one voucher at M = 1, since it can withhold the removal
  and vouch for the old head alone;
- `juist create --voucher`, `juist grant` and `juist admins vouchers` warn of
  a set with no spare or a relay as the one voucher needed; `juist status`
  warns before freshness ends and suggests two relays as vouchers where none
  vouches;
- a longer `juistd --freshness-ttl` suits a network with no device that is
  always on; it is per acceptor, not in the log;
- changes waiting for votes are carried by admin devices
  ([05-roadmap.md](05-roadmap.md), M5b), so a quorum above 1 hints a voucher
  where there is none.

**One tier of revocation.** Every removal bumps the epoch
([08-trust-layer-notes.md](08-trust-layer-notes.md)), and the bump renews every
pair's preshared key, which the next handshake takes up. `juist rotate
group-secret` remains for a suspected group-secret leak with no one to remove.

## Rules a later change must keep

- **Abandoned keys are never overwritten.** Each abandoned set is its own file,
  and every one is a candidate once the log names it, with or without a running
  mesh.
- **An identity rotation needs both keys**, or admins alone could move a
  member's slot, and an admin device's role with it, to a key of their choosing.
- **Which device the daemon is, is proved, not told.** A rotation comes with a
  signature by the device's current identity key, which the CLI checks before
  it signs, so a daemon cannot move another member's slot.
- **A join by link anchors the keystore in the admin's admission.** The CLI
  checks the admission against the link's admin key and pins that network and
  head before it reads the daemon's log, so a juistd compromised before the
  join cannot have its own network pinned.
- **A record is checked before it is signed, and before it is applied.**
  `approve` refuses a record that could not apply to the log as held
  (`Builder.Check`). `approve` and `apply` refuse a record started before the
  latest change that would win or lose on its hash, since winning would undo
  every change since; a removal still goes through, as a revocation never
  loses, with a warning that it undoes those changes.

Accepted, and stated here rather than fixed:

- **Rotating the only admin device's identity makes every member stale** until
  it vouches under the new identity, a reconcile later. Keep two admin devices,
  or rotate while both are online.
- **Stale mode drops only tunnels.** A stale node still gossips with anyone
  holding the group secret, which is how it catches up, and still relays if it
  is a relay. Neither grants membership.
- **Freshness trusts the local clock.** A node whose clock is set back stays
  fresh on an old lease while it is behind; membership expiry has the same
  exposure.
- **A LAN attacker can make a join by code fail**, answering for the nameplate
  under a second instance id or racing the real host's id. The invite is not
  spent, the attacker learns one guess per join at most, and answers are taken
  only from the host's own subnets. The link does not depend on mDNS.
- **Serial sessions can be slowed.** Silent connections cost nothing; one that
  sends a hello holds the session up to ten seconds, and each source may queue
  one more. The invite is never spent by them.
- **The readers' pool on the socket is shared.** Two local users, or one with a
  range of subuids, can keep other unprivileged users from reading the status.
  Root and the operator have a pool of their own.

## Still open

- **An invite with no relay between two hard NATs.** The rendezvous punches
  through every NAT that keeps one public port per socket, and a member's relay
  forwards the rest; a network with no relay-capable member other than the host
  has no way through two NATs that pick a port per destination.
- **A removed device learning it was removed, where it was offline.** The device
  a removal is applied on hands it to every member it removes before applying it
  (`daemon/farewell.go`). A removed device that was offline then, or whose
  tunnel was down, is not told: it keeps reporting itself connected, and as a
  voucher its own leases keep it fresh. Its catch-up needs a tunnel too. Telling
  it takes a path that does not need its WireGuard peer, such as a signed
  refusal handed over by a relay.
- **Vouchers that fail together.** Two vouchers at one provider count as two,
  and nothing in the log says where a device runs, so the warnings cover only a
  set with no spare and a relay as the one voucher needed.
