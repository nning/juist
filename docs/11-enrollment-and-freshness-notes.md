# 11 — Enrollment and freshness notes

What M4 decided, in the spirit of [08-trust-layer-notes.md](08-trust-layer-notes.md)
through [10-connectivity-notes.md](10-connectivity-notes.md): the choices a
reader of the code would otherwise have to reverse-engineer, and what is still
open.

Packages: `trust/enroll` (SPAKE2, invite codes, the enrollment protocol — in the
audit scope), `types.Lease` and `trust/log/lease.go` (freshness), `daemon/fresh.go`
(issuing, holding and enforcing leases), `discovery/mdns/invite.go` (finding an
invite on the LAN), and the CLI in `cmd/juist`.

## The command line is the product loop

`create`, `invite`, `join`, `status`, `devices`, `remove`, `rotate` are what a
person uses; `grant`, `approve`, `apply`, `admins` and `log` are what an admin
of a multi-admin network uses. Records, keys and the log directory are no
longer things an operator handles by hand. Every command that changes the
network goes through one path (`cmd/juist/changes.go`): sign with every local
key that has a part in the record, apply it if that authorizes it, and
otherwise write it to the working directory for the other admins. Pending is an
outcome, not an error: with a quorum above one no machine can finish a change.

Defaults a user does not have to choose: `create` names the network with two
random words of the PGP word list, as Tailscale names a tailnet, the device
after its host and the admin key after the user; the network numbers from a
random /22 in 198.18/15, such as 198.18.36.0/22; the first device gets its
first address and the admin role, and every admitted device the next free
IPv4 address, so `ping 198.18.36.2` works without anyone having assigned it. A name
another member uses gets a numeric suffix, because devices are removed by name.

## The daemon owns the device; the person owns the keys

juistd runs from installation, in no network, and holds everything that is the
device's: its keys (created on first start), its log, its hints. It creates a
network from a genesis the CLI signed, and redeems an invite itself — the
guest's half needs only the device's keys. The CLI holds everything that is the
person's: admin keys and break-glass secrets in `~/.config/juist`.

Where the two meet, the daemon is the less trusted side: it runs the parsers an
attacker reaches first. The CLI asks it for its chain, verifies it in memory
and against the keystore's own anchor (`networks/`: the head it last verified,
and the admins and threshold that governed it), signs against that, and hands
back only signed records. It signs nothing the daemon built without
rebuilding it: a rotation record must be the one the CLI's log produces for
the staged keys. The daemon switches to new keys, restarting the mesh, once
the log names them — however the record arrived.

**The inviting half runs in the daemon too.** `juist invite` asks juistd to
offer the invite (`CmdInvite`, `internal/host`): the TCP listener, the LAN
answers, the public DHT and the sessions all run there, apart from the admin
keys. When a guest proves it knows the invite, the daemon asks the CLI to
admit it, on the same connection. The CLI builds the AddNode from its own
verified log, signs it, waits for the other admins if it must, and answers
with an *admission*: the admin key's signed statement that this guest is a
member of this network as of a head. The link the CLI prints names that admin
key, and the daemon never touches what is printed. A guest holding such a link
stores nothing unless the admission verifies, names it, and names a head on
the chain it was sent. So a compromised juistd on the inviting device can
refuse or stall a guest, but not enroll it into a network of its own. The
typed code carries no admin key, so for it the device that answers is trusted,
which is one reason it stays LAN-only.

Who may call the daemon is decided per call from the kernel-reported uid (see
[04-architecture.md](04-architecture.md)): status for everyone, the rest for
root, the daemon's user and the operator. Two defaults keep that from costing
a step: `sudo juist join` appoints whoever ran sudo, and a user who is not the
operator is offered the one `sudo juist set --operator` it takes, instead of
retrying the whole command as root — which would have put their admin keys in
root's keystore, and is refused for that reason.

Without a daemon — a developer's `--home`, a test, an air-gapped signing
machine — the CLI does the same work on a state directory itself, with the
node keys and admin keys side by side.

## Invites

**One protocol, two secrets.** A typed code (`42-drumbeat-tolerance-glucose`: a
nameplate from 1 to 999 and three words of the PGP word list, 24 bits) and a
link (`juist:` plus 128 random bits and the host's addresses) both run SPAKE2
(RFC 9382, the edwards25519/SHA-256/HKDF/HMAC suite) with the secret as the
password. The link does not need a PAKE; running one anyway keeps a single
handshake to audit. `TestSPAKE2Constants` regenerates M and N from the RFC's
seeds, and `TestKeyScheduleMatchesRFC` checks the transcript and key schedule
against the RFC's vectors, which exist only for P-256 — the reason the schedule
takes encoded elements. `w` is SHA-512 of the password reduced mod ℓ, without
the memory-hard function the RFC recommends: `w` is never stored, and without
the transcript's `K` there is nothing to test a password against offline.

**Exactly one guess, and only a guess spends it.** The guest confirms first. A
wrong code voids the code and both sides say so; the host then refuses the
right code too, and the link still works: voiding the whole invite would let
anyone on the LAN end it with one connection. A wrong link voids nothing:
guessing 128 bits online is hopeless. The code is taken only from the LAN
(`TestAWrongCodeVoidsTheInvite`), never through the DHT or from a routed
address, and 32 hellos for other nameplates retire it too, since asking for a
nameplate costs nothing and there are only 999
(`TestNameplateMissesRetireTheCode`). A session that ends before the guest's
confirmation gave its peer nothing to test, so it leaves the invite open —
otherwise a port scan or a dropped connection would kill invites. Sessions are
serial, so an invite is never guessed at twice at once. A nameplate the host
does not hold is refused before any key exchange and costs nothing. A host
that answers without knowing the code cannot produce the host's confirmation:
the guest reports an impersonator instead of joining it.

**Finding the host.** A code is found by asking the LAN, over the ordinary mDNS
socket, who answers for its nameplate; the answer carries the TCP port and an
instance id, so one host on two interfaces is not mistaken for two hosts. Two
hosts answering for one nameplate is refused rather than guessed between, since
trying the wrong one would spend its invite. The link carries the host's
addresses and works from anywhere that can route to one. The invite listens on
TCP 41642 unless that is taken, so a firewall can be opened for it once.

**Two devices behind NAT.** A link whose addresses the guest cannot reach —
the usual case between two homes — is met through the public DHT instead
(`internal/rendezvous`). The link's secret derives, through HKDF, two DHT keys
and a sealing key. The host asks public STUN servers for its public address and
leaves it, with its LAN and IPv6 addresses, sealed at its key; the guest does
the same at its own, with a random session id, and both send UDP toward the
other's addresses until one side's packets get through its peer's NAT. The
path then carries a small reliable stream (a fixed window, cumulative
acknowledgements, fast retransmit), and the enrollment runs over it unchanged:
nothing on the path is trusted, and an injected packet can end a session but
not spend a guess. The guest gives the link's addresses a two-second head
start, so a reachable host never hears from the DHT, and the host joins the DHT
while it prints the invite. A meeting takes about a minute, most of it joining
the DHT. It fails where both NATs pick a new port for every destination; the
join then says so and suggests running it where the host is reachable. The
typed code stays LAN-only: 24 bits are enough against one online guess, not
against a DHT key anyone can compute offline.

**Through a member's relay.** Without the public DHT and STUN, and wherever
both NATs defeat punching, the link still reaches the host through a relay of
the network's own. The inviting daemon keeps a connection waiting at each
other relay-capable member's relay, over TLS pinned to the certificate that
member announces, registered under the link's forward id (HKDF of the secret,
one way) and a signature by the device's identity key over the relay's
certificate hash, the id and a nonce the relay draws. The relay checks the
signer is a live member. The link names the relays (`r=` addresses); the
guest asks one for the id, the relay joins the two connections, and the
enrollment runs end to end over them as over any other path, so the relay
learns the id, the addresses and the traffic's size, and cannot answer for
the host. It bounds what it holds: 64 invites, four per member, two waiting
connections each, 64 guests waiting at once and four per source, and each
forwarded session's size and silence. The host counts a forwarded guest by
the address the relay reports, and takes no code hello through it.

**Firewalls.** The packages install firewalld services and ufw profiles for
the fixed ports — `juist` for 41643/udp, `juist-relay` for 41645/tcp+udp,
`juist-invite` for 41642/tcp — and let `juist0` in where either firewall
runs, which log sync needs, since it runs inside the tunnel; see residual
weakness 8 in [02-threat-model.md](02-threat-model.md) for what that trusts.
The guest hands the host its signed announcement with its confirmation, so a
host behind NAT learns where a guest with a public address is without the
DHT. A daemon started with its default ports falls back to OS-chosen ones
when another program holds them, and keeps ports it was given explicitly.
`juist invite` prints the one command that opens its port if the firewall is
closed to it, and `juist status` warns when firewalld keeps log sync out of
`juist0`.

**What travels.** Inside the channel: the guest's public keys, a signature by its
identity key over the channel binding (so the request cannot be replayed into
another session), and then the log from the host's anchor, member
announcements and leases. The guest builds the log in memory first and stores it
only if it admits this device under exactly these keys and the group secret
opens; otherwise nothing is written. The hints are signed by their authors and
grant nothing.

**More than one admin.** The invite writes the admission for the others to
approve, tells the guest how many votes it has, and polls its own log until the
device appears in it — applied here, or applied on another admin's device and
gossiped over. The invite's expiry covers the wait.

**Rejoining.** A removed device is never told it was removed: members stop
gossiping with it, and its own log still lists it. So `join` accepts a device
that holds a log, takes the new records into that log rather than replacing it —
its ratchets survive — and refuses only if the invite turns out to be for
another network.

## Freshness

A node's view of the network may be missing a removal it has not heard of. A
**lease** is an admin device's signed statement "my head was H at time T"; a node
holding one that names a record on its own active chain knows it has at least
what the signer had at T. With no such lease younger than the TTL (48 h by
default, `juistd --freshness-ttl`, set by the acceptor), the node is **stale** and
keeps tunnels only to admin devices. Every other peer is dropped in both
directions, which is the fail-closed half of residual weakness 1 in
[02-threat-model.md](02-threat-model.md). Leases are gossiped in every records
frame and persisted, so a restarted node knows its freshness before it hears
from anyone: that is the startup gate.

**Who signs: admin devices, not admin keys.** A lease signed by a quorum would
need k admins online every day; signed by an admin key, an admin's machine would
have to run the CLI on a timer, and the daemon would need the key it must never
hold. So the signer is a *delegate*: a member the log grants the `admin` role,
whose daemon signs with its own identity key. The grant is quorum-signed and
revocable like any other. This gives the role its first meaning — until M4 it
only marked where signing ceremonies happen — and the meaning is narrow: an admin
device can vouch for freshness and can change nothing about membership.

The CLI calls these devices *vouchers* (`juist grant vps voucher`), and the
log keeps the value `admin`, which the CLI still accepts. "Admin" on its own
meant two things a person had to tell apart, admin keys that vote and devices
that vouch; these notes say "admin device" where they mean the role.

**Why stale keeps admin devices.** A node that dropped every tunnel could only
recover over the underlay, and two members behind NAT sync only through their
tunnel. Keeping the signers is free in security terms: the leases that would
make the node fresh come from exactly those devices.

**How many must vouch.** A lease names a head, and the anchor is on every
chain, so one admin device that lies can keep any node it reaches fresh on a
view from before every removal. Naming heads cannot tell a liar from one that
is behind. That is not like an admin key below quorum, which can do nothing
alone: with the default threshold of one, a single dishonest admin device turns
fail-closed off for everyone it reaches. Schema 1 therefore adds a threshold to
the log (`KindSetVouchers`, `juist admins vouchers M`). A node is fresh while M
distinct admin devices have each vouched within the TTL, and it is fresh from
the M-th newest of their leases. The threshold cannot exceed the admin devices
there are. With M = 1 the rule is "every admin device is honest", and the docs
say so. With M, it takes M of them.

**What the design admits, stated plainly.** A signer vouches for what it holds,
so admin devices inside the same partition as the victim keep the partition
fresh. Freshness bounds how long a partition without enough admin devices
survives. An admin device that is itself revoked can keep vouching for the
head before its removal to anyone who has not seen it, which is why the
threshold exists. A network with no admin device does not enforce freshness
at all, and `juist status` says so. And an admin device that is offline for longer than
the TTL takes every other member down to admin-only tunnels: a network should
keep at least one always-on member as an admin device, which is a deployment
rule, not something the code can enforce.

**Two tiers of revocation collapse into one.** The plan's emergency tier was an
epoch bump plus a forced re-handshake. Every removal already bumps the epoch
([08-trust-layer-notes.md](08-trust-layer-notes.md)), and a re-handshake has
nothing to rotate until per-pair preshared keys exist, which is M11a
([05-roadmap.md](05-roadmap.md)). `juist rotate group-secret`
remains for a suspected leak of the group secret with no one to remove.

## What the review of M4 found

The rules behind the fixes, so they survive the next change:

- **Anything that tells a guest whether its guess was right has to spend the
  invite.** RFC 9382 has a party abort when K is the identity, and only an
  element built from the password itself makes it so. A host that aborted
  there and answered every other element told a guest which of its guesses
  was right, for free, one connection each. That element is now the invite's
  one guess (`TestAnElementBuiltFromTheCodeIsItsOneGuess`).
- **The CLI never signs what the daemon built without rebuilding it.** The
  daemon is the side an attacker reaches first. A rotation record it returns
  is compared against the one the CLI's own verified log produces for the
  same keys.
- **Abandoned keys are never overwritten.** Each abandoned set is its own
  file, and every one is a candidate once the log names it, with or without a
  running mesh.
- **A node that cannot see past a schema upgrade vouches for nothing.** Its
  view ends before every removal that came after.

- **One invite admits one device, and a person compares it.** The daemon
  runs the session, so it could admit several devices, or one of its own in
  the guest's place. The CLI answers one admission per invite. Through a
  daemon, it shows the joining device as four words, which "juist join"
  shows on the device, and asks before it signs. The words hash the
  identity, every key, a salt the admin draws, and a nonce the guest
  draws. The daemon in between carries both, so each is fixed before the
  other is known, as in Bluetooth's numeric comparison: the join request
  commits to the nonce, the admin draws the salt after it, the guest
  accepts one salt and only then reveals the nonce, and the CLI holds it
  to the commitment. A daemon in the middle fixes its own nonce before it
  sees the salt and hands the guest a salt before it sees the guest's
  nonce: one try at 32 bits on either screen, not a search. (Salting alone
  was not enough: the daemon relays the salt, and could grind the one it
  gave the guest until the words matched.)
- **An identity rotation needs both keys (schema 1).** Otherwise admins alone
  could move a member's slot, and an admin device's role with it, to a key
  of their choosing. Schema 0 networks keep the old rule until "juist log
  upgrade".
- **Which device the daemon is, is proved, not told.** A rotation comes with a
  signature by the rotated device's current identity key, which the CLI checks
  before it signs; under schema 0 nothing else would stop a daemon from moving
  another member's slot to a key of its own.
- **A join by link anchors the keystore in the admin's admission.** The CLI
  checks the admission the daemon hands back against the link's admin key and
  pins that network and head before it reads the daemon's log, so a juistd
  compromised before the join cannot have its own network pinned. A join by
  code still trusts the device that answers, as below.
- **A record is checked before it is signed, and before it is applied.**
  `approve` refuses a record that could not apply to the log as this device
  holds it (`Builder.Check`), such as a checkpoint that does not state the
  chain's state. A record started before the latest change forks the log
  where it was started: `approve` and `apply` refuse one that would win or
  lose there on its hash, since winning would undo every change since. A
  removal still goes through, as fork choice never lets a revocation lose,
  with a warning that it undoes the changes made since.
- **The DHT nodes are clients.** They answer no queries (BEP 43), so a
  stranger cannot have them store puts.
- **The keystore's anchor follows fork choice, not checkpoints.** A head
  that left the chain is accepted only if this side's own fork choice over
  the chain and the daemon's orphans rejects it. A truncated log fails that.

Accepted, and stated here rather than fixed:

- **Rotating the only admin device's identity makes every member stale.**
  Leases are checked against the current log, which no longer names the old
  identity. They recover once the device vouches under the new one, a
  reconcile later. Keep two admin devices, or rotate while both are online.
- **Stale mode drops only tunnels.** A stale node still gossips with anyone
  holding the group secret, which is how it catches up, and still relays for
  members if it is a relay. Neither grants membership.
- **Freshness trusts the local clock.** A node whose clock can be set back
  stays fresh on an old lease for as long as it is behind. Membership expiry
  has the same exposure.
- **A LAN attacker can make a join by code fail.** It can answer for the
  nameplate under a second instance id, which makes the guest refuse the two,
  or under the real host's id from its own address and win the race to the
  guest's connection. Either way the invite is not spent, and the attacker
  learns one guess per join at most. Answers are taken only from this host's
  own subnets, so the attacker has to be on the link. The link does not
  depend on mDNS.
- **Serial sessions can still be slowed.** Connections that say nothing are
  read concurrently and cost the guest nothing. One that sends a hello gets
  the session for up to ten seconds, and each source address may queue one
  more, so many hellos from many addresses delay a guest; the invite is never
  spent by them.
- **The typed code trusts the device that answers.** It carries no admin key,
  so a compromised daemon on the inviting device could enroll a guest who
  used the code into a network of its own. The link does not have this
  weakness; this is one more reason the code stays LAN-only.
- **The readers' pool on the socket is shared.** Two local users, or one with
  a range of subuids, can keep other unprivileged users from reading the
  status while they loop. Root and the operator have a pool of their own.

## Still open

- **An invite between two symmetric NATs.** The rendezvous punches through
  every NAT that keeps one public port per socket; two that do not need a relay,
  and member relays admit only members. A relay a member grants to one invite
  would close the gap and needs a design of its own.
- **What a break-glass secret authorizes.** Planned in
  [05-roadmap.md](05-roadmap.md) as M11.
- **A QR code.** The link is the payload a QR carries; `juist invite` renders
  it for the Android app to scan, planned in [05-roadmap.md](05-roadmap.md)
  as M10.
- **A removed device learning it was removed, where it was offline.** The
  device a removal is applied on hands it to every member it removes before
  it applies it: until then they are members, so this is an ordinary log
  sync session, and afterwards the tunnel it would run through is gone
  (`daemon/farewell.go`). A removed device that was offline then, or whose
  tunnel the last check found down, is not told. It keeps reporting itself
  connected, although no member accepts its handshakes. Where it is a voucher
  itself its own leases keep its view fresh, so it never goes stale either.
  Its catch-up would learn of the removal, but the catch-up needs a tunnel
  too. Telling it takes a path that does not need its WireGuard peer, such
  as a signed refusal handed over by a relay.
