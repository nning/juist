# 13 — Several networks on one host

How one host is a member of several networks (M5): instances, address
prefixes, which instance yields, and the rules a later change must keep.

## One juistd per network, numbered

A host runs one juistd per network. The packaged service, `juistd.service`, is
instance 0; `juistd@juist1` to `juistd@juist9` run beside it
(`internal/instance`, `packaging/systemd/juistd@.service`). The number decides
everything two instances must not share, so each follows from it and nothing
needs a registry:

| | instance 0 | instance n |
|---|---|---|
| unit | `juistd.service` | `juistd@juistn.service` |
| user | `juist` | `juistn` |
| home | `/var/lib/juist` | `/var/lib/juistn` |
| socket | `/run/juist/juistd.sock` | `/run/juistn/juistd.sock` |
| TUN device | `juist0` | `juistn` |
| ports | 41643 udp, 41644 tcp, 41645 relay | the same plus 10·n |
| routing table | 0x6a75 | 0x6a75 + n |
| rule priorities | 5110, 5130, 5150, 5170 | the same plus n |

Instances are numbered, not named after their network: the name is needed
before the join that learns the network's name, a device name has to fit
IFNAMSIZ, two networks may share a name, and a network can be renamed. People
never type the number unless they want to: the CLI finds a network by its name
(below).

Ports are fixed per instance, not taken free at start, so a firewall can be
told them before the instance runs and peers' endpoint caches stay right across
restarts. Ports another program holds still give way to OS-chosen ones.

Each instance runs as a user of its own, which the packages make, so that
one network's juistd reads none of another's keys; on FreeBSD the homes are
in `/var/db` and the sockets in `/var/run`, named alike. An upgrade from a
package that kept the instances' homes inside the default's moves each once
(`packaging/instances.sh`). LAN discovery joins no instance's device.

## The lower instance wins, so the higher one yields

Every instance's policy rules consult its own table, and instance n's sit n
above the default's: every instance's bypass rule comes before any instance's
table, each deletes and restores only its own rules, and where two tables
claim an address the lowest instance's route wins. That is not a choice juist
makes at runtime; it is what the kernel does with the rules. The conflict rule
follows it.

An instance asks the instances below it what their networks claim, over
their sockets (status is anyone's to read). Their claims move only with their
logs. Where one does not answer, as in a run outside the package, it reads
the kernel instead (`conn.InstanceHoldings`: that instance's routes and its
device's addresses, which needs no privilege and moves with its peers too).
It compares what it learns with what its own network claims
(`daemon/host.go`). No two instances ever ask each other, since each asks
only those below it and the default asks none, so the calls cannot
deadlock.

- **Claims.** A network's ULA, and in IPv4 its prefix and the ranges it is
  moving away from. A network founded before prefixes were drawn has no prefix
  of its own and numbers from all of 198.18/15; it claims its members'
  addresses alone, since claiming the range would keep it off every host in a
  newer network.
- **Only a lower instance conflicts.** A higher one's routes never win, so it
  is the one to yield.
- **IPv4 overlap: run without IPv4.** No IPv4 address on the device and none of
  the members' in the data plane, so none is routed or accepted. Refusing to
  start would stop log sync too, and the renumbering that ends the conflict
  would never reach this host. IPv6 carries log sync, so the fix arrives and
  IPv4 comes back by itself.
- **The same network: do not start.** An instance below in this very network,
  by its genesis hash or, read from the kernel, an address in this network's
  ULA, is this device's membership already; a second would be a second device
  in it. This is checked against every instance below before any IPv4, and a
  held route that merely covers the ULA, such as a default route, does not
  count.
- **An instance below that is not routing yields nothing:** one the network
  removed, one without a device, one whose mesh did not start, or one that
  runs without IPv4 itself. For the same network, only membership counts.
- **Rechecked every five seconds**, and the running mesh drops IPv4 or takes
  it back when the answer changes; one in this very network stops it. Two
  instances starting together both see an empty host, and the check afterwards
  sorts them out. Until it does, the lower instance's routes
  already win. A host that cannot be read is no verdict: the mode stays as it
  was, and the failure is logged once. Nor is a lower instance that is not
  there for a moment, as while it restarts: IPv4 comes back only once three
  checks in a row, about fifteen seconds, find the conflict gone. An
  instance that starts while one below holds a network (a log in its home)
  and does not answer yet, as at boot or when an upgrade restarts both,
  starts without IPv4 and takes it once that one has answered: before then
  the kernel shows nothing of it. Once a mesh has run, one below going quiet
  is no such reason. The instances' units also start after the default's.
- **Which instance yields depends on the numbers, not on which network came
  first.** A network joined into the freed default instance takes IPv4 from
  an overlapping network already running higher. `create`, `join` and
  `network renumber` warn when that happens, naming the one that yields.

`juist status` names both networks and says how to end it: renumber one, or,
for the same network twice, reset the higher instance.

On FreeBSD every instance shares the host's one routing table, with no FIB of
its own: `conn.InstanceHoldings` knows an instance by its device's name and
holds its addresses and the routes into it, so the IPv4 yield works as on
Linux. A route pins its source by naming it as the gateway.

## Prefixes: a /22 each, drawn

`juist create` without `--ipv4` draws a random /22 in 198.18/15, one of the 127
after the first (`drawV4Prefix`). It never draws the first, where networks
without a prefix of their own number from. It skips any /22 that this host's
interfaces or its other networks' claims overlap, and it questions an `--ipv4`
that overlaps them. Status carries each network's claims (`V4Claims`) for this.

A /22 holds 1022 addresses. That is about twice MaxNodes at once, and 1022
admissions over the network's life, since no address is handed out twice
([08-trust-layer-notes.md](08-trust-layer-notes.md#renumbering)). A range full
by history says so and points at renumbering into a larger one. A network
without a prefix of its own that has given out more than 1022 addresses
reaches into the draw's range; a host in both then runs the higher instance
without IPv4 until one of them renumbers.

## The command line

The CLI finds the host's instances by their sockets (`cmd/juist/instances.go`)
and picks the one a command is about:

- A first argument names it: `juist devices home`, `juist network rename
  home office`, `juist network renumber juist1 10.7.0.0/24`. It names a
  network by its name (case-folded), its genesis hash's first eight or more
  hex digits, or its instance's name. It is taken as the network wherever
  it names one and what follows still makes the command, so where a
  command's argument is optional, one that is a network's name comes after
  it: `juist invite home home`. `--network NAME` and `$JUIST_NETWORK` do the
  same for any command. A misspelled `--network` gets a suggestion; two
  networks called the same are told apart by instance.
- Without one, the one instance in a network is chosen. Where there are
  several, or another is enabled but not running and might be in one, the
  listings (`status`, `devices`, `network`, `admins`) show every network,
  and any other command stops with the networks' names and an example. No
  command asks: a question in the middle of a script is a hang.
- `juist status` shows every network, each headed by its instance, and an
  instance that is enabled but not running, with how to start it.
- `juist create` and `juist join` on a device already in a network use an
  instance in no network where there is one, and otherwise make one. While
  an instance is enabled but not running they refuse, saying how to start
  it, since it may already be some network's device. They ignore
  `$JUIST_NETWORK`, which names a network the device is in, not the new one.
  Making an instance happens at once as root; otherwise the CLI asks and
  runs a hidden `sudo juist __instance new` once, which enables the unit,
  lets its device through the host firewall as the package does for
  `juist0`, and appoints the user as the instance's operator. `juist create
  --no-device` starts nothing. On a device in a single
  network, one that network removed, a join still goes to that instance,
  which may take it back in. With several networks the join goes to a new
  instance.
- A failed join or create removes the instance it made. A reset of a network
  other than the default's removes its instance, as root at once and
  otherwise with sudo, asked for or given `--yes`; left in no network it
  would only wait for the next one. The default instance is never removed,
  and neither is an instance that still holds a network, or does not answer
  and has a log in its home.
- An instance number is used again once freed. The keystore's record of which
  network a daemon's socket held
  ([cmd/juist/pin.go](../cmd/juist/pin.go)) is removed by the reset, and, for
  a reset under sudo, from the sudo user's keystore as well. Any other
  keystore that saw the old network there refuses the next one until the
  person deletes the file its error names.
- Approving a genesis founds its network beside the others, as `create` does.

**Joining a network twice.** An invite does not say which network it is for
until the device has been admitted. A device already in that network,
through another instance, is therefore admitted a second time before it can
tell. The new instance refuses the log (`guest.Options.Elsewhere`) and says
which admission an admin should remove. Refusing before admission needs the
join request to carry the networks the device is in, blinded by the session so
that the host learns only whether its own is among them; that changes the
enrollment protocol and is left open.

## Admin keys, one per network

- A network's own key is `admins/PERSON@NETWORK.key`, NETWORK as the network
  was named when the key was filed; nothing renames it afterwards.
- A key named without `@` is either from before keys were filed per network,
  and keeps its name, or carries `juist-unfiled-v1`, and the first log naming
  it files it when `juist admins` lists it, it signs, or `juist create` runs
  beside that network; reading the log alone never writes the keystore. A key without the mark is never filed.
- Without a log, keys filed under different networks never sign one record
  together.

## Packaging

`juistd@.service` is `juistd.service` for another instance, line for line
except for the lines that name it (`packaging/scripts_test.go`). Upgrades
restart the running instances as they do the default. On RPM they are marked
and restarted after systemd reloads the units. Removing the package disables
every instance and revokes every device's firewall rule, and leaves their
homes, which hold keys, as it leaves the default's. `firewall.sh` takes the
device: `allow juist3`, `revoke juist3`, or `revoke` alone for all ten.

## On a phone: slots behind one VPN

A phone has one VPN, and a `VpnService` one device, so the app runs every
network's service in one process (`mobile`), each in a numbered slot that
plays an instance's part:

- **Slot 0** is the app's state directory as it always was, so that a phone
  joined before keeps its network as it is. Slot n's is `juistn` beside it;
  its ports are slot 0's plus 10·n, as an instance's. A join takes the
  lowest free slot above every slot in a network, and the lowest free one
  only where none is left above, so that a new network takes IPv4 from none
  the phone is in; one into a network a slot is in already is reset at once.
  A slot left is deleted, but slot 0, which is reset. A slot's directory without a network, as a join the app did not
  live to finish leaves, is deleted at the next start, and only where it
  holds node keys.
- **At most four networks** (`mobile.MaxNetworks`): each keeps tunnels,
  relays and announcements of its own, which the phone pays for in battery.
- **One Keystore key** seals every slot's keys. Each slot's keys are files
  of their own, but another key would keep nothing apart that the app's own
  user does not already hold.
- **A network's alarm stays its own.** Its mesh stops or limits itself as
  on Linux; the other networks' tunnels, routes and names stay up.

`conn.VPNHub` is the one device. It establishes the union of what the slots
route, and establishes it again only when that union changes, since Android
replaces every connection through the device each time; a mesh restarting
keeps its slot's routes for ten seconds, so that a restart establishes the
device once at most. A packet from the phone goes to the lowest slot whose
routes hold its destination, the internet to the slot whose exit node is in
use, and the rest nowhere. Android picks one source address for the whole
device, so a packet sent from another slot's address leaves from its own,
and the answer is translated back by the flow it belongs to. A slot writes
to the phone only to its own addresses and to multicast groups, and from
nowhere another slot's routes lead, which its exit node or a subnet router
could claim: no slot reaches another's address on the phone, nor has the
phone answer into another network, and Android forwards nothing between
them. A translation goes with its slot's addresses.

The M5 rules hold by slot: a slot asks the slots below it what their
networks claim, in-process, and runs without IPv4 where one holds it, or
does not start in a network a lower slot is in. The phone rechecks at its
pace, every five seconds with the screen on, every ten minutes saving.

- **Names.** The phone asks one resolver, the exit node's slot's where one
  is in use, and else the lowest slot's with names on. It answers every
  slot's names with names on, from their zones in-process, and searches
  their domains, the rest upstream as its own slot does: by the exit node
  where one is in use, so that no lookup leaves beside it. With that slot's
  names off, the exit node's resolvers take every lookup, and no slot's
  names resolve.
- **Exit nodes.** The internet goes to one slot's exit node at a time:
  choosing one lets another slot's go, once the new one is chosen.

## Still open

- **Other networks' addresses in path discovery.** magicsock learns this
  host's addresses from every interface but Tailscale's own, and sends them to
  peers in the call-me-maybe it relays. A network's members may therefore be
  told this host's addresses in its other networks, and try them as paths.
  They lead nowhere for them, but they say which ranges the host is in.
- **Renumbering's deadline** is fixed when the change is proposed, so every
  approval after that leaves less of the transition. Approvers see how much is
  left, with a warning under the freshness TTL; moving the deadline after
  signing would take a new record.

## Verification

Unprivileged: `internal/instance` (names, ports), `conn`
(`TestInstancesKeepTheirRulesApart`, `TestInstanceHoldingsUnprivileged`,
the hub's `TestAHub…`), `mobile/networks_test.go` (two networks in one core
behind one device, one yielding IPv4, one left),
`daemon/host_test.go` (claims, the conflict rule, an instance that runs
without IPv4 and takes it back, one that refuses its own network twice, a
default that never yields), `cmd/juist/instances_test.go` (a host in-process
with the default instance and the instances the CLI starts), `cmd/juistd`
(`--instance`), `packaging` (the units, the scripts, `firewall.sh`).

Privileged, run by `make test-os-plumbing` and skipped without root, TUN and
network namespaces: `TestNetnsInstancesLeaveEachOtherAlone` (two routers side
by side, each seeing the other's holdings), `TestNetnsAHostInTwoNetworks` (two
networks on one host) and `TestNetnsRenumberingKeepsEveryPairReachable` (a
renumbering, as the data plane sees it). The latest run is in
[12-validating.md](12-validating.md#the-last-privileged-run).
