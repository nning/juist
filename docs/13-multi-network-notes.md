# 13 — Several networks on one host

M5 lets one host be a member of several networks. Before it, a juistd held one
network and `juist join` on a device in one refused the next. The keystore
already kept admin keys, anchors and break-glass files per network; what was
missing was the device side, and three things broke when a second juistd was
run by hand: every network numbered from the start of 198.18/15, the Linux
router's table and rule priorities were fixed, and the packaging knew one unit.
This file records how M5 resolved them and the rules a later change must keep.

## One juistd per network, numbered

A host runs one juistd per network. The packaged service, `juistd.service`, is
instance 0; `juistd@juist1` to `juistd@juist9` run beside it
(`internal/instance`, `packaging/systemd/juistd@.service`). The number decides
everything two instances must not share, so each follows from it and nothing
needs a registry:

| | instance 0 | instance n |
|---|---|---|
| unit | `juistd.service` | `juistd@juistn.service` |
| home | `/var/lib/juist` | `/var/lib/juist/juistn` |
| socket | `/run/juist/juistd.sock` | `/run/juist/juistn.sock` |
| TUN device | `juist0` | `juistn` |
| ports | 41643 udp, 41644 tcp, 41645 relay | the same plus 10·n |
| routing table | 0x6a75 | 0x6a75 + n |
| rule priorities | 5110, 5130, 5150, 5170 | the same plus n |

The roadmap had instances named after their network. They are numbered
instead, because the name is needed before the join that learns the network's
name, a device name has to fit IFNAMSIZ, two networks may share a name, and
a network can be renamed. People never type the number unless they
want to: the CLI finds a network by its name (below).

Ports are fixed per instance rather than taken free at start, as the roadmap
planned. A firewall can then be told them before the instance runs, and
peers' endpoint caches stay right across restarts. Ports another program
holds still give way to OS-chosen ones, as the default's do.

`/run/juist` is preserved (`RuntimeDirectoryPreserve=yes` on both units):
every instance's socket is in it, and systemd would otherwise delete the
directory with whichever unit stopped first. The default instance's reset
spares the other instances' homes inside its own. LAN discovery joins no
instance's device.

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
  the members' in the data plane, so none is routed or accepted. The roadmap
  said to refuse to start. Refusing stops log sync too, and then the
  renumbering that ends the conflict never reaches this host: a network
  renumbered on another device would leave this one stuck on its old log.
  IPv6 carries log sync, so the fix arrives and IPv4 comes back by itself.
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
  it back when the answer changes; one in this very network stops it. Two instances starting together both see an empty host, and the
  check afterwards sorts them out. Until it does, the lower instance's routes
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

## Prefixes: a /22 each, drawn

`juist create` without `--ipv4` draws a random /22 in 198.18/15, one of the 127
after the first (`drawV4Prefix`). It never draws the first one, where networks without a
prefix of their own number from. It skips any /22 that this host's interfaces
or its other networks' claims overlap, and it questions an `--ipv4` that
overlaps them. Status carries each network's claims (`V4Claims`) for this.

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
  `juist create --no-device` starts nothing. As root
  this happens at once. Otherwise the CLI asks, and runs a hidden
  `sudo juist __instance new` once. That enables the unit, lets its device
  through the host firewall the way the package does for `juist0`, and
  appoints the user as the instance's operator. On a device in a single
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
which admission an admin should remove. Before M5 the same join was refused
before admission, because it was made under the same keys. Doing that again
needs the join request to carry the networks the device is in, blinded by the
session so that the host learns only whether its own is among them. That
changes the enrollment protocol and is left for later.

## Admin keys, one per network (M5a)

Rules a later change must keep:

- A network's own key is `admins/PERSON@NETWORK.key`, NETWORK as the network
  was named when the key was filed; nothing renames it afterwards.
- A key named without `@` is either from before M5a, and keeps its name, or
  carries `juist-unfiled-v1`, and the first log naming it files it. A key
  without the mark is never filed.
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

## Not built in M5

- **A user per instance.** Every instance runs as `juist`, so one taken over
  holds the device keys of every network on the host and can operate the
  others over their sockets: residual weakness 9 in
  [02-threat-model.md](02-threat-model.md). Closing it needs a user per
  instance. Then an instance's home cannot sit in the default's 0700 one,
  each needs a runtime directory of its own, and the instance above has to be
  allowed to read the exact claims of the one below. That is for the
  boundaries on a host, before the audit (M23).
- **Other networks' addresses in path discovery.** magicsock learns this
  host's addresses from every interface but Tailscale's own, and sends them to
  peers in the call-me-maybe it relays. A network's members may therefore be
  told this host's addresses in its other networks, and try them as paths.
  They lead nowhere for them, but they say which ranges the host is in.

- **FreeBSD** (M7a) keeps every instance in the host's one table, with no
  FIB of its own: `conn.InstanceHoldings` knows an instance by its device's
  name, and holds its addresses and the routes into it, so the IPv4 yield
  works as on Linux. A route pins its source by naming it as the gateway.
- **Renumbering's deadline** is fixed when the change is proposed, so every
  approval after that leaves less of the transition. Approvers now see how
  much is left, with a warning under the freshness TTL. Moving the deadline
  after signing would take a new record.

## Verification

Unprivileged: `internal/instance` (names, ports), `conn`
(`TestInstancesKeepTheirRulesApart`, `TestInstanceHoldingsUnprivileged`),
`daemon/host_test.go` (claims, the conflict rule, an instance that runs
without IPv4 and takes it back, one that refuses its own network twice, a
default that never yields), `cmd/juist/instances_test.go` (a host in-process
with the default instance and the instances the CLI starts), `cmd/juistd`
(`--instance`), `packaging` (the units, the scripts, `firewall.sh`).

Privileged, run by `make test-os-plumbing` and not on this project's own dev
box, which is a container: `TestNetnsInstancesLeaveEachOtherAlone` (two
routers side by side, each seeing the other's holdings),
`TestNetnsAHostInTwoNetworks` (criteria 1 and 3) and
`TestNetnsRenumberingKeepsEveryPairReachable` (criteria 5 and 6, as the data
plane sees them). All three passed on 2026-09-27, the first time they ran, on a
Fedora desktop beside a running juistd
([12-validating.md](12-validating.md#the-last-privileged-run)).
