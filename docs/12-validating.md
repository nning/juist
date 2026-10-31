# 12 — Validating it

Every security exit criterion in [05-roadmap.md](05-roadmap.md) is a test
that keeps running after its milestone closes. This file says how to run the
gates, which test checks which claim, and when the gates CI cannot run last
ran. The walkthroughs in the [README](../README.md) are the manual loop.

## The gates

```sh
make check                     # what every push gates on; needs no privileges
make ci-vm                     # CI in stages: a KVM VM it sets up and the lab beside it; no root
sudo -E make test-os-plumbing  # real devices, network namespaces, NAT; needs root
make test-freebsd              # every test on a FreeBSD host, as root there
make interop                   # Linux and FreeBSD nodes in qemu, with the packages; no root
make repro-freebsd             # the same bytes from this host and a FreeBSD host
make fuzz-long                 # the parser gate: hours per target, never on CI
make test-acme                 # the TLS terminator against Pebble, a CA of its own
```

### When each gate runs

The slow gates run where they can find something `make check` cannot, not on
every push:

| When | What runs | About |
|---|---|---|
| every push | `make check`; `make cross` where a build-tagged file changed | 7 min |
| a change to devices, routes, the firewall or NAT traversal (`conn`, `internal/plumber`, the daemon's host plumbing) | `make ci-vm STAGES=vm` | 2 min |
| a change to the packages, their units and scripts, or what passes between hosts (ingress, exit, subnets, names, sharing) | `make ci-vm STAGES=lab` | 15 min |
| a review round, after `make check` passed on the tree | `make ci-vm FAST=1` | 15 min |
| a milestone, or the review round closing it, is done; before a release | `make ci-vm`, recorded under "The last privileged run" | 18 min |
| where a milestone's criteria ask for it | `make test-freebsd`, `make repro-freebsd`, `make test-acme`, `make fuzz-long`, the hand tests on Fedora | — |
| a change to `mobile` or `android/` | `make android-check`, with a JDK and the Android SDK; the app by hand in an emulator or on a phone | 3 min |
| a change to what a phone, or a peer of one, sends while idle: the pace, the checks, sync, the DHT | `make android-idle`, with the AVD `juist`, recorded under "The last privileged run" | 100 min |
| a change to the website's CSS, scripts or layouts | `make -C website check test-browser`, with Chrome | 1 min |
| documentation alone | nothing; the commit carries `[skip ci]` | — |

The times are KVM's on a four-core host with nothing else running. `make
ci` runs what `make ci-vm` runs but the lab, on this machine, the privileged
tests under sudo.

**`make check` silently skips everything that needs privilege.** The
real-device and namespace tests skip where they cannot create a TUN device or
a namespace, so a container reports green while testing no OS plumbing or NAT
traversal. `make test-os-plumbing` sets `JUIST_REQUIRE_OS_PLUMBING=1`, which
turns such a skip into a failure; `make test-os-plumbing-sudo` does the same
without running `go` as root, which would leave root's files in your Go
caches.

The privileged tests leave a juistd running on the same machine alone: every
node runs in namespaces of its own, the host's holding only an address-less
bridge and veth ends, and the one real-device test in the host's namespace
takes an instance number no juistd holds and documentation addresses
(192.0.2.0/24, 2001:db8::/32). A run cut short leaves namespaces named
`juist…`, `jn…` or `jc…` and a bridge `jbr…`; `ip netns del` and `ip link del`
remove them. To run them on another host, such as a Fedora Cloud VM, as root:
build the binary with `go test -c -o conn.test ./conn`, copy it over, and run
it in a directory named `conn` with `JUIST_REQUIRE_OS_PLUMBING=1` and
`-test.run` as the Makefile's `PLUMBING_TESTS`. Fedora Cloud has no polkit
until the package brings it.

**`make test-freebsd` builds every package's tests for FreeBSD** and runs them
over ssh as root on a FreeBSD host, which needs no Go. `FREEBSD_SSH` reaches
it, by default a qemu VM whose ssh is forwarded to port 2222, which needs
neither root nor KVM here:

```sh
curl -LO https://download.freebsd.org/releases/CI-IMAGES/15.1-RELEASE/amd64/Latest/FreeBSD-15.1-RELEASE-amd64-BASIC-CI-ufs.raw.xz
xz -d FreeBSD-15.1-RELEASE-amd64-BASIC-CI-ufs.raw.xz
qemu-img convert -O qcow2 FreeBSD-15.1-RELEASE-amd64-BASIC-CI-ufs.raw fb.qcow2
qemu-system-x86_64 -machine q35 -accel tcg,thread=multi -smp 2 -m 2048 \
  -drive file=fb.qcow2,if=virtio -nographic \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0
```

The CI image lets root in by ssh without a password. Tests of Linux's
plumbing skip there by name; a test that needs `go` or more than one loopback
address skips too.

**`make interop` is where Linux and FreeBSD meet** (`interop/`): two pairs of
a Debian 12 (lx) and a FreeBSD 15.1 (fb) VM in qemu, each pair's LAN a pair of
UDP sockets on the host's loopback, each VM with its package installed. One
pair, `TestLinuxAndFreeBSD`, joins one network of this build, which crosses
three epoch bumps and then carries every part its rows below name; the other,
`TestLinuxAndFreeBSDUpgraded`, starts on the previous release, the last done
milestone's packages that `make previous` builds once per commit and
FreeBSD release into `INTEROP_CACHE`, in an environment that holds none of
this make's variables but `FREEBSD_ABI`,
upgrades the two beside each other, pings across the epoch bumps, and serves
as exit node, subnet router and ingress and resolves names, resolved there
and gone. Both remove their packages, leaving no
device, rule or forwarding. The pairs run at once, 2 GiB a VM; `INTEROP_PAIRS=1`
runs one after the other. `JUIST_INTEROP_DOCKER=1` adds the service member in a
container. It needs qemu, qemu-img, xz, ssh and Chrome (`INTEROP_CHROME`), and
no root: KVM where `/dev/kvm` opens, TCG elsewhere, which is several times
slower. The images are fetched into `INTEROP_CACHE` once, checked against the
sums pinned in `interop/vm_test.go`, and set up there once by the scripts
beside them; each disk derived, converted or set up, is kept with a sum of its
own that every run checks, and a change to a script sets the image up again.
Setting up needs the network; `JUIST_INTEROP_DNS` names a resolver where the
host's does not answer. Each test logs its longest waits and commands, which
say where its time goes; `build/interop` keeps the consoles.

**`make ci-vm` is CI**, on a machine of our own (`ci/main.go`). It snapshots
the working tree as it is, which every stage then tests, and runs four stages,
cheapest first, a step for each make target, the first step to fail ending the
run:

- **vm**, what only a VM shows: the privileged tests, in parallel;
- **check**, every step of `make check`, with `JUIST_REQUIRE_HOST_NET=1`;
- **lab**, `make interop`, on this host beside the VM from the start, so the
  longest stage sets the run's length, ending at its first failed part;
- **build**, the RPM in the VM, and the cross builds and `govulncheck` on this
  host after the lab, on its CPUs.

The VM's stages run in a Fedora 44 Cloud VM under KVM, set up on first use in
`~/.cache/juist-ci` (`JUIST_CI_CACHE`) from an image pinned by its sum, with a
user `ci` who has sudo, which gets this host's Go and the snapshot. The host
needs qemu, qemu-img, ssh, ssh-keygen and `/dev/kvm`, and no root;
`JUIST_CI_CPUS` and `JUIST_CI_MEM` (MiB) size the VM. Beside the lab, the VM
and the lab each take half the host's CPUs, which the other does not share:
a guest whose CPUs other guests take runs its race tests several times slower
and fails their timing, and the lab on one CPU of four loses pings.
Each takes whole cores, a core's threads never serving both;
`JUIST_CI_LAB_CPUS` gives the lab's count, 0 shares them all. The VM has 6 GiB
beside the lab and 8 where it nests it, one pair at a time. One run at a time holds the host; another waits. Each run logs to
`build/ci`, named by time and commit, `-dirty` where the tree had changes, the
lab's in files beside it, and ends with every step's time. `STAGES=vm,lab`
runs those alone, `FROM=lab` those from one on, `LAB=vm` nests the lab in the
VM, `CI_MAKE` makes targets in the VM alone, and `go run ./ci -keep` leaves the
VM up to look into. A run of fewer stages says it is not a closing run.

`make check` stamps `build/check.stamp` with the hash of the tree it passed on,
where the tree did not change meanwhile. `make ci-vm FAST=1` takes `make check`
from that stamp where it names the snapshot's tree, and runs in its place
`make test-host-net`, the tests the host's network features gate, under the
race detector, which this host's `make check` may have skipped: what a run
before the closing one can leave out. A stamp is written only where `make
check` took none of the variables it reads from the command line or the
environment and ran without `-n`, `-t`, `-q`, `-i` or `-e`, each run from a
hash of its own. An interrupt, or a signal to make, fails the run; the lab
goes with the runner however it ends, and a VM kept with `-keep` stays. The closing run takes no stamp: it runs
`make check` in the VM, `repro` building once from an empty build cache as
ever; it takes the lab's disks, which their sums check, and the previous
release's packages, which its commit and the toolchain key, from their caches. GitHub's workflows run by hand alone.

**`make repro-freebsd` builds HEAD on two builders**, this machine and the
FreeBSD host `FREEBSD_SSH` reaches: juist and juistd for Linux and FreeBSD,
and the FreeBSD package, each from a clone of the commit. It fails unless both
made the same bytes. The host needs `pkg install git go`; its go fetches the
pinned toolchain itself.

**Fuzzing never runs on CI.** [06-verification.md](06-verification.md) sets
the gate at 72 clean CPU-hours per input surface, run by hand before a
milestone closes. `make fuzz` smoke-runs every target in seconds; `make
fuzz-matrix` lists the targets so `make fuzz-one` can give each its own
preserved corpus.

**Measurements gate nothing.** `make throughput` runs iperf3 over each path
in the netns lab, as root; `make load-lab` loads the website through an
ingress and the tunnel in the qemu lab. Their latest numbers are recorded
under "The last privileged run".

**The DHT tests never touch the public network.** They run against a private
swarm on loopback, including the crawler that must learn nothing. Reaching the
real BitTorrent DHT is `juistd` without `--no-dht`, and it is the one thing
here that sends traffic to strangers.

## What checks what

`go test ./<pkg> -run <name> -count=1 -v` runs any single one of these; the
privileged ones need `sudo -E` and `JUIST_REQUIRE_OS_PLUMBING=1` to fail rather
than skip. A NAT cell can be run alone with
`-run 'TestNetnsNATMatrix/symmetric_x_symmetric'`. The last column says what a
row needs beyond `make check`: root on Linux (**yes**, `make
test-os-plumbing`), a FreeBSD host (`make test-freebsd`), or qemu (`make
interop`).

### Tunnels, relays and paths

| Claim | Where it is checked | Privileged |
|---|---|---|
| a tunnel with no coordination server | `conn`: `TestTwoNodeOverlayPing`, `TestTwoNodeOverlayPingBothFamilies` | no |
| nothing reaches a third party | `conn`: `TestNoThirdPartyEgress`; the AF_PACKET tap inside `TestNetnsOverlayCarriesTraffic` | for the tap |
| direct paths across the NAT matrix | `conn`: `TestNetnsNATMatrix` | **yes** |
| relay fallback, and relay over TCP | `conn`: `TestNetnsNATMatrix/symmetric_x_symmetric`, `TestNetnsRelayCarriesWhatUDPCannot` | **yes** |
| a DHT observer learns nothing | `discovery/dht`: `TestCrawlerLearnsNothing`, `TestAnItemIsUselessWithoutTheGroupSecret` | no |
| non-members cannot use member relays | `relay`: `TestNonMemberCannotUseTheRelay`, `TestRemovedMemberLosesTheConnectionItHolds` | no |
| a relay's STUN answers are bounded per host and in all, so one host starves no other | `relay`: `TestSTUNAnswersAreRateLimited`, `TestSTUNFloodFromOneHostStarvesNoOther`, `TestSTUNTracksBoundedHosts`, `TestSTUNCountsAnIPv6HostByItsPrefix` | no |
| the record schema is versioned | `trust/log`: `schema_test.go`; `types`: `TestUnknownEpochSuiteRejected` | no |
| HTTPS alone sends no UDP, its self node takes no peer relay, and its map holds the relays' names on 443 alone; elsewhere a name comes after a relay's public addresses | `conn`: `TestHTTPSOnlySendsNoUDP`, `TestOnlyTCP443KeepsTheNamesAlone`, `TestANamedRelayComesAfterItsPublicAddresses`, `TestUpstreamOnlyTCP443SendsNoUDP` | no |
| a relay shows a CA's certificate to a client asking for its name and the pinned one to the rest, answers TLS-ALPN-01, and relays by the name; the relay's own port reads no PROXY header | `relay`: `TestANameIsServedUnderItsPublicCertificate`, `TestAChallengeForTheNameIsAnswered`, `TestMembersRelayThroughThePublicName`, `TestTheRelaysPortReadsNoHeader` | no |
| the rendezvous answers for the network's members alone, takes a member's own announcement under its own key, bounds each client, and is reached through a proxy | `relay`: `TestTheRendezvousHoldsWhatItTakes`, `TestTheRendezvousLimitsEachClient`, `TestTheRendezvousIsReachedThroughAProxy`; `daemon`: `TestTheRendezvousAnswersForMembersAlone` | no |
| a relay's name is announced, 443 is taken by address unless the ingress hands the name on, and HTTPS alone announces no address, searches no LAN and looks members up at the relays | `daemon`: `TestARelaysNameIsAnnounced`, `TestTheRelayTakes443UnlessTheIngressDoes`, `TestHTTPSAloneAnnouncesNoAddressAndUsesTheRelays`; `internal/ingress`: `TestTheIngressHandsARelaysNameOn` | no |
| links name relays by name; a host and a guest meet there through a CONNECT proxy, verified by WebPKI | `trust/enroll`: `TestLinksNameRelaysByName`; `relay`: `TestAHostAndAGuestMeetByTheRelaysNameThroughAProxy` | no |
| `juist set` keeps the settings of 443, refuses HTTPS alone without a device, and says what it set; the root helper binds 443 at a host's address alone; relay.sh grants and takes back the capability and the port | `daemon`: `TestSettingsOf443AreKeptAndShown`; `cmd/juist`: `TestSetSaysWhatItSetOf443`; `internal/plumber`: `TestTheHelperBindsTheRelaysPortAtAHostsAddress`; `packaging`: `TestRelayScriptGrantsAndTakesBack443` | no |
| a relay's addresses on this host's network first where it is seen from this host's public address, this device's own relay's at an address this host holds, its name at public ones alone; the proxy's user kept from the DERP client; a relay outlives a temporary accept error, bounds an IPv6 client by its /56 and spends nothing on keys of no member's; a challenge is ALPN's protocol alone and a held certificate is never locked out; a host waits at a relay's name where its port fails; the root helper binds no juist device's address | `conn`: `TestAnAddressOnThisHostsNetworkComesFirstAtOneSite`, `TestThisDevicesOwnRelayLeadsWithAnAddressItHolds`, `TestANamedRelaysAddressesArePublic`, `TestTheProxyIsForTheNamesOfHTTPSOnlyRelays`; `relay`: `TestARelayOutlivesATemporaryAcceptError`, `TestTheRendezvousBoundsClientsByNetwork`; `daemon`: `TestARelayOrdersItsCertificateSparingly`, `TestAFailedOrderLocksNoClientOutOfAHeldCertificate`, `TestThisNodesOwnRelayIsInItsOwnMap`; `internal/host`: `TestAHostWaitsAtARelaysNameWhereItsPortFails`; `internal/plumber`: `TestTheHelperBindsTheRelaysPortAtAHostsAddress` | no |
| a public address of this host's is held past one report, a hello without ECDSA orders nothing, credentials taken back are sent no more, and the ingress is handed the name once the relay reads its header | `conn`: `TestAPublicAddressOfThisHostsIsHeld`, `TestTheProxyIsForTheNamesOfHTTPSOnlyRelays`; `daemon`: `TestAHelloWithoutECDSAOrdersNothing`, `TestTheRelayTakes443UnlessTheIngressDoes` | no |
| a relay's name is taken once the server at it says whose it is, in the data plane and in invites; the rendezvous key is none a DHT message carries, and an older epoch's keys are only put, from a budget of their own; the hand-off socket takes the ingress user's connections alone, and one refused holds no slot; a member's name the same as the relay's is not served | `daemon`: `TestARelaysNameIsTakenOnceItsServerSaysWhoseItIs`, `TestAnInviteNamesARelayItCouldNotAsk`, `TestTheRendezvousKeyIsNoneTheDHTShows`, `TestTheRendezvousAnswersForMembersAlone`, `TestTheHandOffTakesTheIngressAlone`; `relay`: `TestARelaySaysWhoseItIsUnderItsName`, `TestAnOlderEpochsKeysSpendABudgetOfTheirOwn`, `TestARefusedHandOffHoldsNoSlot`; `internal/ingress`: `TestARelayKeepsItsNameFromAMembers`; `conn`: `TestARelayNameIsAPublicName` | no |
| no redirect is followed, no SOCKS proxy taken, and a proxy that cannot be told is no way around it; a device not on HTTPS alone invites through no proxy; a proxy's password stays out of errors and off the command line; handshakes order no certificate, nor the relay on the ingress before the ingress hands its name on; an answer without end is cut off; a grant of 443 that outlived its name is warned of and taken back | `daemon`: `TestARelaysRedirectIsNotFollowed`, `TestAnEnvironmentsSOCKSProxyIsRefused`, `TestAnInviteTakesTheProxyOnHTTPSAloneOnly`, `TestARelayOrdersItsCertificateSparingly`, `TestTheRelayOrdersOnceTheIngressHandsItsNameOn`; `conn`: `TestTheProxyFailsClosed`; `ipc`: `TestAProxyRefusedKeepsItsPassword`; `relay/forward`: `TestAnEndlessAnswerIsCutOff`; `cmd/juist`: `TestSetSaysWhatItSetOf443`, `TestAGrantOf443WithoutANameIsTakenBack`; `packaging`: `TestFreeBSDRelayScriptGrantsAndTakesBack443` | no |
| on FreeBSD the helper binds 443 for the relay where root granted it alone, and not where another program answers on the wildcard | `internal/plumber`: `TestTheRelaysPortIsTakenFromNoServer` | FreeBSD |
| between hosts: a device that passes TCP to 443 and DNS alone, and one behind a CONNECT proxy alone, join by a link, reach fb and lx through their relays' names by Pebble's certificates, keep reaching fb once its home relay moves and again after a restart; the first's capture holds TLS to the relays' names and DNS alone, as nDPI classifies it, the second's its proxy alone, asked for those names on 443; fb, the ingress, serves its relay on 443 beside its names | `make interop`: `TestLinuxAndFreeBSD/HTTPS_alone` | qemu |
| handshakes mix in the preshared key, by both paths into the engine; a peer newly keyed loses the session it had, passes nothing until no session without its key is left, and holding another key completes no handshake | `conn`: `TestHandshakesCarryThePresharedKey`, `TestAKeyWhereThereWasNoneEndsTheSession`, `TestAPeerCreatedWithTheKeyItHadPassesNothing`, `TestAPeerPassingNothingPassesNothing` | no |
| the group key is the pair's in its epoch; an exchange gives both the pair key, which a third member cannot derive; messages are bound to sender, receiver, stores and network, replays and stale or runaway follower messages move nothing, lost ones never leave the two apart; generations are paced and follow every epoch, seeds reach a peer far behind, the store survives a restart and decodes what it encodes | `internal/pairkey`: `TestTheGroupKeyIsThePairsInItsEpoch`, `TestAnExchangeGivesBothThePairKey`, `TestAThirdMemberCannotDeriveThePairKey`, `TestAMessageIsBoundToItsSenderAndNetwork`, `TestAReplayedMessageMovesNothingBack`, `TestAStaleFollowerMessageStartsNothing`, `TestAFollowerCannotRunTheCountOut`, `TestLostMessagesNeverLeaveTheTwoApart`, `TestAnOfferForAPairStartedOverIsIgnored`, `TestAPairStartedOverOnOneSideMeetsAgain`, `TestAPairKeyFollowsItsBinding`, `TestAnIdentityRotationKeepsThePairKey`, `TestGenerationsArePaced`, `TestSeedsReachAPeerFarBehind`, `TestTheStoreSurvivesARestart`, `FuzzTake`, `FuzzDecodeStore` | no |
| tunnels move to pair keys and to new ones at an epoch bump; a sleeper reaches the peer it paired with; blocked handshakes never leave a pair without a key; a change not kept is undone; a removed device gives its pairs up; the first announcement names the epoch; a peer without post-quantum keys is refused announcements, routes nothing else | `daemon`: `TestTunnelsMoveToPairKeys`, `TestAnEpochBumpMovesThePairKeys`, `TestASleeperReachesThePeerItPairedWith`, `TestBlockedHandshakesNeverLeaveAPairWithoutAKey`, `TestAPairChangeNotKeptIsUndone`, `TestARemovedDeviceGivesItsPairsUp`, `TestTheFirstAnnouncementNamesTheEpoch`, `TestARouterThatIsNotPostQuantumCarriesNothingElse` | no |
| a TCP stream, over IPv4 and IPv6, survives a new preshared key with a handshake under it, egress refused and back, serving as an exit node and not, a new key and a renumbering, its longest stall under six seconds, a handshake retried once crossed; the IPv4 one ends with its old address | `conn`: `TestNetnsAStreamSurvivesChanges` | **yes** |
| the running data plane takes a new key and new addresses, refuses another ID, disco key or a peer's key or address, and guards new addresses before they go on the device; a peer that took a new key with no relay is reached as disco proves the path, held at most a bound and forgotten once removed; a failed router is retried on the router, without an empty config | `conn`: `TestANewKeyInPlace`, `TestNewAddressesInPlace`, `TestSetSelfRefuses`, `TestNewAddressesAreGuardedAhead`, `TestANewKeyIsReachedAtOnce`, `TestWhatWaitsForAProvenPath`, `TestAnUnprovenPeerIsHeldForAWhileAlone`, `TestReconfigRetriesAfterAFailedRouter`, `TestReconfigReprogramsAFailedRouterOnTheRealEngine` | no |
| new addresses go on before routes take the new source and the old come off, so no route to a peer goes for a moment; on FreeBSD a route's new source goes in beside the old where the kernel takes both | `conn`: `TestNetnsRouterLeavesTailscaleAlone`; `internal/plumber`: `TestARouteFromANewSourceGoesInFirst`; `conn` on FreeBSD: `TestAPlumbedDeviceCarriesTheOverlay` | the first; FreeBSD, the others |
| the running mesh takes a rotation of its keys and moves onto new overlay addresses, a move at once too, and a move said late is forgotten; a host conflict drops IPv4 and takes it back without a restart; log sync's listener moves, and binds an address once it can | `daemon`: `TestRotationIsAdoptedWithoutARestart`, `TestTheMeshMovesOntoNewOverlayAddresses`, `TestAMovedDeviceMovesOntoItsNewAddressAtOnce`, `TestAMoveSaidLateIsForgotten`, `TestAnInstanceRunsWithoutIPv4WhereALowerOneHoldsIt`, `TestRebindMovesTheListener`, `TestRebindTakesAnAddressOnceItCan` | no |
| the confiner takes packets of many flows at once, its count of flows right; serving sets UDP GRO forwarding on the uplink and gives it back; TCP to TCP splices within the kernel, a quiet join holding no pipe; each path's throughput | `conn`: `TestTheConfinerTakesPacketsAtOnce`, `TestServingForwardsUDPInBatchesWhileItServes`; `internal/pipe`: `TestTCPToTCPIsSpliced`, `TestAQuietSplicedJoinHoldsNoPipe`; `make throughput`: `TestNetnsThroughput` | for the last |
| an offer a follower put off within the pace reaches the leader once the pace has passed, so every pair moves at an epoch bump without waiting for anti-entropy | `daemon`: `TestAnOfferPutOffByThePaceIsAnsweredOnceItPasses`, `TestAnEpochBumpMovesThePairKeys`; `internal/pairkey`: `TestGenerationsArePaced` | no |
| between hosts: the previous release's network upgraded, every tunnel is on a pair key; an epoch bump moves both to a new one without a gap in a ping; a juistd stopped across two bumps reaches its peer again | `make interop`: `TestLinuxAndFreeBSDUpgraded/post-quantum`, `TestLinuxAndFreeBSDUpgraded/previous_release` | qemu |
| a service member's stack takes UDP, and drops a datagram whose checksum fails; between hosts it serves HTTP/3 at its overlay address | `internal/netstack`: `TestTheStackTakesUDP`; `make interop`: `TestLinuxAndFreeBSD/service_member` | qemu, for the last |
| a relay speaks HTTP/1.1 alone and holds 256 connections from one site (an IPv4 /24, an IPv6 /48) that nothing admitted yet, across its listeners, a newcomer closing the oldest of the host holding the most in the group (an IPv4 address, an IPv6 /56) holding the most there, and 1024 in all, a newcomer closing the same in the site holding the most, ties going to the oldest, so connections kept open or churned from a few places keep no member out, its own site's included, and listeners taking connections at once evict one another's safely; a DERP session leaves them for four under its key, the newest, a forwarded host for the forwarder's bounds, and a guest admitted to wait for those, any answer to it but the upgrade closing it and one with a body refused while still held | `relay`: `TestTheRelaySpeaksHTTP1Alone`, `TestRelayCapsConnectionsFromOneSite`, `TestASitesConnectionsKeepNoMemberOfItOut`, `TestAStrangerInAMembersSiteDisplacesItsOwn`, `TestRelayCapsConnectionsInAll`, `TestTheBoundInAllClosesTheLargestSitesOldest`, `TestHoldingRacesNoEviction`, `TestConnectionsHeldOpenKeepNoMemberOut`, `TestAWaitingHostLeavesTheBoundInAll`, `TestAGuestTurnedAwayIsClosed`, `TestAGuestWithABodyStaysBounded`, `TestRelayClosesTheOldestSessionOfAKey`, `TestAdmittedSessionsLeaveTheSourceBound`, `TestAFloodInAMembersSiteDisplacesItsOwn`, `TestANeighboursPrefixesDisplaceTheirOwn`, `TestPastTheBoundInAllTheLargestSiteGivesWay`, `TestThePendingSetsIndexesAgree` | no |
| a rendezvous stream sends where it last heard its peer, while that address is heard; a stranger's packet carrying the session id points it nowhere else, and a peer whose address went quiet for three keepalives is followed, the unacknowledged window sent again at once; a window unacknowledged past an outage is sent again, keepalives going on beside it | `internal/rendezvous`: `TestAStrangerCannotPointTheStreamElsewhere`, `TestStreamFollowsAPeerThatMoved`, `TestStreamFollowsItsPeer`, `TestAStreamResendsPastAnOutage` | no |
| a relay's names are asked about four at most, its own longest unclaimed giving way to a new one once every 10 minutes, and 64 in all, the longest unclaimed giving way, so one relay cycling names has few asked about and leaves another's new name provable | `daemon`: `TestOneRelayCyclingNamesLeavesAnothersProvable`, `TestARelaysNameIsTakenOnceItsServerSaysWhoseItIs` | no |
| guests waiting at a relay are counted by group (an IPv4 address, an IPv6 /56), four from one at most, however many addresses it spreads them over | `relay`: `TestGuestsAreBoundedByTheirGroup`; `internal/admit`: `TestHostGroupAndSite` | no |

### The device on its host

| Claim | Where it is checked | Privileged |
|---|---|---|
| a real device is programmed into the host | `conn`: `TestRealDevicePlumbsOverlayIntoHost` | **yes** |
| two nodes carry ICMP over both families, and TCP | `conn`: `TestNetnsOverlayCarriesTraffic` | **yes** |
| default-deny survives the router | `conn`: `TestNetnsDefaultDenySurvivesTheRouter` | **yes** |
| the daemon's privilege footprint | the package, by hand — see [Check the privilege footprint](#check-the-privilege-footprint) | **yes** |
| one host in two networks reaches both, over both families | `conn`: `TestNetnsAHostInTwoNetworks` | **yes** |
| instances keep their tables and rules apart | `conn`: `TestInstancesKeepTheirRulesApart`, `TestNetnsInstancesLeaveEachOtherAlone` | for the second |
| an overlapping instance yields IPv4, the same network twice does not start | `daemon`: `TestAnInstanceRunsWithoutIPv4WhereALowerOneHoldsIt`, `TestAnInstanceRefusesANetworkTheHostRunsAlready`, `TestTheLowerInstanceKeepsItsAddresses` | no |
| the CLI finds, makes and removes instances | `cmd/juist`: `TestASecondNetworkRunsBesideTheFirst`, `TestJoiningASecondNetwork` | no |
| each network's juistd runs as a user of its own, reading none of another's keys; an upgrade moves an instance's home out of the default's once, giving on only what was juist's, nothing that became a link or a file meanwhile; a purge removes an empty home alone | `make interop`: `TestLinuxAndFreeBSD/a_user_per_network`, `TestLinuxAndFreeBSDUpgraded`; `packaging`: `TestInstancesMoveOutOfTheDefaultsHome`, `TestARunningInstanceMovesOverTheHomeItsStopMade`, `TestAHomeSwappedForALinkIsGivenNothing`, `TestAPurgeKeepsAnInstancesHomeThatHoldsKeys`, `TestAnInstanceHomeMovesOnceAndFollowsNoLink`; `cmd/juistd`: `TestTheDaemonRunsAsItsInstancesUser` | qemu, and FreeBSD for the last but one |
| a local user who may not operate is shown no other member's name or identity, each by a pseudonym the same throughout one status | `ipc`: `TestAReaderSeesNoMembersNames`, `TestEveryStatusFieldIsClassifiedForReaders`; `cmd/juist`: `TestStatusVerboseNamesEachDevicesRelay` | no |
| a renumbering keeps every pair reachable, the offline one included | `conn`: `TestNetnsRenumberingKeepsEveryPairReachable`; `trust/log`: `TestRejectsCollidingV4Address` | for the first |
| a descriptor juistd is sent by its binder or plumber is taken only alone, in one whole message; every other that arrives is closed, before an unreadable message or in a truncated read too | `cmd/juistd`: `TestABindersExtraDescriptorsAreClosed` | no |

### The log, membership and freshness

| Claim | Where it is checked | Privileged |
|---|---|---|
| the adversarial suite is rejected 100 % | `trust/log`: `adversarial_test.go`, one test per attack | no |
| parsers survive fuzzing | `make fuzz-long` over `FuzzDecodeAUM`, `FuzzValidateAUM`, `FuzzChainValidate`, `FuzzParseInvite`, `FuzzDecodeEnrollFrames` | no |
| default-deny: no log entry, no handshake | `daemon`: `TestNonMemberIsNeverAPeer`; `conn`: `TestNonMemberIsDenied`, `TestFilterRejectsNonMembers` | no |
| revocation converges inside the budget | `daemon`: `TestRevocationConvergesWithinTheBudget`, `TestRevokedDeviceLosesTheDataPlane` | no |
| LAN-only, zero internet | `daemon`: `TestMeshFormsOnTheLanAlone` | no |
| a member offline across more epoch bumps than the keyring holds, an identity rotation among them, syncs again from one reachable member without an invite; a removed device is refused a catch-up by every member holding the removal and says so; a catch-up proof replayed, foreign or for another nonce gets nothing | `daemon`: `TestAMemberThatSleptThroughManyChangesCatchesUp`, `TestARemovedSleeperSaysItWasRefused`, `TestARemovedSleeperIsRefusedByMembersRestartedSince`; `gossip`: `TestACatchUpProofMustBeFreshAndOwn`, `TestAGrantFromANonMemberGetsNothing`, `TestACatchUpForAnUnlistedDeviceIsRefused` | no |
| a disable record is refused without a secret of the network, or with a signature; with one it ends the network wherever it hangs (on the chain, a losing branch, below a compacted anchor, an unknown parent, past a schema stop), under every schema, finally, and alike in any order; nothing follows it | `trust/log`: `disable_test.go`, `FuzzChainValidate`'s seed; `types`: `fields_test.go` | no |
| a disabled juistd drops every peer, says so, keeps handing the record to members and granting catch-ups, and is reset without `--force` | `daemon`: `TestDisableDropsEveryPeer`, `TestADisabledNodeHandsTheRecordOn`, `TestDisableReachesEveryMember` | no |
| `juist create` shows the one break-glass secret and writes it nowhere; `juist network disable` asks, needs a juistd and a secret of the network, from a line on stdin, a file, or an older network's file in the keystore; nothing signs or applies a change after; admin keys go out and in as one checksummed line, never replacing a key | `cmd/juist`: `backup_test.go`, `TestAKeystoreFoundsSeveralNetworks` | no |
| between hosts: fb ends the network and lx, told by fb's juistd, drops its tunnel | `make interop`: `TestLinuxAndFreeBSD/disable` | qemu |
| each signed thing is refused signed by Ed25519 alone: records, announcements (held as hints), address keys, catch-up, leases, waiting changes, pair-key messages, admissions | `trust/log`: `TestCheckLease`; `gossip`: `TestEd25519AnnouncementsAreHints`, `TestAddressKeysAreHeldOnlySignedByMLDSA`, `TestACatchUpIsSignedByMLDSA`; `internal/waiting`: `TestACopySignedByEd25519AloneIsRefused`; `internal/pairkey`: `TestAMessageSignedByEd25519AloneIsRefused`; `trust/enroll`: `TestLinksNameTheAdminAndAdmissionsBindTheGuest`, `TestAJoinRequestProvesItsSigningKey` | no |
| admin keys carry endorsed signing keys; keys enter with their identities, no two alike; a genesis names them all; a member's names take at most 2048 bytes | `types`: `TestAnAdminKeyTokenIsEndorsed`; `trust/log`: `TestKeysEnterWithTheirIdentities`, `TestAGenesisNamesEverySigningKey`, `TestNameBytesAreCapped` | no |
| an echo signed by Ed25519 alone moves no numbering | `daemon`: `TestAnEchoOfAPreviousRunIsAnnouncedPast` | no |
| a record and a checkpoint at their caps, and every frame at its caps, stay within the limits | `trust/log`: `TestACheckpointFitsAtTheCaps`; `gossip`: `TestFramesAtTheirCapsFit` | no |
| a recorded enrollment whose SPAKE2 key is handed over stays closed; juist's own TLS refuses 1.2 and no ML-KEM, and a relay's public name answers a juist client by the certificate autocert holds | `trust/enroll`: `TestARecordedEnrollmentStaysClosedWithItsSPAKE2Key`; `relay`: `TestARelayRefusesTLSWithoutMLKEM`, `TestARelaysPublicNameAnswersAJuistClient`; `make interop`: `TestLinuxAndFreeBSD/HTTPS_alone` | qemu, for the last |
| a state, genesis or checkpoint below schema 18 is refused, and so is an announcement naming none; every admin key and member has a signing key; without a prefix of its own no member holds an address in 100.64/10 | `types`: `TestAStateBelowTheMinimumSchemaIsRefused`, `TestEveryPayloadIsValidated`; `trust/log`: `TestKeysEnterWithTheirIdentities`, `TestTheOverlayV4Ranges`; `gossip`: `TestEndpointRejectsBadShape`; `cmd/juist`: `TestAMemberIn100_64IsRefused` | no |
| between hosts the previous release runs beside this build: a device upgraded while the other sleeps on it, both reach each other, both upgraded cross an epoch bump without a gap in a ping | `make interop`: `TestLinuxAndFreeBSDUpgraded/previous_release` | qemu |
| an identity rotation names the new identity's signing key in what the quorum, the old key and the new one sign, from schema 19 alone; copies of one record, a minority key's added signature or a relayer's dropped one, are that record in either order, bounded, and sign no branch alone | `trust/log`: `TestARotationsSigningKeyCannotBeSwapped`, `TestARotationNeedsSchema19`, `TestACopySignedByOneMoreKeyIsTheRecord`, `TestAStrippedCopyIsTheRecord`, `TestChangesOnTwoCopiesAreSiblings`, `TestACopyDoesNotSignItsBranch`, `TestCopiesAreBoundedBySigners` | no |
| a hint says where to dial alone: no disco key, relay, epoch or pair store, and a device held by a hint alone moves no pair; what is not shown signed by ML-DSA numbers itself at most ten minutes ahead; a catch-up refusal goes only to a device once listed | `gossip`: `TestEd25519AnnouncementsAreHints`, `TestAnAnnouncementBeforeTheKeysIsNumberedLikeAHint`, `TestOnlyADeviceOnceListedIsToldItWasRefused`; `daemon`: `TestAForgedHintLeavesThePairKey`, `TestAHintAloneMovesNoPair`, `TestAnnouncementsAreHeldToTheSigningKeysFromTheStart` | no |
| the enrollment words cover the ML-DSA key, and an admission holds the guest to it; an address seal's nonce is no MAC under the sealing key; the group secret's KEM is MLKEM768-X25519; pf's juist0 states are bound to it | `trust/enroll`: `TestTheWordsCoverTheSigningKey`; `cmd/juist`: `TestAnAdmissionHoldsTheGuestToItsSigningKey`; `internal/addrkey`: `TestASealsNonceIsNoMACUnderItsKey`; `trust/secrets`: `TestCiphersuiteIsTheIntendedOne`; `internal/plumber`: `TestServingRules` | no |
| no string juistd gives the CLI, a helper or the app carries a control, bidi or zero-width character or a line break; a root command names a device or relay name only where it is an interface or host name; withdrawing authority on a stale view is warned of | `ipc`: `TestEveryStringOfAReplyIsPrintableText`, `TestWhatAHelperReadsIsPrintableText`; `cmd/juist`: `TestACompromisedJuistdPutsNoControlCharacterOrRootCommandOnTheTerminal`, `TestNoRootCommandIsSuggestedForANameThatIsNoInterfaceOrHost`, `TestARevocationOnAStaleViewIsWarnedOf` | no |
| a hint alone says where to dial its member and nothing more: no relay, name, route, epoch or pair store, and a disco key it shares with an announcement leaves the hint's member out; a removed device is refused by members restarted since, by the key the chain named it with | `gossip`: `TestAHintAloneSaysWhereToDialAlone`; `daemon`: `TestAHintAloneNamingAMembersDiscoKeyLeavesThatMembersPeer`, `TestAHintAloneAddsNoRelayAndTakesNoName`, `TestAHintAlonePicksNoPresharedKey`, `TestARemovedSleeperIsRefusedByMembersRestartedSince`; `trust/log`: `TestTheChainNamesTheKeyOfEveryMemberItListed` | no |
| a chain fork choice moves below the epoch floor is held under a rollback alarm that withholds the trusted state, takes the mesh down, survives a restart and clears once the chain is back at the floor, and the node goes on taking records; a late surplus signature that turns fork choice there alarms, never diverges unseen | `trust/log`: `TestAForkSwitchBelowTheEpochFloorFailsClosedAndKeepsTakingRecords`, `TestAnEpochRollbackIsNotFollowed`, `TestALateSurplusSignaturePastTheFloorAlarms`, `TestAnUnreadableUpgradeHidesNoRollback`; `trust/store`: `TestLostRecordsDoNotRegressTheEpoch`; `daemon`: `TestAForkSwitchBelowTheEpochFloorDropsEveryPeer` | no |
| a pin written without its head's content continues the log where the pinned copy can be found or rebuilt, and a join pins the admitted head's content; a checkpoint's copies are kept to a bound so a peer anchored at any is served; a hint alone names no build | `cmd/juist`: `TestAContentlessPinOnAPrunedCopyContinuesTheLog`, `TestAnAdmissionPinsTheAdmittedHeadsContent`; `trust/log`: `TestCheckpointCopiesAreKeptToABound`; `daemon`: `TestMissingServesAPeerAnchoredAtAThirdCopyOfACheckpoint`, `TestAHintAloneNamingAnOlderBuildIsNotOutdated`, `TestALiveMemberHeldByAHintIsNoOlderBuild` | no |
| a member whose disco key is new since the announcement held, a restart's, is installed on the key a newer hint names while this device reaches it by no tunnel, log sync running through the tunnel; such a hint has its member probed at once, past an answer standing and a backoff, and two probes missed in a row, a handshake from before notwithstanding, find it down within seconds; a tunnel that answers keeps its key | `gossip`: `TestEd25519AnnouncementsAreHints`; `daemon`: `TestANewerHintsDiscoKeyIsInstalledWhileItsMemberIsNotReached`, `TestARestartedMembersHintMovesItsDiscoKeyWithinSeconds`; `make interop`: `TestLinuxAndFreeBSDUpgraded/previous_release` | qemu, for the last |
| a log past what a hello lists, with no checkpoint, converges on a change; the admin's CLI follows the change that leaves 256 records past the last checkpoint with one, unasked | `daemon`: `TestALogPastWhatAHelloListsConverges`; `cmd/juist`: `TestAChangePastTheIntervalIsFollowedByACheckpoint` | no |
| devices compact to the checkpoint before the newest once every live member is heard past the newest, or one heard compacted that far, keeping the chain up to it, and not while a lost revocation waits to be redone; a device behind a peer that compacted catches up from that; one further behind is invited again by a link naming its admin, onto a later epoch alone, a disabled log not at all, never by a typed code; a device answered only from beyond its log says so | `internal/guest`: `TestAnInvitesChainReplacesALogOnlyOnAnAdmission`; `daemon`: `TestADeviceOvertakenByItsPeersSaysSo`, `TestDevicesCompactOnceEveryMemberIsPastTheCheckpoint`, `TestCompactionWaitsForEveryMemberOrOneThatCompacted`, `TestCompactionFollowsEveryMemberHeardPastIt`, `TestADeviceBehindACompactedPeerCatchesUp`, `TestMissingRespectsThePeersAnchor`; `trust/log`: `TestAnOrphanedRevocationIsNamed`; `cmd/juist`: `TestADeviceBehindWhatItsPeersKeepIsInvitedAgain`; `trust/log`: `TestRebaseMovesALogBehindToTheInvitesChain`, `TestRebaseRefusesADisabledLog`, `TestBootstrapFromCheckpointAndCompact`; `trust/store`: `TestCompactionRemovesFilesAndSurvivesReopen` | no |
| a pinned head juistd compacted away is stood in for by a checkpoint a quorum of the pinned keys signed and led to from the head, not by one at a later epoch alone, a counterfeit or one on a branch that lost to the head; no checkpoint is drafted or asked for under an alarm | `cmd/juist`: `TestAPinGoesOnPastACompaction`, `TestALosingCheckpointDoesNotStandIn`, `TestNoCheckpointOfALogUnderAnAlarm`, `TestStatusSaysThisDeviceIsBehindWhatItsPeersKeep` | no |
| a checkpoint that loses fork choice raises no alarm and asks no one to redo it | `trust/log`: `TestALostCheckpointRaisesNoAlarm` | no |
| the anchor stays a checkpoint behind the newest, so a removal drafted beside the newest takes effect through sync on a device that compacted as on one that did not, and a record below the anchor, a settled orphan offered again included, is refused without an alarm; the chain kept below ends at a copy of the previous anchor; a rebase takes only a chain whose anchor the trusted admins signed, by a link naming its admin, and a chain holding the anchor or a copy is taken from there; the pin needs the way to its head; no checkpoint under an alarm | `trust/log`: `TestACompactedDeviceTakesARevocationBesideTheNewestCheckpoint`, `TestARecordBelowTheAnchorIsRefused`, `TestCompactedAnchorRejectsPreCheckpointFork`, `TestTheChainKeptBelowEndsAtACopyOfThePreviousAnchor`, `TestRebaseRefusesACheckpointOtherKeysSigned`; `daemon`: `TestARemovalBesideACheckpointReachesACompactedPeer`; `internal/guest`: `TestAnInvitesChainReplacesALogOnlyOnAnAdmission`; `cmd/juist`: `TestALosingCheckpointDoesNotStandIn`, `TestNoCheckpointOfALogUnderAnAlarm` | no |
| two checkpoints minted by a key a raised quorum left without one undo nothing; a device ahead is not said to be behind, nor one rebased; a compaction is not due again at once; a disable record counts in the CLI wherever it hangs | `trust/log`: `TestMintedCheckpointsDoNotUndoARevocation`; `daemon`: `TestADeviceOvertakenByItsPeersSaysSo`, `TestCompactionFollowsEveryMemberHeardPastIt` | no |
| a record names a signing key only for an identity the state has none for, so a rotation onto an admin's identity casts no vote for it, in the log as in the CLI | `trust/log`: `TestARotationOntoAnAdminCastsNoVote` | no |
| every decoder of what arrives from outside juistd turns a panic into an error that names where it was raised, so a parser's slip drops what it decoded and not the process, and a DNS query that cannot be read past its header is a server failure, not asked upstream; code that changes shared state still ends the process on a panic | `internal/malformed`: `TestAPanicIsAnError`, `TestEveryDecoderOfOutsideInputRecovers`; `internal/names`: `TestAnUnreadableQueryIsAServerFailure` | no |
| log sync holds four connections that have said nothing from one source, an overlay address or else a host (an IPv4 address, an IPv6 /64) however many addresses it spreads them over, and eight in all, the oldest closed past either, so silent ones hold half its slots at most and a member whose hello comes at once gets a session | `gossip`: `TestSilentConnectionsOfOneHostShareItsBudget`, `TestSilentConnectionsFromOneGroupLeaveAMemberASlot`, `TestSilentConnectionsCannotHoldEveryInboundSlot` | no |
| a member is admitted by one rule, record by record and in a whole state alike: any member set the records take a genesis or checkpoint takes, and the other way round; an address in a retiring range is refused either way | `trust/log`: `FuzzAdmissibleAlike` (its seeds; `make fuzz` beyond them), `TestRecordsRefuseAnAddressInARetiringRange` | no |

### Enrollment and admins

| Claim | Where it is checked | Privileged |
|---|---|---|
| a code admits exactly one guess, from the LAN | `trust/enroll`: `TestOneGuessPerInvite`; `cmd/juist`: `TestAWrongCodeVoidsTheInvite`; `internal/host`: `TestTheCodeIsTakenFromTheLinkAlone` | no |
| a partitioned member drops a revoked peer at exactly the TTL | `daemon`: `TestPartitionedVictimRefusesARevokedPeerAtTheTTL`, `TestStartupGate` | no |
| admins on separate machines approve a change | `cmd/juist`: `TestInviteWaitsForTheOtherAdmins` | no |
| only root and the operator manage a device; anyone sees its status | `daemon`: `TestSocketIsOpenAndCallsAreChecked`; `cmd/juist`: `TestTheDaemonHoldsTheDeviceAndThePersonHoldsTheKeys` | no |
| SPAKE2 matches RFC 9382 | `trust/enroll`: `TestSPAKE2Constants`, `TestKeyScheduleMatchesRFC` | no |
| a guest stores nothing without the inviting admin's admission | `internal/host`: `TestTheGuestRequiresTheAdminsAdmission` | no |
| a compromised juistd cannot get the admin's signature on anything else | `cmd/juist`: `TestRotationRecordsFromTheDaemonAreChecked`, `TestAnInviteThroughTheDaemonAdmitsOneDevice`, `TestTheKeystoreAnchorsWhatItVerified`, `TestTheAnchorRefusesARollback` | no |
| approve shows a record's effect, not its file name | `cmd/juist`: `TestApproveShowsWhatItSigns` | no |
| freshness needs the threshold of admin devices | `trust/log`: `TestFreshnessNeedsTheThresholdOfAdminDevices` | no |
| each network its own admin key, one shared only on purpose | `cmd/juist`: `TestEachNetworkHasAnAdminKeyOfItsOwn` | no |
| keys from before, and keys made before their network | `cmd/juist`: `TestAKeyFromBeforeKeysPerNetworkSignsUnchanged`, `TestAKeyMadeBeforeItsNetworkIsFiledUnderIt`, `TestWithoutALogKeysOfTwoNetworksSignByName` | no |
| a waiting change reaches the other admin device and applies with its vote | `cmd/juist`: `TestAChangeWaitsOnTheOtherAdminDevice`, `TestAnInviteGoesOnWithAVoteFromAnotherAdminDevice`, `TestAnAdmissionGathersVotesWhileItsInviteRuns`, `TestApprovingTheFileCarriesTheSignature`, `TestAFileIsHandedOnByItsSigner`; `gossip`: `TestWaitingChangesReachTheAdminDevices` | no |
| a copy not from a current admin key, or past the log, is dropped | `daemon`: `TestADaemonHoldsOnlyChangesThatFit`, `TestOneSignerCannotFillTheRoom`; `internal/waiting`: `TestAChangedCopyIsRefused`, `TestASignerLyingAboutItsChangeIsFoundOut` | no |
| no device without the admin role, nor the one a change is about, receives it | `gossip`: `TestWaitingChangesReachNoOtherDevice`; `daemon`: `TestADaemonHandsChangesToAdminDevicesAlone`, `TestHeldChangesAreSaidToAdminDevicesAlone`; `cmd/juist`: `TestAChangeNeverReachesTheDeviceItIsAbout` | no |
| nothing is signed unasked | `cmd/juist`: `TestAChangeWaitsOnTheOtherAdminDevice`, `TestAChangeThatExpiresWhileAskedIsNotSigned` | no |
| a change sealed to its admins opens for no other key | `internal/waiting`: `TestAChangeOpensForItsAdminsAlone`; `trust/secrets`: `TestSealKeyToOpensForItsReaderAlone`; `trust/log`: `TestSetAdminRecipient`, `TestAGenesisRecipientIsSignedForByItsKey` | no |
| a device moved at once is reached at its new address only, and other transitions run on | `cmd/juist`: `TestAMoveAtOnceReachesEveryDevice`, `TestMovingADeviceAtOnce`, `TestAMoveAtOnceReadsAsOne`, `TestHeldAddressesRead`, `TestStatusNamesTheDevicesNotYetMoved`; `daemon`: `TestAMovedDeviceMovesOntoItsNewAddressAtOnce`; `trust/log`: `TestRenumberNodeAtOnce` | no |

### Exit nodes, subnet routers and DNS

| Claim | Where it is checked | Privileged |
|---|---|---|
| only the chosen exit node carries the internet, and a member without a grant is dropped sending from it | `conn`: `TestRoutesCarryTrafficToAndFromTheirPeer`, `TestSetPeersRefusesRoutesThatClash`, `TestAServingNodeAcceptsWhatItServesAlone`, `TestByRouteAtTheEdges`; `daemon`: `TestAClientRoutesThroughItsExitNode` | no |
| no grant overlaps the overlay, and the internet leaves out the overlay, private and special ranges | `trust/log`: `TestRejectsOverlayOverlappingRoutes`, `TestDefaultRouteRequiresExitNodeRole`; `conn`: `TestInternetIsPublicSpaceAlone` | no |
| with a full tunnel up nothing but the LAN is reached outside it, pushed routes, bound sockets and a flushed table notwithstanding, and a lost exit node is refused, not gone around | `conn`: `TestNetnsExitNode`, `TestNetnsARefusingClientHearsItsExitNode`, `TestTheExitTable`, `TestTheGuardDropsWhatElseWouldLeave`, `TestTheGuardLetsTheHostsOwnLinkTrafficOut`, `TestAddrInReadsTheRightAddress`, `TestOtherEgress`; `daemon`: `TestAChosenExitNodeFailsClosed`, `TestNoExitNodeGoesDirect`, `TestAnUnreadableChoiceIsRefused`, `TestAChoiceWithoutAMeshIsRefused`, `TestAnEgressThatFailsIsNotCalledRefused`, `TestAnExitNodeNeedsASystemUser`; `cmd/juist`: `TestDNSOutsideTheTunnel`, `TestOneNetworkAHostUsesAnExitNodeThrough`, `TestTwoNetworksServingAndUsing`, `TestStrictReversePathFiltering`, `TestFirewalldStrictReversePath`; `conn`: `TestExitRoutesReadBack`, `TestTheExitRuleLeavesBypassMarkedPackets`, `TestAStrictReversePathRuleIsToldApart`, `TestNetnsAStrictReversePathFilterIsFound`, `TestAnUnmarkedExitRuleIsFound`, `TestNetnsAFamilyNoExitNodeCarriesIsRefused`; `daemon`: `TestTheStatusSaysAStrictReversePathFilter`, `TestAnUnreadableReversePathFilterIsLogged` | for the first two and the `Netns` ones |
| a withdrawn role ends use and serving, and a stale exit node serves nothing | `daemon`: `TestAChosenExitNodeFailsClosed/withdrawn`, `TestAnExitNodeServesWhenGrantedAndAgreed`, `TestAStaleExitNodeServesNothing`; `cmd/juist`: `TestAnExitNodeFromGrantToOff` | no |
| an exit node opens none of its own networks, and forwards nothing that is no peer's | `conn`: `TestAnExitNodeServesNotItsOwnNetworks`, `TestServingDropsWhatIsNoPeers`, `TestServingLetsEveryJuistDeviceIn`, `TestNetnsExitNode` | for the last |
| serving needs the grant, the operator's word and forwarding, and the setup is undone | `cmd/juist`: `TestServingWaitsForTheGrant`, `TestServingAndUsingExcludeEachOther`, `TestForwardingIsReadFromTheKernel`; `daemon`: `TestARefusedRelaySetEndsServing`; `conn`: `TestServingNeedsForwarding`, `TestTheExitScriptKnowsTheRules`; `packaging`: `TestExitNodeScriptUndoesWhatItDid`, `TestExitNodeScriptKeepsForwardingItFound`, `TestExitNodeScriptClearsWhatAFailedJuistdLeft` | no |
| the choice is the owner's, kept, followed and forgotten with the network | `daemon`: `TestTheExitChoiceIsKept`, `TestTheChoiceFollowsARotatedExitNode`, `TestTheServiceKeepsTheMeshsFollowedChoice`, `TestAResetForgetsTheExitChoice`; `cmd/juist`: `TestForceChoosesAnExitNodeThatDoesNotServe`, `TestTheStatusSaysAnExitNodeIsOffline` | no |
| only a router's granted, agreed subnets are sent to it and taken from it | `conn`: `TestSubnetsAreRoutedIntoTheTunnel`; `daemon`: `TestAClientRoutesAGrantedSubnet`, `TestASubnetIsLeftOutWhereItMustBe`; `trust/log`: `TestTwoMembersNeverRouteOneAddress` | no |
| a subnet is reached through its router, a client's own LAN inside it stays its own, and a wider one gives it up, both said | `conn`: `TestNetnsASubnetThroughItsRouter`, `TestARouterServesItsOwnNetworks`; `daemon`: `TestASubnetIsLeftOutWhereItMustBe`, `TestAnExitNodeCarriesNoRoutedSubnet`; `cmd/juist`: `TestASubnetFromAddToRemove` | for the first |
| a route of the host's own inside a subnet is noticed at once, and a Docker network routed is warned of | `conn`: `TestNetnsASubnetThroughItsRouter`; `cmd/juist`: `TestRoutingADockerNetworkIsWarnedOf` | for the first |
| a withdrawn or stale grant ends routing, on both sides | `daemon`: `TestARouterRoutesWhatItIsGranted`, `TestASubnetIsLeftOutWhereItMustBe/stale`; `cmd/juist`: `TestASubnetFromAddToRemove` | no |
| the operator's and the owner's word are kept and forgotten with the network | `daemon`: `TestTheSubnetWordsAreKept`; `ipc`: `TestASubnetRequestSetsOneThing` | no |
| no subnet takes another overlay, a VPN's or the host's own routes, nor what a network pushed | `trust/log`: `TestRejectsOverlayOverlappingRoutes`; `conn`: `TestTheHostsOwnRoutes`; `daemon`: `TestARouterWithoutIPv4RoutesNoIPv4`, `TestAPeerWithoutIPv4IsSentNoIPv4`, `TestOnlyARoutedDeviceSaysItHasNoIPv4`; `cmd/juist`: `TestForwardingStaysWhileEitherServes` | no |
| a member's DNS is answered through its exit node, and not outside the tunnel; no one else is answered; a forwarder that failed to start is started again 30 s on, and `juist health` says why until it is | `conn`: `TestNetnsExitNodeAnswersDNS`; `internal/dnsfwd`: `TestAQueryIsForwarded`, `TestOnlyMembersQueriesAreForwarded`, `TestAMemberIsAnsweredAtItsRate`, `TestTheHostsResolvers`; `daemon`: `TestAnExitNodeAnswersItsMembersDNS`, `TestAnExitNodesForwarderIsStartedAgain`; `cmd/juist`: `TestHealthSaysAnExitNodeAnswersNoDNS` | for the first |
| resolved is pointed at the exit node while one is chosen, refused too, and given back when off | `daemon`: `TestTheHostsDNSGoesThroughTheExitNode`; `internal/resolved`: `TestRouteAndRevert`, `TestADialledClientRoutes`; `packaging`: `TestThePolkitRuleAllowsJuistsDNSAlone` | no |
| without resolved, or refused by it, nothing is configured and the reason is said | `daemon`: `TestDNSOutsideTheTunnelIsSaid`, `TestDNSAroundResolvedIsSaid`, `TestAFailedDNSRoutingWaits`; `internal/resolved`: `TestWhatResolvedCannotDoIsSaid`; `cmd/juist`: `TestDNSOutsideTheTunnel`, `TestTheStatusSaysWhereDNSGoes` | no |
| DNS follows the choice whatever the network does, and a stopped daemon leaves it alone | `daemon`: `TestDNSFollowsTheChoiceWhateverTheNetwork`, `TestAClosedDaemonLeavesDNSAlone`; `internal/dnsfwd`: `TestAFailingResolverIsPassedOver`, `TestASourceHoldsFewConnections` | no |
| an exit node of one family is sent and asked that family alone, and the other is refused at once and said to be | `conn`: `TestNetnsAFamilyNoExitNodeCarriesIsRefused`, `TestTheGuardRefusesWhatNoPeerCarries`, `TestTheRouterLearnsWhatThePeersCarry`; `daemon`: `TestAnExitNodeOfOneFamilyIsSaid`; `cmd/juist`: `TestTheStatusSaysWhereDNSGoes` | for the first |
| an exit node asks nothing of tailscaled for a member, but the resolvers tailscaled replaced, or resolved's other links | `daemon`: `TestAnExitNodeAsksNothingOfTailscaled` | no |
| members ask the exit node's DNS on port 53 of its own addresses alone, which reaches the forwarder | `conn`: `TestNetnsExitNodeAnswersDNS`, `TestDNSIsRedirectedToTheForwarder`, `TestTheRouterServesDNSAsAsked`; `daemon`: `TestAnExitNodeAnswersItsMembersDNS` | for the first |
| an exit node's rules are added and removed by one path, with or without a mesh: a kernel without IPv6 policy routing takes no IPv6 rule, the guard keeping IPv6 in, and adding one without IPv4's fails | `conn`: `TestEgressRulesWithoutPolicyRouting`, `TestNetnsExitNode`, `TestNetnsARefusingClientHearsItsExitNode` | for the netns |
| a name juistd's resolver or an exit node's forwarder asks by the host's DNS routing goes by a read of resolved's routing begun within a second, which queries at once share; a read that fails, or outlasts 3 s, refuses the name with SERVFAIL, never asking the last routing's link nor the host's resolvers, and `juist health` says it until a read or a reconcile ends it, its log once a minute at most; resolved not running, the resolvers resolv.conf names are asked but its stub, a stub alone refusing; a member's name goes where resolved routes it whatever resolv.conf names, refused where only tailscaled would be asked, "~." included; what resolved asks no DNS server of is refused as resolved answers it (NXDOMAIN for RFC 6303/6761/9476 names, REFUSED for its own, mDNS's, LLMNR's and the host's name), a link's own subnet's reverse names go to that link, what it asks over TLS is refused, an IPv6 link-local server keeps its link; what it asks over TLS is refused for the host's own names alone, not for members'; systemd 258's delegates are scopes, the fallback servers taken where resolved would; a single label of a type LLMNR takes is refused unless a search domain takes it; what resolved's stub refuses and what /etc/hosts answers are refused; a member's overridden name never goes to tailscaled; refusals of the tailnet, of TLS and for want of a server are logged once a minute and said by `juist health` for 10 minutes, with a hint; a dangling link to resolved's resolv.conf refuses; links' servers are read from each link, so loopback servers the manager files under the loopback (systemd 255) stay global or their link's, a link without a DNS scope routes nothing, an escaped dot stays within its label, and no system bus is taken for resolved not running; a server of a link resolved no longer has is no global one, a read during which resolved's servers change is read again and else refused, the host's interfaces are read only where a server is on the loopback, each link in one call; juistd's own link is asked nothing, its "~." refusing what it takes and its being a default route keeping the fallback servers out; a name's bytes are lowered A to Z alone; a read of the routing ends within 5 s, connecting included | `daemon`: `TestADomainMovedIsAskedOfItsNewLinkAtOnce`, `TestAnUnreadRoutingRefusesTheName`, `TestQueriesShareOneRead`, `TestAHangingReadRefusesTheName`, `TestWhatIsNotAnsweredGoesWhereTheHostRoutesIt`, `TestAnExitNodeRefusesANameOnlyTailscaledAnswers`, `TestAnExitNodeAsksNothingOfTailscaled`, `TestAReconcileEndsAFailureToRead`, `TestAFlappingReadIsLoggedRarely`, `TestAMembersNameGoesWhereResolvedRoutesIt`, `TestWhatResolvedAsksNoServerOfIsRefused`, `TestAPersistingFailureIsLogged`, `TestADanglingStubLinkRefusesTheName`, `TestClosingDNSReadsNoRouting`; `internal/resolved`: `TestRouting`, `TestRoutingTakesDelegatesAndFallback`, `TestLoopbackServersStayWhereTheyAre`, `TestAnEscapedDotIsWithinALabel`, `TestNoBusIsNoResolved`, `TestALinkGoneMakesNoServerGlobal`, `TestJuistdsOwnLinkIsAskedNothing`, `TestADomainsEscapedBytesAreCompared`, `TestRouteKeepsWhatResolvedKeeps`, `TestDialContextEndsWithItsContext`; `internal/names`: `TestAQuestionKeepsItsBytes`; `internal/dnsfwd`: `TestARefusedQueryIsAnsweredServerFailure`, `TestARefusalIsAnsweredItsRCode`; `cmd/juist`: `TestHealthSaysTheDNSRoutingIsUnread`, `TestHealthSaysRecentRefusals` | no |

### FreeBSD

| Claim | Where it is checked | Privileged |
|---|---|---|
| on FreeBSD the daemon runs as juist or its instance's user, and a helper as root plumbs its daemon's own device alone, one helper each, addresses of one host, no default route and nothing holding the host's own address or a gateway of its routes, and neither outlives the other | `internal/plumber`: `TestTheHelperPlumbsWhatItIsAsked`, `TestTheHelperTouchesNothingElse`, `TestTheHelperPlumbsItsDaemonsDeviceAlone`, `TestTheHelperRoutesNothingOverTheHostsOwnLAN`; `cmd/juistd`: `TestTheHelperPlumbsTheDaemonsDeviceAlone`; `TestAnAddressIsOneHost`, `TestALargeRouteSetGoesWhole`, `TestALateAnswerIsNoOtherCallsAnswer`, `TestADeviceIsOneHelpers`, `TestManyRoutesGoInFast`; `cmd/juistd`: `TestRootSplitsOffTheDaemon`, `TestADaemonStoppedAtOnceStopsCleanly`, `TestTheDaemonGoesWithItsHelper`, `TestAHelperThatStopsServingStopsTheDaemon`, `TestRootNeedsAHome`, `TestRootGetsHelp`, `TestTheDaemonGetsNoneOfRootsEnvironment`, `TestAJuistUserOfRootsIsRefused` | FreeBSD, for the last ten |
| a device the helper made carries the overlay both ways, from the renumbered source, is another instance's holding, and goes with its routes; the host's own routes are read and heard | `conn`: `TestAPlumbedDeviceCarriesTheOverlay`, `TestAPlumbedDeviceTakesWhatTheNodeWrites`, `TestAPlumbedRouterKnowsTheHostsRoutes`, `TestTheManagerAsksItsRouterForTheHostsRoutes` | FreeBSD, but for the last |
| rc.d runs, reports and stops an instance with juistd_args, and the CLI starts, stops and reads instances through rc.conf | `packaging`: `TestTheRCScriptRunsAnInstance`; `cmd/juist`: `TestStoppingAnInstanceDisablesIt`, `TestAnInstanceIsEnabledByRCConf` | FreeBSD, for the first |
| every test passes on FreeBSD, the CLI's hints in rc.d's words | `make test-freebsd` | FreeBSD |
| a FreeBSD exit node or router masquerades the overlay, takes overlay sources and its forwarder by the tunnel alone, and puts forwarding and pf back as it found them | `internal/plumber`: `TestServingRules`, `TestServingSetsTheHostUpAndBack` | FreeBSD, for the last |
| using an exit node on FreeBSD routes the internet into the device behind a guard by juistd's own uid, refusing outlasts the device, and going direct puts all back; the host's DNS goes by resolvconf, on 53 alone | `internal/plumber`: `TestEgressRules`, `TestEgressIsTheDaemonsUser`, `TestEgressSetsTheHostUpAndBack`, `TestDNSGoesByResolvconf`; `daemon`: `TestAHelpersDNSTakesPort53Alone` | FreeBSD, for the last three |
| pf keeps a device's overlay to it, as Linux's in table does: nothing reaches its addresses by another device but the loopback, by TCP too, and no member's source comes in by a device that is no juist one; the LAN reaches a device's overlay address no more; where the host's rules call no juist anchor the status and `juist health` say why | `internal/plumber`: `TestGuardRules`, `TestAGuardTakesTheOverlaysAddressesAlone`, `TestAGuardSetsTheHostUpAndBack`; `daemon`: `TestAnUnguardedOverlayIsInTheStatus`; `cmd/juist`: `TestHealthSaysTheOverlayIsUnguarded`; `make interop`: `TestLinuxAndFreeBSD/tunnel` | FreeBSD, for the third, and qemu |
| pf rules hold none of the daemon's text, what someone takes of juist's pf is put back, the host's own ruleset must call the anchors first and is left be | `internal/plumber`: `TestServingTakesTheDevicesAddressesAlone`, `TestTheHostsRulesCallTheAnchorsFirst`, `TestPFIsKeptAndLeftBe` | FreeBSD, for the last |
| the FreeBSD package is the same bytes from each build, its manifests first, every file's sum and mode as pkg checks them | `packaging/freebsd/mkpkg`: `TestPackage` | no |
| answers to connections that came in by another device leave by it, past the guard, unless isolated; FreeBSD's helper says where the host's own pf rules decide instead | `conn`: `TestTheGuardPassesAnswersButIsolated`; `internal/plumber`: `TestAnswersLeaveTheWayTheyCame`, `TestTheHelperSaysWhereAnswersGo`; `daemon`: `TestAnIsolatedChoiceSendsAnswersThrough`, `TestTheExitChoiceIsKept`; `ipc`: `TestAnExitRequestSetsOneThing`; `make interop` | qemu, for the last |
| `juist exit use --isolate`, or where the host's own firewall keeps answers in the tunnel, stops where it would end the ssh session it runs in, from the internet, found under sudo too, and `--force` goes on | `cmd/juist`: `TestAnExitNodeFromGrantToOff`, `TestTheSSHSessionIsFoundPastSudo` | no |
| the packages take the binaries `make build` left, which go finds up to date, and their pages: `make build` then `make install` builds once | `packaging`: `TestTheFreeBSDPackageTakesWhatMakeBuildLeft`, `TestTheFreeBSDPackageBuildsElsewhereBeside` | no |
| `service juistd clear` takes the devices, anchors and resolvers a juistd left, and puts forwarding and pf back as found | `packaging`: `TestTheRCScriptClearsWhatAJuistdLeft` | FreeBSD |
| Linux and FreeBSD nodes join one network, reach each other over both families, each is the other's exit node, subnet router and DNS, and both packages go cleanly | `make interop`: `TestLinuxAndFreeBSD` | qemu |
| resolved's list of every link's servers as resolv.conf is named as the reason DNS goes around the exit node, with the stub as the hint | `daemon`: `TestResolvedsUplinkModeIsSaid`; `cmd/juist`: `TestTheStatusSaysWhereDNSGoes` | no |
| two builders on two systems make the same binaries for Linux and FreeBSD, and the same package | `make repro-freebsd` | a FreeBSD host |
| the helper takes no address or source outside a network's space, captures nothing the host keeps to its links, deletes a route by its gateway, keeps what to put back where that fails, leaves a pf rc.conf starts on, and adds answer rules beside no ruleset of the host's | `internal/plumber`: `TestTheHelperKeepsToTheNetworksSpace`, `TestARouteDeletedLeavesTheHosts`, `TestAPfTheHostStartsIsLeftOn`, `TestPFIsKeptAndLeftBe`; `conn`: `TestARedirectsRouteIsNotTheHosts` | FreeBSD, but for the first |
| an instance's home moves out of the juist user's once, never following a link as root nor giving on a hard link's file; clear waits for a supervised juistd | `packaging`: `TestAnInstanceHomeMovesOnceAndFollowsNoLink`, `TestClearWaitsForASupervisedJuistd` | FreeBSD |
| the FreeBSD package's modes go by where a file goes, and a file twice or a stray script is refused | `packaging/freebsd/mkpkg`: `TestModesAndMistakes` | no |

### Names

| Claim | Where it is checked | Privileged |
|---|---|---|
| a name is taken in one form alone, of two labels or more, no address and nothing of `.juist` or the host's own domains, sorted and one member's | `types`: `TestHostNames`, `TestNameSets`, `TestEveryPayloadIsValidated` | no |
| a quorum points names at a member and takes them back; they survive reopening, a checkpoint and an identity rotation, and go with the member; a name another holds, a non-member, the names it has, and a quorum short are refused | `trust/log`: `TestNamesFollowTheMember`, `TestNamesAreRefused`, `TestApplyLeavesItsParentUnchanged` | no |
| `juist names add` and `remove` take a name in its one form, never two devices' or the network's own, `grant` and `revoke` name them for a name or a subnet, and an approver reads what a change points where | `cmd/juist`: `TestNamesAddAndRemove`, `TestNameStates`, `TestASubnetFromAddToRemove`, `TestANamesChangeSaysWhatItPoints` | no |
| members' names are answered from the log with the zone's SOA, a name the network lacks does not exist, and overrides are answered by address alone, their hints empty | `internal/names`: `TestMembersAreAnswered`, `TestOverridesAreAnswered`, `TestTheZoneIsItsAuthority`, `TestTheZonesNamesGoNowhereElse`, `TestLabels`; `internal/dnsfwd`: `TestAnAnswerOfItsOwnReachesNoResolver`, `TestTheHostIsHeldToNoSourcesRate` | no |
| resolved routes the network's domain, and every name with an exit node, to juistd's resolver on an address the device holds, bound to it and answering the host alone, which asks the exit node, else the resolvers resolved would but its own link's; the domains are kept from DNSSEC validation; it is given back on close, and the status says why names do not resolve | `daemon`: `TestTheHostResolvesTheNetworksNames`, `TestNamesThatWillNotStartLeaveTheExitNode`, `TestNamesNotResolvedAreSaid`, `TestTheNamesServerIsBoundToTheDevice`, `TestTheNamesAddressIsOneTheDeviceHolds`, `TestWhatIsNotAnsweredGoesWhereTheHostRoutesIt`; `internal/resolved`: `TestConfigureDomains`, `TestRouting`; `packaging`: `TestThePolkitRuleAllowsJuistsDNSAlone`; `cmd/juist`: `TestStatusSaysHowNamesResolve` | no |
| a public name is resolved to its member only where the owner agreed, never by an exit node for a member that did not, which an exit node whose host's resolver does not ask juist's, as without resolved, asks of its own resolvers, while the view is fresh and the member reachable, and publicly otherwise; the word is kept and forgotten with the network, and the status lists each name and why it resolves publicly | `internal/names`: `TestOverridesAreAnswered`, `TestEDNSIsAnsweredInKind`, `TestOverridden`; `daemon`: `TestAPublicNameNeedsTheOwnersWord`, `TestAnExitNodeHandsNoOverrideOn`, `TestAnExitNodeWithoutNamesAsksTheHostsResolvers`, `TestAStaleViewAnswersNoPublicName`, `TestNoMemberNoNames`, `TestTheNamesWordIsKept`; `ipc`: `TestANamesRequestSetsAcceptingAlone`, `TestAReaderSeesNoPublicNames`; `cmd/juist`: `TestAcceptNames`, `TestStatusListsPublicNames`; `ipc`: `TestEachCommandTakesItsOwnFields` | no |
| with resolved, members resolve by name, a public name resolves to its member through the tunnel without the public resolver being asked, a name beside it publicly, and publicly again while the member is down and once revoked | `make interop`: `TestLinuxAndFreeBSD/names` | qemu |
| a name for members alone and a policy naming a name are on 443 by TLS alone; a rule to names names nothing else and no port, a test one name | `types`: `TestNamesForMembersAlone`, `TestAPolicyMeansWhatItSays`, `TestAPolicyNamingNamesNeedsItsSchema`; `trust/log`: `TestNamesForMembers` | no |
| a rule to a name lets its sources open its device on its port and the name alone there, which the device learns by name; a rule to the device's port is none to a name for members; the text reads back, and says what is wrong | `internal/policy`: `TestARuleToANameLetsItsSourcesOpenIt`, `TestNamesAreReadAsTheyMayBe` | no |
| the ingress passes a name for members to the CA's validation alone, says so, and answers port 80 for it as for no name; the device takes it from the members it is for and from the ingress the CA's validation alone, and ends the connection of a member it is no longer for | `internal/ingress`: `TestANameForMembersPassesTheCAAlone`; `internal/terminator`: `TestANameForMembersIsTheirsAlone` | no |
| juistd tells the terminator and the ingress names for members apart, with the members each is for, as the policy says; `juist publish add --members` keeps the mark, and `juist policy test` takes a name | `daemon`: `TestANameForMembersGoesToTheTerminatorApart`, `TestAnIngressIsToldANameForMembersApart`; `cmd/juist`: `TestPublishANameForMembersAlone`, `TestAPolicyNamesANameForMembers` | no |
| between hosts: the internet and the ingress itself through the tunnel are refused, and none of their hellos has the name's certificate ordered; Pebble issues it through the ingress on the hello of a member it is for, which opens it by it; east, which a rule names it for, opens it, west, which may open any port of lx's, does not | `make interop`: `TestLinuxAndFreeBSD/members_alone`, `TestLinuxAndFreeBSD/access_policy` | qemu |
| a name made for members alone ends the connections others opened while it was public, at the ingress and the device, over TCP and QUIC, and a member it is no longer for loses its QUIC connection; a request for another Host is misdirected; sessions resume; a name for members alone shares no service another name or a share passes on as it is, however its address is spelled; the device itself is none of its members | `internal/terminator`: `TestANameMadeForMembersEndsWhatOthersOpened`, `TestHTTP3ForMembersAlone`, `TestAMemberNoLongerForANameLosesItsQUIC`, `TestARequestForAnotherNameIsMisdirected`, `TestATLSSessionIsResumed`; `internal/ingress`: `TestANameMadeForMembersEndsItsConnections`; `daemon`: `TestANameForMembersSharesNoServicePassedOnAsItIs`, `TestAServiceIsOneHoweverSpelledAndAShareSharesIt`, `TestANameForMembersGoesToTheTerminatorApart` | no |
| a hello refused a name for members, over TCP or QUIC, has no certificate ordered; the member's does | `internal/terminator`: `TestARefusedHelloOrdersNoCertificate` | no |
| a request to upgrade to h2c reaches no service; a service is one with its port written with a leading zero, its address mapped or ending in a dot | `internal/terminator`: `TestNoUpgradeToH2C`; `daemon`: `TestAServiceIsOneHoweverSpelledAndAShareSharesIt` | no |
| a name passed by TCP shares its service though its target offers HTTP/3; a policy test of a name for members passes no ingress, service member or its own device, with a policy or without; a test names one name alone, a label; a name for members resolves for those it is for, never on its own device; the status names each one not reached, and a shared service's warning has its hint; the publish line marks a name for members; an approval says which rules a name it publishes opens | `cmd/juist`: `TestAServiceForMembersGoesToNoPublicName`, `TestStatusSaysHowNamesResolve`, `TestTheStatusWarnsOfANameSharingItsService`, `TestPublishANameForMembersAlone`, `TestAPolicyNamesANameForMembers`; `daemon`: `TestAServiceIsOneHoweverSpelledAndAShareSharesIt`, `TestANameForMembersResolvesForThoseItIsFor`; `internal/policy`: `TestANameForMembersPassesWhomTheDeviceTakes`; `types`: `TestAPolicyMeansWhatItSays` | no |
| juistd holds a service meant for members alone from its name while the log has it public, a mark it keeps across restarts and later commands until `--members=false`, in a line an older version leaves out; a test to a name names no exit node | `daemon`: `TestAServiceForMembersIsWithheldFromAPublicName`, `TestTheMarkOfAServiceForMembersIsKept`; `cmd/juist`: `TestAServiceForMembersGoesToNoPublicName`; `types`: `TestAPolicyMeansWhatItSays` | no |
| whatever a host's program sends juist's resolver is answered with a response to it or passed on, and an answer from upstream has every TTL capped but an additional OPT record's, never panicking | `internal/names`: `FuzzAnswer`; `internal/dnsfwd`: `FuzzForwarded` | no |
| a service member marks its services for members alone by `--members`, as its command line says and not a file left from before; `juist publish` shows the mark; on an admin's device the mark changes nothing in the log by itself | `cmd/juistd`: `TestMembersMarksAServiceMembersServices`, `TestHelpListsEveryOptionWithItsDefault`; `daemon`: `TestAServiceMembersMarkIsItsCommandLines`; `cmd/juist`: `TestAServiceForMembersGoesToNoPublicName` | no |

### Publishing

| Claim | Where it is checked | Privileged |
|---|---|---|
| a published name is one label on a port, sorted and once; an ingress is neither voucher nor exit; a state publishes only under a domain of its own | `types`: `TestPublishedNameSets`, `TestAnIngressIsNothingElse`, `TestPublishedNamesNeedTheirDomain`, `TestEveryPayloadIsValidated` | no |
| a quorum sets the domain and publishes names, which survive reopening and a checkpoint; a name before the domain, the domain withdrawn under names, a label another publishes and a name both published and pointed at a member are refused, the domain's move included | `trust/log`: `TestPublishedNamesNeedTheDomain`, `TestPublishedNamesAreOneMembers`, `TestTheIngressRole`, `TestApplyLeavesItsParentUnchanged`, `TestStateCarriesEveryField` | no |
| `juist network domain` and `juist publish` set and list what is published, `juist grant` an ingress, and an approver reads what a change publishes | `cmd/juist`: `TestPublishAddAndRemove`, `TestGrantAnIngress`, `TestAPublishChangeSaysWhatItPublishes`, `TestEveryKindIsDescribed` | no |
| a member takes from an ingress TCP to its own addresses on the ports it publishes and serves and log sync's, and replies to what it opened, nothing else, whatever the flags, the protocol or the address it serves; the engine's own hooks still run | `conn`: `TestTheConfinerKeepsAnIngressToItsPorts`, `TestTheConfinerCallsTheEnginesHooks`, `TestAnIngressReachesItsPortsAlone` | no |
| an ingress is confined, and reaches the published port only once the operator agreed and while the view is fresh; the word is kept and goes with the network, and the status says what is served or why not | `daemon`: `TestAnIngressReachesWhatIsServedAlone`, `TestThePublishWordIsKept`; `ipc`: `TestEachCommandTakesItsOwnFields`, `TestEveryStatusFieldIsClassifiedForReaders`; `cmd/juist`: `TestPublishServe` | no |
| the user juist-ingress may ask what is published and nothing else, from a pool of its own; an ingress is told every published name and where it goes, and nothing once it is no ingress or stale; it reads a reply of a newer juistd | `daemon`: `TestTheIngressAsksWhatIsPublishedAlone`, `TestReadersCannotCrowdOutTheIngress`, `TestAnIngressServesWhatIsPublishedWhileFresh`; `ipc`: `TestTheIngressReadsAReplyOfANewerJuistd`, `FuzzDecodePublished` | no |
| an ingress passes a connection for a published name to its target untouched, its ClientHello first and a PROXY v2 header where asked, past an address that does not answer; a name not published reaches nothing; HTTP redirects a served name to https alone; a silent juistd takes the names down after two asks, and a client that says nothing is let go | `internal/ingress`: `TestTheIngressSplicesByServerName`, `TestTheIngressSaysWhoTheClientIs`, `TestTheIngressRedirectsToHTTPS`, `TestASilentJuistdPublishesNothing`, `TestAClientThatSaysNothingIsLetGo` | no |
| the ingress logs each connection with its client, name, outcome, bytes each way and duration, and each request on port 80 with its path and User-Agent, quoted | `internal/ingress`: `TestTheIngressLogsEachConnection` | no |
| `juist ingress serve` runs the package's script on a device that is an ingress alone, and lists what it serves; the script starts the unit and opens 443 and 80, and takes both back, and removing the package does | `cmd/juist`: `TestIngressServe`; `packaging`: `TestIngressScriptOpensAndCloses`, `TestARemovalStopsTheIngress`, `TestFirewalldServicesParse` | no |
| flows this node opened to confined peers are bounded per address and in all; one peer's churn evicts its own flows, never another's, and a peer no longer confined leaves none behind | `conn`: `TestOnePeersFlowsEvictNoOthers` | no |
| between hosts, from the packages: an ingress serves a name a member publishes once the member's operator agrees, redirects HTTP to it, and reaches nothing else of that member's; a withdrawn name reaches nothing; the package's removal stops the ingress and leaves its user | `make interop`: `TestLinuxAndFreeBSD/ingress`, `TestLinuxAndFreeBSD/removal` | qemu |
| TLS ends at the target for a name served alone, the plain connection reaching the local service; the CA's challenge goes no further; ALPN is offered for it alone; a PROXY header is believed from an ingress alone and passed on; what is served no longer is listened for no longer, and a port another program holds is said | `internal/terminator`: `TestTheTerminatorEndsTLSForWhatItServes`, `TestTheChallengeStopsHere`, `TestTheServiceLearnsTheClientFromAnIngress`, `TestTheTerminatorListensWhereItServes`; `internal/proxyproto`: `TestAHeaderReadsBack`, `TestABadHeaderIsRefused` | no |
| the terminator is told what this device serves and where it goes, on its own addresses, nothing without the word or while stale; it may ask nothing else; where to is kept apart from the word, added to and taken from one name at a time; `juist publish add NAME HOST:PORT` starts it; members resolve a name published on 443 to a target that serves it | `daemon`: `TestATerminatorIsToldWhereNamesGo`, `TestWhereToServeIsKept`, `TestWhereToServeMovesOutOfTheWord`, `TestTheTerminatorAsksWhatItServesAlone`, `TestMembersReachAPublishedNameDirectly`; `ipc`: `TestAPublishRequestNamesWhereTo`; `cmd/juist`: `TestPublishAddEndsTLS`; `packaging`: `TestServeScriptStartsAndStops`, `TestARemovalStopsTheIngress` | no |
| with Pebble as the CA, the terminator takes a certificate by TLS-ALPN-01, answering the challenge itself, which a client trusting Pebble's root alone takes, and tells juistd the account and the CA's name for itself | `make test-acme`: `internal/terminator`: `TestACertificateFromPebble` | no |
| the CAA record: the account key is autocert's own; a terminator's account reaches juistd only where it fits a record as it is; the status holds a record for each name whose TLS juist ends, and `juist publish add` and `serve` print them | `internal/terminator`: `TestTheAccountKeyIsAutocertsOwn`; `ipc`: `TestAServingRequestCarriesAnAccountThatFitsCAA`; `daemon`: `TestTheStatusHoldsTheCAARecords`; `cmd/juist`: `TestPublishAddEndsTLS` | no |
| FreeBSD's helpers: the terminator's root parent listens where juistd says this device serves and nowhere else, and hands it the listener; a helper started as root drops to its user for good; the rc.d scripts run juistd as the helpers on the default socket and stop them; libexec's scripts are executable | `cmd/juistd`: `TestTheBinderListensWhereNamesAreServed`, `TestAHelperDropsRoot`; `packaging`: `TestTheHelpersRCScriptsRunThem`; `packaging/freebsd/mkpkg`: `TestModesAndMistakes` | root, the rc.d one FreeBSD |
| `juist invite --service NAME` admits a service member publishing NAME, under the domain alone and with no other role, and the approval says what it publishes | `cmd/juist`: `TestInviteAServiceMember` | no |
| the service member's image: what docker load takes, the same bytes twice, its binaries runnable and its home its user's | `packaging/image/mkimage`: `TestTheImageLoads` | no |
| a name served that a client found no certificate for is said by the terminator, with why, until one is found, the CA's challenge and a name not served changing nothing; juistd keeps it for the status, which warns of it while the terminator runs | `internal/terminator`: `TestTheTerminatorSaysWhichNamesHaveNoCertificate`; `ipc`: `TestAServingRequestCarriesAnAccountThatFitsCAA`; `daemon`: `TestTheStatusSaysWhereTheTerminatorListens`; `cmd/juist`: `TestTheStatusWarnsOfANameWithoutACertificate` | no |
| systemd starts the terminator by juistd's file: juistd keeps it while a share or a name whose TLS juist ends needs the terminator, and tells the terminator when nothing does, which then stops, though not while it has a name to serve; where systemd starts it, sharing runs no script; a fresh install enables `juist-serve.path`, an upgrade moves a terminator enabled the old way to it and enables nothing else, and `serve.sh` turns the path on and off | `daemon`: `TestJuistdSaysWhenTheTerminatorIsNeeded`; `internal/terminator`: `TestAnIdleTerminatorStops`; `cmd/juist`: `TestAShareWhereSystemdStartsTheTerminatorTakesNoRoot`; `packaging`: `TestTheTerminatorStartsByItsPath`, `TestServeScriptStartsAndStops` | no |
| `juistd --join LINK`, or `$JUIST_JOIN`, which `--help` does not show and a helper ignores: once started, a juistd in no network joins by it and says how it went, and one in a network ignores it | `cmd/juist`: `TestAJuistdJoinsByTheInviteItWasGiven`; `cmd/juistd`: `TestJoinTakesTheInviteFromTheEnvironment`, `TestHelpListsEveryOptionWithItsDefault` | no |
| the Compose example runs juistd with options it takes and passes `$JUIST_JOIN` | `cmd/juistd`: `TestTheComposeExampleRunsAServiceMember` | no |
| over two network stacks, a member opens a connection to a service member and is answered, and the service member opens none to the member; a daemon on a network stack hands the data plane a device, syncs in the tunnel alone, is reached on its overlay addresses alone, binds its sockets to no interface and blames no firewall of its own | `conn`: `TestAServiceMemberAnswersAndOpensNothing`, `TestTheConfinerKeepsAnIngressToItsPorts`; `daemon`: `TestADaemonOnANetworkStack`, `TestANetstackNodeBindsItsSocketsToNoInterface`, `TestTheStatusNamesATunnelTheFirewallBlocks`; `types`: `TestAnIngressIsNothingElse`; `cmd/juistd`: `TestServeMakesAServiceMember` | no |
| with Pebble as the CA, a client outside the network fetches a name a full member publishes, and one a service member publishes, through the ingress, by a certificate each took by TLS-ALPN-01 through it; the service member answers no other port | `make interop`: `TestLinuxAndFreeBSD/TLS_at_the_target`, `TestLinuxAndFreeBSD/service_member` | qemu |
| the service member as its image runs it in Docker, beside a service on an internal network with it alone, serves the service's name through the ingress with a certificate from Pebble; that service reaches neither the LAN nor the overlay, and what it reaches of the host is logged | `make interop` with `JUIST_INTEROP_DOCKER=1`: `TestLinuxAndFreeBSD/service_member_in_a_container` | qemu, Docker |
| the publish role: never beside the ingress role, for a member whose name gives a label, which is then its alone against published labels, other members' publish labels and names | `trust/log`: `TestThePublishRole` | no |
| a share is announced signed, and a change of the announcement; a device shares under its name, its end at most a lease ahead or its own, the terminator ends TLS for it without the published names' word, an ingress may open its port while fresh; announced only while it can be served; renewed as its end moves; an ingress serves members' shares while their announcement holds and takes none ending further ahead than a lease; a share lasts as long as its call and outlives a restart of the network | `gossip`: `TestAShareIsAnnounced`; `daemon`: `TestADeviceSharesUnderItsName`, `TestAShareIsAnnouncedWhileItCanBeServed`, `TestAShareIsRenewedAsItsEndMoves`, `TestAnIngressServesMembersShares`, `TestAnIngressTakesNoShareEndingFarAhead`, `TestAShareLastsAsLongAsTheCall`, `TestAShareOutlivesARestart` | no |
| a shared directory is read under its token alone: anywhere else 404 listing nothing, no link out of it, nothing written, no Referer, no dot-entries, nothing run as the name's origin; a linked file, `index.html` and a name needing escapes are served; `juist share` holds the share until stopped, with the role and a domain, starting the terminator, and says when juistd ends it; `juist publish PORT` takes its port past `--for`, refuses one that is none, and takes IPv6's loopback where only it answers; the CLI knows juistd's refusals by juistd's words | `cmd/juist`: `TestAShareIsReadUnderItsTokenAlone`, `TestAShareServesWhatItNames`, `TestShareUntilStopped`, `TestAShareEndsWithJuistd`, `TestPublishAPort`, `TestTheShareWordsAreJuistds` | no |
| between hosts: a client on the LAN fetches a file lx shares through fb with Pebble's certificate, finds nothing without the token; fb serves the name no longer once the share is stopped, or past its end, which ends the command | `make interop`: `TestLinuxAndFreeBSD/share` | qemu |
| a share in the background: the command returns once the share is up, which serves on until `juist share --stop`, a foreground share heeds that too, stopping none says so, and the share is taken up again under its path after juistd restarts; juistd ends a share from another call, whose call ends without error | `cmd/juist`: `TestAShareInTheBackground`, `TestABackgroundShareOutlivesJuistd`, `TestTheShareWordsAreJuistds`; `daemon`: `TestAShareIsStoppedFromAnotherCall` | no |
| a shared directory is listed folders first and sorted as asked, its links kept under the token whatever a name holds, its dot-entries left out, running nothing and free to download, while what is shared stays sandboxed; a folder with an `index.html` is that page; a directory, or a folder in it, is sent as a ZIP under its name, without dot-entries or what a link reaches outside | `cmd/juist`: `TestASharedDirectoryIsListed`, `TestASharedDirectoryIsZipped` | no |
| the listing looks as the website does, its colours, wordmark and fonts the website's own, the fonts reached under the token alone and not beside a shared file | `internal/webstyle`: `TestThePagesLookAsTheWebsiteDoes`; `cmd/juist`: `TestTheListingLooksAsTheWebsiteDoes`, `TestTheListingsFontsAreUnderTheToken` | no |
| juistd holds up to 16 at once, each file's under its own path and one port's beside them, tells the terminator the paths and announces the last end, and stops one by its path or all; the terminator sends a request under a path to that path's service and any other to the name's, as the name goes at each request on a connection kept open, and ends a piped connection once its name goes elsewhere; `juist share` lists them, `--stop` takes the one named by its file, port or link and names one where several run, and `juist status` counts them | `ipc`: `TestAShareRequestIsBounded`, `TestAnUnshareRequestNamesAShareByItsPath`; `daemon`: `TestADeviceHoldsSeveralShares`, `TestAnUnshareStopsTheShareItNames`; `internal/terminator`: `TestANamesPathsReachTheirOwnServices`, `TestANameGoneElsewhereEndsItsPipedConnections`; `cmd/juist`: `TestAShareInTheBackground`, `TestPublishAPort`, `TestShareUntilStopped` | no |
| the admin's hint names the domain itself, `juistd --serve` takes no empty name, a domain moved is said to publish the domain itself and to have every member resolve it through juistd, and the Names line is never empty | `cmd/juist`: `TestTheTerminatorStartsBeforeTheName`, `TestPublishTheDomainItself`, `TestTheNamesLineNamesTheNames`; `cmd/juistd`: `TestServeMakesAServiceMember` | no |
| the domain itself: the empty label, on one member at most and never a name pointed at a member, either first, the domain moving included; kept as `@` in the names' file; the network's domain goes to juistd whole on every member, the domain itself and its names published on 443 answered names on or not, the rest passed on; published spelled out, with the approval saying so and the apex's records hinted | `types`: `TestPublishedNameSets`; `trust/log`: `TestTheDomainItselfIsOneMembers`; `daemon`: `TestWhereTheDomainItselfGoesIsKept`, `TestTheDomainGoesToJuistdWhole`; `cmd/juist`: `TestPublishTheDomainItself` | no |
| between hosts: a client on the LAN fetches the domain itself through fb with Pebble's certificate; a second device publishing it, and a name pointed at a member equal to it, are refused, each for its reason; the target, a member, sends the domain to juistd, resolves the domain itself to itself, and another name of the domain at the resolver the host routes example.org to, which logs it | `make interop`: `TestLinuxAndFreeBSD/domain_itself` | qemu |
| renaming a device: a name and nothing else changed, kept across reopening and a checkpoint; refused for the name it has, one another member's folds like, and one its share label cannot follow; the approval says what it is then resolved and shared as, and the old name no longer resolves | `types`: `TestEveryPayloadIsValidated`; `trust/log`: `TestRenameNode`, `TestApplyLeavesItsParentUnchanged`; `daemon`: `TestARenamedDeviceIsAnsweredByItsNewName`; `cmd/juist`: `TestRenameADevice`, `TestARenameKeepsNamesApart` | no |
| a rename is carried to the other admin devices, never the renamed one; lost to a concurrent change, it is said in words; a running share is said again under the new name, without the first time's warning, and ends once its role or domain is gone; the approval quotes the name and says nothing of names for a change of case, and gives a label two devices held to the other; the CLI refuses a share name the device publishes or points at itself, and says a refusal of the log's in words | `internal/waiting`: `TestEveryKindIsDecidedOnWhomItIsAbout`; `daemon`: `TestALostRenameIsSaid`, `TestARenamedShareIsSaidAgain`, `TestAShareEndsWithItsRole`; `cmd/juist`: `TestRenameADevice`, `TestARenameKeepsNamesApart`, `TestARenameGivesASharedLabelToTheOther`, `TestAShareSaidAgainWarnsOnce` | no |
| between hosts: fb, renamed on fb, is resolved on lx by its new name at its addresses and no longer by its old, and lx's log names the rename | `make interop`: `TestLinuxAndFreeBSD/rename` | qemu |
| a status page target says what the public sees and is no HOST:PORT; a member is known by its address alone; the terminator reads a newer juistd's page and its refusal | `ipc`: `TestAStatusPageTargetSaysWhatThePublicSees`, `TestAStatusPageKnowsItsMembers`, `TestTheTerminatorReadsAStatusPage`, `TestAPublishRequestNamesWhereTo` | no |
| the terminator is told the status page only where its operator serves one, its members every member's addresses but an ingress's, its changes the log's newest; no reader is told | `daemon`: `TestTheTerminatorIsToldTheStatusPage`; `internal/changelog`: `TestEveryKindIsNamed` | no |
| a member sees the whole page, the public what `--public` says, a page for members alone 404 with its assets; a forged PROXY header from an ingress is the public still; what it shows is escaped, juistd asked once a moment, and its silence said | `internal/statuspage`: `TestWhatAClientSees`, `TestThePageSaysWhoseViewItIs`, `TestThePageEscapesWhatItShows`, `TestThePageServesItsAssetsAndNothingElse`, `TestJuistdIsAskedOnceAMoment`; `internal/terminator`: `TestTheStatusPageKnowsAMemberByItsAddress` | no |
| `juist publish status-page` publishes the page as a name whose TLS juist ends, says what the public sees, changes it, and takes it down | `cmd/juist`: `TestPublishTheStatusPage` | no |
| plain HTTP to an address a name is served on is redirected to https, for names served there alone; port 80 held by another program is told juistd, warned of by `juist status` and the page; the FreeBSD binder listens on port 80 where a name is served; the page sends HSTS | `internal/terminator`: `TestPlainHTTPIsRedirected`; `cmd/juist`: `TestTheStatusWarnsOfPort80HeldByAnother`; `cmd/juistd`: `TestTheBinderListensWhereNamesAreServed`; `internal/statuspage`: `TestWhatAClientSees`, `TestThePageServesItsAssetsAndNothingElse` | no |
| the log: an admission publishes under the domain alone, a published name fits DNS, a label is published once, and an ingress publishes nothing on 80 or 443 | `trust/log`: `TestAnAdmissionPublishesUnderTheDomainAlone`, `TestAPublishedNameFitsDNS`, `TestALabelIsPublishedOnce`, `TestAnIngressPublishesNothingOnItsOwnPorts` | no |
| the helpers: a quiet client gives its slot back, a host holds a few connections, a withdrawn name or a stale view ends the connections for it, a juistd that hangs takes the names down within two polls, the redirect lets idle clients go, the ingress says juistd is gone, a failed listener is listened for again, a closed network stack ends its listeners and listens on its own addresses alone, and the ingress and the terminator each keep a slot | `internal/ingress`: `TestAQuietClientGivesItsSlotBack`, `TestAHostHoldsAFewConnections`, `TestAWithdrawnNameEndsItsConnections`, `TestAJuistdThatHangsPublishesNothing`, `TestTheRedirectLetsAnIdleClientGo`; `internal/terminator`: `TestANameNoLongerServedEndsItsConnections`, `TestAJuistdThatHangsEndsServing`, `TestAFailedListenerIsListenedAgain`; `internal/netstack`: `TestClosingTheDeviceEndsItsListeners`, `TestTheStackListensOnItsAddressesAlone`; `daemon`: `TestOneHelperCannotCrowdOutTheOther`, `TestAnIngressReachesWhatIsServedAlone`; `cmd/juistd`: `TestTheIngressSaysJuistdIsGone` | no |
| the CLI and the package: the terminator starts once told where a name goes, before it is published, and stops with the word or the last name; the status says when it does not run; what answers on the port must end TLS; a name not yet published is said, with the admin's command; the helpers serve the default instance alone; a withdrawn ingress or service role warns; no hint for a service member; a stale ingress is told why it serves nothing; systemctl says nothing, and a firewall that refuses the ingress is said | `cmd/juist`: `TestTheTerminatorStartsBeforeTheName`, `TestTheTerminatorMustEndTLS`, `TestEndsTLSTellsTLSFromPlain`, `TestHelpersServeTheDefaultInstanceAlone`, `TestGrantAnIngress`, `TestPublishingOnAServiceMemberHintsNothing`, `TestAStaleIngressIsToldWhy`; `packaging`: `TestIngressScriptOpensAndCloses`, `TestServeScriptStartsAndStops` | no |
| the daemon: a share's end ends that share alone, a restarted share leaves another's, a look at what is published changes nothing, an expired device's helpers are told nothing, and the status says where the terminator listens and where another program holds the port | `daemon`: `TestAShareEndsItselfAlone`, `TestARestartedShareLeavesAnothers`, `TestPublishedHasNoSideEffectsAndExpiryEndsServing`, `TestTheStatusSaysWhereTheTerminatorListens` | no |
| the helpers: the binder answers each request alone, however many came before and however late, binds no address another program listens on, and its terminator hears it go; the terminator says where it listens; a connection idles only both ways at once | `cmd/juistd`: `TestTheBinderAnswersEachRequestAlone`, `TestTheTerminatorHearsItsParentGo`; `internal/terminator`: `TestTheTerminatorSaysWhereItListens`; `internal/pipe`: `TestJoinIdlesBothWaysAtOnce` | no |
| the CLI: what the terminator says decides whether TLS ends where a name is published; a share keeps its terminator; a taken label is said before anything is asked | `cmd/juist`: `TestTheTerminatorsWordDecides`, `TestAShareKeepsItsTerminator`, `TestATakenLabelIsSaidAtOnce` | no |
| a name behind `--proxy` is not resolved to its device; the domain itself is answered with its device's address through the reachability check; the status names the public domain; `juist network domain` warns that every member resolves it through juistd; `juistd --serve @=ADDR` serves the domain itself | `daemon`: `TestMembersReachAPublishedNameDirectly`, `TestTheDomainGoesToJuistdWhole`, `TestTheStatusNamesThePublicDomain`; `cmd/juist`: `TestTheNamesLineNamesTheNames`, `TestPublishAddAndRemove`; `ipc`: `TestAReaderSeesNoPublicNames`; `cmd/juistd`: `TestServeMakesAServiceMember` | no |
| the CLI waits for a terminator it just started by what juistd says then, and a terminator that stops says so, so the status counts it down at once; the terminator orders no certificate for a name it no longer serves; the ingress lets go a client that does not answer its target's hello within a minute, bounds a site's connections and port 80's by source, and redirects by the path alone; a spliced connection whose source fails ends both ways, one that cannot write leaves the other way to finish, on FreeBSD too; the confiner takes echo replies and ICMP errors on what this node opened, and ends a TCP flow at an RST, or a minute after FINs both ways; the RPM owns `/usr/lib/juist`, and both packages recommend polkit; `juist grant` names the role that excludes the one granted | `cmd/juist`: `TestAStartedTerminatorIsWaitedFor`, `TestARoleThatExcludesAnotherIsSaid`, `TestGrantAnIngress`; `internal/terminator`: `TestANameNotServedIsNotOrdered`, `TestATerminatorSaysItStops`; `daemon`: `TestTheStatusSaysWhereTheTerminatorListens`; `internal/ingress`: `TestAClientThatStopsAfterItsHelloIsLetGo`, `TestTheRedirectNamesItsHostAndBoundsASource`; `internal/pipe`: `TestSourcesBoundHostsAndSites`, `TestAFailedWayEndsBoth`, `TestAWayThatCannotWriteLetsTheOtherFinish`; `conn`: `TestAConfinedPeerAnswersPingsAndErrors`, `TestAConfinedFlowEndsWithItsConnection`; `packaging`: `TestTheRPMOwnsItsDirectories`, `TestThePackagesRecommendPolkit` | no |
| where firewalld keeps the port a device serves on from arriving on its juist device, `juist share`, `juist publish add` and `serve` say so, with the command that puts the device in the trusted zone, and say nothing where it lets the port in; an interface counts as blocked as log sync's check counts it | `cmd/juist`: `TestAFirewallKeepingOutWhatIsServedIsSaid`; `internal/firewalld`: `TestBlocksAsksFirewalldOnTheSystemBus`, `TestAZoneWhosePortsCannotBeAskedCountsAsFirewalled` | no |
| a public TCP port is one name's, off 80, 443, juist's own ports and those an ingress's own names go to | `types`: `TestNamesPublishedByTCP`, `TestTheIngressHoldsThePublicPorts`; `trust/log`: `TestNamesPublishedByTCP` | no |
| every ingress holds each public port, passes TCP at once, with a PROXY header where asked, within the bounds, and closes a port withdrawn | `internal/ingress`: `tcp_test.go`; `make interop`: `TestLinuxAndFreeBSD/TCP` | qemu, for the last |
| the terminator passes a name by TCP on unread, from an ingress's header where asked | `internal/terminator`: `tcp_test.go` | no |
| the firewall follows the public ports while the ingress runs, one run at a time, its own rules noted and others' left; it lets in those alone the ingress listens on, never one another program holds, and juistd's restart leaves them | `packaging`: `TestIngressScriptFollowsThePorts`, `TestIngressScriptRunsOneAtATime`; `daemon`: `TestTheIngressPortsFollowTheLog`, `TestTheFirewallLetsInWhatTheIngressHolds`; by hand on Fedora and Ubuntu | no |
| `juist publish add … --tcp`, its approval, the status and the listings | `cmd/juist`: `tcp_test.go` | no |
| the Initial packets of versions 1 and 2 read by the keys their DCID gives, coalesced ones of one connection alone, the ClientHello reassembled out of order and over datagrams within its bounds, and the header IDs read without keys | `internal/quicinitial`: `quicinitial_test.go`, `FuzzParse`, `FuzzHello` | no |
| the ingress passes QUIC by the name the Initials ask for and no datagram for another; keeps nothing of what does not parse; drops a client's PROXY header; passes three times what an unproven client sent until the terminator says, naming the client, it is proven; bounds unproven flows by host, the oldest giving way past the bound in all, one without a target first, ends them after twice the hello timeout and logs them once a second; carries connections from one socket to the same target, eight live at most and any number one after another, refuses one to another target and any past the rate of new flows; ends a flow once the terminator says its connections ended, a withdrawn name's and a quiet one's; takes 443/udp once free, telling juistd meanwhile | `internal/ingress`: `quic_test.go` | no |
| the terminator ends QUIC for names offered HTTP/3 alone, proxies them as HTTP/1.1 or h2c over QUIC and TCP with `Alt-Svc`, tells an ingress, naming the client, that it completed its handshake and that its connection ended, believes a header from an ingress alone, counts QUIC against its bound, gives each client connection its own proxy, gone with it, the idle connections of others giving way past a service's bound, passes upgrades, takes headers of 64 KiB without a client's naming one, and ends a withdrawn name's QUIC | `internal/terminator`: `quic_test.go`, `proxy_test.go` | no |
| a member lets an ingress send UDP to the ports of names offered HTTP/3 alone, and later fragments to itself; a reply from such a port opens nothing | `conn`: `TestTheConfinerKeepsAnIngressToItsPorts`, `TestFragmentsOfAConfinedPeersDatagramPass`, `TestAQUICReplyOpensNothing`; `daemon`: `TestAnIngressSendsQUICToNamesOfferedHTTP3Alone` | no |
| `juist publish add … --http3`, the HTTPS record it prints, and the hint that a name with records of its own needs its own addresses; the ingress's status says 443/udp, or that another program holds it | `cmd/juist`: `TestPublishAddOffersHTTP3`, `TestPublishAddEndsTLS`, `TestTheIngressSummaryNamesItsPorts`; `daemon`: `TestTheStatusSaysTheIngressPorts` | no |
| between hosts: Chrome fetches a name on lx over HTTP/3 through fb, and over HTTP/2 where 443/udp is not forwarded | `make interop`: `TestLinuxAndFreeBSD/HTTP/3` | qemu |

### The access policy

| Claim | Where it is checked | Privileged |
|---|---|---|
| a policy names members by key, follows a rotation, loses a removed member with the rules and tests that named it alone, survives a checkpoint; tables nested as densely as allowed are checked in linear time | `types`: `TestAPolicyMeansWhatItSays`, `TestRekeyingKeepsSetsSorted`, `TestDenselyNestedTablesValidateQuickly`; `trust/log`: `TestThePolicyFollowsItsMembers`, `TestARemovedExitNodeLeavesNoOpenInternet` | no |
| the text reads back to its record and formats to one form; a mistake is said by its line; a rule lets its sources open what it names and not the reverse; who is a peer, a carrier's included; tests and warnings | `internal/policy`: `TestTheCanonicalTextRoundTrips`, `TestTheTextFormatsCanonically`, `TestParseSaysWhatIsWrong`, `TestWhatARuleLets`, `TestWhoArePeers`, `TestAnIngressPeersItsPublishers`, `TestTestsAreChecked`, `TestWarnings`, `FuzzParse` | no |
| a restricted peer opens what its access passes, statefully, and this node on it what its access sends; through a real tunnel the receiver takes nothing else from a sender that restricts nothing, and forwards it nothing to the internet until its access passes it | `conn`: `TestAPeerIsKeptToItsAccess`, `TestTheReceiverEnforcesWhateverTheSenderSends` | no |
| the policy decides the peers, what each may open and log sync's reach; exit nodes and subnets are used and forwarded for as it passes; a view stale past the TTL keeps its vouchers for juist's own traffic alone | `daemon`: `TestThePolicyDecidesThePeers`, `TestThePolicyScopesExitNodes`, `TestAnExitNodeTakesWhatThePolicyPasses`, `TestThePolicyNarrowsSubnets`, `TestAStaleViewFailsClosedUnderAPolicy` | no |
| a member kept apart from another seals its addresses, which its peers alone open, by the key gossip carries for them | `internal/addrkey`: `TestAPeerAloneOpensTheAddresses`, `TestTheKeyFollowsEpochAndPeers`; `gossip`: `TestAddressKeysTravelWithTheAnnouncements`, `TestSealedAddressesStandAlone`; `daemon`: `TestAddressesAreForPeersAlone`, `TestAPeersSealedAddressesOpenWithItsKey`; `discovery/dht`: `TestAnnouncementFitsTheItemLimit` | no |
| `juist policy` sets, shows, diffs, checks, edits and formats; a policy that does not read or fails a test is refused; a change waiting for votes shows as a diff; a device lists itself and its peers | `cmd/juist`: `TestAPolicyIsSetAndShown`, `TestABadPolicyIsRefused`, `TestAPolicyWaitsForVotes`, `TestPolicyFmtNeedsNoNetwork`, `TestAPolicyIsEdited`, `TestADeviceListsItsPeersAlone`, `TestAnInviteUnderAPolicySaysSo` | no |
| between hosts: east and west, kept apart, exchange no packet and hold no address of each other's; east opens on lx the port passed alone; fb carries west's internet traffic and not east's | `make interop`: `TestLinuxAndFreeBSD/access_policy` | qemu |
| sealing is decided before anything announces and before a reconcile can end early; address keys outlive a restart with the endpoint cache; a table emptied by removals prints as text that reads back, and an emptied policy's note goes to stderr; ingresses are closed in the peer set last installed; later fragments and a router's own ICMP errors pass through it; an invite under `pass from any` says nothing of the policy; an ingress as a source is warned of; fmt -l goes past a file that does not read | `daemon`: `TestAddressesAreSealedFromTheStart`, `TestAPeersSealedAddressesOpenWithItsKey`, `TestIngressesCloseInThePeerSetInstalled`; `internal/policy`: `TestAnEmptiedTableReadsBack`, `TestAnEmptyTableSpansLines`, `TestWarnings`; `cmd/juist`: `TestAnEmptiedPolicyPrintsAsText`, `TestAnInviteUnderAnOpenPolicySaysNothing`, `TestPolicyFmtFlags`; `conn`: `TestWhatPassesThroughARouter` | no |
| a restricted router's other sources reach this node alone, and its ICMP errors are about what this node sent and addressed to it; a device that cannot make its address key withholds its addresses; juist policy test says which rule passes a connection, and a failing test which rule passes it; names are said by their line; warnings name devices in no rule, exit nodes and routers no rule uses, and a device's address for its name; remove says what the policy loses; devices --all lists every device | `conn`: `TestARoutersOtherSourcesReachThisNodeAlone`; `daemon`: `TestAddressesAreWithheldWithoutAKey`; `internal/policy`: `TestParseSaysWhatIsWrong`, `TestALineGoesOnAfterABackslash`, `TestTestsAreChecked`, `TestWarningsOfWhatIsUnused`, `TestDiff`; `cmd/juist`: `TestAPolicyIsAsked`, `TestRemovingADeviceSaysWhatThePolicyLoses`, `TestADeviceListsItsPeersAlone`, `TestAnInviteUnderAPolicySaysSo` | no |
| tests are checked against the whole policy's view, at its limits in a moment; a failing test is said by its line; the invite's hint follows an admission alone; arguments of juist policy test that are no word go in quotes, and a character the text cannot hold is named whole; a relay or voucher alone is no device in no rule, and a warning is said once; the first policy is asked about, and approving without the log hints where names show | `internal/policy`: `TestTestsAreCheckedQuickly`, `TestTestLines`, `TestWords`, `TestADeviceNamedLikeAKeyword`, `TestWarningsOfCarriersAndRepeats`, `TestParseSaysWhatIsWrong`; `cmd/juist`: `TestABadPolicyIsRefused`, `TestTheFirstPolicyIsAskedAbout`, `TestAPolicyWaitsForVotes` | no |

### Multicast

| Claim | Where it is checked | Privileged |
|---|---|---|
| a group datagram sent on a member's device reaches the others' listeners from its overlay address, over IPv6 its link-local, full-sized too, directly and through a relay alone, and an answer goes back unicast to the link-local | `conn`: `TestNetnsAGroupDatagramReachesEveryMember`, `TestNetnsAGroupDatagramCrossesARelay`, `TestAGroupDatagramReachesEveryMember`, `TestAGroupDatagram6ReachesEveryMemberAndIsAnswered` | netns |
| a ping to ff02::1 is answered by every member, through a firewall dropping what conntrack takes for invalid too, and under a policy goes, with its answers by identifier, only where a `pass multicast` rule without a port passes it | `conn`: `TestNetnsAGroupDatagramReachesEveryMember`, `TestNetnsAGroupPingIsAnsweredUnderAnAccess`, `TestAGroupPingReachesEveryMemberAndIsAnswered`; `internal/policy`: `TestAMulticastRulePassesGroupsAlone` | netns, in part |
| a wrapped packet is delivered only as juistd makes it, from a member without an access, its inner source the member's own, UDP or an IPv6 echo request to a group, no other ICMPv6 and no DHCPv6, IPv6 of link or site scope, without options or extension headers | `conn`: `TestOnlyAMembersOwnGroupDatagramUnwraps`, `TestOnlyAMembersOwnGroupDatagram6Unwraps`, `TestAGroupEchoRequestUnwrapsAndNoOtherICMPv6`, `TestARestrictedPeerTakesNoPartInGroups`, `FuzzUnwrapGroup`, `FuzzUnwrapGroup6` | no |
| a sender past the limit is cut at the receiver | `conn`: `TestAReceiverHoldsASenderToItsOwnAndToTheLimit` | no |
| only this node's own group datagrams leave, no LAN host's, IGMP or MLD | `conn`: `TestOnlyThisNodesOwnGroupDatagramsAreSent`, `TestOnlyThisNodesOwnGroupDatagram6sAreSent`, `TestAGroupDatagramReachesEveryMember` | no |
| a member's link-local is the overlay address's low half, neither's where two would share it, derived again with this node's addresses, kept out of the guard, routes and serving | `conn`: `TestALinkLocalIsTheOverlayAddresssLowHalf`, `TestALinkLocalTwoWouldShareIsNeithers`, `TestSetSelfDerivesThePeersLinkLocalsAgain`, `TestAPeerRegainingItsLinkLocalIsReachedAtIt`, `TestTheGuardTakesNoLinkLocal`, `TestAPlumbedRouterKeepsLinkLocalsToTheDevice`; `internal/plumber`: `TestALinkLocalAddressIsTheDevicesOwn`, `TestALinkLocalAddressGivenIsTheDevicesOnly` | FreeBSD root, in part |
| a routed group reaches a listener on the default interface from a member's overlay address | `conn`: `TestNetnsARoutedGroupReachesTheDefaultInterface` | netns |
| `juist set --multicast` and `--groups` are kept, refused whole where they cannot be set, said by the status, and taken by the mesh; a groups file is bounded | `daemon`: `TestMulticastSettingsAreKeptAndTaken`, `TestARefusedSettingSetsNothing`, `TestASettingNotWrittenUndoesTheOthers`, `TestASettingTheMeshDoesNotTakeRestartsNothing`, `TestGroupsKeptWithoutADeviceBlockNothing`, `TestAGroupsFileIsBounded`; `cmd/juist`: `TestStatusSaysMulticast`, `TestGroupsAreIPv4MulticastAlone` | no |
| health warns where avahi runs and leaves the device out | `cmd/juist`: `TestHealthWarnsOfAvahiLeavingTheDeviceOut` | no |
| under a policy, a group datagram goes only where a `pass multicast` rule passes it, by port, each way alone, its unicast answer for ten seconds, nothing from a member no rule passes; the rule reads back, needs schema 22, and reaches the data plane | `conn`: `TestAccessPassesGroupsAndTheirAnswersAlone`, `TestAnAccessDecidesEachWayAlone`, `TestAnAnswerPassesForItsWindow`, `TestAnAnswerLeavesAFlowItsReplies`, `TestOnePeersQuestionsCrowdOutNoOthers`, `TestEveryPortPassesFragments`, `TestAnAnswerIsThisNodesAlone`, `TestARestingPeerIsSentNoGroups`, `TestNothingWrappedForThisNodeReachesTheHost`; `cmd/juist`: `TestAMulticastPolicyAsksForTheUpgrade`; `internal/policy`: `TestAMulticastRulePassesGroupsAlone`; `trust/log`: `TestAMulticastPolicyNeedsSchema22`; `daemon`: `TestAMulticastRuleReachesTheDataPlane` | no |

### Android and battery

| Claim | Where it is checked | Privileged |
|---|---|---|
| the core runs in the app's process, over a pipe, its keys sealed by the platform | `mobile`: `TestACoreKeepsItsKeysSealedAcrossRestarts`; `daemon`: `TestAServiceInProcessAnswersThroughItsPipeAlone`; `internal/keys`: `TestSealedNodeKeysOpenOnlyWithTheirSealer` | no |
| a VPN device moves to each descriptor established, and serves nothing | `conn`: `TestAVPNDeviceMovesToEachEstablishedDescriptor`, `TestAVPNPlumberServesNothing` | no |
| the app judges the status as `juist status` does, and reads what the core writes | `mobile`: `TestTheViewJudgesAsJuistStatusDoes`, `TestTheViewIsWhatTheAppReads`; `android/app`: `CoreTest` | no |
| every socket the core opens on the underlay is protected from the VPN | `internal/underlay`: `TestASocketIsProtectedBeforeItIsUsed`; `discovery/dht`: `TestTheDHTSocketIsProtected`; `discovery/mdns`: `TestTheMulticastSocketIsProtected`; `internal/rendezvous`: `TestTheRendezvousSocketIsProtected`; `internal/guest`: `TestTheDialToTheHostIsProtected`; `relay/forward`: `TestTheDialToTheRelayIsProtected` | no |
| through an exit node, the VPN routes the internet and its DNS, refused where it cannot be used | `conn`: `TestAVPNRoutesTheInternetToAnExitNodeAndItsDNS`; `daemon`: `TestAVPNsDNSIsThroughWithoutAResolvConf`; `mobile`: `TestTheViewOffersTheExitNodes` | no |
| a member joining does not establish the VPN again, and a listener Android took down listens again | `conn`: `TestAVPNRoutesTheNetworkWholeAndIsNotEstablishedAgainForAMember`; `daemon`: `TestAListenerTakenDownIsOpenedAgain` | no |
| a ping through the tunnel | `daemon`: `TestPingAnswersWithTheRoundTrip` | no |
| `juist invite` draws its link as a QR code, on a terminal alone | `cmd/juist`: `TestTheInviteDrawsItsLinkAsAQRCode`, `TestQRCodeOnlyOnATerminal` | no |
| the core follows the phone's network outside its own VPN, which Android reports as the app's default once up, and a network lost after another replaced it changes nothing | `android/app`: `UnderlayTest`; the app by hand in an emulator | no |
| the core's dials into the overlay leave by the VPN device, from its own address, and fail before it is established rather than leave by the LAN | `conn`: `TestAVPNDialLeavesByTheDeviceAlone` | no |
| the epoch secrets kept beside the node's keys are sealed as they are | `daemon`: `TestKeptSecretsAreSealedAsTheNodesKeys` | no |
| the app brings the VPN up as the core says: its addresses, routes and, through an exit node, DNS servers, from the file the Go side's test writes | `mobile`: `TestTheVPNConfigIsWhatTheAppReads`; `android/app`: `VpnConfigTest` | no |
| the app's connection follows the core: starting, on, off, failed, off when another VPN took over and not wanted again; its last view outlives the process; a join ends as the core says; an exit node chosen reaches the core; a reboot or update turns on what was on, with consent | `android/app`: `JuistTest` | no |
| an invite link opened from elsewhere asks to join and joins nothing untapped, changes nothing in a network, and no other link is taken; every screen survives a recreated activity; the exit nodes are chosen by a tap, not while off, and one chosen and no longer offered stays listed and refused | `android/app`: `AppRootTest`, `ExitSectionTest` | no |
| every screen in both themes, both languages and at 200 % | `make android-check`: the Roborazzi tests against `android/app/screenshots` | no |
| a quiet peer a relay can wake is probed every 5 minutes, its answer standing meanwhile, and every check without this device's relay or where this device does not reach the peer's; LAN discovery slows from its first interval while nothing changes and starts over when the announcement or connectivity changes | `daemon`: `TestAQuietPeerARelayCanWakeIsProbedRarely`, `TestAnAnswerStandsOnlyWhereThePeersRelayIsReached`, `TestAChangeWakesTheBeacon`; `discovery/mdns`: `TestABeaconSlowsDownUntilWoken` | no |
| a node that reaches no member relay is homeless and asks STUN only while its tunnels carry traffic and it does not save battery, not every few seconds for a STUN server it took for its home; one that reaches a relay, by HTTPS alone too, or reaches it again, saving or not, homes there; a report that measured nothing changes no home | `conn`: `TestAnIdleNodeWithoutARelayStopsAskingSTUN`, `TestASavingNodeAsksNoSTUNThoughProbed`, `TestAHomeIsARelayReachedOrNone`, `TestAConnectionToTheSTUNRegionIsDropped`, `TestAHomelessNodeSaysNoHomeItDoesNotTake`, `TestARelayReachedByHTTPSAloneIsAHome`, `TestAReportMeasuringNothingKeepsTheHome`, `TestAHomeTakenOutOfOrderIsSetRight`, `TestASavingNodeHomesAgainWhenItsRelayReturns`, `TestARelayIsMeasuredBesideThreeSTUNServers` | no |
| saving battery, the tunnels are checked at the saving pace, an answer a relay can wake stands longer, sync ticks due sooner are skipped and the data plane's heartbeat is off; back from saving, the tunnels are checked at once and the heartbeat resumes | `daemon`: `TestWhileSavingAnAnswerStandsLonger`, `TestSavingSlowsTheChecksAndBackFromItChecksAtOnce`, `TestSavingSkipsTicksDueSooner` | no |
| the app saves battery while the screen is off, the phone dozes or battery saver is on, and on a metered network while it is not in front, and holds the multicast lock, and LAN discovery announces, only while not saving or while joining | `android/app`: `PaceTest`, `UnderlayTest`; `daemon`: `TestSavingQuietsTheBeacon`; `discovery/mdns`: `TestAQuietBeaconSendsNothing`; [Measure an idle phone](#measure-an-idle-phone) | no |
| a peer that rests, or any while this device saves, is probed once in 30 minutes and pinged quietly in the checks between where no relay can wake it; a quiet ping starts no heartbeat, sends nothing through WireGuard, and one unanswered, or a key changed since the last answer, is followed by a probe, and a new announcement that moved the peer's addresses alone has it probed no sooner | `daemon`: `TestARestingPeerIsCheckedQuietly`, `TestWhileSavingEveryPeerIsCheckedQuietly`, `TestAQuietPingUnansweredIsFollowedByAProbe`, `TestAChangedKeyIsProbedNotPinged`, `TestAMoveAloneHasNoQuietPeerProbed`, `TestAChangedKeyIsProbedThoughARelayWakes`, `TestAHandshakeUnderTheKeyRenewsTheAnswer`, `TestAClockSetBackHasThePeerProbed`; `conn`: `TestAQuietProbeStartsNoHeartbeat` | no |
| a device that rests says so in its announcement from schema 20 alone; the periodic sync leaves a member that rests alone, but for one every 30 minutes where all rest; a new address, nothing else in its announcement changed and no relay's, is pushed by the device and on by each member to the members awake alone, a deferred push as asked, and one saving and homed waits for the next reconcile or the end of saving; a device that rests joins the public DHT only once checked and while no member that does not rest answers it, and a node that does not take part sends the DHT nothing | `daemon`: `TestARestingDeviceSaysSoFromSchema20`, `TestTheBackstopSyncLeavesARestingMemberAlone`, `TestTheBackstopSyncReachesARestingMemberWhereAllRest`, `TestWhileSavingTheRestingSyncFollowsTheTick`, `TestAnAddressIsPushedToTheAwakeAlone`, `TestAMoveIsPushedAsPeersPushItOn`, `TestALearnedAnnouncementIsPushedOnToTheAwakeAlone`, `TestADisplacedPushIsDeferredNotDropped`, `gossip`: `TestAnnouncementsAloneAreAnnouncedNotRecords`, `TestTheCacheSaysWhatAnAnnouncementChanged`; `daemon`: `TestWhileSavingANewAddressWaitsForTheNextSync`, `TestAWaitingAddressIsPushedLater`, `TestARestingDeviceJoinsTheDHTAloneOnly`, `TestADeviceWhoseLowerLivePeerRestsSeeksItself`, `TestAHintAloneSaysNoMemberRests`, `TestANewerHintLeavesAMembersRestAlone`; `discovery/dht`: `TestANodeThatDoesNotJoinSendsTheDHTNothing` | no |
| a device that rests passes on nothing it hears while a member awake does, and pushes its own news to two members awake; a push reaches `PushFanout` members awake and every member that rests, and others' announcements, address keys and leases go on to the members awake alone, a pair exchange to its peer and the members awake, and a member found down on a hint's key is reinstalled without a push; from schema 21 a hello says what its sender holds of each node and the records frame answering it carries what is newer, all of it to a hello that says nothing, within `MaxFrameSize` at every cap | `daemon`: `TestAPushReachesTheFanoutAwakeAndEveryMemberThatRests`, `TestADeviceThatRestsPushesToFewAwake`, `TestADeviceThatRestsRelaysNothing`, `TestANewLeaseIsPushedToTheAwakeAlone`, `TestHellosSayWhatTheyHoldFromSchema21`, `TestADeviceThatRestsPushesItselfAfterRecords`, `TestARestingVoucherPushesItsOwnLease`, `TestAPairExchangeWakesNoMemberThatRests`, `TestARestartedMembersHintMovesItsDiscoKeyWithinSeconds`; `gossip`: `TestASeenHelloCarriesWhatThePeerLacks`, `TestARecordsFrameCarriesWhatIsNewerThanSeen`, `TestSeenAndFullHellosMeet`, `TestKeysInARecordsFrameLeaveRoomForARecord`, `TestFramesAtTheirCapsFit` | no |
| the mesh reconciles at the next deadline the log, the leases, the announcements and the host's DNS name, a membership's expiry among them, and otherwise every 2 minutes; a resolver that starts again is routed again at once, and the routing renewed hourly while watched; an offer of a pair key put off is due after the pace | `daemon`: `TestAMembershipIsReconciledAwayAtItsExpiry`, `TestTheNextReconcileIsDueAtTheSoonestDeadline`, `TestADevicePastItsExpiryWaitsForTheBackstop`, `TestASoonerDeadlineRearmsTheLoop`, `TestARestartedResolverIsRoutedAgain`; `internal/resolved`: `TestARestartedResolvedIsSeen`, with `dbus-daemon`; `internal/pairkey`: `TestGenerationsArePaced` | no |
| every lookup of the phone goes to juistd's resolver at the network's prefix and ::53, routed into the tunnel and taken before the engine from the phone's own packets alone, where no member's derived address lies; it answers the network's names and the reverse names of its addresses, over UDP and TCP, and searches the network's domain alone, asks the network beneath the VPN the rest by the resolvers the app last reported, protected, over TLS first, sessions resumed, where automatic Private DNS found them answering it, and in plain text for 10 minutes after TLS failed, and through the tunnel the exit node in use; a lookup it can ask no one of, or one for a refused exit node, fails at once, and a listener failing for good is not spun on; an answer longer than a datagram the stack carries goes out truncated and whole over TCP, and one from upstream keeps its TTL but for a name the network may answer itself; while Private DNS names a host the VPN takes no lookup, and the app says why and names each name for members alone then out of reach | `daemon`: `TestAPhoneAsksJuistdsResolverAlone`, `TestAPhoneWithoutResolversFailsAtOnce`, `TestPrivateDNSLeavesThePhonesNamesUnresolved`, `TestAPhonesOtherLookupsGoToTheExitNode`, `TestAPhoneAsksOverTLSWhereAndroidWould`, `TestARefusedExitNodesLookupsFailAtOnce`, `TestAPhoneKeepsUpstreamTTLs`, `TestAPhoneGetsALongAnswerOverTCP`; `internal/names`: `TestReverseNamesOfTheNetworkAreAnswered`; `conn`: `TestALocalAddressIsAnsweredInTheProcess`, `TestAVPNRoutesTheInternetToAnExitNodeAndItsDNS`, `TestAVPNDialLeavesByTheDeviceAlone`; `internal/dnsfwd`: `TestAQueryNoneCanBeAskedFailsAtOnce`, `TestAForwarderListensAndDialsAsItIsGiven`, `TestAResolverOn853IsAskedOverTLS`, `TestAFailingListenerIsNotSpunOn`, `TestCappedSaysWhichAnswersAreCapped`, `TestAnAnswerTooLongForUDPIsTruncated`; `types`: `TestTheResolverAddressIsTheNetworksAndNoMembers`; `mobile`: `TestTheViewSaysWhyNamesAreNotResolved`, `TestTheUnderlaysResolversAreReadAsTheAppSaysThem`, `TestTheVPNConfigIsWhatTheAppReads`; `android/app`: `UnderlayTest`, `VpnConfigTest`; [Check names on Android](#check-names-on-android) | no |
| an idle phone in the emulator stays within its budget, with and without a relay, and answers a member's ping with its screen off | `make android-idle` | the emulator |

### CI

| Claim | Where it is checked | Privileged |
|---|---|---|
| the log gives each step's time, and the lab its longest waits and commands | `make ci-vm`, its last lines; `TestLinuxAndFreeBSD`, `TestLinuxAndFreeBSDUpgraded`, their `lab:` lines | KVM |
| a failure in each stage ends the run in that stage, the lab with it; a run of fewer stages, or one taking `make check` from the stamp, is no closing run | `make ci-vm` with a failure planted in each stage, by hand; `ci`: `TestStagesArePickedInTheirOrder`, `TestOnlyAWholeRunCloses` | KVM, for the first |
| nothing is built, converted or fetched twice: the lab's disks and the previous release kept, the image taking the binaries `make deb` built, the lab in a copy of the snapshot the VM is sent | `make ci-vm`, its steps; `ci`: `TestTheLabWritesIntoACopyOfItsOwn`, `TestTheVMAndTheLabShareNoCPU` | KVM, for the first |
| the closing run in at most half of 45 minutes on the four-core host | `make ci-vm`, under "The last privileged run" | KVM |
| the privileged tests run in parallel, no two labs on one tag; a ping across an epoch bump ends once a session on the new key carried data, and fails where none did; a connection older than the exit choice outlives it on Linux as on FreeBSD | `conn`: `TestNetns…`; `make interop`: `TestLinuxAndFreeBSDUpgraded/previous_release`, `TestLinuxAndFreeBSDUpgraded/post-quantum`, `TestLinuxAndFreeBSD/FreeBSD_serves_Linux` | **yes**, qemu |


### The last privileged run

The latest `make ci-vm` that closed a milestone, and the latest run of each
gate it does not cover. Replace an entry when its gate runs again, so it is
clear how old the evidence is.

- **`make ci-vm`, 2026-10-31, M25 done**, at M25: every stage passed
  in 36m41s, the privileged tests in 2m53s, `test-race` in 10m29s, and the
  lab in 29m48s, the multicast netns tests and the upgrade from M24, at
  schema 21, to this build with multicast on among it. The run before, at
  M25, failed in that upgrade, which looked for a second network's home
  where releases before M24 keep it; M25 takes either. At b168780, M25
  review 5, the lab's `access_policy` failed once, east reaching no relay
  as it started, and passed whole on the same commit run again. `make
  test-freebsd` did not run on M25: the 15.1 VM here was gone.
- **`make ci-vm`, 2026-10-31, M24 done**, at M24: every stage passed
  in 36m8s, the privileged tests in 2m53s, `test-race` in 10m4s, and the
  lab, on FreeBSD 15.1, in 33m4s, a user per network and the LAN kept from
  fb's overlay address among it. A run at M24 hung in `HTTPS alone`
  while another worktree's lab shared the host's cores, fb's juistd no
  longer answering; the lab alone passed at 6bc0a2d, as at M24 and in
  the run above. The parts carried from M22 passed at M24, in 32m27s,
  after ten lab runs in a row at M24 where hotel met lx within 25 to
  37 s. `make test-freebsd` passed all 54 packages on the 15.1 VM at
  M24.
- **FreeBSD 15.1, 2026-10-30, at the commit making it the target**:
  `make test-freebsd` passed all 54 packages on a 15.1 VM, after it had shown
  `pfctl -F all` failing in an anchor; `make repro-freebsd` made the same
  binaries and package from a Debian 12 container and the 15.1 VM; `make
  interop` passed `TestLinuxAndFreeBSD` whole, with the guard passing the
  loopback without state (M24), and `TestLinuxAndFreeBSDUpgraded` on its own, its
  first run having lost the FreeBSD VM's ssh under load. `make check` and
  `make cross` passed. `make android-check`
  passed at the commit closing M23.
- **`make test-acme`, 2026-10-02, at M9 review 1**: passed, the CAA record's
  account among it.
- **`make fuzz-long`**: no run over every target is recorded. `FuzzPayloads`
  (`internal/quicinitial`) ran clean for 72 CPU-hours at M11, 3.43
  billion inputs, and `FuzzParse` for 5 CPU-hours, on 2026-10-06.
- **The privileged tests beside firewalld and tailscaled, 2026-10-03, at
  M9**: on a Fedora 44 Cloud VM, kernel 6.19.10, SELinux enforcing, all
  23 passed, none skipped.
- **Hand tests**, with the packages: [Check an exit node](#check-an-exit-node)
  and [Check a subnet router](#check-a-subnet-router) on 2026-09-28 at
  M6, a Debian 12 exit node and router (Docker 29.8, ufw off) and a
  Fedora 44 client (firewalld, Tailscale beside juist), then a public Ubuntu
  24.04 exit node, its IPv4 and IPv6 shown to the client; a client below
  systemd 256 was not tried. [Check a FreeBSD node](#check-a-freebsd-node) on
  2026-09-30, at M8c, between two FreeBSD 14.5 VMs on one LAN. [Check an
  ingress and a published name](#check-an-ingress-and-a-published-name) on
  2026-10-03, at M9, a name and a share fetched from outside with Let's
  Encrypt's certificates; its TCP and HTTP/3 parts last on 2026-10-06, at
  M11, the RPM on Fedora 44 with firewalld and SELinux enforcing and the
  deb on Ubuntu 24.04 with ufw as two ingresses, HTTP/2 taking over where
  443/udp is blocked, no SELinux denial. [Check the privilege
  footprint](#check-the-privilege-footprint) and [Check two networks on one
  host](#check-two-networks-on-one-host) have no recorded run.
- **Names on Android by hand, 2026-10-24, M23 review 3**, at M23,
  [Check names on Android](#check-names-on-android) in the Android 16
  emulator: a member's name, its short name and a name for members alone
  resolve to their overlay addresses and open through the tunnel; `ping`
  names the member it reaches without a reverse lookup on `wlan0`; a name
  without a dot the network's domain lacks is asked of the phone's network
  as it is; other names resolve as without the VPN; without Wi-Fi a lookup
  failed in 37 ms (2026-10-23). Off, automatic and a host name for Private
  DNS each as the handbook says. With an exit node in docker-vm, no lookup
  on `wlan0`, the names resolved and an HTTP request left by it; refused by
  `juist exit serve --stop`, a lookup failed in 35 ms; its container
  stopped, Android gave up after 1.7 s. The VPN off, the phone's own DNS.
  Not tried by hand: DNS over TLS to the network's resolvers and TTLs, as
  the emulator's resolver answers no TLS and every TTL as 30 s itself.
- **The app by hand, 2026-10-05**, in an Android 16 emulator: the VPN turned
  off and on three times within seconds ends on, log sync leaves from the
  overlay address, and the kept epoch secrets are sealed.
- **An idle phone beside ten members, 2026-10-24, M23 review 3**, `make
  android-idle` at M23, one member restarting every 3 minutes. With `a`
  relaying: 7 261 datagrams and segments an hour, the members' data planes
  4 582, the phone answering a member's ping in 7 ms; 6 871 at M23, and
  10 662 with the resolver in the app before a quiet peer that moved its
  addresses alone was spared a probe, its data planes 7 493, a restart's 3
  minutes carrying 500 to 850 where they now carry mostly 250 to 420. Without
  a relay 13 584, and 14 664 at M23, the phone answering after 10 s. M22
  review 3 measured 9 017 to 11 568 beside a relay and 14 224 and 15 303
  without; M21's 8 408 at ea4d7cc was one run. The same lab at M21,
  before M21, sent 53 000 an hour with a relay and 30.5 MB with the members.
- **A real phone's day at schema 21, 2026-10-21, M21 done**, the same
  Pixel 8 Pro with the app at M21, the network of 11 upgraded to schema
  21, from 11:32 to 16:03, nearly all of it on Wi-Fi (182 KB over LTE),
  battery saver on 31 % of it, Devvm off most of it: juist at 5 % in
  Android's own list, 93 mAh of 959 computed, 21 mAh an hour against 54 the
  day before; of it 88 mAh the radio, active 13 minutes in all, 3 an hour
  against 30, and 2 mAh the CPU. juist's own traffic through its tunnel
  about 1.2 MB an hour in and 0.9 out, against 5 to 20 MB each way an hour
  the day before and that morning until the upgrade. Not taken: a day on
  mobile data (M23).
- **A real phone's day, 2026-10-20, M21**, a Pixel 8 Pro on Android 17 with
  the app at M21, the network of 11 at schema 20, from 07:14 to 16:49
  on LTE and Wi-Fi, battery saver on 90 % of it, its bug report read by
  hand: juist 512 mAh of 2 385, 32 % in Android's own list, against 65 % on
  2026-10-12 before M21; of it 496 mAh the radio, held up 4 h 42 min by
  306 000 packets, and 13 mAh the CPU. Through its own tunnel juist sent
  110 MB and received 111 MB, its log sync, and Devvm 1.6 MB; 257
  connectivity changes. What followed is in the roadmap's M21, "Log sync on
  a phone".
- **`make throughput`, 2026-10-11**, in the CI VM, medians of three 5 s runs
  in Mbit/s, before M15's steps (907135b) and after (51c48b9): a proxy on the
  host 11 100 and 24 100 (splice); a service member's netstack 1 650 and
  2 460; a proxy through the tunnel 3 200 and 3 320; a confined peer 3 330
  and 3 380; the tunnel itself 3 460 to 3 520 both; TCP through an exit node
  about 2 950 both; UDP through it about 300 both, bound by the tunnel.
- **`make load-lab`, 2026-10-06, at M11**: 20 visitors a second for 90 s
  lost none over HTTP/1.1, HTTP/2 or HTTP/3; HTTP/3's p50 34 ms and p99 94 ms,
  HTTP/2's 31 and 69 ms.

## Check the privilege footprint

The daemon's privileges are a claim about the installed package, not a binary
in `build/`:

```sh
make rpm && sudo dnf install ./build/rpm/RPMS/*/juist-*.rpm
sudo systemctl enable --now juistd
juist create testbox
```

```sh
pid=$(systemctl show -p MainPID --value juistd)
ps -o user,pid,comm -p $pid                 # juist, never root
getpcaps $pid                               # cap_net_admin=eip, and nothing else
grep -E 'CapBnd|NoNewPrivs' /proc/$pid/status   # CapBnd 0x1000, NoNewPrivs 1
ip -br addr show juist0                     # the device, with its overlay addresses
systemd-analyze security juistd.service
```

`CapBnd` matters as much as `CapEff`: nothing beyond `CAP_NET_ADMIN` may be
reachable. A network of one member programs no peer routes.

## Check two networks on one host

Two instances side by side are checked against the package too. On a host
with the package installed and in one network already, with a second device to
invite from:

```sh
juist create lab --yes                # asks for sudo once; says juist1
juist status                        # both, headed juist0 and juist1
systemctl status juistd@juist1      # running, as the juist1 user
sudo ls /var/lib/juist1             # its keys, juist1's alone, 0700
sudo -u juist cat /var/lib/juist1/node.keys   # permission denied
ip -br addr show juist1             # the second network's addresses
ip rule | grep -E '^51[0-9][0-9]'   # 5110 … 5170 and 5111 … 5171
ip route show table 27254           # juist1's routes, and nothing else's
sudo systemctl restart juistd       # juist1's routes and rules stay put
juist reset lab --force            # juist1 goes, with its home; the user stays
```

For the conflict, found the second network with `--ipv4` set to the first
one's range (`juist create lab --ipv4 RANGE --yes`, which warns). `juist status`
then reports the second one without IPv4 and names the first, and
`ip -br addr show juist1` shows no IPv4 address. Renumbering either network
out of the other's range, and retiring the old addresses
(`juist network renumber lab PREFIX`, then
`juist network renumber lab --finish`), brings IPv4 back after
three checks in a row find the conflict gone, about fifteen seconds.

## Check an exit node

An exit node needs two installed packages and a real uplink: an exit node
with a public address (a test VM), and a client behind a LAN running
systemd-resolved. On the exit node, after
`juist grant vps exit` from an admin device:

```sh
juist exit serve                      # asks for sudo once; "serving as an exit node"
cat /etc/sysctl.d/60-juist-exit.conf  # "# for: juist0", forwarding on
sudo nft list table ip juist0         # masquerade of the overlay, out of any device but juist0
ip -6 route show default              # still there where the host takes router advertisements
ss -ulpn | grep 41646                 # juistd, on the overlay addresses alone
```

On Debian with ufw, `sudo ufw status` lists `ALLOW FWD` in on juist0; on
Fedora, `firewall-cmd --get-zone-of-interface=juist0` says `trusted`. With
Docker, `sudo iptables -L DOCKER-USER` holds the two juist0 rules. On the
client:

```sh
juist exit                            # vps  …  serving
juist exit use vps                    # "internet via vps"
juist status                          # Exit node  vps, DNS too
resolvectl status juist0              # this device's IPv6 overlay address at :41647, home.juist and ~.
resolvectl query example.com          # answered on juist0
resolvectl query router.lan           # the LAN's own domain, answered on the LAN's link
sudo tcpdump -ni eth0 port 53 & dig example.com   # nothing on eth0
curl -4 ifconfig.me; curl -6 ifconfig.me          # the exit node's addresses
ping -c1 192.168.1.1                  # the LAN router, directly
ip rule | grep -E '^5(18|20)0'        # juistd's own traffic, then the exit table
sudo nft list table ip juist0guard    # what may leave outside the tunnel
sudo tcpdump -ni eth0 host 1.1.1.1 & ping -c3 1.1.1.1   # answered, and nothing on eth0
ping -c1 -I eth0 1.1.1.1              # refused by the guard, and still nothing on eth0
```

Then stop the exit node's juistd: the client's `curl` fails at once, and
`juist status` says why; `juist exit off` brings the internet back directly,
and `resolvectl status juist0` routes the network's domain alone again. `juist status`
saying "systemd-resolved refused juistd" means the package's
`/usr/share/polkit-1/rules.d/60-juist.rules` is not in force. `juist exit
serve --stop` puts forwarding back as it found it, and removing the package
leaves no `/etc/sysctl.d/60-juist-exit.conf`, no `ip rule` from 5180 to 5209
and no `juist0` or `juist0guard` nftables table. Where `serve` reports
forwarding off on Fedora after the script ran, suspect SELinux on
`/etc/sysctl.d` before the script.

## Check an ingress and a published name

An ingress needs a public address, a CA and the internet: an ingress with a
public address (a test VM), a public domain whose `*.DOMAIN` and `DOMAIN` point at it, and a target behind
a LAN. From an admin device:

```sh
juist network domain pub.example.org  # warning: every member then resolves pub.example.org through juistd …
juist grant vps ingress               # hint: on vps, juist ingress serve
juist grant laptop publish            # for juist share
juist publish add nas immich          # on nas's port 443, once nas's operator agrees
```

On the ingress:

```sh
juist ingress serve                   # "serving N names on 443, 443/udp and 80"
ss -ltnp | grep -E ':(80|443) '       # juistd, as juist-ingress, on every address
sudo firewall-cmd --list-services     # Fedora: juist-ingress among them
sudo ufw status                       # Debian and Ubuntu: juist-ingress allowed
```

On the target, nas, as its operator, and then from outside the network:

```sh
juist publish add immich 127.0.0.1:2283   # "ending TLS for immich.pub.example.org to 127.0.0.1:2283"
juist status                              # Published …; Names home.juist, pub.example.org
curl -sI https://immich.pub.example.org   # the service, with a certificate from Let's Encrypt
curl -sI http://immich.pub.example.org    # 308 to https
```

From another member, `resolvectl query immich.pub.example.org` gives the
target's overlay address, and `ping` to the ingress is answered. On the
ingress, `nc -zv TARGET-OVERLAY-ADDRESS 22` gets nothing: members take from
it only what they publish and serve. `juist share ~/some-dir` on laptop
prints a link that `curl` fetches from outside, and nothing without its
token. `juist ingress serve --stop` takes `juist-ingress` out of the
firewall again; removing the package leaves the users `juist`,
`juist-ingress` and `juist-serve` and `/var/lib/juist`, nothing else. On
Fedora, `ausearch -m avc -ts today` stays empty, and `juist status` saying
"systemd-resolved refused juistd" means polkit, which the package
recommends, is missing. A target whose `juist0` firewalld does not trust,
as on a host that had the package before it set that, is warned of by
`juist share` and `juist publish`: "firewalld blocks tcp/443 on juist0".

## Check a subnet router

A router on a LAN, 192.168.1.0/24 here, and a client on another network. After `juist subnet add nas 192.168.1.0/24` from an admin device,
on the router:

```sh
juist subnet serve                    # "routing 192.168.1.0/24"; sudo once, as for an exit node
juist subnet                          # 192.168.1.0/24  nas (this device)  routed
```

On the client:

```sh
juist subnet                          # 192.168.1.0/24  nas  in use
ip route show table 27253             # 192.168.1.0/24 dev juist0
ping -c1 192.168.1.10                 # a host behind nas, which sees nas's address
```

A second client on 192.168.1.0/24 itself shows the prefix "not in use: this
device reaches it by a route of its own", and reaches the LAN directly; so
does one with `juist subnet off`. `juist subnet remove nas 192.168.1.0/24` takes the
route from every client within a sync. A Docker network is no subnet to test
with: Docker 28 and later drop what is routed to its containers from any
device but their bridge, which `juist subnet serve` warns of; a namespace
behind the router is (`ip netns add`, a veth pair, an address each side).

## Check a FreeBSD node

The split into a root helper and a daemon shows in the package alone: two
FreeBSD hosts on one LAN, each with the package `make pkg-freebsd` builds:

```sh
pkg add ./juist-*.pkg                         # the juist user: uid 829, or the next free below
sysrc juistd_enable=YES && service juistd start
ps -axo user,pid,ppid,command | grep juistd   # daemon(8), juistd as root, juistd as juist
ifconfig juist0                               # once in a network: mtu 1280, the overlay addresses
juist create lab --device fb1                 # on one; juist invite, and juist join on the other
ping -c3 OTHER-V4; ping6 -c3 OTHER-V6         # through the tunnel, "direct" in juist status
pfctl -a juist/juist0_in -s rules             # the guard: the overlay kept to juist0
netstat -rn | grep juist0                     # the other's addresses, and nothing else
service juistd stop; ifconfig juist0          # does not exist: the helper destroyed it
```

Serving, with a network behind the router in a VNET jail on an epair, as a
namespace stands in for one on Linux:

```sh
juist subnet add fb2 192.168.77.0/24; juist grant fb2 exit   # on the admin device
juist subnet serve; juist exit serve                    # on fb2
pfctl -a juist/juist0 -s nat; sysctl net.inet.ip.forwarding   # masquerade, redirect; 1
ping -c3 192.168.77.2                                   # on fb1: the jail, through fb2
drill -p 53 @FB2-V4 example.com                         # on fb1: answered through the tunnel
jexec jt drill -p 41646 @FB2-V4 example.com             # from the LAN: not answered
```

Using fb2 from fb1, juistd running as a system user (below 1000), as a
login user's traffic would go around the exit node:

```sh
juist exit use fb2                     # internet via fb2; juist status: fb2, DNS too
cat /etc/resolv.conf                   # fb2's overlay addresses alone
tcpdump -ni vtnet0 icmp or port 53 or port 80 & ping -c2 1.1.1.1; fetch -o /dev/null http://example.org
ping -S LAN-ADDRESS 1.1.1.1            # dropped: nothing on vtnet0 above or here
service juistd stop                    # on fb2: fb1's internet waits, and nothing leaves directly
juist exit off                         # internet direct, resolv.conf and pf as they were
juist exit serve --stop; juist subnet serve --stop      # on fb2: forwarding and pf as they were
```

The package, on one of them serving and using as above:

```sh
pkg add ./juist-NEWER.pkg      # juistd runs on, the old one: service juistd restart
pkg delete juist               # every juistd stops; no juist0, pf and forwarding as found
cat /etc/resolv.conf; ls /var/run/juist*   # the host's resolvers; nothing of juist's
```

The removal says what it keeps: the users juist and juist1 to juist9,
`/var/db/juist` with the device's keys, another network's `/var/db/juistN`,
the logs, and `juistd_` settings in `rc.conf`.

`kill -9` of the root juistd stops the daemon, which reads its helper's end
of a pipe close, and daemon(8) starts both again, the new helper destroying
the device left behind; `kill -9` of the daemon has the helper destroy it at
once, and daemon(8) likewise starts both again.

## Measure an idle phone

`make android-idle` measures the app in the Android emulator, the AVD
`juist` (a `userdebug` image, so `adb root` works), which it boots where no
device is attached: ten juistds on this host (`-members`), each on a
network stack of its own, one creating the network and inviting the others
and the phone, whose join screen a link opens. With the app connected, the
phone unplugged and its screen off, it waits 5 minutes, captures on the
phone's interface for 35, so that every saving interval passes, while a
member but the first two restarts every 3 minutes in turn (`-churn`), news
every member hears, and counts the datagrams and segments, and their bytes,
an hour by flow: the members' data planes, log sync and relay, STUN and its
lookups and the DHT routers', juist's mDNS, ICMP about juist's ports, the
rest; ARP, other ICMP, adbd's mDNS and Android's other lookups are shown and
not counted. Android's own unicast traffic counts, which fails the gate
rather than passes it. Last, a member pings the phone, which must answer with its screen
off. It runs a network without a relay and one where `a` relays (`IDLE=relay`
for one alone, `IDLE_MINUTES` for another length), logs to `build/idle`, and
fails where a scenario passes the budget in `ci/idle`. `dumpsys
batterystats` beside each capture gives the wakeups and wake locks, and the
phone's log, `logcat.txt`, what the core did. The emulator brings its Wi-Fi
back from airplane mode only with the screen on, so the members' restarts
stand in for a phone changing networks.

On a real phone, a day's use with the app connected: `adb shell dumpsys
batterystats --reset` with the phone charged and unplugged, then at the end
of the day `adb bugreport idle.zip`, read with Battery Historian
(`gcr.io/android-battery-historian/stable:3.1`, by docker-vm here) or `adb
shell dumpsys batterystats io.juist`: the app's share of the battery, its
mobile radio and Wi-Fi time, wakeups and wake locks, and Settings' battery
use for the app beside it.

## Check names on Android

In the AVD `juist`, beside juistds on this host as `make android-idle` runs
them: `a` creating the network `names`, `juist network domain
pub.example.org`, `juist grant a relay`; `c`, invited with `--service wiki`,
as `juistd --serve wiki=127.0.0.1:PORT --members --join LINK`, and `juist
publish add c wiki --members` on `a`; the phone joined by a link. Then from
`adb shell`:

```sh
dumpsys connectivity | grep 'InterfaceName: tun'   # DnsAddresses: the network's prefix and ::53; Domains: names.juist
ping -c1 a.names.juist; ping -c1 a           # a's overlay address, answered through the tunnel
ping -c1 wiki.pub.example.org                # c's, once the phone has heard c serves it
echo | nc -w 3 wiki.pub.example.org 443 && echo open
ping -c1 example.org                         # as without the VPN
tcpdump -i wlan0 -n port 53 &                # while pinging a.names.juist: no PTR of its address
ping -c1 printerxyz                          # asked of the phone's network as it is
svc wifi disable; ping -c1 example.org; svc wifi enable   # unknown host within a second
settings put global private_dns_mode opportunistic        # names resolve
settings put global private_dns_specifier dns.google
settings put global private_dns_mode hostname             # no DnsAddresses on tun; the app warns
```

For an exit node, a juistd with a device of its own in a container of
docker-vm (`--cap-add NET_ADMIN --device /dev/net/tun --sysctl
net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1`), joined,
granted `exit` and `juist exit serve`, chosen in the app: the names still
resolve, `tcpdump -i wlan0 port 53` on the phone sees nothing while other
names resolve, and an HTTP request leaves by the exit node; after `juist
exit serve --stop` there, the app says it is refused and other names fail
at once. Stopping the VPN
gives the phone its own DNS back: `example.org` resolves, `a.names.juist`
does not.

## Reading a failure in the NAT matrix

The matrix classifies each NAT before it tests anything — one socket, two
reflectors — and logs the mapped ports it saw. A cell that fails on
`is configured as … but maps one socket to …` is a fault in the lab's own
netfilter rules and not in juist. Past that point the nodes log magicsock's
NAT-traversal chatter: `sent ping … (10.77.0.22:41641)` with no matching
`got ping` on the other side means the punch packets are being dropped, and
`learned no address on the lab's LAN` means STUN never answered, so there was
nothing to punch to. `make ci-vm` keeps the whole log in `build/ci`; from
GitHub's workflow, run by hand, it is the `OS plumbing (privileged)` job's,
more readable with the job prefix stripped:

```sh
gh run view <id> --log-failed | sed 's/.*make test-os-plumbing\t//'
```

## What no test does for you

- **Two real machines on a real LAN.** The tests inject sockets and the labs
  emulate the LAN, so multicast discovery between real daemons shows on real
  hardware alone ([09-mesh-layer-notes.md](09-mesh-layer-notes.md)).
- **The public DHT.** `juistd --verbose` without `--no-dht` bootstraps from the
  public routers and logs `discovered … through the DHT` when rendezvous
  succeeds. It publishes an encrypted blob to strangers and tells a passive
  observer that this host speaks the BitTorrent DHT, residual weakness 5 in
  [02-threat-model.md](02-threat-model.md): turn it on deliberately. One
  invite test uses the real DHT and STUN servers, skipped unless asked for:
  `JUIST_PUBLIC_TESTS=1 go test -run PublicDHT -v ./internal/rendezvous`.
- **Upgrades across more than one release.** `make interop` runs the previous
  release beside this build; nothing older. The readiness check that would
  stop an admin stranding members is M33's
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)).
- **The freshness TTL on a real clock.** The tests move a fake one. On real
  devices, stopping every admin device for longer than the TTL is what shows the
  other members going down to admin-only tunnels.
