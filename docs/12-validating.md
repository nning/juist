# 12 — Validating it

Every milestone in [05-roadmap.md](05-roadmap.md) has a security exit
criterion, and each one is a test that keeps running after its milestone
closes. The walkthroughs in the [README](../README.md) are the manual loop; this is the gates — how to
run them yourself, and, more importantly, which ones a green run does *not*
cover.

## Three gates, and what each leaves out

```sh
make check                     # what every push gates on; needs no privileges
make ci-vm                     # CI: make ci and make interop in a KVM VM it sets up; no root
sudo -E make test-os-plumbing  # real devices, network namespaces, NAT; needs root
make test-freebsd              # every test on a FreeBSD host, as root there
make interop                   # Linux and FreeBSD nodes in qemu, with the packages; no root
make fuzz-long                 # the parser gate: hours per target, never on CI
make test-acme                 # the TLS terminator against Pebble, a CA of its own
```

### When each gate runs

The slow gates run where they can find something `make check` cannot, not on
every push:

| When | What runs | About |
|---|---|---|
| every push | `make check`; `make cross` where a build-tagged file changed | 5 min |
| a change to devices, routes, the firewall or NAT traversal (`conn`, `internal/plumber`, the daemon's host plumbing) | `make ci-vm CI_MAKE=test-os-plumbing-sudo` | 6 min |
| a change to the packages, their units and scripts, or what passes between hosts (ingress, exit, subnets, names, sharing) | `make ci-vm CI_MAKE=interop` | 13 min |
| a milestone, or the review round closing it, is done; before a release | `make ci-vm`, recorded under "The last privileged run" | 25 min |
| where a milestone's criteria ask for it | `make test-freebsd`, `make test-acme`, `make fuzz-long`, the hand tests on Fedora | — |
| a change to `mobile` or `android/` | `make android-check`, with a JDK and the Android SDK; the app by hand in an emulator or on a phone | 3 min |
| documentation alone | nothing; the commit carries `[skip ci]` | — |

The times are KVM's on a four-core host; `make ci` runs the same jobs as
`make ci-vm` but `make interop` on the local machine, the privileged tests
under sudo.

**`make check` silently skips everything that needs privilege.** The real-device
and namespace tests call `t.Skip` when they cannot create a TUN device or a
namespace, so a machine without them reports green while testing none of the OS
plumbing or NAT traversal. That is deliberate — an unprivileged `go test ./...`
has to stay useful — and it is why the privileged tests have a target of their
own, which sets `JUIST_REQUIRE_OS_PLUMBING=1` so a skip there becomes a failure.
If you are checking a claim about devices, routes or NAT, `make check` is not the
command.

Where no Fedora desktop is at hand, a Fedora Cloud VM under libvirt does, as
root: build the test binary with `go test -c -o conn.test ./conn`, copy it
over, and run it in a directory named `conn` with
`JUIST_REQUIRE_OS_PLUMBING=1` and `-test.run` as the Makefile's
`PLUMBING_TESTS`. Fedora Cloud has no polkit until the package brings it.

The privileged tests leave a juistd running on the same machine alone. The
namespace tests run every node in namespaces of their own, and put only a
bridge without an address and its veth ends in the host's. The one real-device
test in the host's namespace takes an instance number no juistd holds, with its
own table and rules, and documentation addresses (192.0.2.0/24,
2001:db8::/32). `make test-os-plumbing-sudo` does the same without running `go`
as root, which would leave root's files in your Go caches. A run cut short
leaves namespaces named `juist…`, `jn…` or `jc…` and a bridge `jbr…`;
`ip netns del` and `ip link del` remove them.

**`make test-freebsd` builds every package's tests for FreeBSD** and runs them
over ssh on a FreeBSD host, as root there with `JUIST_REQUIRE_OS_PLUMBING=1`;
the host needs no Go. `FREEBSD_SSH` reaches it, by default a qemu VM whose ssh
is forwarded to port 2222, which needs neither root nor KVM here:

```sh
curl -LO https://download.freebsd.org/releases/CI-IMAGES/14.5-RELEASE/amd64/Latest/FreeBSD-14.5-RELEASE-amd64-BASIC-CI-ufs.raw.xz
xz -d FreeBSD-14.5-RELEASE-amd64-BASIC-CI-ufs.raw.xz
qemu-img convert -O qcow2 FreeBSD-14.5-RELEASE-amd64-BASIC-CI-ufs.raw fb.qcow2
qemu-system-x86_64 -machine q35 -accel tcg,thread=multi -smp 2 -m 2048 \
  -drive file=fb.qcow2,if=virtio -nographic \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0
```

The CI image lets root in by ssh without a password. Tests of Linux's
plumbing skip there by name; a test that needs `go` or more than one loopback
address skips too.

**`make interop` is where Linux and FreeBSD meet** (`interop/`): a Debian 12
and a FreeBSD 14.5 VM in qemu, their LAN a pair of UDP sockets on the host's
loopback, each with its package installed. FreeBSD creates a network and
Linux joins it by link; each reaches the other over both families. Then each
serves the other as exit node and subnet router: a target on a public
address behind the server, in a VNET jail or a network namespace, must see
the server's masquerade as its source, the subnet's target must answer, the
server's port 53 must, and the client's resolver must take the server and
give it back after `juist exit off`. A host on a public address behind the
client reaches it, and must be answered, but not once the client isolates.
Then names: Debian resolves FreeBSD by `fb.interop.juist` and `fb`, and a
public name the network points at FreeBSD resolves publicly until Debian
accepts names, then to FreeBSD's overlay addresses and through the tunnel,
without the public resolver (a probe on Debian's target) being asked A, AAAA
or HTTPS for it; publicly again while FreeBSD's juistd is stopped, and once
the name is revoked. Last, both packages are removed, leaving no device,
rule or forwarding. It needs qemu, qemu-img, xz and ssh, and no
root: KVM where `/dev/kvm` opens, as in `make ci-vm`, TCG
elsewhere, which takes about an hour. The images are fetched into
`INTEROP_CACHE` once and checked against the sums pinned in
`interop/vm_test.go`; `build/interop` keeps the consoles.

**`make ci-vm` is CI**, on a machine of our own (`ci/main.go`): a Fedora 44
Cloud VM under KVM, set up on first use in `~/.cache/juist-ci`
(`JUIST_CI_CACHE`) from an image pinned by its sum, with a user `ci` who has
sudo, as a hosted runner's. It copies this host's Go and the working tree as it
is, then runs `make ci`, the privileged tests among them, and `make interop`
under nested KVM. The host needs qemu, qemu-img, ssh, ssh-keygen and
`/dev/kvm`, and no root; `JUIST_CI_CPUS` and `JUIST_CI_MEM` (MiB) size the VM,
all CPUs and 8 GiB by default. Each run logs to `build/ci`, named by time and
commit, `-dirty` where the tree had changes. `make ci-vm CI_MAKE=interop` runs
the targets given alone, and `go run ./ci -keep` leaves the VM up to look
into. GitHub's workflows run by hand alone.

**`make repro-freebsd` builds HEAD on two builders**, this machine and the
FreeBSD host `FREEBSD_SSH` reaches: juist and juistd for Linux and FreeBSD,
and the FreeBSD package, each from a clone of the commit. It fails unless both
made the same bytes. The host needs `pkg install git go`; its go fetches the
pinned toolchain itself.

**Fuzzing never runs on CI.** [06-verification.md](06-verification.md) sets
the gate at 72 clean CPU-hours per input surface, which is far more hosted-runner
time than this project will spend, so it is run by hand before a milestone
closes. `make fuzz` smoke-runs every target in seconds and belongs in the
pre-push routine; `make fuzz-matrix` lists the targets so `make fuzz-one` can
give each its own preserved corpus.

**The DHT tests never touch the public network.** They run against a private
swarm on loopback, including the crawler that must learn nothing. Reaching the
real BitTorrent DHT is `juistd` without `--no-dht`, and it is the one thing here
that sends traffic to strangers.

## What checks what

`go test ./<pkg> -run <name> -count=1 -v` runs any single one of these; the
privileged ones need `sudo -E` and `JUIST_REQUIRE_OS_PLUMBING=1` to fail rather
than skip. A NAT cell can be run alone with
`-run 'TestNetnsNATMatrix/symmetric_x_symmetric'`.

| Claim | Where it is checked | Privileged |
|---|---|---|
| M0 — a tunnel with no coordination server | `conn`: `TestTwoNodeOverlayPing`, `TestTwoNodeOverlayPingBothFamilies` | no |
| M0 — nothing reaches a third party | `conn`: `TestNoThirdPartyEgress`; the AF_PACKET tap inside `TestNetnsOverlayCarriesTraffic` | for the tap |
| M1 — the adversarial suite is rejected 100 % | `trust/log`: `adversarial_test.go`, one test per attack | no |
| M1, M4 — parsers survive fuzzing | `make fuzz-long` over `FuzzDecodeAUM`, `FuzzValidateAUM`, `FuzzChainValidate`, `FuzzParseInvite`, `FuzzDecodeEnrollFrames` | no |
| M2 — default-deny: no log entry, no handshake | `daemon`: `TestNonMemberIsNeverAPeer`; `conn`: `TestNonMemberIsDenied`, `TestFilterRejectsNonMembers` | no |
| M2 — revocation converges inside the budget | `daemon`: `TestRevocationConvergesWithinTheBudget`, `TestRevokedDeviceLosesTheDataPlane` | no |
| M2 — LAN-only, zero internet | `daemon`: `TestMeshFormsOnTheLanAlone` | no |
| M3a — a real device is programmed into the host | `conn`: `TestRealDevicePlumbsOverlayIntoHost` | **yes** |
| M3a — two nodes carry ICMP over both families, and TCP | `conn`: `TestNetnsOverlayCarriesTraffic` | **yes** |
| M3a — default-deny survives the router | `conn`: `TestNetnsDefaultDenySurvivesTheRouter` | **yes** |
| M3a — the daemon's privilege footprint | the package, by hand — see [Check the privilege footprint](#check-the-privilege-footprint) | **yes** |
| M3b — direct paths across the NAT matrix | `conn`: `TestNetnsNATMatrix` | **yes** |
| M3b — relay fallback, and relay over TCP | `conn`: `TestNetnsNATMatrix/symmetric_x_symmetric`, `TestNetnsRelayCarriesWhatUDPCannot` | **yes** |
| M3b — a DHT observer learns nothing | `discovery/dht`: `TestCrawlerLearnsNothing`, `TestAnItemIsUselessWithoutTheGroupSecret` | no |
| M3b — non-members cannot use member relays | `relay`: `TestNonMemberCannotUseTheRelay`, `TestRemovedMemberLosesTheConnectionItHolds` | no |
| M3b — the record schema is versioned | `trust/log`: `schema_test.go`; `types`: `TestUnknownEpochSuiteRejected` | no |
| M4 — a code admits exactly one guess, from the LAN | `trust/enroll`: `TestOneGuessPerInvite`; `cmd/juist`: `TestAWrongCodeVoidsTheInvite` | no |
| M4 — a partitioned member drops a revoked peer at exactly the TTL | `daemon`: `TestPartitionedVictimRefusesARevokedPeerAtTheTTL`, `TestStartupGate` | no |
| M4 — admins on separate machines approve a change | `cmd/juist`: `TestInviteWaitsForTheOtherAdmins` | no |
| M4 — only root and the operator manage a device; anyone sees its status | `daemon`: `TestSocketIsOpenAndCallsAreChecked`; `cmd/juist`: `TestTheDaemonHoldsTheDeviceAndThePersonHoldsTheKeys` | no |
| M4 — SPAKE2 matches RFC 9382 | `trust/enroll`: `TestSPAKE2Constants`, `TestKeyScheduleMatchesRFC` | no |
| M4 — a guest stores nothing without the inviting admin's admission | `internal/host`: `TestTheGuestRequiresTheAdminsAdmission` | no |
| M4 — a compromised juistd cannot get the admin's signature on anything else | `cmd/juist`: `TestRotationRecordsFromTheDaemonAreChecked`, `TestAnInviteThroughTheDaemonAdmitsOneDevice`, `TestTheKeystoreAnchorsWhatItVerified`, `TestTheAnchorRefusesARollback` | no |
| M4 — approve shows a record's effect, not its file name | `cmd/juist`: `TestApproveShowsWhatItSigns` | no |
| M4 — freshness needs the threshold of admin devices | `trust/log`: `TestFreshnessNeedsTheThresholdOfAdminDevices` | no |
| M5 — one host in two networks reaches both, over both families | `conn`: `TestNetnsAHostInTwoNetworks` | **yes** |
| M5 — instances keep their tables and rules apart | `conn`: `TestInstancesKeepTheirRulesApart`, `TestNetnsInstancesLeaveEachOtherAlone` | for the second |
| M5 — an overlapping instance yields IPv4, the same network twice does not start | `daemon`: `TestAnInstanceRunsWithoutIPv4WhereALowerOneHoldsIt`, `TestAnInstanceRefusesANetworkTheHostRunsAlready`, `TestTheLowerInstanceKeepsItsAddresses` | no |
| M5 — the CLI finds, makes and removes instances | `cmd/juist`: `TestASecondNetworkRunsBesideTheFirst`, `TestJoiningASecondNetwork` | no |
| M5 — a renumbering keeps every pair reachable, the offline one included | `conn`: `TestNetnsRenumberingKeepsEveryPairReachable`; `trust/log`: `TestRejectsCollidingV4Address` | for the first |
| M5a — each network its own admin key, one shared only on purpose | `cmd/juist`: `TestEachNetworkHasAnAdminKeyOfItsOwn` | no |
| M5a — keys from before, and keys made before their network | `cmd/juist`: `TestAKeyFromBeforeKeysPerNetworkSignsUnchanged`, `TestAKeyMadeBeforeItsNetworkIsFiledUnderIt`, `TestWithoutALogKeysOfTwoNetworksSignByName` | no |
| M5b — a waiting change reaches the other admin device and applies with its vote | `cmd/juist`: `TestAChangeWaitsOnTheOtherAdminDevice`, `TestAnInviteGoesOnWithAVoteFromAnotherAdminDevice`, `TestAnAdmissionGathersVotesWhileItsInviteRuns`, `TestApprovingTheFileCarriesTheSignature`, `TestAFileIsHandedOnByItsSigner`; `gossip`: `TestWaitingChangesReachTheAdminDevices` | no |
| M5b — a copy not from a current admin key, or past the log, is dropped | `daemon`: `TestADaemonHoldsOnlyChangesThatFit`, `TestOneSignerCannotFillTheRoom`; `internal/waiting`: `TestAChangedCopyIsRefused`, `TestASignerLyingAboutItsChangeIsFoundOut` | no |
| M5b — no device without the admin role, nor the one a change is about, receives it | `gossip`: `TestWaitingChangesReachNoOtherDevice`; `daemon`: `TestADaemonHandsChangesToAdminDevicesAlone`, `TestHeldChangesAreSaidToAdminDevicesAlone`; `cmd/juist`: `TestAChangeNeverReachesTheDeviceItIsAbout` | no |
| M5b — nothing is signed unasked | `cmd/juist`: `TestAChangeWaitsOnTheOtherAdminDevice`, `TestAChangeThatExpiresWhileAskedIsNotSigned` | no |
| M5b — a change sealed to its admins opens for no other key | `internal/waiting`: `TestAChangeOpensForItsAdminsAlone`; `trust/secrets`: `TestSealKeyToOpensForItsReaderAlone`; `trust/log`: `TestSetAdminRecipient`, `TestAGenesisRecipientIsSignedForByItsKey` | no |
| M5c — a device moved at once is reached at its new address only, and other transitions run on | `cmd/juist`: `TestAMoveAtOnceReachesEveryDevice`, `TestMovingADeviceAtOnce`, `TestAMoveAtOnceReadsAsOne`, `TestHeldAddressesRead`, `TestStatusNamesTheDevicesNotYetMoved`; `daemon`: `TestAMovedDeviceRestartsOnItsNewAddressAtOnce`; `trust/log`: `TestRenumberNodeAtOnce` | no |
| M6a (1) — only the chosen exit node carries the internet, and a member without a grant is dropped sending from it | `conn`: `TestRoutesCarryTrafficToAndFromTheirPeer`, `TestSetPeersRefusesRoutesThatClash`, `TestAServingNodeAcceptsWhatItServesAlone`, `TestByRouteAtTheEdges`; `daemon`: `TestAClientRoutesThroughItsExitNode` | no |
| M6a (2) — no grant overlaps the overlay, and the internet leaves out the overlay, private and special ranges | `trust/log`: `TestRejectsOverlayOverlappingRoutes`, `TestDefaultRouteRequiresExitNodeRole`; `conn`: `TestInternetIsPublicSpaceAlone` | no |
| M6a (3) — with a full tunnel up nothing but the LAN is reached outside it, pushed routes, bound sockets and a flushed table notwithstanding, and a lost exit node is refused, not gone around | `conn`: `TestNetnsExitNode`, `TestNetnsARefusingClientHearsItsExitNode`, `TestTheExitTable`, `TestTheGuardDropsWhatElseWouldLeave`, `TestTheGuardLetsTheHostsOwnLinkTrafficOut`, `TestAddrInReadsTheRightAddress`, `TestOtherEgress`; `daemon`: `TestAChosenExitNodeFailsClosed`, `TestNoExitNodeGoesDirect`, `TestAnUnreadableChoiceIsRefused`, `TestAChoiceWithoutAMeshIsRefused`, `TestAnEgressThatFailsIsNotCalledRefused`, `TestAnExitNodeNeedsASystemUser`; `cmd/juist`: `TestDNSOutsideTheTunnel`, `TestOneNetworkAHostUsesAnExitNodeThrough`, `TestTwoNetworksServingAndUsing`, `TestStrictReversePathFiltering`, `TestFirewalldStrictReversePath`; `conn`: `TestExitRoutesReadBack`, `TestTheExitRuleLeavesBypassMarkedPackets`, `TestAStrictReversePathRuleIsToldApart`, `TestNetnsAStrictReversePathFilterIsFound`, `TestAnUnmarkedExitRuleIsFound`, `TestNetnsAFamilyNoExitNodeCarriesIsRefused`; `daemon`: `TestTheStatusSaysAStrictReversePathFilter`, `TestAnUnreadableReversePathFilterIsLogged` | for the first two and the `Netns` ones |
| M6a (4) — a withdrawn role ends use and serving, and a stale exit node serves nothing | `daemon`: `TestAChosenExitNodeFailsClosed/withdrawn`, `TestAnExitNodeServesWhenGrantedAndAgreed`, `TestAStaleExitNodeServesNothing`; `cmd/juist`: `TestAnExitNodeFromGrantToOff` | no |
| M6a — an exit node opens none of its own networks, and forwards nothing that is no peer's | `conn`: `TestAnExitNodeServesNotItsOwnNetworks`, `TestServingDropsWhatIsNoPeers`, `TestServingLetsEveryJuistDeviceIn`, `TestNetnsExitNode` | for the last |
| M6a — serving needs the grant, the operator's word and forwarding, and the setup is undone | `cmd/juist`: `TestServingWaitsForTheGrant`, `TestServingAndUsingExcludeEachOther`, `TestForwardingIsReadFromTheKernel`; `daemon`: `TestARefusedRelaySetEndsServing`; `conn`: `TestServingNeedsForwarding`, `TestTheExitScriptKnowsTheRules`; `packaging`: `TestExitNodeScriptUndoesWhatItDid`, `TestExitNodeScriptKeepsForwardingItFound`, `TestExitNodeScriptClearsWhatAFailedJuistdLeft` | no |
| M6a — the choice is the owner's, kept, followed and forgotten with the network | `daemon`: `TestTheExitChoiceIsKept`, `TestTheChoiceFollowsARotatedExitNode`, `TestTheServiceKeepsTheMeshsFollowedChoice`, `TestAResetForgetsTheExitChoice`; `cmd/juist`: `TestForceChoosesAnExitNodeThatDoesNotServe`, `TestTheStatusSaysAnExitNodeIsOffline` | no |
| M6b (1) — only a router's granted, agreed subnets are sent to it and taken from it | `conn`: `TestSubnetsAreRoutedIntoTheTunnel`; `daemon`: `TestAClientRoutesAGrantedSubnet`, `TestASubnetIsLeftOutWhereItMustBe`; `trust/log`: `TestTwoMembersNeverRouteOneAddress` | no |
| M6b (2) — a subnet is reached through its router, a client's own LAN inside it stays its own, and a wider one gives it up, both said | `conn`: `TestNetnsASubnetThroughItsRouter`, `TestARouterServesItsOwnNetworks`; `daemon`: `TestASubnetIsLeftOutWhereItMustBe`, `TestAnExitNodeCarriesNoRoutedSubnet`; `cmd/juist`: `TestASubnetFromAddToRemove` | for the first |
| M6b — a route of the host's own inside a subnet is noticed at once, and a Docker network routed is warned of | `conn`: `TestNetnsASubnetThroughItsRouter`; `cmd/juist`: `TestRoutingADockerNetworkIsWarnedOf` | for the first |
| M6b (3) — a withdrawn or stale grant ends routing, on both sides | `daemon`: `TestARouterRoutesWhatItIsGranted`, `TestASubnetIsLeftOutWhereItMustBe/stale`; `cmd/juist`: `TestASubnetFromAddToRemove` | no |
| M6b — the operator's and the owner's word are kept and forgotten with the network | `daemon`: `TestTheSubnetWordsAreKept`; `ipc`: `TestASubnetRequestSetsOneThing` | no |
| M6b — no subnet takes another overlay, a VPN's or the host's own routes, nor what a network pushed | `trust/log`: `TestRejectsOverlayOverlappingRoutes`; `conn`: `TestTheHostsOwnRoutes`; `daemon`: `TestARouterWithoutIPv4RoutesNoIPv4`, `TestAPeerWithoutIPv4IsSentNoIPv4`, `TestOnlyARoutedDeviceSaysItHasNoIPv4`; `cmd/juist`: `TestForwardingStaysWhileEitherServes` | no |
| M6c (1) — a member's DNS is answered through its exit node, and not outside the tunnel; no one else is answered | `conn`: `TestNetnsExitNodeAnswersDNS`; `internal/dnsfwd`: `TestAQueryIsForwarded`, `TestOnlyMembersQueriesAreForwarded`, `TestAMemberIsAnsweredAtItsRate`, `TestTheHostsResolvers`; `daemon`: `TestAnExitNodeAnswersItsMembersDNS` | for the first |
| M6c (2) — resolved is pointed at the exit node while one is chosen, refused too, and given back when off | `daemon`: `TestTheHostsDNSGoesThroughTheExitNode`; `internal/resolved`: `TestRouteAndRevert`, `TestADialledClientRoutes`; `packaging`: `TestThePolkitRuleAllowsJuistsDNSAlone` | no |
| M6c (3) — without resolved, or refused by it, nothing is configured and the reason is said | `daemon`: `TestDNSOutsideTheTunnelIsSaid`, `TestDNSAroundResolvedIsSaid`, `TestAFailedDNSRoutingWaits`; `internal/resolved`: `TestWhatResolvedCannotDoIsSaid`; `cmd/juist`: `TestDNSOutsideTheTunnel`, `TestTheStatusSaysWhereDNSGoes` | no |
| M6c — DNS follows the choice whatever the network does, and a stopped daemon leaves it alone | `daemon`: `TestDNSFollowsTheChoiceWhateverTheNetwork`, `TestAClosedDaemonLeavesDNSAlone`; `internal/dnsfwd`: `TestAFailingResolverIsPassedOver`, `TestASourceHoldsFewConnections` | no |
| M6c — an exit node of one family is sent and asked that family alone, and the other is refused at once and said to be | `conn`: `TestNetnsAFamilyNoExitNodeCarriesIsRefused`, `TestTheGuardRefusesWhatNoPeerCarries`, `TestTheRouterLearnsWhatThePeersCarry`; `daemon`: `TestAnExitNodeOfOneFamilyIsSaid`; `cmd/juist`: `TestTheStatusSaysWhereDNSGoes` | for the first |
| M7a — on FreeBSD the daemon runs as juist, and a helper as root plumbs juist's own devices alone, one helper each, addresses of one host and no default route, and neither outlives the other | `internal/plumber`: `TestTheHelperPlumbsWhatItIsAsked`, `TestTheHelperTouchesNothingElse`, `TestAnAddressIsOneHost`, `TestALargeRouteSetGoesWhole`, `TestALateAnswerIsNoOtherCallsAnswer`, `TestADeviceIsOneHelpers`, `TestManyRoutesGoInFast`; `cmd/juistd`: `TestRootSplitsOffTheDaemon`, `TestTheDaemonGoesWithItsHelper`, `TestAHelperThatStopsServingStopsTheDaemon`, `TestRootNeedsAHome`, `TestRootGetsHelp`, `TestTheDaemonGetsNoneOfRootsEnvironment`, `TestAJuistUserOfRootsIsRefused` | FreeBSD, for the last nine |
| M8a — a name is taken in one form alone, of two labels or more, no address and nothing of `.juist` or the host's own domains, sorted and one member's; a state names members only from schema 8 | `types`: `TestHostNames`, `TestNameSets`, `TestNamesNeedTheirSchema`, `TestEveryPayloadIsValidated` | — |
| M8a — a quorum points names at a member and takes them back; they survive reopening, a checkpoint and an identity rotation, and go with the member; a name another holds, a non-member, the names it has, a quorum short and schema 7 are refused | `trust/log`: `TestNamesFollowTheMember`, `TestNamesAreRefused`, `TestApplyLeavesItsParentUnchanged` | — |
| M8a — `juist names add` and `remove` take a name in its one form, never two devices' or the network's own, `grant` and `revoke` name them for a name or a subnet, and an approver reads what a change points where | `cmd/juist`: `TestNamesAddAndRemove`, `TestNameStates`, `TestASubnetFromAddToRemove`, `TestANamesChangeSaysWhatItPoints` | — |
| M8b — members' names are answered from the log with the zone's SOA, a name the network lacks does not exist, and overrides are answered by address alone, their hints empty | `internal/names`: `TestMembersAreAnswered`, `TestOverridesAreAnswered`, `TestTheZoneIsItsAuthority`, `TestTheZonesNamesGoNowhereElse`, `TestLabels`; `internal/dnsfwd`: `TestAnAnswerOfItsOwnReachesNoResolver`, `TestTheHostIsHeldToNoSourcesRate` | — |
| M8b — resolved routes the network's domain, and every name with an exit node, to juistd's resolver on an address the device holds, bound to it and answering the host alone, which asks the exit node, else the resolvers resolved would but its own link's; the domains are kept from DNSSEC validation; it is given back on close, and the status says why names do not resolve | `daemon`: `TestTheHostResolvesTheNetworksNames`, `TestNamesThatWillNotStartLeaveTheExitNode`, `TestNamesNotResolvedAreSaid`, `TestTheNamesServerIsBoundToTheDevice`, `TestTheNamesAddressIsOneTheDeviceHolds`, `TestWhatIsNotAnsweredGoesWhereTheHostRoutesIt`; `internal/resolved`: `TestConfigureDomains`, `TestRouting`; `packaging`: `TestThePolkitRuleAllowsJuistsDNSAlone`; `cmd/juist`: `TestStatusSaysHowNamesResolve` | — |
| M8c — a public name is resolved to its member only where the owner agreed, never by an exit node for a member that did not, which an exit node whose host's resolver does not ask juist's, as without resolved, asks of its own resolvers, while the view is fresh and the member reachable, and publicly otherwise; the word is kept and forgotten with the network, and the status lists each name and why it resolves publicly | `internal/names`: `TestOverridesAreAnswered`, `TestEDNSIsAnsweredInKind`, `TestOverridden`; `daemon`: `TestAPublicNameNeedsTheOwnersWord`, `TestAnExitNodeHandsNoOverrideOn`, `TestAnExitNodeWithoutNamesAsksTheHostsResolvers`, `TestAStaleViewAnswersNoPublicName`, `TestNoMemberNoNames`, `TestTheNamesWordIsKept`; `ipc`: `TestANamesRequestSetsAcceptingAlone`, `TestAReaderSeesNoPublicNames`; `cmd/juist`: `TestAcceptNames`, `TestStatusListsPublicNames`; `ipc`: `TestEachCommandTakesItsOwnFields` | — |
| M9a — a published name is one label on a port, sorted and once; an ingress is neither voucher nor exit; a state publishes only under a domain of its own, from schema 9 | `types`: `TestPublishedNameSets`, `TestAnIngressIsNothingElse`, `TestPublishedNamesNeedTheirDomain`, `TestRolesNeedTheirSchema`, `TestEveryPayloadIsValidated` | — |
| M9a — a quorum sets the domain and publishes names, which survive reopening and a checkpoint; a name before the domain, the domain withdrawn under names, a label another publishes and a name both published and pointed at a member are refused, the domain's move included; the ingress role at schema 8 too | `trust/log`: `TestPublishedNamesNeedTheDomain`, `TestPublishedNamesAreOneMembers`, `TestTheIngressRole`, `TestApplyLeavesItsParentUnchanged`, `TestStateCarriesEveryField` | — |
| M9a — `juist network domain` and `juist publish` set and list what is published, `juist grant` an ingress, and an approver reads what a change publishes | `cmd/juist`: `TestPublishAddAndRemove`, `TestGrantAnIngress`, `TestAPublishChangeSaysWhatItPublishes`, `TestEveryKindIsDescribed` | — |
| M9a (2) — a member takes from an ingress TCP to its own addresses on the ports it publishes and serves and log sync's, and replies to what it opened, nothing else, whatever the flags, the protocol or the address it serves; the engine's own hooks still run | `conn`: `TestTheConfinerKeepsAnIngressToItsPorts`, `TestTheConfinerCallsTheEnginesHooks`, `TestAnIngressReachesItsPortsAlone` | — |
| M9a — an ingress is confined, and reaches the published port only once the operator agreed and while the view is fresh; the word is kept and goes with the network, and the status says what is served or why not | `daemon`: `TestAnIngressReachesWhatIsServedAlone`, `TestThePublishWordIsKept`; `ipc`: `TestEachCommandTakesItsOwnFields`, `TestEveryStatusFieldIsClassifiedForReaders`; `cmd/juist`: `TestPublishServe` | — |
| M9a — the user juist-ingress may ask what is published and nothing else, from a pool of its own; an ingress is told every published name and where it goes, and nothing once it is no ingress or stale; it reads a reply of a newer juistd | `daemon`: `TestTheIngressAsksWhatIsPublishedAlone`, `TestReadersCannotCrowdOutTheIngress`, `TestAnIngressServesWhatIsPublishedWhileFresh`; `ipc`: `TestTheIngressReadsAReplyOfANewerJuistd`, `FuzzDecodePublished` | — |
| M9a — an ingress passes a connection for a published name to its target untouched, its ClientHello first and a PROXY v2 header where asked, past an address that does not answer; a name not published reaches nothing; HTTP redirects a served name to https alone; a silent juistd takes the names down after two asks, and a client that says nothing is let go | `internal/ingress`: `TestTheIngressSplicesByServerName`, `TestTheIngressSaysWhoTheClientIs`, `TestTheIngressRedirectsToHTTPS`, `TestASilentJuistdPublishesNothing`, `TestAClientThatSaysNothingIsLetGo` | — |
| M9a — the ingress logs each connection with its client, name, outcome, bytes each way and duration, and each request on port 80 with its path and User-Agent, quoted | `internal/ingress`: `TestTheIngressLogsEachConnection` | — |
| M9a — `juist ingress serve` runs the package's script on a device that is an ingress alone, and lists what it serves; the script starts the unit and opens 443 and 80, and takes both back, and removing the package does | `cmd/juist`: `TestIngressServe`; `packaging`: `TestIngressScriptOpensAndCloses`, `TestARemovalStopsTheIngress`, `TestFirewalldServicesParse` | — |
| M9a — flows this node opened to confined peers are bounded per address and in all; one peer's churn evicts its own flows, never another's, and a peer no longer confined leaves none behind | `conn`: `TestOnePeersFlowsEvictNoOthers` | — |
| M9a (2), (5) — between hosts, from the packages: an ingress serves a name a member publishes once the member's operator agrees, redirects HTTP to it, and reaches nothing else of that member's; a withdrawn name reaches nothing; the package's removal stops the ingress and leaves its user | `make interop`: `TestLinuxAndFreeBSD/ingress`, `TestLinuxAndFreeBSD/removal` | qemu |
| M9b — TLS ends at the target for a name served alone, the plain connection reaching the local service; the CA's challenge goes no further; ALPN is offered for it alone; a PROXY header is believed from an ingress alone and passed on; what is served no longer is listened for no longer, and a port another program holds is said | `internal/terminator`: `TestTheTerminatorEndsTLSForWhatItServes`, `TestTheChallengeStopsHere`, `TestTheServiceLearnsTheClientFromAnIngress`, `TestTheTerminatorListensWhereItServes`; `internal/proxyproto`: `TestAHeaderReadsBack`, `TestABadHeaderIsRefused` | — |
| M9b — the terminator is told what this device serves and where it goes, on its own addresses, nothing without the word or while stale; it may ask nothing else; where to is kept apart from the word, added to and taken from one name at a time; `juist publish add NAME HOST:PORT` starts it; members resolve a name published on 443 to a target that serves it | `daemon`: `TestATerminatorIsToldWhereNamesGo`, `TestWhereToServeIsKept`, `TestWhereToServeMovesOutOfTheWord`, `TestTheTerminatorAsksWhatItServesAlone`, `TestMembersReachAPublishedNameDirectly`; `ipc`: `TestAPublishRequestNamesWhereTo`; `cmd/juist`: `TestPublishAddEndsTLS`; `packaging`: `TestServeScriptStartsAndStops`, `TestARemovalStopsTheIngress` | — |
| M9b — with Pebble as the CA, the terminator takes a certificate by TLS-ALPN-01, answering the challenge itself, which a client trusting Pebble's root alone takes, and tells juistd the account and the CA's name for itself | `make test-acme`: `internal/terminator`: `TestACertificateFromPebble` | — |
| M9b — the CAA record: the account key is autocert's own; a terminator's account reaches juistd only where it fits a record as it is; the status holds a record for each name whose TLS juist ends, and `juist publish add` and `serve` print them | `internal/terminator`: `TestTheAccountKeyIsAutocertsOwn`; `ipc`: `TestAServingRequestCarriesAnAccountThatFitsCAA`; `daemon`: `TestTheStatusHoldsTheCAARecords`; `cmd/juist`: `TestPublishAddEndsTLS` | — |
| M9b — FreeBSD's helpers: the terminator's root parent listens where juistd says this device serves and nowhere else, and hands it the listener; a helper started as root drops to its user for good; the rc.d scripts run juistd as the helpers on the default socket and stop them; libexec's scripts are executable | `cmd/juistd`: `TestTheBinderListensWhereNamesAreServed`, `TestAHelperDropsRoot`; `packaging`: `TestTheHelpersRCScriptsRunThem`; `packaging/freebsd/mkpkg`: `TestModesAndMistakes` | root, the rc.d one FreeBSD |
| M9b — `juist invite --service NAME` admits a service member publishing NAME, under the domain alone and with no other role, and the approval says what it publishes | `cmd/juist`: `TestInviteAServiceMember` | — |
| M9b — the service member's image: what docker load takes, the same bytes twice, its binaries runnable and its home its user's | `packaging/image/mkimage`: `TestTheImageLoads` | — |
| M9c — the publish role: schema 9's, never beside the ingress role, for a member whose name gives a label, which is then its alone against published labels, other members' publish labels and names | `trust/log`: `TestThePublishRole` | — |
| M9c — a share is announced signed, and a change of the announcement; a device shares under its name, its end at most a lease ahead or its own, the terminator ends TLS for it without the published names' word, an ingress may open its port while fresh; announced only while it can be served; renewed as its end moves; an ingress serves members' shares while their announcement holds and takes none ending further ahead than a lease; a share lasts as long as its call and outlives a restart of the network | `gossip`: `TestAShareIsAnnounced`; `daemon`: `TestADeviceSharesUnderItsName`, `TestAShareIsAnnouncedWhileItCanBeServed`, `TestAShareIsRenewedAsItsEndMoves`, `TestAnIngressServesMembersShares`, `TestAnIngressTakesNoShareEndingFarAhead`, `TestAShareLastsAsLongAsTheCall`, `TestAShareOutlivesARestart` | — |
| M9c (6) — a shared directory is read under its token alone: anywhere else 404 listing nothing, no link out of it, nothing written, no Referer, no dot-entries, nothing run as the name's origin; a linked file, `index.html` and a name needing escapes are served; `juist share` holds the share until stopped, with the role and a domain, starting the terminator, and says when juistd ends it; `juist publish PORT` takes its port past `--for`, refuses one that is none, and takes IPv6's loopback where only it answers; the CLI knows juistd's refusals by juistd's words | `cmd/juist`: `TestAShareIsReadUnderItsTokenAlone`, `TestAShareServesWhatItNames`, `TestShareUntilStopped`, `TestAShareEndsWithJuistd`, `TestPublishAPort`, `TestTheShareWordsAreJuistds` | — |
| M9c (5), (6) — between hosts: a client on the LAN fetches a file lx shares through fb with Pebble's certificate, finds nothing without the token; fb serves the name no longer once the share is stopped, or past its end, which ends the command | `make interop`: `TestLinuxAndFreeBSD/share` | qemu |
| M9d review — the admin's hint names the domain itself, `juistd --serve` takes no empty name, a domain moved is said to publish the domain itself and to have every member resolve it through juistd, and the Names line is never empty | `cmd/juist`: `TestTheTerminatorStartsBeforeTheName`, `TestPublishTheDomainItself`, `TestTheNamesLineIsNeverEmpty`; `cmd/juistd`: `TestServeMakesAServiceMember` | — |
| M9d — the domain itself: the empty label, on one member at most and never a name pointed at a member, either first, the domain moving included; kept as `@` in the names' file; the network's domain goes to juistd whole on every member, the domain itself and its names published on 443 answered names on or not, the rest passed on; published spelled out, with the approval saying so and the apex's records hinted | `types`: `TestPublishedNameSets`; `trust/log`: `TestTheDomainItselfIsOneMembers`; `daemon`: `TestWhereTheDomainItselfGoesIsKept`, `TestTheDomainGoesToJuistdWhole`; `cmd/juist`: `TestPublishTheDomainItself` | — |
| M9 review 3 — a name behind `--proxy` is not resolved to its device; the domain itself is answered with its device's address through the reachability check; the status names the public domain; `juist network domain` warns that every member resolves it through juistd; `juistd --serve @=ADDR` serves the domain itself | `daemon`: `TestMembersReachAPublishedNameDirectly`, `TestTheDomainGoesToJuistdWhole`, `TestTheStatusNamesThePublicDomain`; `cmd/juist`: `TestTheNamesLineIsNeverEmpty`, `TestPublishAddAndRemove`; `ipc`: `TestAReaderSeesNoPublicNames`; `cmd/juistd`: `TestServeMakesAServiceMember` | — |
| M9 review 4 — the CLI waits for a terminator it just started by what juistd says then, and a terminator that stops says so, so the status counts it down at once; the terminator orders no certificate for a name it no longer serves; the ingress lets go a client that does not answer its target's hello within a minute, bounds a site's connections and port 80's by source, and redirects by the path alone; a spliced connection whose source fails ends both ways, one that cannot write leaves the other way to finish, on FreeBSD too; the confiner takes echo replies and ICMP errors on what this node opened, and ends a TCP flow at an RST, or a minute after FINs both ways; the RPM owns `/usr/lib/juist`, and both packages recommend polkit; `juist grant` names the role that excludes the one granted | `cmd/juist`: `TestAStartedTerminatorIsWaitedFor`, `TestARoleThatExcludesAnotherIsSaid`, `TestGrantAnIngress`; `internal/terminator`: `TestANameNotServedIsNotOrdered`, `TestATerminatorSaysItStops`; `daemon`: `TestTheStatusSaysWhereTheTerminatorListens`; `internal/ingress`: `TestAClientThatStopsAfterItsHelloIsLetGo`, `TestTheRedirectNamesItsHostAndBoundsASource`; `internal/pipe`: `TestSourcesBoundHostsAndSites`, `TestAFailedWayEndsBoth`, `TestAWayThatCannotWriteLetsTheOtherFinish`; `conn`: `TestAConfinedPeerAnswersPingsAndErrors`, `TestAConfinedFlowEndsWithItsConnection`; `packaging`: `TestTheRPMOwnsItsDirectories`, `TestThePackagesRecommendPolkit` | — |
| M9 review 6 — where firewalld keeps the port a device serves on from arriving on its juist device, `juist share`, `juist publish add` and `serve` say so, with the command that puts the device in the trusted zone, and say nothing where it lets the port in; an interface counts as blocked as log sync's check counts it | `cmd/juist`: `TestAFirewallKeepingOutWhatIsServedIsSaid`; `internal/firewalld`: `TestBlocksAsksFirewalldOnTheSystemBus`, `TestAZoneWhosePortsCannotBeAskedCountsAsFirewalled` | — |
| M9c — a share in the background: the command returns once the share is up, which serves on until `juist share --stop`, a foreground share heeds that too, a second share is refused, stopping none says so, and the share is taken up again under its path after juistd restarts; juistd ends a share from another call, whose call ends without error | `cmd/juist`: `TestAShareInTheBackground`, `TestABackgroundShareOutlivesJuistd`, `TestTheShareWordsAreJuistds`; `daemon`: `TestAShareIsStoppedFromAnotherCall` | — |
| M9c — a shared directory is listed folders first and sorted as asked, its links kept under the token whatever a name holds, its dot-entries left out, running nothing and free to download, while what is shared stays sandboxed; a folder with an `index.html` is that page; a directory, or a folder in it, is sent as a ZIP under its name, without dot-entries or what a link reaches outside | `cmd/juist`: `TestASharedDirectoryIsListed`, `TestASharedDirectoryIsZipped` | — |
| M9c — the listing looks as the website does, its colours, wordmark and fonts the website's own, the fonts reached under the token alone and not beside a shared file | `internal/webstyle`: `TestThePagesLookAsTheWebsiteDoes`; `cmd/juist`: `TestTheListingLooksAsTheWebsiteDoes`, `TestTheListingsFontsAreUnderTheToken` | — |
| M9b — a name served that a client found no certificate for is said by the terminator, with why, until one is found, the CA's challenge and a name not served changing nothing; juistd keeps it for the status, which warns of it while the terminator runs | `internal/terminator`: `TestTheTerminatorSaysWhichNamesHaveNoCertificate`; `ipc`: `TestAServingRequestCarriesAnAccountThatFitsCAA`; `daemon`: `TestTheStatusSaysWhereTheTerminatorListens`; `cmd/juist`: `TestTheStatusWarnsOfANameWithoutACertificate` | — |
| M9b — systemd starts the terminator by juistd's file: juistd keeps it while a share or a name whose TLS juist ends needs the terminator, and tells the terminator when nothing does, which then stops, though not while it has a name to serve; where systemd starts it, sharing runs no script; a fresh install enables `juist-serve.path`, an upgrade moves a terminator enabled the old way to it and enables nothing else, and `serve.sh` turns the path on and off | `daemon`: `TestJuistdSaysWhenTheTerminatorIsNeeded`; `internal/terminator`: `TestAnIdleTerminatorStops`; `cmd/juist`: `TestAShareWhereSystemdStartsTheTerminatorTakesNoRoot`; `packaging`: `TestTheTerminatorStartsByItsPath`, `TestServeScriptStartsAndStops` | — |
| M9b — `juistd --join LINK`, or `$JUIST_JOIN`, which `--help` does not show and a helper ignores: once started, a juistd in no network joins by it and says how it went, and one in a network ignores it | `cmd/juist`: `TestAJuistdJoinsByTheInviteItWasGiven`; `cmd/juistd`: `TestJoinTakesTheInviteFromTheEnvironment`, `TestHelpListsEveryOptionWithItsDefault` | — |
| M9b — the Compose example runs juistd with options it takes and passes `$JUIST_JOIN`; by hand under rootless Podman 5.8 on Fedora 44, with its override, both containers ran, the service's network internal, and the service member waited to join | `cmd/juistd`: `TestTheComposeExampleRunsAServiceMember` | — |
| M9d (7) — between hosts: a client on the LAN fetches the domain itself through fb with Pebble's certificate; a second device publishing it, and a name pointed at a member equal to it, are refused, each for its reason; the target, a member, sends the domain to juistd, resolves the domain itself to itself, and another name of the domain at the resolver the host routes example.org to, which logs it | `make interop`: `TestLinuxAndFreeBSD/domain_itself` | qemu |
| M9e — renaming a device: schema 10's, a name and nothing else changed, kept across reopening and a checkpoint; refused for the name it has, one another member's folds like, and one its share label cannot follow; the approval says what it is then resolved and shared as, and the old name no longer resolves | `types`: `TestEveryPayloadIsValidated`; `trust/log`: `TestRenameNode`, `TestApplyLeavesItsParentUnchanged`, `TestKindsBeforeTheirSchema`; `daemon`: `TestARenamedDeviceIsAnsweredByItsNewName`; `cmd/juist`: `TestRenameADevice`, `TestARenameKeepsNamesApart` | — |
| M9e review — a rename is carried to the other admin devices, never the renamed one; lost to a concurrent change, it is said in words; a running share is said again under the new name, without the first time's warning, and ends once its role or domain is gone; the approval quotes the name and says nothing of names for a change of case, and gives a label two devices held to the other; the CLI refuses a share name the device publishes or points at itself, and says a refusal of the log's in words | `internal/waiting`: `TestEveryKindIsDecidedOnWhomItIsAbout`; `daemon`: `TestALostRenameIsSaid`, `TestARenamedShareIsSaidAgain`, `TestAShareEndsWithItsRole`; `cmd/juist`: `TestRenameADevice`, `TestARenameKeepsNamesApart`, `TestARenameGivesASharedLabelToTheOther`, `TestAShareSaidAgainWarnsOnce` | — |
| M9e — between hosts: fb, renamed on fb, is resolved on lx by its new name at its addresses and no longer by its old, and lx's log names the rename | `make interop`: `TestLinuxAndFreeBSD/rename` | qemu |
| M9f — a status page target says what the public sees and is no HOST:PORT; a member is known by its address alone; the terminator reads a newer juistd's page and its refusal | `ipc`: `TestAStatusPageTargetSaysWhatThePublicSees`, `TestAStatusPageKnowsItsMembers`, `TestTheTerminatorReadsAStatusPage`, `TestAPublishRequestNamesWhereTo` | — |
| M9f — the terminator is told the status page only where its operator serves one, its members every member's addresses but an ingress's, its changes the log's newest; no reader is told | `daemon`: `TestTheTerminatorIsToldTheStatusPage`; `internal/changelog`: `TestEveryKindIsNamed` | — |
| M9f — a member sees the whole page, the public what `--public` says, a page for members alone 404 with its assets; a forged PROXY header from an ingress is the public still; what it shows is escaped, juistd asked once a moment, and its silence said | `internal/statuspage`: `TestWhatAClientSees`, `TestThePageSaysWhoseViewItIs`, `TestThePageEscapesWhatItShows`, `TestThePageServesItsAssetsAndNothingElse`, `TestJuistdIsAskedOnceAMoment`; `internal/terminator`: `TestTheStatusPageKnowsAMemberByItsAddress` | — |
| M9f — `juist publish status-page` publishes the page as a name whose TLS juist ends, says what the public sees, changes it, and takes it down | `cmd/juist`: `TestPublishTheStatusPage` | — |
| M9f review 1 — plain HTTP to an address a name is served on is redirected to https, for names served there alone; port 80 held by another program is told juistd, warned of by `juist status` and the page; the FreeBSD binder listens on port 80 where a name is served; the page sends HSTS | `internal/terminator`: `TestPlainHTTPIsRedirected`; `cmd/juist`: `TestTheStatusWarnsOfPort80HeldByAnother`; `cmd/juistd`: `TestTheBinderListensWhereNamesAreServed`; `internal/statuspage`: `TestWhatAClientSees`, `TestThePageServesItsAssetsAndNothingElse` | — |
| M9 review 2 — the daemon: a share's end ends that share alone, a restarted share leaves another's, a look at what is published changes nothing, an expired device's helpers are told nothing, and the status says where the terminator listens and where another program holds the port | `daemon`: `TestAShareEndsItselfAlone`, `TestARestartedShareLeavesAnothers`, `TestPublishedHasNoSideEffectsAndExpiryEndsServing`, `TestTheStatusSaysWhereTheTerminatorListens` | — |
| M9 review 2 — the helpers: the binder answers each request alone, however many came before and however late, binds no address another program listens on, and its terminator hears it go; the terminator says where it listens; a connection idles only both ways at once | `cmd/juistd`: `TestTheBinderAnswersEachRequestAlone`, `TestTheTerminatorHearsItsParentGo`; `internal/terminator`: `TestTheTerminatorSaysWhereItListens`; `internal/pipe`: `TestJoinIdlesBothWaysAtOnce` | — |
| M9 review 2 — the CLI: what the terminator says decides whether TLS ends where a name is published; a share keeps its terminator; a taken label is said before anything is asked | `cmd/juist`: `TestTheTerminatorsWordDecides`, `TestAShareKeepsItsTerminator`, `TestATakenLabelIsSaidAtOnce` | — |
| M9 review — the log: an admission publishes under the domain alone, a published name fits DNS, a label is published once, and an ingress publishes nothing on 80 or 443 | `trust/log`: `TestAnAdmissionPublishesUnderTheDomainAlone`, `TestAPublishedNameFitsDNS`, `TestALabelIsPublishedOnce`, `TestAnIngressPublishesNothingOnItsOwnPorts` | — |
| M9 review — the helpers: a quiet client gives its slot back, a host holds a few connections, a withdrawn name or a stale view ends the connections for it, a juistd that hangs takes the names down within two polls, the redirect lets idle clients go, the ingress says juistd is gone, a failed listener is listened for again, a closed network stack ends its listeners and listens on its own addresses alone, and the ingress and the terminator each keep a slot | `internal/ingress`: `TestAQuietClientGivesItsSlotBack`, `TestAHostHoldsAFewConnections`, `TestAWithdrawnNameEndsItsConnections`, `TestAJuistdThatHangsPublishesNothing`, `TestTheRedirectLetsAnIdleClientGo`; `internal/terminator`: `TestANameNoLongerServedEndsItsConnections`, `TestAJuistdThatHangsEndsServing`, `TestAFailedListenerIsListenedAgain`; `internal/netstack`: `TestClosingTheDeviceEndsItsListeners`, `TestTheStackListensOnItsAddressesAlone`; `daemon`: `TestOneHelperCannotCrowdOutTheOther`, `TestAnIngressReachesWhatIsServedAlone`; `cmd/juistd`: `TestTheIngressSaysJuistdIsGone` | — |
| M9 review — the CLI and the package: the terminator starts once told where a name goes, before it is published, and stops with the word or the last name; the status says when it does not run; what answers on the port must end TLS; a name not yet published is said, with the admin's command; the helpers serve the default instance alone; a withdrawn ingress or service role warns; no hint for a service member; a stale ingress is told why it serves nothing; systemctl says nothing, and a firewall that refuses the ingress is said | `cmd/juist`: `TestTheTerminatorStartsBeforeTheName`, `TestTheTerminatorMustEndTLS`, `TestEndsTLSTellsTLSFromPlain`, `TestHelpersServeTheDefaultInstanceAlone`, `TestGrantAnIngress`, `TestPublishingOnAServiceMemberHintsNothing`, `TestAStaleIngressIsToldWhy`; `packaging`: `TestIngressScriptOpensAndCloses`, `TestServeScriptStartsAndStops` | — |
| M9b (3) — over two network stacks, a member opens a connection to a service member and is answered, and the service member opens none to the member; a daemon on a network stack hands the data plane a device, syncs in the tunnel alone, is reached on its overlay addresses alone, binds its sockets to no interface and blames no firewall of its own | `conn`: `TestAServiceMemberAnswersAndOpensNothing`, `TestTheConfinerKeepsAnIngressToItsPorts`; `daemon`: `TestADaemonOnANetworkStack`, `TestANetstackNodeBindsItsSocketsToNoInterface`, `TestTheStatusNamesATunnelTheFirewallBlocks`; `types`: `TestAnIngressIsNothingElse`; `cmd/juistd`: `TestServeMakesAServiceMember` | — |
| M9b (1), (4) — with Pebble as the CA, a client outside the network fetches a name a full member publishes, and one a service member publishes, through the ingress, by a certificate each took by TLS-ALPN-01 through it; the service member answers no other port | `make interop`: `TestLinuxAndFreeBSD/TLS_at_the_target`, `TestLinuxAndFreeBSD/service_member` | qemu |
| M9b — the service member as its image runs it in Docker, beside a service on an internal network with it alone, serves the service's name through the ingress with a certificate from Pebble; that service reaches neither the LAN nor the overlay, and what it reaches of the host is logged | `make interop` with `JUIST_INTEROP_DOCKER=1`: `TestLinuxAndFreeBSD/service_member_in_a_container` | qemu, Docker |
| Battery — a quiet peer a relay can wake is probed every 5 minutes, its answer standing meanwhile, and every check without this device's relay; LAN discovery slows from its first interval while nothing changes and starts over when the announcement or connectivity changes | `daemon`: `TestAQuietPeerARelayCanWakeIsProbedRarely`, `TestAChangeWakesTheBeacon`; `discovery/mdns`: `TestABeaconSlowsDownUntilWoken` | — |
| M8 (1), (3)–(5) — with resolved, members resolve by name, a public name resolves to its member through the tunnel without the public resolver being asked, a name beside it publicly, and publicly again while the member is down and once revoked | `make interop`: `TestLinuxAndFreeBSD/names` | qemu |
| M7 review — the helper takes no address or source outside a network's space, captures nothing the host keeps to its links, deletes a route by its gateway, keeps what to put back where that fails, leaves a pf rc.conf starts on, and adds answer rules beside no ruleset of the host's | `internal/plumber`: `TestTheHelperKeepsToTheNetworksSpace`, `TestARouteDeletedLeavesTheHosts`, `TestAPfTheHostStartsIsLeftOn`, `TestPFIsKeptAndLeftBe`; `conn`: `TestARedirectsRouteIsNotTheHosts` | FreeBSD, but for the first |
| M7 review — an instance's home is made as the juist user, never followed as root; clear waits for a supervised juistd | `packaging`: `TestAnInstanceHomeFollowsNoLink`, `TestClearWaitsForASupervisedJuistd` | FreeBSD |
| M7 review — the FreeBSD package's modes go by where a file goes, and a file twice or a stray script is refused | `packaging/freebsd/mkpkg`: `TestModesAndMistakes` | — |
| M7a — a device the helper made carries the overlay both ways, from the renumbered source, is another instance's holding, and goes with its routes; the host's own routes are read and heard | `conn`: `TestAPlumbedDeviceCarriesTheOverlay`, `TestAPlumbedDeviceTakesWhatTheNodeWrites`, `TestAPlumbedRouterKnowsTheHostsRoutes`, `TestTheManagerAsksItsRouterForTheHostsRoutes` | FreeBSD, but for the last |
| M7a — rc.d runs, reports and stops an instance with juistd_args, and the CLI starts, stops and reads instances through rc.conf | `packaging`: `TestTheRCScriptRunsAnInstance`; `cmd/juist`: `TestStoppingAnInstanceDisablesIt`, `TestAnInstanceIsEnabledByRCConf` | FreeBSD, for the first |
| M7a — every test passes on FreeBSD, the CLI's hints in rc.d's words | `make test-freebsd` | FreeBSD |
| M7b — a FreeBSD exit node or router masquerades the overlay, takes overlay sources and its forwarder by the tunnel alone, and puts forwarding and pf back as it found them | `internal/plumber`: `TestServingRules`, `TestServingSetsTheHostUpAndBack` | FreeBSD, for the last |
| M7b — using an exit node on FreeBSD routes the internet into the device behind a guard by juistd's own uid, refusing outlasts the device, and going direct puts all back; the host's DNS goes by resolvconf, on 53 alone | `internal/plumber`: `TestEgressRules`, `TestEgressIsTheDaemonsUser`, `TestEgressSetsTheHostUpAndBack`, `TestDNSGoesByResolvconf`; `daemon`: `TestAHelpersDNSTakesPort53Alone` | FreeBSD, for the last three |
| M7c — the FreeBSD package is the same bytes from each build, its manifests first, every file's sum and mode as pkg checks them | `packaging/freebsd/mkpkg`: `TestPackage` | — |
| M7c — answers to connections that came in by another device leave by it, past the guard, unless isolated; FreeBSD's helper says where the host's own pf rules decide instead | `conn`: `TestTheGuardPassesAnswersButIsolated`; `internal/plumber`: `TestAnswersLeaveTheWayTheyCame`, `TestTheHelperSaysWhereAnswersGo`; `daemon`: `TestAnIsolatedChoiceSendsAnswersThrough`, `TestTheExitChoiceIsKept`; `ipc`: `TestAnExitRequestSetsOneThing`; `make interop` | qemu, for the last |
| M7c — `juist exit use --isolate`, or where the host's own firewall keeps answers in the tunnel, stops where it would end the ssh session it runs in, from the internet, found under sudo too, and `--force` goes on | `cmd/juist`: `TestAnExitNodeFromGrantToOff`, `TestTheSSHSessionIsFoundPastSudo` | — |
| M7c — the packages take the binaries `make build` left, which go finds up to date, and their pages: `make build` then `make install` builds once | `packaging`: `TestTheFreeBSDPackageTakesWhatMakeBuildLeft`, `TestTheFreeBSDPackageBuildsElsewhereBeside` | — |
| M7c — `service juistd clear` takes the devices, anchors and resolvers a juistd left, and puts forwarding and pf back as found | `packaging`: `TestTheRCScriptClearsWhatAJuistdLeft` | FreeBSD |
| M7c — Linux and FreeBSD nodes join one network, reach each other over both families, each is the other's exit node, subnet router and DNS, and both packages go cleanly | `make interop`: `TestLinuxAndFreeBSD` | qemu |
| M7c — resolved's list of every link's servers as resolv.conf is named as the reason DNS goes around the exit node, with the stub as the hint | `daemon`: `TestResolvedsUplinkModeIsSaid`; `cmd/juist`: `TestTheStatusSaysWhereDNSGoes` | — |
| M7c — two builders on two systems make the same binaries for Linux and FreeBSD, and the same package | `make repro-freebsd` | a FreeBSD host |
| M7b — pf rules hold none of the daemon's text, what someone takes of juist's pf is put back, the host's own ruleset must call the anchors first and is left be | `internal/plumber`: `TestServingTakesTheDevicesAddressesAlone`, `TestTheHostsRulesCallTheAnchorsFirst`, `TestPFIsKeptAndLeftBe` | FreeBSD, for the last |
| M6c, M7b — members ask the exit node's DNS on port 53 of its own addresses alone, which reaches the forwarder | `conn`: `TestNetnsExitNodeAnswersDNS`, `TestDNSIsRedirectedToTheForwarder`, `TestTheRouterServesDNSAsAsked`; `daemon`: `TestAnExitNodeAnswersItsMembersDNS` | for the first |
| M10 — the core runs in the app's process, over a pipe, its keys sealed by the platform | `mobile`: `TestACoreKeepsItsKeysSealedAcrossRestarts`; `daemon`: `TestAServiceInProcessAnswersThroughItsPipeAlone`; `internal/keys`: `TestSealedNodeKeysOpenOnlyWithTheirSealer` | no |
| M10 — a VPN device moves to each descriptor established, and serves nothing | `conn`: `TestAVPNDeviceMovesToEachEstablishedDescriptor`, `TestAVPNPlumberRefusesServingAndEgress` | no |
| M10 — the app judges the status as `juist status` does, and reads what the core writes | `mobile`: `TestTheViewJudgesAsJuistStatusDoes`, `TestTheViewIsWhatTheAppReads`; `android/app`: `CoreTest` | no |
| M10 — every socket the core opens on the underlay is protected from the VPN | `internal/underlay`: `TestASocketIsProtectedBeforeItIsUsed`; `discovery/dht`: `TestTheDHTSocketIsProtected`; `discovery/mdns`: `TestTheMulticastSocketIsProtected`; `internal/rendezvous`: `TestTheRendezvousSocketIsProtected`; `internal/guest`: `TestTheDialToTheHostIsProtected`; `relay/forward`: `TestTheDialToTheRelayIsProtected` | no |
| M10 — through an exit node, the VPN routes the internet and its DNS, refused where it cannot be used | `conn`: `TestAVPNRoutesTheInternetToAnExitNodeAndItsDNS`; `daemon`: `TestAVPNsDNSIsThroughWithoutAResolvConf`; `mobile`: `TestTheViewOffersTheExitNodes` | no |
| M10 — a member joining does not establish the VPN again, and a listener Android took down listens again | `conn`: `TestAVPNRoutesTheNetworkWholeAndIsNotEstablishedAgainForAMember`; `daemon`: `TestAListenerTakenDownIsOpenedAgain` | no |
| M10 — a ping through the tunnel | `daemon`: `TestPingAnswersWithTheRoundTrip` | no |
| M10 — `juist invite` draws its link as a QR code, on a terminal alone | `cmd/juist`: `TestTheInviteDrawsItsLinkAsAQRCode`, `TestQRCodeOnlyOnATerminal` | no |
| M10 — the core follows the phone's network outside its own VPN, which Android reports as the app's default once up, and a network lost after another replaced it changes nothing | `android/app`: `UnderlayTest`; the app by hand in an emulator | no |
| M6c — an exit node asks nothing of tailscaled for a member, but the resolvers tailscaled replaced, or resolved's other links | `daemon`: `TestAnExitNodeAsksNothingOfTailscaled` | no |
| M10 — the core's dials into the overlay leave by the VPN device, from its own address, and fail before it is established rather than leave by the LAN | `conn`: `TestAVPNDialLeavesByTheDeviceAlone` | no |
| M10 — the epoch secrets kept beside the node's keys are sealed as they are | `daemon`: `TestKeptSecretsAreSealedAsTheNodesKeys` | no |
| M10 — every screen in both themes, both languages and at 200 % | `make android-check`: the Roborazzi tests against `android/app/screenshots` | no |

### The last privileged run

CI runs on our own machines since 2026-10-03, as `make ci-vm`; GitHub's
workflows, which the account's minutes no longer cover, run by hand alone.
Its first runs, on devvm at M9 with the change that brought it, passed
`make ci` in the VM three times, the 17 privileged tests among them, none
skipped. `make interop` under nested KVM passed every part but the share,
which shared before lx held the role fb had just granted; waiting for it, the
whole lab passed at M9's tree in 13 minutes. What CI cannot run, Fedora with firewalld and Tailscale beside juistd,
was last checked by hand, and this records the latest such run. Update it with
each one, so it is clear how old the evidence is.

- **2026-10-05, at M10, an exit node asking nothing of tailscaled.**
  `make ci-vm CI_MAKE=interop` passed whole in 13 minutes; on edge01, whose
  resolv.conf tailscaled writes, a member's query for a ts.net name is
  answered with its public addresses.
- **2026-10-05, at M10, an exit node whose host's resolver does not ask
  juist's.** `make ci-vm CI_MAKE=interop` passed whole in 13 minutes; on
  edge01, without resolved, a member's query for docs.juist.nning.io is
  answered again.
- **2026-10-05, the app after review.** In an Android 16 emulator the VPN
  turned off and on three times within seconds ends on, the core's log sync
  leaves from the device's overlay address and carries a rename made on the
  partner, and the kept epoch secrets are sealed on the phone. `make
  check`, `make android-check` and `make -C website check` passed.
- **2026-10-05, at M10, an exit node without resolved answering
  members' published names.** `make ci-vm CI_MAKE=interop` passed whole in
  13 minutes.
- **2026-10-04, the app following the phone's network.** In an Android 16
  emulator with an exit node chosen, the core took its own VPN for the
  phone's network, its VPN's underlying network was that VPN, and Wi-Fi
  going and coming told it nothing; with the change it follows the Wi-Fi,
  pauses when it goes and rebinds when it comes, and the member it reached
  directly reaches it directly again. `make check` and `make android-check`
  passed; `make ci-vm` did not run, the change being the app's alone.
- **2026-10-04, the overlay's addresses kept to the tunnel on Linux.** `make
  ci-vm CI_MAKE=test-os-plumbing-sudo` passed the 18 privileged tests, none
  skipped, on this change over M10; the commits it was rebased onto
  touch no Linux router. Over M10 without the change, the new
  `TestNetnsTheLANReachesNoOverlayAddress` failed on all four of its
  checks, the 17 others passing.
- **2026-10-04, at M10, M10's exit node and protected sockets.** `make
  ci-vm` passed `make ci`, its 17 privileged tests none skipped, and `make
  interop` whole, in 26 minutes. The run before it failed in two tests M10
  did not touch, which pass alone under the race detector and repeated:
  `TestARestartedMeshKeepsItsSession` writes a mesh's `startAddrs` while its
  reconcile reads them, a race in the test; and
  `internal/pipe`'s `TestJoinIdlesBothWaysAtOnce` got 19456 bytes.
- **2026-10-04, at M10, M10's core and app.** `make ci-vm` passed `make
  ci` with its 17 privileged tests, none skipped, and `make interop` whole,
  in 25 minutes: the VPN device, the interfaces through netmon and the
  in-process service change nothing a Linux or FreeBSD node does. The app
  itself was tried by hand in an Android 16 emulator (the M10 rows above;
  05-roadmap.md, M10).
- **2026-10-04, M9 closed.** `make ci-vm` on M9's tree, Tailscale
  1.104 and Go 1.27, passed `make ci` with its 17 privileged tests, none
  skipped, and `make interop` whole, Linux and FreeBSD nodes, in 35 minutes.
  On desktop (32 cores, Fedora 44, kernel 7.2.8) it passed again at M9,
  with M9's per-address bound on confined flows, in 22 minutes, the 17
  privileged tests none skipped. `make test-freebsd` on desktop, FreeBSD
  14.5 under KVM, then failed three packages: a spliced connection that
  could not write one way lost the other, as FreeBSD takes a socket shut
  for writing twice down whole, which M9 fixes; and two tests ran
  without what the host has not, extra loopback addresses and the module's
  source, which now skip there. At M9 all 42 packages passed, the
  FreeBSD device's reads on the new TUN interface among them, and `make
  ci-vm CI_MAKE=interop` passed again in 10 minutes.
- **2026-09-30, at M7, M7 review 5.** `make test-os-plumbing-sudo` on the
  Fedora 44 desktop, kernel 7.2.5, beside its running juistd and Tailscale:
  all twenty tests passed and none skipped, the exit node's, refusal's and
  subnet router's among them, with the guard's new answer chains, whose
  `fib` and `ct` rules the kernel took. That answers leave the way they came
  is shown by `make interop`, on Debian's 6.1 kernel, not by these.
- **2026-09-28, at M6.** `make test-os-plumbing-sudo` on the same host,
  kernel 7.2.5, beside its running juistd and Tailscale: all seventeen tests
  passed and none skipped, M6's six netns tests among them, as the first five
  had at M6 earlier that day, when they first ran. The runs before, at M6
  and M6, failed M6 tests in the harness alone (IPv4 forwarding only, a
  tap before the route, a resolver answering from a wildcard socket).
- **2026-09-27, at M5.** `make test-os-plumbing-sudo` ran on a Fedora 44
  Workstation desktop (kernel 7.2.5, iptables 1.8.11 on nf_tables,
  iproute2 6.17), beside a running juistd in a network of four devices and
  beside Tailscale. All eleven tests passed and none skipped: every row marked
  privileged above, including all six cells of the NAT matrix and M5's three
  netns tests, which ran for the first time. Afterwards the host's juistd
  still had all three tunnels up, with its policy rules in place.
- **By hand, 2026-10-03, M9c's listing.** In headless Chrome
  (chromedp): the listing renders light, dark and at 390 px wide, in the
  website's colours and IBM Plex; a click on
  "Download all (.zip)" downloaded the ZIP, which the same page under the
  CSP `sandbox` files have did not, hence the listing's own policy.
- **By hand, 2026-10-03, M9c's background share.** On the Fedora desktop, as
  its user, against the installed juistd: `juist share --background --for 3m`
  returned in 50 ms, piped into `cat` too, leaving a process in a session of
  its own with no terminal; the link fetched from outside through the
  ingress with Let's Encrypt's certificate, 404 without its token, and
  nothing once the process had its SIGTERM.
- **By hand, 2026-10-03, the terminator by its path.** The RPM on the Fedora
  44 VM, SELinux enforcing: upgraded over one whose `juist-serve.service` was
  enabled, it disabled that and enabled `juist-serve.path`, and the
  terminator, restarted, was told it was idle and stopped. A user who is the
  operator and has no sudo shared a file in the background: juistd made
  `/run/juist/serve-wanted`, systemd started the terminator, which listened
  on 443 at the overlay addresses; `juist share --stop` removed the file and
  the terminator stopped within a poll, and a second share started it again.
  Removed, the package left no path unit or link; installed afresh, it
  enabled the path.
- **By hand, 2026-10-03, at M9, M9 review 6.** A live network with a
  public ingress (the deb) and Let's Encrypt as the CA: a name published from
  a Debian member, and a share from a Fedora 44 desktop with firewalld, were
  fetched from outside with certificates Let's Encrypt issued by TLS-ALPN-01
  through the ingress. The share reached nothing at first: the desktop had
  the RPM since before M4, so `juist0` was in no zone, and its default zone,
  FedoraWorkstation, lets in TCP from 1025 alone; the CA's challenge failed
  with it, which autocert reports as "no viable challenge type found".
- **2026-10-03, at M9 review 4.** `make interop` passed under KVM in 10
  minutes, with the ingress's answer wait, the confiner's ICMP and closing
  flows, and the terminator's order guard in it.
- **2026-10-03, at M9 review 4, Fedora.** A Fedora 44 Cloud VM under libvirt
  on desktop, kernel 6.19.10, SELinux enforcing, firewalld and tailscaled
  running. The privileged tests, built here and run there as root: all 23
  passed and none skipped, at M9 and again with this round's confiner.
  The RPM, built there, installed: names resolved through resolved once
  polkit came with it; a share started the terminator cold, which at
  M9 it could not say it did, and again right after it was stopped; the ingress unit bound 80 and 443 and
  added `juist-ingress` to firewalld, and took it back on stop. Removing
  it left the three users and `/var/lib/juist`, nothing else. No SELinux
  denial. Not covered: a public ingress with a real CA.
- **2026-10-03, at M9e and M9 review 3.** `make interop` passed under KVM
  in 11 minutes. fb, renamed to bsd on fb, was resolved on lx by its new
  name at its addresses, and no longer by its old, and two more renames
  under a running ping lost no packet; lx passed another name of the domain
  on to the resolver the host routes example.org to, and its status named
  `interop.juist, pub.example.org`. A single ping just after the rename was
  lost once, unrelated to it, so the step pings until it answers.
- **2026-10-03, at M9d.** `make interop` passed under KVM in 10 minutes, the
  domain itself among it: FreeBSD fetched `https://pub.example.org`, which
  Debian publishes, through itself as the ingress with Pebble's certificate;
  publishing it twice and pointing a name at it were refused; Debian sent
  the domain to juistd, resolved the domain itself and passed another name
  of the domain on upstream, answered in 53 ms.
- **2026-10-03, at M9 review 2.** `make interop` passed under KVM in 10
  minutes. On FreeBSD, root's binder no longer bound over the probe that
  held `*:8443`, and `juist publish add` said another program holds the
  port; once the probe was gone, it ended TLS there. `make test-freebsd`:
  all 38 packages passed, on the VM after an fsck its unclean shutdown
  needed.
- **2026-10-03, at M9c.** `make interop` passed under KVM in 10 minutes,
  the share among it: lx, granted the publish role, shared a directory,
  which a client on the LAN fetched through FreeBSD's ingress with Pebble's
  certificate and not without its token; the ingress dropped the name once
  the share was stopped, and once it was past its `--for`, which ended the
  command too.
- **2026-10-02, at M9b's image.** `make interop JUIST_INTEROP_DOCKER=1`
  passed under KVM in 12 minutes: Debian's docker.io, 20.10.24, ran the
  service member from `make image` beside a service on an internal network,
  and FreeBSD fetched the service's name through itself. That service
  reached neither the LAN nor the overlay, but reached the host's sshd at the
  network's gateway, 172.18.0.1. By hand on the same VM, Docker 29.8.2 from
  its static release, with Debian's runc, since its own wants a time
  namespace the cloud kernel lacks: an internal network reached the host at
  its gateway likewise; one created with
  `-o com.docker.network.bridge.gateway_mode_ipv4=isolated` had no address
  on the host and reached nothing, its containers each other by name still.
- **2026-10-02, at M9 review 1 and FreeBSD's helpers.** `make interop`
  passed under KVM in 9 minutes, after the review's fixes and again with
  FreeBSD's ingress started by `juist ingress serve` from the package,
  running as juist-ingress, and FreeBSD's terminator, as juist-serve,
  taking a certificate from Pebble through it for a name of its own.
  `make test-freebsd`: all 35 packages passed, and the binder's, the drop's
  and the helpers' rc.d tests ran there as root. `make test-acme` passed,
  the CAA record's account among it.
- **2026-10-02, at M9b.** `make interop` passed under KVM in 8 minutes, M9b's
  exit criteria (1) and (4) among it: with Pebble on FreeBSD as the CA and
  FreeBSD the ingress, FreeBSD fetched a name Debian's full member serves and
  one a service member beside it serves, each by a certificate taken by
  TLS-ALPN-01 through the ingress, and reached no other port of the service
  member's. The service member's first runs reached nobody but its own host:
  run without root, netns bound its sockets to the default route's interface.
  `make test-freebsd`: all 35 packages passed.
- **2026-10-02, at M9a.** `make interop` passed under KVM in 6 minutes, the
  ingress among it: Debian, granted the role, served a name FreeBSD
  publishes through the deb's `juist-ingress` unit once FreeBSD's operator
  agreed, redirected HTTP to it, and reached nothing else of FreeBSD's, its
  probe on port 80 included; the withdrawn name reached nothing, and the
  purge left the `juist-ingress` user. Its first runs failed in the harness
  alone: the role granted to a device still an exit node, which the log
  refuses, and the lab's probe on lx's port 80.
- **By hand, 2026-10-02, at M9, M9a.** The ingress from the packages
  in libvirt VMs: the deb on Ubuntu 26.04 with ufw active, then the RPM on
  Fedora 44 Cloud with firewalld and SELinux enforcing, each in a live
  network of three or four. `juist ingress serve` opened 443 and 80 by the
  `juist-ingress` profile, firewalld's runtime and permanent; the ingress
  ran as `juist-ingress` with `cap_net_bind_service` alone (`CapBnd` 0x400,
  `NoNewPrivs` 1). A client outside the network fetched a name with the
  target's own certificate, got a PROXY v2 header with its address where
  the name asks for one and a 308 to https on 80, and nothing for an
  unknown or missing SNI. From the ingress, the target's published ports and
  every member's gossip port answered, nothing else, ICMP and DNS included.
  Names went down with the ingress's juistd and back within 6 s of its
  start; a withdrawn consent or name closed the target's port at once.
  Removing either package stopped the ingress and took its rules back,
  leaving the three users and `/var/lib/juist`, the RPM an empty
  `/usr/lib/juist` too. On Fedora Cloud, which has no polkit, resolved
  refused juistd, and the hint named the package's polkit rule. Not
  covered: a stale ingress, and members reaching a name directly.
- **FreeBSD, 2026-10-02, at M8 review 2.** `make test-freebsd` on FreeBSD 14.5
  in qemu: all 32 packages passed, the helper refusing routes of the host's
  links and resolvers outside the overlay among them.
- **FreeBSD, 2026-09-30, at M7 review 5.** `make test-freebsd` on FreeBSD
  14.5-RELEASE in qemu without KVM, as root: all 31 packages passed, the
  FreeBSD tests of the helper, the split, the device, serving, egress, DNS
  and the rc.d script, `clear` among them; skipped were Linux's plumbing, the
  setup script's, the tests that read the pinned module's source, and those
  that need more than one loopback address. `make interop` passed under TCG
  in 13 minutes, a connection older than the exit node's choice kept on
  both systems, and `make repro-freebsd` found the binaries for both systems
  and the package the same bytes from this Debian 12 container and that VM.
  The review's rc.d, pf and route fixes each failed their test there before.
- **2026-09-30, at M8c.** `make interop` passed under TCG in 12 minutes,
  names among it: Debian's resolved (systemd 252) resolved FreeBSD by name
  and a public name pointed at it only once accepted, through the tunnel,
  never asking the public resolver on its own link for it, and publicly
  again, by that link, while FreeBSD's juistd was stopped and once the name
  was revoked. `make test-freebsd` on FreeBSD 14.5 in qemu: all 32 packages
  passed.
  [Check a FreeBSD node](#check-a-freebsd-node) passed by hand between two
  such VMs on one LAN, serving and using an exit node and the package
  included.
- **By hand, 2026-09-28, at M6:** [Check an exit node](#check-an-exit-node)
  and [Check a subnet router](#check-a-subnet-router) passed with the
  packages on a Debian 12 exit node and router (systemd 252, Docker 29.8, ufw
  off) and a Fedora 44 client (systemd 259, firewalld, Tailscale beside
  juist), in a live network of four. The exit node was on the client's LAN,
  behind the same NAT and without public IPv6; a public Ubuntu 24.04 server
  as the exit node then showed its own addresses to the client, IPv4 and
  IPv6 alike, the client having no IPv6 of its own, and warned of firewalld's
  IPv6 reverse-path filter when strict alone. A client below systemd 256 was
  not tried.
- **Not covered by those runs:** the privilege footprint and two networks on
  one host (below), and what the exit node's hand test leaves out.

## Check the privilege footprint

M3a's third exit criterion is a claim about the *installed* daemon, so it is
checked against the package rather than against a binary in `build/`:

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
ip -br addr show juist0                     # the device, carrying the derived overlay address
systemd-analyze security juistd.service
```

`CapBnd` matters as much as `CapEff`: the effective set alone would still pass
if the bounding set were left wide, and the criterion is that nothing beyond
`CAP_NET_ADMIN` is reachable. A node enrolled without an explicit overlay IPv4
address carries only its derived ULA address on the device, and a network of one
member programs no peer routes — both are the expected picture, not a half-built
device.

## Check two networks on one host

M5's criteria are about the installed services side by side, so they too are
checked against the package. On a host with the package installed and in one
network already, with a second device to invite from:

```sh
juist create lab --yes                # asks for sudo once; says juist1
juist status                        # both, headed juist0 and juist1
systemctl status juistd@juist1      # running, as the juist user
ip -br addr show juist1             # the second network's addresses
ip rule | grep -E '^51[0-9][0-9]'   # 5110 … 5170 and 5111 … 5171
ip route show table 27254           # juist1's routes, and nothing else's
sudo systemctl restart juistd       # juist1's routes and rules stay put
juist reset lab --force            # juist1 goes, with its home
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

M6a and M6c are about two installed packages and a real uplink, so they are
checked by hand as well: an exit node with a public address (a test VM), and
a client behind a LAN running systemd-resolved. On the exit node, after
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

M9 is about a host with a public address, a CA and the internet, so it is
checked by hand as well: an ingress with a public address (a test VM), a
public domain whose `*.DOMAIN` and `DOMAIN` point at it, and a target behind
a LAN. From an admin device:

```sh
juist network domain pub.example.org  # warning: every member then resolves pub.example.org through juistd …
juist grant vps ingress               # hint: on vps, juist ingress serve
juist grant laptop publish            # for juist share
juist publish add nas immich          # on nas's port 443, once nas's operator agrees
```

On the ingress:

```sh
juist ingress serve                   # "serving N names on 443 and 80"
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

M6b likewise: a router on a LAN, 192.168.1.0/24 here, and a client on
another network. After `juist subnet add nas 192.168.1.0/24` from an admin device,
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

M7a is about the split into a helper and a daemon, which a test binary run
as root does not show, so it is checked by hand as well: two FreeBSD hosts on
one LAN, each with the package `make pkg-freebsd` builds:

```sh
pkg add ./juist-*.pkg                         # the juist user: uid 829, or the next free below
sysrc juistd_enable=YES && service juistd start
ps -axo user,pid,ppid,command | grep juistd   # daemon(8), juistd as root, juistd as juist
ifconfig juist0                               # once in a network: mtu 1280, the overlay addresses
juist create lab --device fb1                 # on one; juist invite, and juist join on the other
ping -c3 OTHER-V4; ping6 -c3 OTHER-V6         # through the tunnel, "direct" in juist status
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

The removal says what it keeps: the juist user, `/var/db/juist` with the
device's keys, the logs, and `juistd_` settings in `rc.conf`.

`kill -9` of the root juistd stops the daemon, which reads its helper's end
of a pipe close, and daemon(8) starts both again, the new helper destroying
the device left behind; `kill -9` of the daemon has the helper destroy it at
once, and daemon(8) likewise starts both again.

## Reading a failure in the NAT matrix

The matrix classifies each NAT before it tests anything — one socket, two
reflectors — and logs the mapped ports it saw. A cell that fails on
`is configured as … but maps one socket to …` is a fault in the lab's own
netfilter rules and not in juist. Past that point the nodes log magicsock's
NAT-traversal chatter: `sent ping … (10.77.0.22:41641)` with no matching
`got ping` on the other side means the punch packets are being dropped, and
`learned no address on the lab's LAN` means STUN never answered, so there was
nothing to punch to. In CI the whole log is in the `OS plumbing (privileged)`
job; `gh run view <id> --log-failed` is more readable with the job prefix
stripped:

```sh
gh run view <id> --log-failed | sed 's/.*make test-os-plumbing\t//'
```

## What no test does for you

- **Two real machines on a real LAN.** Everything above runs namespaces or
  loopback. M2's multicast-socket bug was found by running two real daemons and
  by nothing else, because the tests inject a socket
  ([09-mesh-layer-notes.md](09-mesh-layer-notes.md)).
- **The public DHT.** `juistd --verbose` without `--no-dht` bootstraps from the
  public routers and logs `discovered … through the DHT` when rendezvous
  succeeds. This publishes an encrypted blob to a network of strangers and tells
  a passive observer that this host speaks the BitTorrent DHT — residual
  weakness 5 in [02-threat-model.md](02-threat-model.md). Turn it on
  deliberately. The invite rendezvous has one test that uses the real DHT and
  STUN servers, skipped unless asked for:
  `JUIST_PUBLIC_TESTS=1 go test -run PublicDHT -v ./internal/rendezvous`.
- **Upgrades.** Nothing yet tests a network whose members run different builds;
  the schema version exists so that case fails loudly rather than silently, but
  the readiness check that would stop an admin stranding members is M16's
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)). Mixed builds do not
  sync at all across M4, whose gossip frames carry leases older builds reject,
  nor across M5b between two admin devices while either holds waiting
  changes, nor across M6, whose announcements of an exit node, a subnet
  router, an exit node's DNS or a routed device without IPv4 older builds
  reject, and with them the tunnel to it.
- **The freshness TTL on a real clock.** The tests move a fake one. On real
  devices, stopping every admin device for longer than the TTL is what shows the
  other members going down to admin-only tunnels.
