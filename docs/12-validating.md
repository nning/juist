# 12 — Validating it

Every milestone in [05-roadmap.md](05-roadmap.md) has a security exit
criterion, and each one is a test that keeps running after its milestone
closes. The walkthroughs in the [README](../README.md) are the manual loop; this is the gates — how to
run them yourself, and, more importantly, which ones a green run does *not*
cover.

## Three gates, and what each leaves out

```sh
make check                     # what CI gates on; needs no privileges
sudo -E make test-os-plumbing  # real devices, network namespaces, NAT; needs root
make test-freebsd              # every test on a FreeBSD host, as root there
make interop                   # Linux and FreeBSD nodes in qemu, with the packages; no root
make fuzz-long                 # the parser gate: hours per target, never on CI
```

**`make check` silently skips everything that needs privilege.** The real-device
and namespace tests call `t.Skip` when they cannot create a TUN device or a
namespace, so a machine without them reports green while testing none of the OS
plumbing or NAT traversal. That is deliberate — an unprivileged `go test ./...`
has to stay useful — and it is why the privileged tests have a target of their
own, which sets `JUIST_REQUIRE_OS_PLUMBING=1` so a skip there becomes a failure.
If you are checking a claim about devices, routes or NAT, `make check` is not the
command.

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
client reaches it, and must be answered, but not once the client isolates. Last, both packages are removed, leaving
no device, rule or forwarding. It needs qemu, qemu-img, xz and ssh, and no
root: KVM where `/dev/kvm` opens, as in CI's `interop` workflow, TCG
elsewhere, which takes about an hour. The images are fetched into
`INTEROP_CACHE` once and checked against the sums pinned in
`interop/vm_test.go`; `build/interop` keeps the consoles.

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
| M6b (2) — a subnet is reached through its router, a client's own LAN inside it stays its own, and a wider one gives it up, both said | `conn`: `TestNetnsASubnetThroughItsRouter`, `TestARouterServesItsOwnNetworks`; `daemon`: `TestASubnetIsLeftOutWhereItMustBe`, `TestAnExitNodeCarriesNoRoutedSubnet`; `cmd/juist`: `TestASubnetFromGrantToRevoke` | for the first |
| M6b — a route of the host's own inside a subnet is noticed at once, and a Docker network routed is warned of | `conn`: `TestNetnsASubnetThroughItsRouter`; `cmd/juist`: `TestRoutingADockerNetworkIsWarnedOf` | for the first |
| M6b (3) — a withdrawn or stale grant ends routing, on both sides | `daemon`: `TestARouterRoutesWhatItIsGranted`, `TestASubnetIsLeftOutWhereItMustBe/stale`; `cmd/juist`: `TestASubnetFromGrantToRevoke` | no |
| M6b — the operator's and the owner's word are kept and forgotten with the network | `daemon`: `TestTheSubnetWordsAreKept`; `ipc`: `TestASubnetRequestSetsOneThing` | no |
| M6b — no subnet takes another overlay, a VPN's or the host's own routes, nor what a network pushed | `trust/log`: `TestRejectsOverlayOverlappingRoutes`; `conn`: `TestTheHostsOwnRoutes`; `daemon`: `TestARouterWithoutIPv4RoutesNoIPv4`, `TestAPeerWithoutIPv4IsSentNoIPv4`, `TestOnlyARoutedDeviceSaysItHasNoIPv4`; `cmd/juist`: `TestForwardingStaysWhileEitherServes` | no |
| M6c (1) — a member's DNS is answered through its exit node, and not outside the tunnel; no one else is answered | `conn`: `TestNetnsExitNodeAnswersDNS`; `internal/dnsfwd`: `TestAQueryIsForwarded`, `TestOnlyMembersQueriesAreForwarded`, `TestAMemberIsAnsweredAtItsRate`, `TestTheHostsResolvers`; `daemon`: `TestAnExitNodeAnswersItsMembersDNS` | for the first |
| M6c (2) — resolved is pointed at the exit node while one is chosen, refused too, and given back when off | `daemon`: `TestTheHostsDNSGoesThroughTheExitNode`; `internal/resolved`: `TestRouteAndRevert`, `TestADialledClientRoutes`; `packaging`: `TestThePolkitRuleAllowsJuistsDNSAlone` | no |
| M6c (3) — without resolved, or refused by it, nothing is configured and the reason is said | `daemon`: `TestDNSOutsideTheTunnelIsSaid`, `TestDNSAroundResolvedIsSaid`, `TestAFailedDNSRoutingWaits`; `internal/resolved`: `TestWhatResolvedCannotDoIsSaid`; `cmd/juist`: `TestDNSOutsideTheTunnel`, `TestTheStatusSaysWhereDNSGoes` | no |
| M6c — DNS follows the choice whatever the network does, and a stopped daemon leaves it alone | `daemon`: `TestDNSFollowsTheChoiceWhateverTheNetwork`, `TestAClosedDaemonLeavesDNSAlone`; `internal/dnsfwd`: `TestAFailingResolverIsPassedOver`, `TestASourceHoldsFewConnections` | no |
| M6c — an exit node of one family is sent and asked that family alone, and the other is refused at once and said to be | `conn`: `TestNetnsAFamilyNoExitNodeCarriesIsRefused`, `TestTheGuardRefusesWhatNoPeerCarries`, `TestTheRouterLearnsWhatThePeersCarry`; `daemon`: `TestAnExitNodeOfOneFamilyIsSaid`; `cmd/juist`: `TestTheStatusSaysWhereDNSGoes` | for the first |
| M7a — on FreeBSD the daemon runs as juist, and a helper as root plumbs juist's own devices alone, one helper each, addresses of one host and no default route, and neither outlives the other | `internal/plumber`: `TestTheHelperPlumbsWhatItIsAsked`, `TestTheHelperTouchesNothingElse`, `TestAnAddressIsOneHost`, `TestALargeRouteSetGoesWhole`, `TestALateAnswerIsNoOtherCallsAnswer`, `TestADeviceIsOneHelpers`, `TestManyRoutesGoInFast`; `cmd/juistd`: `TestRootSplitsOffTheDaemon`, `TestTheDaemonGoesWithItsHelper`, `TestAHelperThatStopsServingStopsTheDaemon`, `TestRootNeedsAHome`, `TestRootGetsHelp`, `TestTheDaemonGetsNoneOfRootsEnvironment`, `TestAJuistUserOfRootsIsRefused` | FreeBSD, for the last nine |
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

### The last privileged run

No CI job has started since 2026-09-25: the GitHub account's spending limit
ends every run within seconds, so a red run there is no test failure, and
`make check` and `make cross` run locally are the gates meanwhile. The
privileged rows above were therefore last checked by hand, and this records the
latest such run. Update it with each one, so it is clear how old the evidence
is.

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
resolvectl status juist0              # the exit node's overlay addresses at :53, and ~.
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
and `resolvectl status juist0` shows no DNS servers again. `juist status`
saying "systemd-resolved refused juistd" means the package's
`/usr/share/polkit-1/rules.d/60-juist.rules` is not in force. `juist exit
serve --stop` puts forwarding back as it found it, and removing the package
leaves no `/etc/sysctl.d/60-juist-exit.conf`, no `ip rule` from 5180 to 5209
and no `juist0` or `juist0guard` nftables table. Where `serve` reports
forwarding off on Fedora after the script ran, suspect SELinux on
`/etc/sysctl.d` before the script.

## Check a subnet router

M6b likewise: a router on a LAN, 192.168.1.0/24 here, and a client on
another network. After `juist grant nas 192.168.1.0/24` from an admin device,
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
does one with `juist subnet off`. `juist revoke nas 192.168.1.0/24` takes the
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
juist grant fb2 192.168.77.0/24; juist grant fb2 exit   # on the admin device
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
  the readiness check that would stop an admin stranding members is M11's
  ([08-trust-layer-notes.md](08-trust-layer-notes.md)). Mixed builds do not
  sync at all across M4, whose gossip frames carry leases older builds reject,
  nor across M5b between two admin devices while either holds waiting
  changes, nor across M6, whose announcements of an exit node, a subnet
  router, an exit node's DNS or a routed device without IPv4 older builds
  reject, and with them the tunnel to it.
- **The freshness TTL on a real clock.** The tests move a fake one. On real
  devices, stopping every admin device for longer than the TTL is what shows the
  other members going down to admin-only tunnels.
