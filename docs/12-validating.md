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
| M5b — a waiting change reaches the other admin device and applies with its vote | `cmd/juist`: `TestAChangeWaitsOnTheOtherAdminDevice`, `TestAnInviteGoesOnWithAVoteFromAnotherAdminDevice`, `TestAnAdmissionGathersVotesWhileItsInviteRuns`, `TestApprovingTheFileCarriesTheSignature`; `gossip`: `TestWaitingChangesReachTheAdminDevices` | no |
| M5b — a copy not from a current admin key, or past the log, is dropped | `daemon`: `TestADaemonHoldsOnlyChangesThatFit`, `TestOneSignerCannotFillTheRoom`; `internal/waiting`: `TestAChangedCopyIsRefused`, `TestASignerLyingAboutItsChangeIsFoundOut` | no |
| M5b — no device without the admin role, nor the one a change is about, receives it | `gossip`: `TestWaitingChangesReachNoOtherDevice`; `daemon`: `TestADaemonHandsChangesToAdminDevicesAlone`, `TestHeldChangesAreSaidToAdminDevicesAlone`; `cmd/juist`: `TestAChangeNeverReachesTheDeviceItIsAbout` | no |
| M5b — nothing is signed unasked | `cmd/juist`: `TestAChangeWaitsOnTheOtherAdminDevice`, `TestAChangeThatExpiresWhileAskedIsNotSigned` | no |
| M5b — a change sealed to its admins opens for no other key | `internal/waiting`: `TestAChangeOpensForItsAdminsAlone`; `trust/secrets`: `TestSealKeyToOpensForItsReaderAlone`; `trust/log`: `TestSetAdminRecipient`, `TestAGenesisRecipientIsSignedForByItsKey` | no |
| M5c — a device moved at once is reached at its new address only, and other transitions run on | `cmd/juist`: `TestAMoveAtOnceReachesEveryDevice`, `TestMovingADeviceAtOnce`, `TestAMoveAtOnceReadsAsOne`, `TestHeldAddressesRead`, `TestStatusNamesTheDevicesNotYetMoved`; `daemon`: `TestAMovedDeviceRestartsOnItsNewAddressAtOnce`; `trust/log`: `TestRenumberNodeAtOnce` | no |

### The last privileged run

No CI job has started since 2026-09-25: the GitHub account's spending limit
ends every run within seconds, so a red run there is no test failure, and
`make check` and `make cross` run locally are the gates meanwhile. The
privileged rows above were therefore last checked by hand, and this records the
latest such run. Update it with each one, so it is clear how old the evidence
is.

- **2026-09-27, at M5.** `make test-os-plumbing-sudo` ran on a Fedora 44
  Workstation desktop (kernel 7.2.5, iptables 1.8.11 on nf_tables,
  iproute2 6.17), beside a running juistd in a network of four devices and
  beside Tailscale. All eleven tests passed and none skipped: every row marked
  privileged above, including all six cells of the NAT matrix and M5's three
  netns tests, which ran for the first time. Afterwards the host's juistd
  still had all three tunnels up, with its policy rules in place.
- **Not covered by that run:** the checks done by hand against the installed
  package, the privilege footprint and two networks on one host (below).

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
  changes.
- **The freshness TTL on a real clock.** The tests move a fake one. On real
  devices, stopping every admin device for longer than the TTL is what shows the
  other members going down to admin-only tunnels.
