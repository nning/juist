---
title: Formal verification
linkTitle: Formal verification
description: Which of juist's protocols and rules are checked by machine against an attacker, what holds, what the models find, and where they stop.
lead: juist's own protocols and the rules of its membership log are written as formal models and checked by machine, with ProVerif and TLA+. The models check the design, for small networks; they do not prove the code correct.
---

## Why model at all

juist builds on established cryptography: WireGuard, X25519, ML-KEM-768,
ML-DSA-44, SPAKE2. How it combines them is its own: joining a network, the
keys each pair of devices shares, how devices choose between changes made at
the same time. A flaw there is a flaw in the design, and a test of the code
finds it only if someone thought of the case.

A model states the design and the attacker precisely, and a tool then tries
everything the attacker can do, or every order in which messages can arrive.
The models have found flaws in the design this way. Those that are fixed have
a test each that fails without the fix; those that are not are
[listed below](#what-the-models-find).

## The tools

- **[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/)** 2.05, for
  the protocols. The attacker controls the network: it reads, drops, replays
  and sends messages built from everything it knows, across any number of
  sessions. The cryptography is taken as perfect. ProVerif proves secrecy,
  that a side accepts only what the other side really sent, that a code
  resists offline guessing, and that an attacker cannot tell two situations
  apart.
- **[TLA+](https://lamport.azurewebsites.net/tla/tla.html)**, checked by
  TLC 1.8.0, for the rules that decide state. TLC visits every state the
  model can reach within its bounds: every order of delivery, every message
  lost or repeated.

## What is modelled

| Model | Code | Attacker | What holds |
|---|---|---|---|
| Joining (`enroll*.pv`) | `trust/enroll` | the network, active throughout; later, a quantum computer | An invite code cannot be guessed offline, and online costs the invite its one guess. What the new device receives stays secret while either SPAKE2 or ML-KEM-768 holds. Both sides agree on what was said, and only the keys whose words the admin compared are admitted. |
| Pair keys (`pairkey*.pv`) | `internal/pairkey` | the network, and a third member holding the group secret | No one but the two devices learns their key, and both agree on key and epoch before either uses it. |
| Pair key exchange (`PairKey.tla`) | `internal/pairkey` | the network, dropping, repeating and reordering every message; epoch changes, resets of a device's store | The key the follower uses is one the leader tries; two sides on one generation derived the same key; an old message moves no key back; no generation is used twice. |
| Catching up on missed keys (`catchup.pv`) | `gossip` | the network, and a removed device holding every key it ever had | Keys go only to a listed member that proved itself for this request; the removed device gets nothing. |
| Changes waiting for votes (`waiting.pv`) | `internal/waiting` | the network and every daemon, admin devices' included | A waiting change opens only for the admin keys it is sealed to, and only as its signer proposed it. |
| Meeting an inviting device (`relay.pv`) | `relay/forward`, `internal/rendezvous` | the network, a relay of the attacker's, the DHT's nodes | The link's secret stays with the two devices; a relay takes a registration only from the member that made it; the new device dials only the addresses the inviting device published, which stay sealed. |
| Replacing an outdated log (`rebase.pv`) | `internal/guest`, `trust/log` | the inviting daemon, the network, and a removed admin the device still trusts | A device replaces its log only by a chain that the admin named in the link checked and admitted it to. |
| The membership log (`Log.tla`) | `trust/log` | the network, delivering any change in any order or not at all; a compromised admin below the quorum; a removed admin | Every change on a chain has its quorum; no device trusts a state below the epoch floor; a removed key undoes no removal, also for people holding several keys and for copies of one change. Devices that hear the same changes hold the same head, or all alarm, as long as none compacts. |
| Freshness (`Freshness.tla`) | `trust/log` | the network, keeping a removal from a member; up to M − 1 lying vouchers; clocks that differ | A member cut off from a removal refuses the removed device at the latest once its lease has run out and twice the clock difference has passed. |

Each model file names its attacker and its simplifications in its first
lines, in [`models/`](https://github.com/nning/juist/tree/main/models).

## What the models find

ProVerif and TLC also find attacks. These are known limits of juist as it is,
recorded as expected outcomes, so that the run fails if one disappears
unnoticed or a new one appears:

- **No forward secrecy for pair keys.** Whoever records a pair's traffic and
  later steals both devices learns their pair key. With a quantum computer,
  which breaks WireGuard's own handshake, that opens the recorded traffic.
- **A waiting change can be guessed.** A daemon that carries a waiting change
  that holds no new group secret, such as removing an admin key, can tell
  which change it is by trying each candidate.
- **A restored pairs file can cut a tunnel.** A device whose pairs file is
  restored from an older copy can hold a key its peer has moved past, until
  the file is removed.
- **Compaction can split devices.** A change made below a checkpoint is
  refused by devices that compacted and taken by those that did not. The two
  then hold different members, and neither alarms.
- **A raised quorum can be undone.** Admins who together had the quorum
  before a change raised it can sign a removal at the same point in the log
  and redraw it until theirs wins, undoing the raise and what followed it.

The [threat model](https://github.com/nning/juist/blob/main/docs/02-threat-model.md)
lists the first four among its residual weaknesses, with what limits them.

## How the models stay tied to the code

A model checks what it states, not what the code does. Three things connect
the two, and `make check` runs them on every push:

- Each protocol model names the labels and fields the code uses, in order.
  A test fails where the code's differ from the model's.
- TLC writes traces of the log and the pair key exchange: what each device
  should hold after each step. Tests replay them against `trust/log` and
  `internal/pairkey`, and fail where the code holds something else.
- Each protocol has a model of an honest run, which ProVerif must find, so
  that a proof does not hold only because nothing ever happens.

## Where they stop

- The cryptography is taken as perfect. The models do not show that SPAKE2
  and ML-KEM-768 are strong enough, or that their combination is, and they
  do not see timing.
- Signatures and encryption are simplified: Ed25519 and ML-DSA count as one
  signature, X25519 and ML-KEM-768 as one encryption. A flaw that needs one
  half broken is not seen.
- TLC checks small networks: two devices, three admin keys, at most three
  changes, and for the pair key three generations across two epochs. Changes
  that alter a person's votes, schema upgrades, disabling a member and
  identity rotation are not in the log's model.
- WireGuard is not modelled; it has published proofs of its own. Nor are
  juist's encryption helpers, standard constructions read in review.
- The models are run by hand, not on CI: all of them take about three hours
  on four cores. The last run, its revision and its tool versions are in
  [12-validating.md](https://github.com/nning/juist/blob/main/docs/12-validating.md).

A proof about a model is evidence about the design, not about every line of
the code, and it does not replace a security audit. See
[Quality assurance]({{< relref "docs/quality-assurance" >}}).

## Running them yourself

With ProVerif 2.05, a JDK and TLC's `tla2tools.jar` 1.8.0:

```sh
make models TLA2TOOLS=/path/to/tla2tools.jar
```

It runs every model and fails where an outcome is not the one
`models/expected` holds. `make model-traces` writes the traces the tests
replay anew.
