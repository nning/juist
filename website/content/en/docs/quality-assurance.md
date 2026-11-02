---
title: Quality assurance and security
linkTitle: Quality assurance
description: How juist checks agent-written code, what the tests establish, and where the evidence stops.
lead: juist is developed with AI agents. Confidence in it rests on inspectable code, tests and recorded validation, not on who wrote it. It has not had a human security audit.
---

## What agentic development means here

juist is developed with AI agents, using Opus 5.5. Agents write code and
tests and review changes. That origin is disclosed in the README so that
you can take it into account before installing a VPN on your devices.

A model can misunderstand a requirement and write a test that repeats the
same mistake. Another review by a model can miss it too. Passing tests are
evidence for the cases they exercise, not proof that the implementation or
its security design is correct. Agentic development does not lower the
project's requirements, but neither does automation establish that they
have all been met.

## What is checked

The repository makes its checks available to readers and contributors:

| Check | What it establishes, and its limit |
|---|---|
| `make check` | Formatting, static analysis, dependency-file consistency, builds, race tests, core size and reproducible builds. Without the required privileges and host facilities, networking tests are skipped. |
| Adversarial and property tests | Rejection of forged signatures, insufficient quorums, replays and rollback; convergence and unchanged state after refused records. These cover explicit attacks and generated cases. |
| `make ci-vm` | Privileged Linux networking, a lab with installed packages, Linux/FreeBSD interoperability, cross builds and a dependency vulnerability scan. This exercises devices, routes, NAT and package lifecycles beyond in-process tests. |
| Fuzz targets | Parsers and validators receive generated malformed input. A short smoke run and a long campaign provide different amounts of evidence; having a target is not evidence that a long run happened. |
| Regression tests | A fix for a finding must include a test observed failing with the fix reverted, then passing with it restored. This checks that the test detects the defect. |

`make check` is required before a push. Slower gates are selected according
to the affected behavior, and the full VM run is required before a release.
Long fuzz campaigns run separately from CI. The documented long-run evidence
currently covers one QUIC parser target, not every input surface.

A skipped test is not a pass. Real TUN devices and network namespaces need
privileges; a successful unprivileged test run says nothing about those
checks. Cross-compilation alone does not establish that a platform works.
Hand tests supplement the lab for real networks, phones and installed
packages.

## Security is part of the design

The [security overview]({{< relref "docs/security" >}}) describes the trust
boundaries: devices verify the signed membership log themselves, admin keys
stay out of the daemon, and access rules are enforced by the receiving
device. It also explains what remains trusted and the limits of revocation,
key custody and discovery privacy.

The repository identifies the security-sensitive code in an explicit [audit
scope](https://github.com/nning/juist/blob/main/audit-scope). `make tcb` checks that packages are classified and limits the size of
the trust core. A smaller core helps review; a line count is no security
certificate. Established cryptographic primitives do not by themselves
validate juist's protocols or the code connecting them.

Release checksums are signed, and reproducibility checks compare builds.
These help establish which artifact you received and how it was built;
they do not establish that its code is safe. See
[installing and verifying a download]({{< relref "docs/install" >}}).

## Evidence you can inspect

The source repository contains the
[threat model](https://github.com/nning/juist/blob/main/docs/02-threat-model.md),
[verification strategy](https://github.com/nning/juist/blob/main/docs/06-verification.md)
and [validation instructions and recorded runs](https://github.com/nning/juist/blob/main/docs/12-validating.md).
They describe the tested properties, remaining gaps and the revision and
environment of recorded runs. Read results against the version you use;
a pass on one revision does not certify every later change.

## Is that enough for your use?

juist has not had a security audit. Model reviews, automated tests and use on
real devices are useful evidence, but do not replace an independent human
security audit. They cannot exclude unknown vulnerabilities or shared
mistakes in the implementation, tests and documentation.

The basis for evaluating juist is therefore concrete but limited: inspectable
source, repeatable checks, documented trust boundaries and explicit gaps.
Whether that is enough depends on what your network protects and the
consequences of a failure. If your use requires independently audited
software, juist does not meet that requirement.

Report a suspected vulnerability privately through the
[repository's Security tab](https://github.com/nning/juist/security).
