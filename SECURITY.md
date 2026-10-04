# Security

## Reporting a vulnerability

Report it privately, through **Report a vulnerability** on the repository's
[Security tab](https://github.com/nning/juist/security), not in a public
issue. Say what an attacker can do, from where, and how to reproduce it.

You get an answer within a week. A fix is released before the details are
published, and you are credited unless you ask not to be.

## What counts

Only the latest release and `main` get fixes.

What juist trusts and what it accepts on purpose is in
[02-threat-model.md](docs/02-threat-model.md). A weakness listed there as
accepted is not a vulnerability, but a way to exploit it further than it says
is.

## State

juist has not had a security audit. Its own checks are an adversarial test
suite for the membership log, fuzz targets for everything it decodes from the
network, tests of real devices in network namespaces, and builds reproducible
from two builders; [12-validating.md](docs/12-validating.md) records when each
last ran.
