# Working in this repository

## Comments

Comments are brief or absent. Only these earn a place, each in as few words as
will do:

- the contract of an exported symbol — one line, two only if a caller cannot
  use it without the second (Go convention);
- an invariant or ordering requirement a caller must honour;
- a warning about a failure mode that is silent or misleading;
- one short sentence of *why*, where a choice is genuinely non-obvious.

Everything else goes: paragraphs of rationale, war stories about how a bug was
found, measurement narratives, milestone references, restatements of what the
code plainly says, and comments that only repeat the symbol's name. Prefer a
clearer name over a comment explaining an unclear one. Git holds the history;
the comment holds the rule.

A multi-paragraph comment is a smell. If a rule needs that much room it belongs
in `docs/`, with at most a one-line pointer at the code. When a finding
produces a rule the project must keep following, write the rule in one
sentence, not the story that produced it.

## Planning documents (`docs/`)

They hold plans: what is intended, what is still open, and the constraints a
future decision has to respect. They are not a changelog. Findings that have
been fixed do not belong there — record a constraint only while it still binds a
decision that has not been made yet.

Milestones still to come carry whole numbers, no letters: a new one takes
its place in the order, those after it move up, and every reference in the
repository moves with them. Done milestones keep their names.

The state of the project lives here too: which milestone is done and what
it was validated with (`05-roadmap.md`), and the latest run of the gates CI
cannot run (`12-validating.md`, "The last privileged run"). Record it in the
same commit as the work, not only in an agent's own notes.

## User documentation

A change a user can notice (a command, flag, default, output line, port,
platform or limit) updates, in the same commit, every place that describes
it: the README, `--help`, and the handbook in `website/content`, English and
German alike. A new feature gets its page or section and its row in
`website/data/features.yaml`. The website says what juist does now: no
milestones, plans or work in progress, except the comparison matrix's
"planned" mark. Grep `website/` for the command or
term to find each page, and run `make -C website check`.

## Landing changes

Work lands directly on `main`, without pull requests. Fetch and rebase onto
`origin/main` before reading code for a change or a review, and again just
before pushing: other agents push to `main` meanwhile. Review rounds are one
commit each, `M<N> review <k>: …`.

A fix for a finding comes with a regression test that fails against the code
before the fix: revert the fix, watch the test fail, restore it. A test that
exists for a scenario is not evidence that the scenario works.

## Gates

`make check` gates every push; it must pass before pushing. `make cross` builds
every v1 target platform; run it whenever a build-tagged file changes, which
`make check` does not compile for other platforms. CI is `make ci-vm`: `make
ci` and `make interop` in a KVM VM it sets up itself, about 25 minutes, logged
to `build/ci`; GitHub's workflows run by hand alone. Run it whole, in the
background, when a milestone or the review round closing it is done, and
record it in `12-validating.md`. A change to what `make check` skips runs the
part that covers it: devices, routes, firewall or NAT `make ci-vm
CI_MAKE=test-os-plumbing-sudo`, packages, units or what passes between hosts
`make ci-vm CI_MAKE=interop`. Say its result, or that it did not run.
`12-validating.md`, "When each gate runs", has the whole table. Claims about the
embedded Tailscale stack are verified against the pinned module cache
(`~/go/pkg/mod/tailscale.com@<version>`), not from memory.

The real-device and netns tests (`conn/osplumbing_test.go`,
`conn/netns*_linux_test.go`) skip without root, `/dev/net/tun` and network
namespaces, as in a container. A skip is not a pass: say which gates did not
run. They are safe to run beside a juistd in a network. Each round of these
tests on another machine is expensive, so a change to the harness carries the
diagnostic that would answer the next question as well.

## Hand tests and packaging

Recipes for hand tests target Fedora as well as Debian: `dnf`, firewalld, and
SELinux as a suspect where file capabilities do not take. Anything tested by
installing it is tested as the package, and the package removes cleanly; what
it leaves on purpose (the `juist` user, the keys in `/var/lib/juist`) is said.
A host running tailscaled is a normal test host; what juist must not share
with it is in `07-embedding-notes.md`, "Sharing a host with tailscaled".

## CLI

Few commands, each clear on its own. Every option has a default that makes it
unnecessary to give, and the important ones can be overridden. No command asks
which network or device is meant: where that is ambiguous it stops and says
what to add. New commands go through the command table and helpers in
`cmd/juist` (`cli.go`, `changes.go`), and are tested through the in-process
app with injected output, never `os.Stdout`.

### Output

juist speaks like a Unix tool, not a chat: one line per outcome, lowercase,
no trailing period, no ✓. Warnings are `warning: …` and suggestions `hint: …`,
both on stderr; errors are `juist: …` with at most one `hint:` line, or a
`usage:` line for bad arguments. Say what happened, not what to do next unless
it is needed to act; explanations belong in `--help` and `docs/`, and `--help`
text stays a few lines.
