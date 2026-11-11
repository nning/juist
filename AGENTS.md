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

The state of the project lives here too: which milestone is done, what
it was validated with and the sizes `make tcb` reports (`05-roadmap.md`), and the latest run of the gates CI
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

"WireGuard" is Jason A. Donenfeld's registered trademark
([policy](https://www.wireguard.com/trademark-policy/)): name it only to say
what juist uses, with both capitals, never in a name of juist's own (product,
package, command, feature), never its logo, and never as a claim of
compatibility, endorsement or affiliation. Its notice stays in the README,
the website's footer and both man pages. "Tailscale" is Tailscale Inc.'s
registered trademark, and its BSD license forbids the name in promoting
what derives from its code: name it only where the text is about Tailscale
itself (what juist takes from it, the comparison, running beside it), never
to describe or advertise juist ("Tailscale-like"), never its logo; its
notice stays in the README and the footer.
`TestTrademarksAreNamedAsTheirOwnersAsk` checks both marks.

## Landing changes

Work lands directly on `main`, without pull requests. Fetch and rebase onto
`origin/main` before reading code for a change or a review, and again just
before pushing: other agents push to `main` meanwhile. Review rounds are one
commit each, `M<N> review <k>: …`.

A fix for a finding comes with a regression test that fails against the code
before the fix: revert the fix, watch the test fail, restore it. A test that
exists for a scenario is not evidence that the scenario works.

### Reviews

No milestone is done without a review round. Reviewers did not write the
code: fresh agents given the diff since the last `M<N> done`, the
milestone's section of `05-roadmap.md` and `02-threat-model.md`, never the
author's summary. A part that lands on its own is reviewed when it lands;
the closing review covers the whole diff.
`.claude/workflows/milestone-review.js` runs a round.

- One reviewer per area and lens: correctness, security against the threat
  model, failure and restart paths, platforms, CLI output and docs. What the
  threat model names gets an adversarial reviewer, of another model where
  one is available.
- Severity: critical and high are a lost security property or wrong
  behaviour in normal use, medium is wrong behaviour in a realistic edge
  case. Wording, docs, output layout and a missing test are minor, however
  they read.
- A finding names input, state and wrong outcome, a failing test where it
  can. Someone other than its finder confirms it before it is fixed.
- Every confirmed finding is settled in the round's commit, fixed or
  rejected with a reason in its body; none is carried to the roadmap or a
  later round. A minor is fixed where that is cheap, else rejected.
- A fix is the smallest that ends the wrong behaviour: a correction, a
  revert of its cause, or the limit said where users read it. A fix that
  would need new functionality is not made; the limit is said instead.
- A round's fixes get a follow-up round: one fresh reviewer, the fixes'
  diff alone, its minors settled without another round. Where a follow-up
  finds something above minor in the previous follow-up's fix, that fix is
  reverted and the limit said instead, which ends the rounds.
- Rounds end when one confirms nothing above minor; the `M<N> done` commit
  and the roadmap say how many there were.

### Commit messages

A commit message is a subject line of at most 72 characters, a blank line,
and a body wrapped at 72 columns; the `Co-Authored-By:` trailer ends it. The
subject names the change, prefixed as above (`M<N> done` for a milestone's,
which `make publish` and `make previous` look for), with `[skip ci]` at its
end where `12-validating.md` asks for it. The body says what changed and
why, in paragraphs or a list, everything the subject leaves out. A change
too small for a body still keeps its subject short. Commits from
2026-10-12 to 2026-10-30 put all of it into one line: do not copy them.

## Publishing

Work happens in `nning/juist-dev`; the public repository, which `public` in
`private/publish/scrub.txt` names, gets one commit per done milestone and
per fix release. `make publish M=M<N>` builds it in `build/public` from the
milestone's `M<N> done` commit, scrubbed as `scrub.txt` says, and stops on an
address or domain the public tree has not shown; `PUSH=1` publishes it, only
when the user says so. `private/` is never published. An own host, domain or address enters
`scrub.txt` in the commit that brings it.

A release on the public repository starts with the tag `PUSH=1` pushes:
the workflow `release.yml` builds its packages and the app, unsigned, into a
draft release. `make release-public V=0.<N>.<K> NOTES=FILE`, outside working
hours, checks the packages against its own build, signs the app and
`SHA256SUMS`, and publishes the release, not as a pre-release, since the
handbook's download links follow `releases/latest`. Every version `PUSH=1`
tags gets its release the same evening, a fix release too; its notes cover
every tag since the last release. `make release` builds and
signs one here instead, where CI cannot. Its keys live in
`~/.local/share/juist-signing` and never enter the repository or an agent's
context: refer to the files, never print them.

Until v1.0, milestone M<N> is release `v0.<N>.0`, and its fix release
`make publish M=M<N>.<K>` is `v0.<N>.<K>`, from an `M<N>.<K> done` commit or
`AT=` one on a branch off the milestone's; its fixes land on `main` too, or
the next milestone's publish stops. Once pushed, that commit is merged into
`main`, where `git merge-tree` must show it changes no file, so that every
release tag stays behind `main`. `PUSH=1` tags the public commit and the
private one with the version, and the GitHub release takes the tag, titled
`juist 0.<N>.<K>`. Every package's version is `packaging/version.sh`'s, which
follows the highest tag behind the commit as Go's stamp in the binaries does.
Once `M<N> done` is tagged, the next commit on `main` gets the annotated tag
`v0.<N+1>.0-dev`, pushed with it, so that dev builds say `0.<N+1>.0-dev.…`
rather than a patch of the last release; it is never published, and never
on a release's own commit, whose version it would take.

## Gates

`make check` gates every push; it must pass before pushing. `make cross` builds
every v1 target platform; run it whenever a build-tagged file changes, which
`make check` does not compile for other platforms. CI is `make ci-vm`: the
privileged tests and `make check` in a KVM VM it sets up itself, the lab
beside it, then the cross builds, about 18 minutes, logged to `build/ci`; the
first failure ends it. GitHub's workflows run on each push to the public
repository and by hand alone here. Run it whole, in
the background, when a milestone or the review round closing it is done, and
record it in `12-validating.md`; `make ci-vm FAST=1` takes `make check` from
the stamp the last pass left, for the rounds before. A change to what `make
check` skips runs the stage that covers it: devices, routes, firewall or NAT
`make ci-vm STAGES=vm`, packages, units or what passes between hosts `make
ci-vm STAGES=lab`. Say its result, or that it did not run.
A change to a message the lab expects (`grep -rn` its words in `interop/`)
updates the lab in the same commit. `12-validating.md`, "When each gate
runs", has the whole table. Claims about the
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

A done milestone, and a commit that raises `types.CurrentSchema`, is followed
by a new Android app: `make android` and `make android-check` at that commit,
and the release APKs, signed by the release key, published on this
repository as a pre-release tagged `android-schema<N>-<short commit>`. An
app on an older schema stops following any network upgraded past it.

## CLI

Few commands, each clear on its own. Every option has a default that makes it
unnecessary to give, and the important ones can be overridden. No command asks
which network or device is meant: where that is ambiguous it stops and says
what to add. New commands go through the command table and helpers in
`cmd/juist` (`cli.go`, `changes.go`), and are tested through the in-process
app with injected output, never `os.Stdout`.

A command, subcommand or form that is replaced is gone: no alias, no
message naming the old form, no hint for it, no test for it.

### Output

juist speaks like a Unix tool, not a chat: one line per outcome, lowercase,
no trailing period, no ✓. Warnings are `warning: …` and suggestions `hint: …`,
both on stderr; errors are `juist: …` with at most one `hint:` line, or a
`usage:` line for bad arguments: a wrong option, a missing or extra
argument, or a value the command does not take (`a.usageErr`), as a Unix
tool says it: what is wrong in a few words, then the usage, no hint. Say what happened, not what to do next unless
it is needed to act; explanations belong in `--help` and `docs/`, and `--help`
text stays a few lines.

Messages are plain English, worded as a user would say them: the thing,
then what is wrong with it, in the user's words. `name cannot be only
digits`, `name cannot start with a digit`, `--members cannot be used with
--tcp`, `"x" is not a port`. Not, in new or changed messages:

- noun chains and possessives: `a new name's label`, `juist publish's own
  words`;
- literary or inverted turns: `is no more`, `not digits alone`, `where it
  was meant so`, `the name X stops with Y` (say `to stop X: Y`);
- the code's terms where the user's say it: label, target, form.

`juist status` says the state, without errors, warnings or hints: what needs
attention is a warning in `juist health`, and status only counts them and
points there. A status line names what is, never why: `Names` lists the
names, and at most a word or two in brackets for a state chosen on purpose,
as `home.juist (DNS off)`. Reasons, errors (a socket that cannot be bound, a
resolver that refused) and what they mean are `juist health`'s, which may
take a sentence.
