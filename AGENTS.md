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

## Gates

`make check` is what CI runs; it must pass before pushing. `make cross` builds
every v1 target platform. `make ci` runs every CI job on the local machine,
the privileged tests last under sudo. Claims about the embedded Tailscale stack are verified
against the pinned module cache, not from memory.

## CLI output

juist speaks like a Unix tool, not a chat: one line per outcome, lowercase,
no trailing period, no ✓. Warnings are `warning: …` and suggestions `hint: …`,
both on stderr; errors are `juist: …` with at most one `hint:` line, or a
`usage:` line for bad arguments. Say what happened, not what to do next unless
it is needed to act; explanations belong in `--help` and `docs/`, and `--help`
text stays a few lines.
