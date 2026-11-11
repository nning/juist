export const meta = {
  name: 'milestone-review',
  description: 'One review round of a juist milestone: fresh reviewers per lens, or one for a follow-up, each finding above minor attacked by a skeptic',
  whenToUse: 'A milestone, a part of one, or a previous round\'s fixes need a review round (AGENTS.md, "Reviews")',
  phases: [
    { title: 'Review', detail: 'one fresh reviewer per lens over the diff, one alone for a follow-up' },
    { title: 'Verify', detail: 'a skeptic per finding above minor tries to refute it, with a failing test where it can' },
  ],
}

// args: {
//   milestone: 'M26',            roadmap section to review against
//   repo: '/home/devvm/src/juist-x', a checkout reviewers read, never edit
//   base, head: commits whose diff is under review
//   at: commit findings must still hold at (default head)
//   focus: optional text, e.g. "the fixes of M26 review 1"
//   followUp: true for a round over the previous round's fixes alone: one
//     reviewer for every lens (AGENTS.md, "Reviews")
//   known: optional list of findings already fixed or rejected, with the reason
// }
const a = args || {}
for (const k of ['milestone', 'repo', 'base', 'head']) {
  if (!a[k]) throw new Error(`args.${k} is required`)
}
const at = a.at || a.head
const SEVERITY = 'Severity: critical = a security property lost; high = wrong behaviour a user or attacker hits in normal use; ' +
  'medium = wrong behaviour in a realistic edge case; minor = wording, docs, output layout, a missing test, and everything else, however it reads.'
const known = (a.known || []).map(k => `- ${k}`).join('\n')

const LENSES = [
  {
    key: 'correctness',
    ask: 'logic errors, races and lock ordering, wrong state after an error, leaks, what a restart or an upgrade of one end leaves behind',
  },
  {
    key: 'security',
    model: 'fable',
    ask: 'attacks against what docs/02-threat-model.md defends: a removed or malicious member, a hostile network or relay, a local unprivileged user, a phone that is lost. Fail-open paths, keys or secrets that leave where they belong, privilege that is not dropped, input from outside parsed without bound',
  },
  {
    key: 'platforms',
    ask: 'Linux (Debian and Fedora, SELinux, firewalld), FreeBSD, macOS, Windows and Android: build tags, what one platform does that another silently does not, packages that install, upgrade and remove cleanly, schema and version skew between members',
  },
  {
    key: 'user-facing',
    ask: 'CLI output against AGENTS.md "Output" and "CLI", juist status vs juist health, --help, README and the handbook in website/content (English and German) describing what the code now does, the trademark rules, the app\'s strings in both languages',
  },
  {
    key: 'evidence',
    ask: 'whether the milestone\'s exit criteria in docs/05-roadmap.md are actually met, and whether the tests prove what they claim: a test that would pass with the feature broken, a regression test missing for a fix, a skipped gate reported as passed',
  },
]

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'minor'] },
          file: { type: 'string' },
          line: { type: 'integer' },
          scenario: { type: 'string', description: 'input and state, then the wrong outcome' },
          evidence: { type: 'string', description: 'the code that causes it, quoted with paths' },
          test: { type: 'string', description: 'a test that would fail today, sketched or written' },
        },
        required: ['title', 'severity', 'file', 'scenario', 'evidence'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['confirmed', 'refuted', 'unclear'] },
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'minor'] },
    reason: { type: 'string' },
    poc: { type: 'string', description: 'the test or command run and its output, or why none could be' },
  },
  required: ['verdict', 'severity', 'reason', 'poc'],
}

const context = `You review juist milestone ${a.milestone} as one of several independent reviewers.
Read-only checkout: ${a.repo} (do not edit, commit or check out anything there; other agents use it).
Under review: \`git -C ${a.repo} diff ${a.base} ${a.head}\`, and the code it touches as it is at ${at}.
What it was meant to do: ${a.milestone}'s section in docs/05-roadmap.md; what it must defend: docs/02-threat-model.md.
${a.focus ? `Focus: ${a.focus}\n` : ''}${known ? `Already fixed or rejected, do not report again:\n${known}\n` : ''}`

function reviewPrompt(lens) {
  return `${context}
Your lens: ${lens.ask}.
Stay in your lens; others cover the rest. Read the code, not commit messages or docs about it, as the source of truth.
Report only what you can tie to code: each finding names input and state, the wrong outcome, the lines that cause it, and a test that would fail today.
${SEVERITY}
An empty list is a valid answer. Do not pad it.`
}

function verifyPrompt(lens, f, i) {
  return `${context}
Another reviewer (lens: ${lens.key}) reports this. Try to refute it.

Title: ${f.title}
Severity claimed: ${f.severity}
Where: ${f.file}${f.line ? `:${f.line}` : ''}
Scenario: ${f.scenario}
Evidence: ${f.evidence}
${f.test ? `Suggested test: ${f.test}` : ''}

Check it against the code at ${at}: is the path reachable, is it guarded elsewhere, does the claimed outcome follow? Where a test can show it, write and run one in a worktree of your own:
\`git -C ${a.repo} worktree add --detach ${a.repo}-verify-${lens.key}-${i} ${at}\`, run only the package's tests (\`go test -count=1 ./pkg/...\`), then \`git -C ${a.repo} worktree remove --force ${a.repo}-verify-${lens.key}-${i}\`.
Tests that need root, /dev/net/tun or network namespaces skip here; say so rather than calling them passed.
confirmed = you showed it or traced it beyond doubt; refuted = you found why it cannot happen; unclear otherwise.
Judge the severity yourself. ${SEVERITY}`
}

// A follow-up has one reviewer, every lens its own.
const lenses = a.followUp
  ? [{ key: 'follow-up', ask: LENSES.map(l => l.ask).join('; and ') + '. The diff is the previous round\'s fixes alone: attack them' }]
  : LENSES

const rounds = await pipeline(
  lenses,
  lens => agent(reviewPrompt(lens), {
    label: `review:${lens.key}`, phase: 'Review', schema: FINDINGS, model: lens.model,
  }),
  // Minors go to whoever fixes the round, who confirms them by reading.
  (r, lens) => parallel((r ? r.findings : []).map((f, i) => () => f.severity === 'minor'
    ? Promise.resolve({ lens: lens.key, ...f, minor: true })
    : agent(verifyPrompt(lens, f, i), {
      label: `verify:${lens.key}:${i}`, phase: 'Verify', schema: VERDICT,
    }).then(v => ({ lens: lens.key, ...f, verdict: v })))),
)

const found = rounds.filter(Boolean).flat().filter(Boolean)
const minors = found.filter(f => f.minor)
const all = found.filter(f => !f.minor)
const by = v => all.filter(f => f.verdict && f.verdict.verdict === v)
const unverified = all.filter(f => !f.verdict)
if (unverified.length) log(`${unverified.length} findings lost their verifier`)
const rank = { critical: 0, high: 1, medium: 2, minor: 3 }
const confirmed = by('confirmed').sort((x, y) => rank[x.verdict.severity] - rank[y.verdict.severity])
log(`${confirmed.length} confirmed, ${by('refuted').length} refuted, ${by('unclear').length} unclear, ${minors.length} minor to settle`)
return {
  confirmed,
  minors,
  unclear: by('unclear'),
  refuted: by('refuted'),
  unverified,
  done: !confirmed.some(f => f.verdict.severity !== 'minor'),
}
