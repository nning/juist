# 14 — Website

A documentation site for users, beside these planning documents: what juist
does, feature by feature, how it is designed, and what it trades. English and
German from the start, built statically and published through juist itself.

## Decided

- **Hugo**, pinned in `website/go.mod` as a tool and run with the
  repository's `GOTOOLCHAIN`. v0.165.0 is the last release that builds with
  Go 1.26; v0.166 needs 1.27, so Hugo moves with the toolchain.
- **A theme of its own:** a paper chart by day, a night chart by night,
  around a chart of Juist on the home page. Plain CSS, two small scripts and
  no inline script, so a strict CSP holds; no request leaves the site, fonts
  included (IBM Plex, OFL, in `static/fonts`). The fonts are IBM's files,
  unchanged: the OFL reserves the name Plex for them, so a subset of our own
  would need another name. The site loads IBM's variable fonts, Latin1 and
  Latin2, one file each for every weight; the pages juist serves itself carry
  the three static weights they use.
- **Languages:** `content/en` and `content/de`, with the same slugs, so the
  switcher and links stay stable; CLI output stays English on every page.
- **Two parts.** The home page is one page: what juist is, its rules, a
  first network, the features, publishing in short, every trade-off, and the
  status. *Documentation* is the handbook, a page per task in the order of
  `data/nav.yaml`; its sidebar lists only pages that exist.
- **Handbook pages** follow one shape: what it is, how to (steps, each on a
  named device), good to know, if something goes wrong.
- **Trade-offs** take each residual weakness from
  [02-threat-model.md](02-threat-model.md) as what happens, why it is accepted
  and what moves it; this is M24's documentation of the acceptances.
- **Writing.** Every command, flag, default and output line is checked
  against the README, the commands' help or the code, and left out if it
  cannot be. Each juist term is explained where a page first uses it. Short
  sentences in the second person ("du" in German), no slogans, metaphors or
  em dashes; commands and output stay English on German pages. German pages
  say what the English ones say in idiomatic German, not sentence by
  sentence in English word order.
- **The current state only.** Pages say what juist does today; no
  milestones, plans, or work in progress, and nothing promised for a later
  version. The one exception is the comparison matrix's "planned" mark.
- **Hosting:** the image serves plain HTTP on a member's `127.0.0.1`,
  published with `juist publish add NAME 127.0.0.1:PORT` through an
  ingress on a VPS of its own; TLS ends at `juist-serve`. The apex of a
  domain needs M9d. A service member in front of it is the stricter form,
  once it has a recipe for a container.
- **Following main:** `website/deploy` builds the site on a member whenever
  `website/` or `design/` changed on `main`, as the user that builds the
  deb there, and serves it on `127.0.0.1:8181` with a `DynamicUser`; it is
  pulled, not pushed, because `[skip ci]` would stop a CI deploy. Each
  instance builds from a repository of its own; a preview of unpublished
  work is served with `-noindex`.
- **Under load:** the site is published with `--http2` and its server
  takes h2c, so a browser holds one connection rather than six of the
  ingress's 16384 slots (256 per address, 1024 per /24); the server closes a
  quiet one after 10 s and sends text as Brotli, zstd or gzip, whichever is
  smallest. `make load-lab` loads it along the published path and fails
  where a visitor is lost.
- The home page's chart is drawn from OpenStreetMap's outline of Juist
  (`data/juist_outline.json`), which ODbL requires the footer to credit.

## Shared with the Android app

M10 wants a theme of its own as tokens, light and dark. The website and the
app take it from one place, `design/`:

- `tokens.json` holds the colours by Material 3 role for day and night, the
  status colours of a member's reach and of an alarm, the chart's colours and
  the fonts. The website renders it into CSS variables (`css/tokens.css`);
  the app generates its Compose `ColorScheme` from the same file. Text and its
  background meet WCAG AA in both themes.
- The status colours mean the same in both: direct, relay, sought, absent,
  alarm. The website uses them for nothing else.
- `logo/wordmark.svg` is "juist" in IBM Plex Mono SemiBold, its two tittles
  joined as two linked nodes. `logo/icon.svg` is the same for a square, "jı"
  with the link, and works down to 16 px; `icon-mono.svg` is the themed
  launcher icon. The glyph outlines are taken from the font, so the logo
  changes only with it.
- IBM Plex is shipped with the app too. The small monospace labels the
  website uses do not scale to 200 %, so they stay out of the app's tokens.
- The app's screenshot tests render every screen in both themes and both
  languages; the website's Android pages take their pictures from them, and
  the invite page shows the words to compare as the app does.

## Phases

- **W0 — the look.** Done on the branch `website`: the home page, the
  features section, *Publishing services* and *Trade-offs*, in both
  languages, both palettes, desktop and phone, checked in headless Chrome;
  the tokens and the logo in `design/`.
- **W1 — the frame.** Built: `website/Containerfile`, an image of the pages
  and `website/server` from scratch, as an unprivileged user, every answer
  with the CSP and no listing, and a line for each on stderr: host, path,
  status, bytes, referrer and User-Agent, the client's address being the
  terminator's; `make -C website check` fails on inline
  script or style, which that CSP refuses; `website/compose.yml` builds and
  runs it on `127.0.0.1:8181`, read-only and without capabilities, with
  `docker compose up -d`. Still to come: the root Makefile's targets and a
  CI job.
- **W2 — the handbook.** Eighteen pages on the branch, from how juist works
  to troubleshooting, in both languages, each command and flag checked
  against the commands' help; still to come, the command reference generated
  as `__manpage` is.
- **W3 — design and security.** Begun: *Architecture*, *Compared with
  others* and *Security* under *Design* in the sidebar; the comparison takes
  its facts from [research/project-survey.md](research/project-survey.md),
  rechecked against each project's sources; the architecture page explains the layers,
  zero trust and where juist falls short of it, and what WireGuard and
  Tailscale contribute, with sources. Still to come: every trade-off,
  cryptography, diagrams drawn at build time.
- **W4 — search and staleness.** Pagefind; a check that every page exists in
  both languages and that a translation is not older than its source.

## Open

- **The site on the ingress's own host** for a launch, where its member sits
  behind a home line or reaches the ingress through a relay.
- **The source language**, which the other follows and the staleness check
  measures against.
- **The domain**, and an imprint if the site is published under a
  person's or a company's name.
- **`baseURL`**: `hreflang` and canonical links need the absolute one.
- **The generators** of the chart and the logo are Python and a throwaway
  Go program; whether they become Go in the tree, since their output is
  committed.
- **`[skip ci]`** skips every workflow: a website job in CI must not depend
  on a commit that carries it.
- **What the handbook could not say**, because neither the README nor the
  help does: how to get the source and what a build needs; uninstalling and
  what stays; running a service member in a container; how to learn the
  ACME account for a CAA record, which juist does not print yet; FreeBSD's
  daemon log, its instances and running without the DHT and STUN.
