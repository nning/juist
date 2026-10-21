# Refactoring proposal, 2026-10-19

What a structural review of `M21` found and is still open. Every package
of work has landed; what remains is held below, what the landed packages
left, and what was weighed and not taken, with the reason a later change has
to answer.

## Held: schema 19 as the floor

Branch `minschema-19` raises `types.MinSchema` to 19 and drops the schema-18
rules (the content fork-choice switch, the rotation guard, gossip's schema
check). It stays off `main` until every live network's log starts past
schema 18: the network "lab" is anchored at a checkpoint at 18. Before it
lands an admin runs `juist log checkpoint` twice, each device holding the
first before the second; every member must be heard at the second with no
alarm before any device compacts, so phones and paused hosts stay online
until then; each device's `juist log` must then start with a checkpoint with
no schema upgrade after it. A log-only admin keystore never compacts and
needs `juist --home DIR reset --force` after the update. The procedure is in
`docs/08-trust-layer-notes.md` on that branch; the website's updating page
takes it in the same commit. Hint paths there are not quoted, which breaks a
copied command for a home with spaces (`cmd/juist/main.go`,
`cmd/juistd/main.go`, as `join.go:126` already does).

## Left from the landed packages

- A first contact that races a restarted peer's warm-up costs one WireGuard
  retry (5 s): the late side could start a handshake once its path is proven.
- juistd follows resolved's routing but not its relaxed single-label rule for
  queries with the DO bit; it refuses there, failing closed.

## Not taken

- **The daemon's status in wire types.** `d.status` is the reconcile's
  derived view, which `juist status` answers whole; an internal type would
  mirror `ipc.Status` field by field.
- **A device factory.** The one type switch in `conn`'s `openDevice` picks
  the kernel, plumbed or VPN device; what each OS router can is held at
  compile time.
- **A `mesh` interface for the service.** It calls some thirty of the
  daemon's methods, and a nil `*Daemon` in an interface is not nil; what it
  still reads of the daemon's fields is set by `New` and not changed after.
- **A `Sidecar` interface in gossip.** Pair keys, waiting changes, leases and
  announcements differ in which frame carries them, what a catch-up leaves
  out and their order against the records; an interface would carry each as
  a flag on the sync path.
- **A structured error from `types.Policy.Validate`.** It would cost the
  core lines it does not have (10987 of 11000), and the parser's messages
  name the line a name was first defined on.
- **One qemu harness.** The CI runner and the lab share `internal/testvm`;
  they network their VMs differently, user-mode and socket, and stay apart.
- **One package manifest.** The .deb and the RPM keep their own lists, held
  to the same files by `packaging/manifest_test.go`.
