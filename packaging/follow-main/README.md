# Following main on a test host

Builds the package of `main`, the deb or FreeBSD's, whenever code changes
there and installs it, so a test host runs the latest commit without anyone
typing sudo. The build runs as the user `juist-build`, from GitHub; root only
installs the result when it is newer than the installed package. Whoever can
push to `main` is root on such a host within minutes.

As root, from this directory, once per host (Debian, Ubuntu or FreeBSD):

```sh
sudo [JUIST_REPO=URL] sh setup [GOROOT]
```

GOROOT names a Go to copy when the system's is missing or too old to fetch
the toolchain `go.mod` asks for (Go 1.21 or later can). JUIST_REPO names
another repository to follow than `https://github.com/nning/juist.git`; it is
kept in `~juist-build/repo`.
Without `~juist-build/.git-credentials`, setup gives juist-build an SSH key
and prints it: add it to a private repository as a read-only deploy key. The first build takes
a while; `journalctl -fu juist-follow-main` shows it, on FreeBSD
`/var/log/juist-follow-main.log`. A build needs about 2.5 GB in
`~juist-build`, which is `/var/lib/juist-build`, on FreeBSD
`/var/db/juist-build`. A failed build is not retried until `main` moves on,
or `~juist-build/failed` is removed.

On FreeBSD, cron starts it every minute (`/etc/cron.d/juist-follow-main`),
the build runs at idle priority, and an upgrade restarts the juistd
instances, the ingress and the terminator that were running.
