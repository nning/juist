# Following main on a test host

Builds the deb of `main` whenever code changes there and installs it, so a
test host runs the latest commit without anyone typing sudo. The build runs
as the user `juist-build`, from GitHub; root only installs the result when
it is newer than the installed package. Whoever can push to `main` is root
on such a host within minutes.

As root, from this directory, once per host (Debian or Ubuntu):

```sh
sudo sh setup [GOROOT]
```

GOROOT names a Go to copy when the system's is missing or too old to fetch
the toolchain `go.mod` asks for (Go 1.21 or later can). Without
`~juist-build/.git-credentials`, setup gives juist-build an SSH key and prints
it: add it to nning/juist as a read-only deploy key. The first build takes
a while; `journalctl -fu juist-follow-main` shows it. A build needs about
2.5 GB in `/var/lib/juist-build`. A failed build is not retried until `main`
moves on, or `/var/lib/juist-build/failed` is removed.
