#!/bin/sh
# test.sh GO SSH: build every package's tests for FreeBSD with GO, and run
# them over SSH on a FreeBSD host, as root there, the OS plumbing required.
# The host needs no Go; each test runs in its package's directory.
set -eu
go=$1
ssh=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# What git has or would take, nothing it ignores.
git ls-files -co --exclude-standard | while IFS= read -r f; do [ -e "$f" ] && printf '%s\n' "$f"; done |
	tar -cf - -T - | tar -xf - -C "$work"
pkgs=$(GOOS=freebsd GOARCH=amd64 "$go" list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}} {{.Dir}}{{end}}' ./...)
root=$(pwd)
echo "$pkgs" | while read -r pkg dir; do
	[ -n "$pkg" ] || continue
	rel=${dir#"$root"/}
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 "$go" test -c -o "$work/$rel/pkg.test" "$pkg"
done
# A directory of its own there, which no other user can have made first,
# readable, as the tests run their binaries as the juist user too.
there=$(tar -cf - -C "$work" . | $ssh 'd=$(mktemp -d /tmp/juist-test.XXXXXX) && tar -xf - -C "$d" && chmod 755 "$d" && echo "$d"')
$ssh "cd $there"' && failed= &&
	for t in $(find . -name pkg.test | sort); do
		d=${t%/pkg.test}
		if (cd "$d" && JUIST_REQUIRE_OS_PLUMBING=1 ./pkg.test -test.count=1 -test.timeout=20m >test.log 2>&1); then
			echo "ok   $d"
		else
			echo "FAIL $d"; tail -30 "$d/test.log"; failed="$failed $d"
		fi
	done
	cd / && rm -rf '"$there"' && [ -z "$failed" ]'
