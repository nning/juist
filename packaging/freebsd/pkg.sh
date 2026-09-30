#!/bin/sh
# pkg.sh GO OUT VERSION ABI BUILDDIR: build the FreeBSD package OUT for ABI,
# as FreeBSD:14:amd64, from this tree, on any system and to the same bytes.
# The binaries are built in BUILDDIR where they run here, as "make build"
# leaves them, and in BUILDDIR/freebsd-GOARCH elsewhere; go relinks neither
# while it is up to date.
set -eu
go=$1
out=$2
version=$3
abi=$4
builddir=$5
case ${abi##*:} in
amd64) goarch=amd64 ;;
aarch64) goarch=arm64 ;;
*) echo "pkg.sh: no GOARCH for $abi" >&2; exit 1 ;;
esac
bin=$builddir/freebsd-$goarch
native=
if [ "$("$go" env GOOS)/$("$go" env GOARCH)" = "freebsd/$goarch" ]; then
	bin=$builddir
	native=1
fi
mkdir -p "$bin"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for c in juist juistd; do
	GOOS=freebsd GOARCH=$goarch CGO_ENABLED=0 "$go" build -trimpath -o "$bin/$c" "./cmd/$c"
done
# The pages FreeBSD's binaries write: theirs where they run, else the same
# rendered by the freebsdman tag, with the binary's version, which go run
# stamps only where told to.
for c in juist.1 juistd.8; do
	if [ -n "$native" ]; then
		"$bin/${c%.*}" __manpage > "$work/$c"
	else
		vcs=
		"$go" version -m "$bin/${c%.*}" | grep -q 'vcs=' && vcs=-buildvcs=true
		"$go" run $vcs -tags freebsdman "./cmd/${c%.*}" __manpage > "$work/$c"
	fi
done
p=/usr/local
mkdir -p "$(dirname "$out")"
"$go" run ./packaging/freebsd/mkpkg -manifest packaging/freebsd/manifest.json \
	-scripts packaging/freebsd/scripts -version "$version" -abi "$abi" \
	-mtime "$(git log -1 --format=%ct)" -o "$out" \
	$p/bin/juist="$bin/juist" \
	$p/sbin/juistd="$bin/juistd" \
	$p/etc/rc.d/juistd=packaging/freebsd/juistd \
	$p/etc/newsyslog.conf.d/juistd.conf=packaging/freebsd/newsyslog.conf \
	$p/share/man/man1/juist.1.gz="$work/juist.1" \
	$p/share/man/man8/juistd.8.gz="$work/juistd.8" \
	$p/share/doc/juist/README.md=README.md \
	$p/share/bash-completion/completions/juist=packaging/completions/juist.bash \
	$p/share/zsh/site-functions/_juist=packaging/completions/_juist \
	$p/share/fish/vendor_completions.d/juist.fish=packaging/completions/juist.fish
echo "$out"
