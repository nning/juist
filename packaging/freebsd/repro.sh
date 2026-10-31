#!/bin/sh
# repro.sh GO SSH TOOLCHAIN: build HEAD's juist and juistd for Linux and
# FreeBSD, and the FreeBSD package, here and, from a clone of the same
# commit, on a FreeBSD host over SSH, and fail unless both builders made the
# same bytes. The host needs git and a go, which fetches TOOLCHAIN itself.
#
# repro.sh build GO OUT TOOLCHAIN is what each builder runs in its clone.
set -eu
if [ "$1" = build ]; then
	go=$2
	out=$3
	export GOTOOLCHAIN=$4 CGO_ENABLED=0
	mkdir -p "$out"
	for p in linux/amd64 freebsd/amd64; do
		for c in juist juistd; do
			GOOS=${p%/*} GOARCH=${p#*/} "$go" build -trimpath -o "$out/${p%/*}-${p#*/}-$c" "./cmd/$c"
		done
	done
	version=0.$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S)
	sh packaging/freebsd/pkg.sh "$go" "$out/juist-$version.pkg" "$version" FreeBSD:15:amd64 "$out.bin" >/dev/null
	exit 0
fi
go=$1
ssh=$2
toolchain=$3
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git bundle create -q "$work/head.bundle" HEAD
git clone -q "$work/head.bundle" "$work/src"
(cd "$work/src" && sh packaging/freebsd/repro.sh build "$go" "$work/here" "$toolchain")
$ssh 'command -v git >/dev/null && command -v go >/dev/null' ||
	{ echo "repro: the FreeBSD host needs git and go: pkg install git go" >&2; exit 1; }
# A directory of its own there, which no other user can have made first.
there=$($ssh 'd=$(mktemp -d /tmp/juist-repro.XXXXXX) && cat > "$d/head.bundle" && echo "$d"' < "$work/head.bundle")
$ssh "cd $there && git clone -q head.bundle src && cd src &&
	sh packaging/freebsd/repro.sh build go $there/out $toolchain &&
	cd ../out && sha256 -r *; s=\$?; cd / && rm -rf $there; exit \$s" > "$work/there.sums"
(cd "$work/here" && sha256sum *) | awk '{print $1, $2}' | sort -k2 > "$work/here.sums"
awk '{print $1, $2}' "$work/there.sums" | sort -k2 > "$work/there.sorted"
if ! cmp -s "$work/here.sums" "$work/there.sorted"; then
	echo "repro: the two builders differ:" >&2
	diff "$work/here.sums" "$work/there.sorted" >&2 || true
	exit 1
fi
while read -r sum name; do echo "==> $name the same from both builders: $sum"; done < "$work/here.sums"
