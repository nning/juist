#!/bin/sh
# version.sh FORMAT [DIRTY]: this tree's version as FORMAT (go, android,
# rpm-version, rpm-release, deb, freebsd, image) takes it, following the
# version Go stamps into the binaries from the highest tag vX.Y.Z or
# vX.Y.Z-dev behind HEAD: the tag on its own commit, a pre-release of the
# next patch after a release's, of X.Y.Z itself after a -dev one, 0 with no
# tag. DIRTY, the time of a build of a tree with changes, marks one.
set -eu
format=$1 dirty=${2:-}
tag= exact=
if git rev-parse -q --verify HEAD >/dev/null 2>&1; then
	stamp=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S)
	hash=$(git rev-parse --short=12 HEAD)
	short=$(git rev-parse --short HEAD)
	# A -dev tag sorts below the release of its version.
	tag=$(git tag --merged HEAD --list 'v[0-9]*.[0-9]*.[0-9]*' |
		awk '/^v[0-9]+\.[0-9]+\.[0-9]+(-dev)?$/ { split(substr($0, 2), v, /[.-]/); print v[1], v[2], v[3], (v[4] == "dev" ? 0 : 1), $0 }' |
		sort -n -k1,1 -k2,2 -k3,3 -k4,4 | tail -n 1 | cut -d' ' -f5)
	[ -z "$tag" ] || [ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ] || exact=1
else
	stamp=$(date -u +%Y%m%d%H%M%S) hash=unknown short=unknown
fi
dev=
case $tag in *-dev) dev=1 ;; esac
if [ -z "$tag" ]; then
	ver=0
elif [ -n "$exact" ] || [ -n "$dev" ]; then
	ver=${tag#v}
	ver=${ver%-dev}
else
	ver=$(echo "${tag#v}" | awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }')
fi
# Packages take a -dev tag's own commit as a build after it.
release=$exact
[ -z "$dev" ] || release=
case $format in
go | android)
	if [ -z "$tag" ]; then
		s=v0.0.0-$stamp-$hash
	elif [ -n "$exact" ]; then
		s=$tag
	elif [ -n "$dev" ]; then
		s=$tag.0.$stamp-$hash
	else
		s=v$ver-0.$stamp-$hash
	fi
	[ -z "$dirty" ] || s=$s+dirty
	[ "$format" = go ] || s=${s#v}
	;;
rpm-version)
	s=$ver
	;;
rpm-release)
	if [ -n "$release" ]; then s=1; else s=0.${stamp}git$short; fi
	[ -z "$dirty" ] || s=$s.dirty$dirty
	;;
deb)
	if [ -n "$release" ]; then s=$ver; else s=$ver~${stamp}git$short; fi
	[ -z "$dirty" ] || s=$s+dirty$dirty
	;;
freebsd | image)
	# pkg sorts "pre" before a release; the epoch puts every version above
	# the 0.<time> of builds before tags.
	if [ -n "$release" ]; then s=$ver; else s=$ver.pre$stamp; fi
	[ -z "$dirty" ] || s=$s.$dirty
	[ "$format" = image ] || s=$s,1
	;;
*)
	echo "usage: version.sh go|android|rpm-version|rpm-release|deb|freebsd|image [DIRTY]" >&2
	exit 2
	;;
esac
echo "$s"
