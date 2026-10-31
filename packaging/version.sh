#!/bin/sh
# version.sh FORMAT [DIRTY]: this tree's version as FORMAT (go, android,
# rpm-version, rpm-release, deb, freebsd, image) takes it, following the
# version Go stamps into the binaries from the newest tag vX.Y.Z behind HEAD:
# the tag on its own commit, a pre-release of the next patch after it, 0 with
# no tag. DIRTY, the time of a build of a tree with changes, marks one.
set -eu
format=$1 dirty=${2:-}
tag= exact=
if git rev-parse -q --verify HEAD >/dev/null 2>&1; then
	stamp=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S)
	hash=$(git rev-parse --short=12 HEAD)
	short=$(git rev-parse --short HEAD)
	tag=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude 'v*-*' 2>/dev/null || true)
	[ -z "$tag" ] || [ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ] || exact=1
else
	stamp=$(date -u +%Y%m%d%H%M%S) hash=unknown short=unknown
fi
if [ -z "$tag" ]; then
	ver=0
elif [ -n "$exact" ]; then
	ver=${tag#v}
else
	ver=$(echo "${tag#v}" | awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }')
fi
case $format in
go | android)
	if [ -z "$tag" ]; then
		s=v0.0.0-$stamp-$hash
	elif [ -n "$exact" ]; then
		s=v$ver
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
	if [ -n "$exact" ]; then s=1; else s=0.${stamp}git$short; fi
	[ -z "$dirty" ] || s=$s.dirty$dirty
	;;
deb)
	if [ -n "$exact" ]; then s=$ver; else s=$ver~${stamp}git$short; fi
	[ -z "$dirty" ] || s=$s+dirty$dirty
	;;
freebsd | image)
	# pkg sorts "pre" before a release; the epoch puts every version above
	# the 0.<time> of builds before tags.
	if [ -n "$exact" ]; then s=$ver; else s=$ver.pre$stamp; fi
	[ -z "$dirty" ] || s=$s.$dirty
	[ "$format" = image ] || s=$s,1
	;;
*)
	echo "usage: version.sh go|android|rpm-version|rpm-release|deb|freebsd|image [DIRTY]" >&2
	exit 2
	;;
esac
echo "$s"
