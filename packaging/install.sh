#!/bin/sh
# Installs juist from its package repository: adds the repository and its key
# to apt (Debian, Ubuntu), dnf (Fedora) or pkg (FreeBSD), installs juist, and
# on FreeBSD starts it. As root, or with sudo or doas at hand:
#   curl -fsSL https://juist.nning.io/install | sh
# JUIST_REPO names another repository than juist's.
set -eu
repo=${JUIST_REPO:-https://pkg.juist.nning.io/juist}
name=${repo##*/}

die() {
	echo "juist: $*" >&2
	exit 1
}

if [ "$(id -u)" -eq 0 ]; then
	root=
elif command -v sudo >/dev/null 2>&1; then
	root=sudo
elif command -v doas >/dev/null 2>&1; then
	root=doas
else
	die "run it as root"
fi

# get URL FILE: URL into FILE, as root.
get() {
	if command -v curl >/dev/null 2>&1; then
		$root curl -fsSL -o "$2" "$1"
	elif command -v fetch >/dev/null 2>&1; then
		$root fetch -q -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		$root wget -q -O "$2" "$1"
	else
		die "no curl, fetch or wget to download with"
	fi
}

# put FILE: stdin into FILE, as root.
put() {
	$root tee "$1" >/dev/null
}

# Nothing may read the terminal's stdin: under curl | sh it is this script.
case $(uname) in
Linux)
	if command -v apt-get >/dev/null 2>&1; then
		$root install -d -m 755 /etc/apt/keyrings
		get "$repo/key.gpg" "/etc/apt/keyrings/$name.gpg"
		echo "deb [signed-by=/etc/apt/keyrings/$name.gpg] $repo/deb/ ./" | put "/etc/apt/sources.list.d/$name.list"
		$root apt-get update -q </dev/null
		$root env DEBIAN_FRONTEND=noninteractive apt-get install -y -q juist </dev/null
	elif command -v dnf >/dev/null 2>&1; then
		printf '[%s]\nname=%s\nbaseurl=%s/rpm\ngpgcheck=0\nrepo_gpgcheck=1\ngpgkey=%s/key.asc\n' \
			"$name" "$name" "$repo" "$repo" | put "/etc/yum.repos.d/$name.repo"
		$root dnf install -y juist </dev/null
	else
		die "neither apt-get nor dnf here; https://docs.juist.nning.io/en/docs/install/ says how to build juist"
	fi
	;;
FreeBSD)
	$root mkdir -p /usr/local/etc/pkg/repos /usr/local/etc/pkg/keys
	get "$repo/freebsd.pub" "/usr/local/etc/pkg/keys/$name.pub"
	printf '%s: {\n  url: "%s/freebsd/${ABI}",\n  signature_type: "pubkey",\n  pubkey: "/usr/local/etc/pkg/keys/%s.pub"\n}\n' \
		"$name" "$repo" "$name" | put "/usr/local/etc/pkg/repos/$name.conf"
	$root env ASSUME_ALWAYS_YES=yes pkg install -r "$name" juist </dev/null
	$root sysrc juistd_enable=YES >/dev/null
	$root service juistd status >/dev/null 2>&1 || $root service juistd start </dev/null
	;;
*)
	die "$(uname) has no juist package"
	;;
esac
echo "juist installed from $repo"
