#!/bin/sh
# Installs juist on a systemd host no package of it serves, from the tree
# make stage-systemd builds, as the RPM would; uninstall removes it again.
# The files it installed are listed in /usr/lib/juist/files, the directories
# it made in /usr/lib/juist/dirs. DESTDIR moves every path, for tests.
set -eu
umask 022
r=${DESTDIR:-}
lib=$r/usr/lib/juist
self=/usr/lib/juist/manual-install.sh

die() {
	echo "juist: $*" >&2
	exit 1
}

install_tree() {
	stage=$1
	[ -x "$stage/usr/bin/juistd" ] || die "$stage holds no staged juist; make stage-systemd builds it"
	fresh=
	if [ ! -f "$lib/files" ]; then
		fresh=1
		for f in /usr/bin/juist /usr/bin/juistd; do
			[ ! -e "$r$f" ] || die "$f is not from make install; remove the juist installed otherwise first"
		done
	fi
	old=$(cat "$lib/files" 2>/dev/null || true)
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	(cd "$stage" && find . ! -type d | sed 's/^\.//' | LC_ALL=C sort) >"$tmp/files"
	while read -r f; do
		d=${f%/*}
		made=
		while [ -n "$d" ] && [ ! -d "$r$d" ]; do
			made="$d
$made"
			d=${d%/*}
		done
		for d in $made; do
			mkdir -m 0755 "$r$d"
			echo "$d" >>"$tmp/dirs"
		done
		# A rename, so a running juistd keeps its binary and no reader sees half a file.
		m=0644
		[ ! -x "$stage$f" ] || m=0755
		install -m "$m" "$stage$f" "$r$f.new"
		mv -f "$r$f.new" "$r$f"
	done <"$tmp/files"
	echo "$old" | while read -r f; do
		[ -z "$f" ] || grep -qxF "$f" "$tmp/files" || rm -f "$r$f"
	done
	cat "$lib/dirs" "$tmp/dirs" 2>/dev/null | LC_ALL=C sort -u >"$tmp/alldirs" || true
	cp "$tmp/alldirs" "$lib/dirs"
	cp "$tmp/files" "$lib/files"

	systemd-sysusers "$r/usr/lib/sysusers.d/juist.conf"
	install -d -m 0700 "$r/var/lib/juist"
	chown juist:juist "$r/var/lib/juist"
	systemctl daemon-reload
	"$lib/firewall.sh" reload
	if [ -n "$fresh" ]; then
		"$lib/firewall.sh" allow
		systemctl enable --now --quiet juistd.service
		systemctl enable --now --quiet juist-serve.path
		echo "hint: sudo $self uninstall removes juist again" >&2
	else
		"$lib/instances.sh" move
		set --
		for i in 1 2 3 4 5 6 7 8 9; do set -- "$@" "juistd@juist$i.service"; done
		systemctl try-restart juistd.service juist-ingress.service juist-serve.service "$@"
	fi
}

uninstall() {
	[ -f "$lib/files" ] || die "juist was not installed by make install"
	systemctl disable --now --quiet juistd.service || true
	for i in 1 2 3 4 5 6 7 8 9; do
		systemctl disable --now "juistd@juist$i.service" >/dev/null 2>&1 || true
	done
	"$lib/firewall.sh" revoke
	"$lib/ingress.sh" off
	"$lib/serve.sh" off
	"$lib/relay.sh" off
	"$lib/exit-node.sh" off
	"$lib/exit-node.sh" clear
	dirs=$(cat "$lib/dirs" 2>/dev/null || true)
	while read -r f; do rm -f "$r$f"; done <"$lib/files"
	rm -f "$lib/files" "$lib/dirs"
	# Deepest first, and only what is empty: a file of another's stays.
	echo "$dirs" | awk '{ print length($0) "\t" $0 }' | LC_ALL=C sort -rn | cut -f2- | while read -r d; do
		[ -z "$d" ] || rmdir "$r$d" 2>/dev/null || true
	done
	systemctl daemon-reload
	if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		firewall-cmd --reload >/dev/null 2>&1 || true
	fi
	for d in "$r/var/lib/juist" "$r"/var/lib/juist[1-9] "$r/var/lib/juist-serve"; do
		[ -d "$d" ] && [ ! -L "$d" ] || continue
		case $d in
		*/juist-serve) echo "juist: kept /var/lib/juist-serve, the terminator's ACME account, which CAA records may name" >&2 ;;
		*/juist) rmdir "$d" 2>/dev/null || echo "juist: kept /var/lib/juist, which still holds this device's keys and log" >&2 ;;
		*) rmdir "$d" 2>/dev/null || echo "juist: kept ${d#"$r"}, which still holds a network's keys and log" >&2 ;;
		esac
	done
}

case ${1:-} in
install)
	[ $# -eq 2 ] || die "usage: manual-install.sh install STAGE"
	install_tree "$2"
	;;
uninstall) uninstall ;;
*)
	echo "usage: manual-install.sh install STAGE | uninstall" >&2
	exit 2
	;;
esac
