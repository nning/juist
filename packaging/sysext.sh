#!/bin/sh
# Installs juist where /usr is read-only, as on SteamOS: the /usr of an
# unpacked .deb becomes the system extension /var/lib/extensions/juist.raw,
# a squashfs systemd-sysext lays over /usr at every boot. uninstall removes
# it. DESTDIR moves every path, for tests.
#
#   sysext.sh install TREE | uninstall | boot
#
# systemd plans the boot before systemd-sysext brings juist's units, so
# juist-sysext.service, in /etc, runs boot, which starts those enabled.
set -eu
umask 022
r=${DESTDIR:-}
img=$r/var/lib/extensions/juist.raw
self=/usr/lib/juist/sysext.sh
unit=$r/etc/systemd/system/juist-sysext.service
# What SteamOS keeps of /etc across its updates, where juist and its hints write.
keep=$r/etc/atomic-update.conf.d/juist.conf
units="juistd.service juist-serve.path juist-serve.service juist-ingress.service juist-ingress-ports.path"
for i in 1 2 3 4 5 6 7 8 9; do units="$units juistd@juist$i.service"; done

die() {
	echo "juist: $*" >&2
	exit 1
}

# activate merges what is in /var/lib/extensions and has systemd read it.
activate() {
	systemctl enable --quiet systemd-sysext.service
	systemd-sysext refresh
	systemctl daemon-reload
}

install_tree() {
	tree=$1
	[ -x "$tree/usr/bin/juistd" ] || die "$tree holds no unpacked juist"
	fresh=
	[ -e "$img" ] || fresh=1
	stage=$(mktemp -d)
	trap 'rm -rf "$stage"' EXIT
	cp -R "$tree/usr" "$stage/"
	install -d -m 0755 "$stage/usr/lib/extension-release.d"
	# _any: SteamOS changes VERSION_ID with every update and sets no SYSEXT_LEVEL.
	echo ID=_any >"$stage/usr/lib/extension-release.d/extension-release.juist"
	mkdir -p "${img%/*}"
	rm -f "$img.new"
	# What becomes /usr is root's alone, whoever unpacked it: -all-root, and
	# cp copied it under umask 022.
	mksquashfs "$stage" "$img.new" -comp zstd -all-root -noappend -quiet >/dev/null
	mv -f "$img.new" "$img"
	mkdir -p "${unit%/*}"
	printf '%s\n' "# Written by $self." "[Unit]" "Description=Start juist from its system extension" \
		"After=systemd-sysext.service" "ConditionPathExists=$self" "" "[Service]" "Type=oneshot" \
		"ExecStart=$self boot" "" "[Install]" "WantedBy=multi-user.target" >"$unit"
	if [ -d "${keep%/*}" ]; then
		printf '%s\n' /etc/firewalld/zones/trusted.xml /etc/sysctl.d/60-juist-exit.conf \
			/etc/avahi/avahi-daemon.conf >"$keep"
	fi
	activate
	systemctl enable --quiet juist-sysext.service

	lib=$r/usr/lib/juist
	systemd-sysusers "$r/usr/lib/sysusers.d/juist.conf"
	install -d -m 0700 "$r/var/lib/juist"
	chown juist:juist "$r/var/lib/juist"
	# polkit reads juist's rule at its start, before the extension came.
	systemctl try-restart polkit.service
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
	[ -e "$img" ] || die "juist is not installed as a system extension"
	lib=$r/usr/lib/juist
	systemctl disable --now --quiet juistd.service juist-serve.path juist-ingress-ports.path juist-sysext.service || true
	for i in 1 2 3 4 5 6 7 8 9; do
		systemctl disable --now "juistd@juist$i.service" >/dev/null 2>&1 || true
	done
	"$lib/firewall.sh" revoke
	"$lib/ingress.sh" off
	"$lib/serve.sh" off
	"$lib/relay.sh" off
	"$lib/exit-node.sh" off
	"$lib/exit-node.sh" clear
	rm -f "$img" "$img.new" "$keep" "$unit"
	rmdir "${img%/*}" 2>/dev/null || true
	activate
	systemctl try-restart polkit.service
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
	[ $# -eq 2 ] || die "usage: sysext.sh install TREE"
	install_tree "$2"
	;;
uninstall) uninstall ;;
boot)
	for u in $units; do
		! systemctl is-enabled --quiet "$u" || systemctl start --no-block "$u"
	done
	;;
*)
	echo "usage: sysext.sh install TREE | uninstall | boot" >&2
	exit 2
	;;
esac
