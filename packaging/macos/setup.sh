#!/bin/sh
# Installs juist on macOS from an unpacked release, or removes it, and
# starts or stops another network's instance, juist1 to juist9:
#   setup.sh install DIR                    DIR holds juist, juistd and this kit
#   setup.sh remove [--keys]                --keys removes this Mac's keys too
#   setup.sh instance start|stop juistN     as juist does for another network
# All as root.
# install.sh runs it; it stays as /Library/juist/setup.sh for removing.
# DESTDIR moves every path, for tests.
set -eu
umask 022
# The system's tools, not what an admin's PATH finds first.
[ -n "${DESTDIR:-}" ] || PATH=/usr/bin:/bin:/usr/sbin:/sbin
r=${DESTDIR:-}
label=io.nning.juist.juistd
plist=/Library/LaunchDaemons/$label.plist
lib=/Library/juist
link=/usr/local/bin/juist

die() {
	echo "juist: $*" >&2
	exit 1
}

[ -n "$r" ] || [ "$(id -u)" -eq 0 ] || die "run it as root"

# freeID is the first ID from 300 that neither a user nor a group has.
freeID() {
	taken=$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{ print $2 }')
	id=300
	while echo "$taken" | grep -qx "$id"; do
		id=$((id + 1))
		[ "$id" -lt 500 ] || die "no free ID below 500 for the $user user"
	done
	echo "$id"
}

# makeUser makes the hidden system user $1, with a group of its own.
makeUser() {
	user=$1
	dscl . -read "/Users/$user" UniqueID >/dev/null 2>&1 && return
	id=$(freeID)
	dscl . -create "/Groups/$user"
	dscl . -create "/Groups/$user" PrimaryGroupID "$id"
	dscl . -create "/Groups/$user" RealName "juist"
	dscl . -create "/Groups/$user" Password "*"
	dscl . -create "/Users/$user"
	dscl . -create "/Users/$user" UniqueID "$id"
	dscl . -create "/Users/$user" PrimaryGroupID "$id"
	dscl . -create "/Users/$user" UserShell /usr/bin/false
	dscl . -create "/Users/$user" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$user" RealName "juist"
	dscl . -create "/Users/$user" Password "*"
	dscl . -create "/Users/$user" IsHidden 1
}

# logFile makes juistd's log $1 root's alone, as it names members and their
# addresses; one launchd makes anew is, by the plist's Umask.
logFile() {
	mkdir -p "$r/var/log"
	[ -f "$r/var/log/$1" ] || : >"$r/var/log/$1"
	chown root:wheel "$r/var/log/$1"
	chmod 0600 "$r/var/log/$1"
}

# ours reports whether $r$link is the link this script makes.
ours() {
	[ -L "$r$link" ] && [ "$(readlink "$r$link")" = "$lib/juist" ]
}

install_kit() {
	src=$1
	for f in juist juistd juistd-launch setup.sh $label.plist; do
		[ -f "$src/$f" ] || die "$src holds no $f"
	done
	if [ -e "$r$link" ] && ! ours; then
		die "$link is not juist's; remove it first"
	fi
	makeUser _juist
	# A juistd its user stopped stays stopped across an update.
	stopped=
	if launchctl print-disabled system 2>/dev/null | grep -Eq "\"$label\" => (disabled|true)"; then
		stopped=1
	fi
	launchctl bootout "system/$label" 2>/dev/null || true
	mkdir -p "$r$lib" "$r/Library/LaunchDaemons" "$r/usr/local/bin"
	for f in juist juistd juistd-launch setup.sh; do
		cp "$src/$f" "$r$lib/$f.new"
		chmod 0755 "$r$lib/$f.new"
		chown root:wheel "$r$lib/$f.new"
		mv -f "$r$lib/$f.new" "$r$lib/$f"
	done
	chown root:wheel "$r$lib"
	chmod 0755 "$r$lib"
	cp "$src/$label.plist" "$r$plist.new"
	chmod 0644 "$r$plist.new"
	chown root:wheel "$r$plist.new"
	mv -f "$r$plist.new" "$r$plist"
	rm -f "$r$link"
	ln -s "$lib/juist" "$r$link"
	logFile juistd.log
	# The other networks' instances run the new juistd too.
	for n in 1 2 3 4 5 6 7 8 9; do
		ip=/Library/LaunchDaemons/$label.juist$n.plist
		[ -e "$r$ip" ] || continue
		instancePlist "juist$n" >"$r$ip.new"
		chmod 0644 "$r$ip.new"
		chown root:wheel "$r$ip.new"
		mv -f "$r$ip.new" "$r$ip"
		logFile "juistd.juist$n.log"
		if launchctl print "system/$label.juist$n" >/dev/null 2>&1; then
			launchctl kickstart -k "system/$label.juist$n"
		fi
	done
	if [ -n "$stopped" ]; then
		echo "juist: juistd stays stopped, as it was"
		return
	fi
	launchctl bootstrap system "$plist"
}

# instancePlist is instance $1's LaunchDaemon.
instancePlist() {
	cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label.$1</string>
	<key>ProgramArguments</key>
	<array>
		<string>$lib/juistd-launch</string>
		<string>$1</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardOutPath</key>
	<string>/var/log/juistd.$1.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/juistd.$1.log</string>
</dict>
</plist>
PLIST
}

start_instance() {
	inst=$1
	[ -x "$r$lib/juistd-launch" ] || die "juist is not installed in $lib"
	makeUser "_$inst"
	p=/Library/LaunchDaemons/$label.$inst.plist
	instancePlist "$inst" >"$r$p.new"
	chmod 0644 "$r$p.new"
	chown root:wheel "$r$p.new"
	mv -f "$r$p.new" "$r$p"
	logFile "juistd.$inst.log"
	launchctl enable "system/$label.$inst"
	if launchctl print "system/$label.$inst" >/dev/null 2>&1; then
		launchctl kickstart "system/$label.$inst"
	else
		launchctl bootstrap system "$p"
	fi
}

# stop_instance stops instance $1 and keeps it stopped: its home and user
# stay, as juist removes the home itself.
stop_instance() {
	launchctl disable "system/$label.$1" 2>/dev/null || true
	launchctl bootout "system/$label.$1" 2>/dev/null || true
	rm -f "$r/Library/LaunchDaemons/$label.$1.plist"
}

remove_kit() {
	for n in 1 2 3 4 5 6 7 8 9; do
		[ ! -e "$r/Library/LaunchDaemons/$label.juist$n.plist" ] || stop_instance "juist$n"
		launchctl enable "system/$label.juist$n" 2>/dev/null || true
	done
	launchctl bootout "system/$label" 2>/dev/null || true
	# Forgets a disable, which launchd keeps past the plist.
	launchctl enable "system/$label" 2>/dev/null || true
	rm -f "$r$plist"
	! ours || rm -f "$r$link"
	# The helper removes its resolver files as it stops; a helper killed
	# leaves them.
	for f in "$r"/etc/resolver/*; do
		[ -f "$f" ] && [ ! -L "$f" ] || continue
		case $(head -n 1 "$f") in "# juistd utun10"[0-9]) rm -f "$f" ;; esac
	done
	# And its pf anchors, its hold on pf and DNS through an exit node.
	for a in $(pfctl -a com.apple -s Anchors 2>/dev/null | sed -n 's#^ *com\.apple/\(juist\.\(daemon_\)\{0,1\}utun10[0-9]\(_[a-z]*\)\{0,1\}\)$#\1#p'); do
		# As the helper flushes one: -F all fails in an anchor, as on FreeBSD.
		pfctl -a "com.apple/$a" -F rules >/dev/null 2>&1 || true
		pfctl -a "com.apple/$a" -F nat >/dev/null 2>&1 || true
		for t in $(pfctl -a "com.apple/$a" -s Tables 2>/dev/null); do
			pfctl -a "com.apple/$a" -t "$t" -T kill >/dev/null 2>&1 || true
		done
	done
	token=$(sed -n 's/^token \([0-9][0-9]*\)$/\1/p' "$r/var/run/juistd.pf" 2>/dev/null || true)
	[ -z "$token" ] || pfctl -X "$token" >/dev/null 2>&1 || true
	for n in 0 1 2 3 4 5 6 7 8 9; do
		printf 'remove State:/Network/Service/juist-utun10%s/DNS\nquit\n' "$n" | scutil >/dev/null 2>&1 || true
	done
	rm -rf "$r$lib" "$r/var/run/juist" "$r"/var/run/juist[1-9] "$r/var/log/juistd.log" "$r"/var/log/juistd.juist[1-9].log
	rm -f "$r"/var/run/juistd.utun10[0-9].lock "$r/var/run/juistd.pf" "$r/var/run/juistd.pf.lock" "$r/var/run/juistd.pf.new"
	if [ "${1:-}" = --keys ]; then
		rm -rf "$r/var/db/juist" "$r"/var/db/juist[1-9]
		for u in _juist _juist1 _juist2 _juist3 _juist4 _juist5 _juist6 _juist7 _juist8 _juist9; do
			dscl . -delete "/Users/$u" >/dev/null 2>&1 || true
			dscl . -delete "/Groups/$u" >/dev/null 2>&1 || true
		done
	elif [ -d "$r/var/db/juist" ]; then
		echo "juist: kept /var/db/juist and /var/db/juistN, this Mac's keys, and the _juist users who own them; setup.sh remove --keys, also from a release's tarball, removes them"
	fi
}

case ${1:-} in
install)
	[ $# -eq 2 ] || die "usage: setup.sh install DIR"
	install_kit "$2"
	;;
instance)
	[ $# -eq 3 ] || die "usage: setup.sh instance start|stop juistN"
	case $3 in juist[1-9]) ;; *) die "no instance $3: juist1 to juist9" ;; esac
	case $2 in
	start) start_instance "$3" ;;
	stop) stop_instance "$3" ;;
	*) die "usage: setup.sh instance start|stop juistN" ;;
	esac
	;;
remove)
	[ $# -le 2 ] && { [ $# -eq 1 ] || [ "$2" = --keys ]; } || die "usage: setup.sh remove [--keys]"
	shift
	remove_kit "$@"
	;;
*)
	die "usage: setup.sh install DIR | remove [--keys] | instance start|stop juistN"
	;;
esac
