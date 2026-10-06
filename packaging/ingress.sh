#!/bin/sh
# Has this host serve as the network's ingress, or no longer: the
# juist-ingress service, and 443 and 80 let through an active firewalld or
# ufw. Only the firewall's own tools are used, so its configuration stays its
# own.
#
# The ports names are published on by TCP follow the log: juistd lists them
# in /run/juist/ingress-ports, and juist-ingress-ports.path has "ports" let
# exactly those through while the ingress runs, as its start and stop do
# too: no other program takes a port the firewall lets in. firewalld keeps
# them across reloads and restarts, this script noting which are its own;
# ufw marks them with the comment juist-ingress.
#
#   ingress.sh on | off | ports
set -u
unit=juist-ingress.service
path=juist-ingress-ports.path
ports=/run/juist/ingress-ports
# What this script let through firewalld, and its lock, where only root
# writes.
opened=/var/lib/juist-ingress-ports/opened
lock=/run/juist-ingress-ports.lock

firewalld=
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
	firewalld=running
elif command -v firewall-offline-cmd >/dev/null 2>&1; then
	firewalld=stopped
fi
ufw=
if command -v ufw >/dev/null 2>&1; then
	ufw=stopped
	if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
		ufw=active
	fi
fi

# wanted is the ports juistd lists, one a line, while the ingress runs.
# juistd's file is the juist user's: it is read as a plain file, through no
# link, without waiting on it, and only for ports.
wanted() {
	systemctl is-active --quiet "$unit" 2>/dev/null || return 0
	[ -f "$ports" ] && [ ! -L "$ports" ] || return 0
	timeout 5 dd if="$ports" iflag=nofollow,nonblock bs=65536 count=1 2>/dev/null | grep -E '^[0-9]{1,5}$' |
		awk '$1 > 0 && $1 < 65536 && !($1 >= 41640 && $1 <= 41739) && $1 != 80 && $1 != 443' | sort -nu | head -n 1024
}

# ufw_ours is the ports ufw lets in for the ingress, and ufw_any those it
# lets in by any rule of the same form.
ufw_ours() {
	LC_ALL=C ufw show added 2>/dev/null | sed -n "s|^ufw allow \([0-9][0-9]*\)/tcp comment 'juist-ingress'\$|\1|p"
}
ufw_any() {
	LC_ALL=C ufw show added 2>/dev/null | sed -n "s|^ufw allow \([0-9][0-9]*\)/tcp\( comment .*\)\{0,1\}\$|\1|p"
}

# follow lets exactly the ports in $1 through, and takes back what this
# script let through before and is wanted no longer.
follow() {
	want=$1
	had=$(cat "$opened" 2>/dev/null)
	case $firewalld in
	running)
		install -d -m 0700 "${opened%/*}"
		keep=
		for p in $had; do
			if ! printf '%s\n' "$want" | grep -qx "$p"; then
				firewall-cmd --remove-port="$p/tcp" >/dev/null 2>&1 || true
				firewall-cmd --permanent --remove-port="$p/tcp" >/dev/null 2>&1 || true
				continue
			fi
			keep="$keep $p"
			# Its own: let through again where a reload or someone took it.
			firewall-cmd --query-port="$p/tcp" >/dev/null 2>&1 || firewall-cmd --add-port="$p/tcp" >/dev/null 2>&1 || true
			firewall-cmd --permanent --query-port="$p/tcp" >/dev/null 2>&1 ||
				firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1 || true
		done
		for p in $want; do
			# Open already, and not by this script, it is someone else's.
			if printf '%s\n' $had | grep -qx "$p" || firewall-cmd --query-port="$p/tcp" >/dev/null 2>&1 ||
				firewall-cmd --permanent --query-port="$p/tcp" >/dev/null 2>&1; then
				continue
			fi
			if firewall-cmd --add-port="$p/tcp" >/dev/null 2>&1 &&
				firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1; then
				keep="$keep $p"
			else
				firewall-cmd --remove-port="$p/tcp" >/dev/null 2>&1 || true
				echo "warning: firewalld did not let port $p in" >&2
			fi
		done
		printf '%s\n' $keep | sort -nu | grep . >"$opened.new" || true
		mv -f "$opened.new" "$opened"
		;;
	stopped)
		# Nothing is let through while firewalld is stopped; its own go.
		if [ -z "$want" ]; then
			for p in $had; do
				firewall-offline-cmd --remove-port="$p/tcp" >/dev/null 2>&1 || true
			done
			rm -f "$opened"
		fi
		;;
	esac
	if [ -n "$ufw" ]; then
		had=$(ufw_ours)
		for p in $had; do
			if ! printf '%s\n' "$want" | grep -qx "$p"; then
				ufw delete allow "$p/tcp" >/dev/null 2>&1 || true
			fi
		done
		if [ "$ufw" = active ]; then
			# A rule of someone else's for the port stays theirs.
			any=$(ufw_any)
			for p in $want; do
				if ! printf '%s\n' "$any" | grep -qx "$p" &&
					! ufw allow "$p/tcp" comment juist-ingress >/dev/null 2>&1; then
					echo "warning: ufw did not let port $p in" >&2
				fi
			done
		fi
	fi
}

# steady follows what is wanted until it holds still: juistd may list
# ports anew while the firewall is told, which systemd does not start this
# for again.
steady() {
	# One at a time: what one notes the other reads. Not around systemctl,
	# whose stopping the ingress runs this too.
	exec 9>"$lock"
	flock 9
	# Until juistd says, which it does once its view is fresh, as it was.
	if systemctl is-active --quiet "$unit" 2>/dev/null && { [ ! -f "$ports" ] || [ -L "$ports" ]; }; then
		exec 9>&-
		return
	fi
	for _ in 1 2 3 4 5; do
		want=$(wanted)
		follow "$want"
		[ "$(wanted)" = "$want" ] && break
	done
	exec 9>&-
}

case ${1:-} in
on)
	systemctl enable --now --quiet "$unit" || exit 1
	systemctl enable --now --quiet "$path" || true
	if [ "$firewalld" = running ]; then
		if ! firewall-cmd --add-service=juist-ingress >/dev/null 2>&1 ||
			! firewall-cmd --permanent --add-service=juist-ingress >/dev/null 2>&1; then
			echo "warning: firewalld did not let juist-ingress in" >&2
		fi
	fi
	if [ "$ufw" = active ] && ! ufw allow juist-ingress >/dev/null 2>&1; then
		echo "warning: ufw did not let juist-ingress in" >&2
	fi
	steady
	;;
off)
	systemctl disable --now "$unit" "$path" >/dev/null 2>&1 || true
	case $firewalld in
	running)
		firewall-cmd --remove-service=juist-ingress >/dev/null 2>&1 || true
		firewall-cmd --permanent --remove-service=juist-ingress >/dev/null 2>&1 || true
		;;
	stopped) firewall-offline-cmd --remove-service=juist-ingress >/dev/null 2>&1 || true ;;
	esac
	if [ -n "$ufw" ]; then
		ufw delete allow juist-ingress >/dev/null 2>&1 || true
	fi
	steady
	[ -s "$opened" ] || rm -rf "${opened%/*}"
	;;
ports)
	steady
	;;
*)
	echo "usage: ingress.sh on | off | ports" >&2
	exit 2
	;;
esac
exit 0
