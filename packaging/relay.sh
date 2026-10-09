#!/bin/sh
# Lets this host's juistd serve its relay on 443/tcp under a public name, or
# no longer: CAP_NET_BIND_SERVICE for juistd.service, by a drop-in, which
# takes a restart, and 443/tcp let through an active firewalld or ufw. Only
# the firewall's own tools are used, so its configuration stays its own.
#
#   relay.sh on | off
set -u
unit=juistd.service
dropin=/etc/systemd/system/juistd.service.d/juist-relay-443.conf
service=juist-relay-443

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

grant='# juist set --relay-name: the relay binds 443/tcp.
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE'

case ${1:-} in
on)
	if [ "$(cat "$dropin" 2>/dev/null)" != "$grant" ]; then
		mkdir -p "${dropin%/*}" || exit 1
		printf '%s\n' "$grant" >"$dropin.new" && mv -f "$dropin.new" "$dropin" || exit 1
		systemctl daemon-reload || exit 1
		# A capability is granted at start alone.
		systemctl try-restart "$unit" || exit 1
	fi
	if [ "$firewalld" = running ]; then
		if ! firewall-cmd --add-service=$service >/dev/null 2>&1 ||
			! firewall-cmd --permanent --add-service=$service >/dev/null 2>&1; then
			echo "warning: firewalld did not let $service in" >&2
		fi
	fi
	if [ "$ufw" = active ] && ! ufw allow $service >/dev/null 2>&1; then
		echo "warning: ufw did not let $service in" >&2
	fi
	;;
off)
	if [ -e "$dropin" ]; then
		rm -f "$dropin"
		rmdir "${dropin%/*}" 2>/dev/null
		systemctl daemon-reload || true
		systemctl try-restart "$unit" || true
	fi
	case $firewalld in
	running)
		firewall-cmd --remove-service=$service >/dev/null 2>&1 || true
		firewall-cmd --permanent --remove-service=$service >/dev/null 2>&1 || true
		;;
	stopped) firewall-offline-cmd --remove-service=$service >/dev/null 2>&1 || true ;;
	esac
	if [ -n "$ufw" ]; then
		ufw delete allow $service >/dev/null 2>&1 || true
	fi
	;;
*)
	echo "usage: relay.sh on | off" >&2
	exit 2
	;;
esac
exit 0
