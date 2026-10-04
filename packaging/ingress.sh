#!/bin/sh
# Has this host serve as the network's ingress, or no longer: the
# juist-ingress service, and 443 and 80 let through an active firewalld or
# ufw. Only the firewall's own tools are used, so its configuration stays its
# own.
#
#   ingress.sh on | off
set -u
unit=juist-ingress.service

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

case ${1:-} in
on)
	systemctl enable --now --quiet "$unit" || exit 1
	if [ "$firewalld" = running ]; then
		if ! firewall-cmd --add-service=juist-ingress >/dev/null 2>&1 ||
			! firewall-cmd --permanent --add-service=juist-ingress >/dev/null 2>&1; then
			echo "warning: firewalld did not let juist-ingress in" >&2
		fi
	fi
	if [ "$ufw" = active ] && ! ufw allow juist-ingress >/dev/null 2>&1; then
		echo "warning: ufw did not let juist-ingress in" >&2
	fi
	;;
off)
	systemctl disable --now "$unit" >/dev/null 2>&1 || true
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
	;;
*)
	echo "usage: ingress.sh on | off" >&2
	exit 2
	;;
esac
exit 0
