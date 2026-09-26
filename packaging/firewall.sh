#!/bin/sh
# Lets traffic arriving on juist0 through the host firewall, or takes that
# back. What reaches juist0 has already passed WireGuard and juist's own
# packet filter, which admits only members and only to this device's overlay
# addresses — the same arrangement Tailscale makes for tailscale0. Only the
# firewall's own tools are used, so its configuration stays its own.
#
#   firewall.sh allow | revoke | reload
#
# reload makes a running firewalld read the service files this package
# installs, which it does only at start and reload: without it,
# "firewall-cmd --add-service=juist" fails until the next one.
#
# allow acts only on a firewall that is running. revoke acts on one that is
# stopped too: a rule left in its saved configuration would come back when
# it starts, for whatever interface is called juist0 by then.
set -u
action=${1:-}

if [ "$action" = reload ]; then
	if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		firewall-cmd --reload >/dev/null 2>&1 || true
	fi
	exit 0
fi

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
	case $action in
	allow)
		firewall-cmd --zone=trusted --add-interface=juist0 >/dev/null 2>&1 || true
		firewall-cmd --permanent --zone=trusted --add-interface=juist0 >/dev/null 2>&1 || true
		;;
	revoke)
		firewall-cmd --zone=trusted --remove-interface=juist0 >/dev/null 2>&1 || true
		firewall-cmd --permanent --zone=trusted --remove-interface=juist0 >/dev/null 2>&1 || true
		;;
	esac
elif [ "$action" = revoke ] && command -v firewall-offline-cmd >/dev/null 2>&1; then
	firewall-offline-cmd --zone=trusted --remove-interface=juist0 >/dev/null 2>&1 || true
fi

# ufw edits its rules whether or not it is enabled. Its status line is
# translated, so it is read in the C locale.
if command -v ufw >/dev/null 2>&1; then
	case $action in
	allow)
		if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
			ufw allow in on juist0 comment 'juist members' >/dev/null 2>&1 || true
		fi
		;;
	revoke) ufw delete allow in on juist0 >/dev/null 2>&1 || true ;;
	esac
fi
exit 0
