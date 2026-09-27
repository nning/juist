#!/bin/sh
# Lets traffic arriving on a juist device through the host firewall, or takes
# that back. What reaches the device has already passed WireGuard and juist's
# own packet filter, which admits only members and only to this device's
# overlay addresses — the same arrangement Tailscale makes for tailscale0.
# Only the firewall's own tools are used, so its configuration stays its own.
#
#   firewall.sh allow [DEVICE] | revoke [DEVICE] | reload
#
# DEVICE is juist0, the default instance's, or juist1 to juist9, another
# network's instance on this host. allow defaults to juist0. revoke defaults
# to all ten, which is what removing the package means.
#
# reload makes a running firewalld read the service files this package
# installs, which it does only at start and reload: without it,
# "firewall-cmd --add-service=juist" fails until the next one.
#
# allow acts only on a firewall that is running. revoke acts on one that is
# stopped too: a rule left in its saved configuration would come back when
# it starts, for whatever interface is called that by then.
set -u
action=${1:-}
device=${2:-}

if [ "$action" = reload ]; then
	if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		firewall-cmd --reload >/dev/null 2>&1 || true
	fi
	exit 0
fi

case $action in
allow | revoke) ;;
*)
	echo "usage: firewall.sh allow [DEVICE] | revoke [DEVICE] | reload" >&2
	exit 2
	;;
esac

# Only juist's own devices: the argument reaches firewall-cmd and ufw as root.
case $device in
juist[0-9]) devices=$device ;;
'')
	if [ "$action" = allow ]; then
		devices=juist0
	else
		devices="juist0 juist1 juist2 juist3 juist4 juist5 juist6 juist7 juist8 juist9"
	fi
	;;
*)
	echo "firewall.sh: $device is not a juist device (juist0 to juist9)" >&2
	exit 2
	;;
esac

firewalld=
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
	firewalld=running
elif command -v firewall-offline-cmd >/dev/null 2>&1; then
	firewalld=stopped
fi
# ufw edits its rules whether or not it is enabled. Its status line is
# translated, so it is read in the C locale.
ufw=
if command -v ufw >/dev/null 2>&1; then
	ufw=stopped
	if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
		ufw=active
	fi
fi

for dev in $devices; do
	case $firewalld,$action in
	running,allow)
		firewall-cmd --zone=trusted --add-interface="$dev" >/dev/null 2>&1 || true
		firewall-cmd --permanent --zone=trusted --add-interface="$dev" >/dev/null 2>&1 || true
		;;
	running,revoke)
		firewall-cmd --zone=trusted --remove-interface="$dev" >/dev/null 2>&1 || true
		firewall-cmd --permanent --zone=trusted --remove-interface="$dev" >/dev/null 2>&1 || true
		;;
	stopped,revoke)
		firewall-offline-cmd --zone=trusted --remove-interface="$dev" >/dev/null 2>&1 || true
		;;
	esac
	case $ufw,$action in
	active,allow) ufw allow in on "$dev" comment 'juist members' >/dev/null 2>&1 || true ;;
	?*,revoke) ufw delete allow in on "$dev" >/dev/null 2>&1 || true ;;
	esac
done
exit 0
