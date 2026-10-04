#!/bin/sh
# Has systemd start the terminator, which ends TLS for what this device
# publishes, whenever juistd needs it (juist-serve.path), or stops it for
# good. It listens on juist's own devices alone, which firewall.sh lets in
# already, so no firewall changes.
#
#   serve.sh on | off
set -u
case ${1:-} in
on) systemctl enable --now --quiet juist-serve.path || exit 1 ;;
off) systemctl disable --now juist-serve.path juist-serve.service >/dev/null 2>&1 || true ;;
*)
	echo "usage: serve.sh on | off" >&2
	exit 2
	;;
esac
exit 0
