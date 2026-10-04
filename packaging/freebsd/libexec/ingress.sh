#!/bin/sh
# Has this host serve as the network's ingress, or no longer: the
# juist_ingress service, started at boot. pf, where the host runs it, is the
# host's: it lets 443 and 80 in itself.
#
#   ingress.sh on | off
set -u
svc=juist_ingress
case ${1:-} in
on)
	/usr/sbin/sysrc -q ${svc}_enable=YES >/dev/null || exit 1
	/usr/sbin/service $svc status >/dev/null 2>&1 || /usr/sbin/service $svc start >/dev/null || exit 1
	;;
off)
	/usr/sbin/service $svc onestop >/dev/null 2>&1
	/usr/sbin/sysrc -q -x ${svc}_enable >/dev/null 2>&1
	;;
*)
	echo "usage: ingress.sh on | off" >&2
	exit 2
	;;
esac
exit 0
