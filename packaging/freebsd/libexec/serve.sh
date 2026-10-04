#!/bin/sh
# Starts the terminator that ends TLS for the names published on this device,
# at boot too, or stops it.
#
#   serve.sh on | off
set -u
svc=juist_serve
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
	echo "usage: serve.sh on | off" >&2
	exit 2
	;;
esac
exit 0
