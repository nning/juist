#!/bin/sh
# Lets this host's juistd serve its relay on 443/tcp under a public name, or
# no longer: juistd's root helper binds it while this grant, root's, is in
# place. pf, where the host runs it, is the host's: it lets 443 in itself.
#
#   relay.sh on | off
set -u
grant=/usr/local/etc/juist/relay-443
case ${1:-} in
on)
	if [ ! -f "$grant" ]; then
		mkdir -p -m 755 "${grant%/*}" || exit 1
		printf '# juist set --relay-name: juistd binds 443/tcp for its relay.\n' >"$grant.new" &&
			chmod 644 "$grant.new" && mv -f "$grant.new" "$grant" || exit 1
	fi
	;;
off)
	rm -f "$grant"
	rmdir "${grant%/*}" 2>/dev/null
	;;
*)
	echo "usage: relay.sh on | off" >&2
	exit 2
	;;
esac
exit 0
