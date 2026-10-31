#!/bin/sh
# instances.sh move: an upgrade's one step for the other networks' juistd
# instances, which kept their homes in the default's, /var/lib/juist/juistN,
# as the juist user. Each moves to /var/lib/juistN, as the user juistN, so
# that one network's daemon reads none of another's keys. An instance that
# runs is stopped for it and started again. Root acts here in a directory
# the juist user could write, so nothing is followed that is a link.
set -u

state=${JUIST_STATE:-/var/lib}
from=${JUIST_USER:-juist}

case ${1:-} in
move) ;;
*)
	echo "usage: instances.sh move" >&2
	exit 64
	;;
esac

systemd=
[ -d /run/systemd/system ] && systemd=1

for n in 1 2 3 4 5 6 7 8 9; do
	old=$state/juist/juist$n
	new=$state/juist$n
	[ -d "$old" ] && [ ! -L "$old" ] || continue
	unit=juistd@juist$n.service
	running=
	if [ -n "$systemd" ] && systemctl is-active --quiet "$unit" 2>/dev/null; then
		running=1
		systemctl stop "$unit" || true
	fi
	# Stopping runs the new unit's ExecStopPost, for which systemd makes
	# the new, empty StateDirectory.
	[ -d "$new" ] && [ ! -L "$new" ] && rmdir "$new" 2>/dev/null
	if [ -e "$new" ] || [ -L "$new" ]; then
		echo "juist: $old and $new both exist; instance $n keeps $new, $old is left" >&2
	elif ! mv -T "$old" "$new"; then
		:
	elif [ -L "$new" ] || [ ! -d "$new" ]; then
		# Swapped by the juist user since it was looked at; where it is now,
		# only root changes it, and root's chown and chmod follow a link.
		rm -f "$new"
		echo "juist: $old was no directory once moved; instance $n has no home" >&2
	else
		# The juist user is shut out first, then juistN given what was that
		# user's alone: a hard link it planted to another's file keeps its
		# owner.
		chown root:root "$new"
		chmod 0700 "$new"
		find "$new" -mindepth 1 -user "$from" -exec chown -h "juist$n:juist$n" {} +
		chown "juist$n:juist$n" "$new"
		echo "juist: instance $n's home is $new now"
	fi
	if [ -n "$running" ]; then
		systemctl start "$unit" || true
	fi
done
exit 0
