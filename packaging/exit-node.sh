#!/bin/sh
# Sets the host up to forward what a juist exit node carries, or undoes that:
# IP forwarding, router advertisements that forwarding would stop the host
# taking, and the firewalls that would drop what is forwarded. juistd itself
# masquerades, in an nftables table of its own; firewalld's trusted zone,
# where firewall.sh puts the device, forwards already.
#
#   exit-node.sh on DEVICE | off [DEVICE] | clear
#
# on adds DEVICE to those the sysctl file is kept for, and the first time
# notes what it changes. off takes DEVICE out; with the last, or without
# DEVICE, as removing the package does, everything goes back as it was.
#
# clear removes the routing rules, tables, guards and masquerade a juistd that
# did not stop cleanly leaves, refusing the internet on purpose; removing the
# package runs it once every juistd has stopped, and so should anyone else.
set -u
conf=/etc/sysctl.d/60-juist-exit.conf
proc=/proc/sys/net
action=${1:-}
device=${2:-}

usage() {
	echo "usage: exit-node.sh on DEVICE | off [DEVICE] | clear" >&2
	exit 2
}
case $action in
on | off) ;;
clear)
	[ -z "$device" ] || usage
	# conn's egress rules, juistd's own at 5180 and the exit table at 5200
	# with the instance added, each only as conn makes it; the exit table,
	# 0x6a75 + 0x100 + the instance; and its nftables tables.
	for i in 0 1 2 3 4 5 6 7 8 9; do
		if command -v ip >/dev/null 2>&1; then
			for fam in -4 -6; do
				while ip $fam rule del pref $((5180 + i)) table main 2>/dev/null; do :; done
				# the host's routes before the exit table, as the first
				# builds of exit nodes had it
				while ip $fam rule del pref $((5190 + i)) table main 2>/dev/null; do :; done
				while ip $fam rule del pref $((5200 + i)) table $((27509 + i)) 2>/dev/null; do :; done
				ip $fam route flush table $((27509 + i)) 2>/dev/null
			done
		fi
		if command -v nft >/dev/null 2>&1; then
			for t in juist$i juist${i}guard juist${i}in; do
				nft delete table ip $t 2>/dev/null
				nft delete table ip6 $t 2>/dev/null
			done
		fi
	done
	exit 0
	;;
*) usage ;;
esac
# Only juist's own devices: the argument reaches ufw and iptables as root.
case $device in
juist[0-9]) ;;
'') [ "$action" = off ] || usage ;;
*)
	echo "exit-node.sh: $device is not a juist device (juist0 to juist9)" >&2
	exit 2
	;;
esac

# The file's comments hold its state: the devices it is kept for, forwarding
# as it was before, and the interfaces whose accept_ra it raised.
field() { sed -n "s/^# $1: *//p" "$conf" 2>/dev/null; }
devices=$(field for)
was=$(field was)
ra=$(field accept_ra)

v6=
[ -d $proc/ipv6 ] && v6=yes

write() {
	{
		echo "# Kept by juist's exit-node.sh; exit-node.sh off removes it."
		echo "# for: $1"
		echo "# was: $was"
		echo "# accept_ra: $ra"
		echo "net.ipv4.ip_forward = 1"
		if [ -n "$v6" ]; then
			echo "net.ipv6.conf.all.forwarding = 1"
			for i in $ra; do
				echo "net.ipv6.conf.$(echo "$i" | tr . /).accept_ra = 2"
			done
		fi
	} >"$conf.tmp" && chmod 0644 "$conf.tmp" && mv "$conf.tmp" "$conf"
}

# ufw and Docker's DOCKER-USER chain drop forwarded traffic by default. Each
# rule is added once and removed whole.
docker_rules() { # iptables-command -I|-D device
	"$1" -n -L DOCKER-USER >/dev/null 2>&1 || return 0
	case $2 in
	-I)
		"$1" -C DOCKER-USER -i "$3" -j ACCEPT 2>/dev/null || "$1" -I DOCKER-USER -i "$3" -j ACCEPT
		"$1" -C DOCKER-USER -o "$3" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
			"$1" -I DOCKER-USER -o "$3" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		;;
	-D)
		while "$1" -D DOCKER-USER -i "$3" -j ACCEPT 2>/dev/null; do :; done
		while "$1" -D DOCKER-USER -o "$3" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
		;;
	esac
}
firewalls() { # -I|-D device
	if command -v ufw >/dev/null 2>&1; then
		if [ "$1" = -I ]; then
			ufw route allow in on "$2" comment 'juist exit node' >/dev/null 2>&1 || true
		else
			ufw route delete allow in on "$2" >/dev/null 2>&1 || true
		fi
	fi
	for ipt in iptables ip6tables; do
		command -v $ipt >/dev/null 2>&1 && docker_rules $ipt "$1" "$2"
	done
	return 0
}

case $action in
on)
	if [ -z "$devices" ]; then
		was="$(cat $proc/ipv4/ip_forward) $(cat $proc/ipv6/conf/all/forwarding 2>/dev/null || echo -)"
		ra=
		if [ -n "$v6" ]; then
			for p in $proc/ipv6/conf/*/accept_ra; do
				i=${p#"$proc/ipv6/conf/"}
				i=${i%/accept_ra}
				# A container's veth takes no router advertisement, and goes with it.
				case $i in all | default | lo | juist[0-9] | veth*) continue ;; esac
				[ "$(cat "$p")" = 1 ] && ra="${ra:+$ra }$i"
			done
		fi
	fi
	case " $devices " in
	*" $device "*) ;;
	*) devices="${devices:+$devices }$device" ;;
	esac
	mkdir -p "${conf%/*}" && write "$devices" || exit 1
	# accept_ra first, so that the host keeps its IPv6 default route.
	for i in $ra; do
		[ -e "$proc/ipv6/conf/$i/accept_ra" ] && echo 2 >"$proc/ipv6/conf/$i/accept_ra"
	done
	echo 1 >$proc/ipv4/ip_forward || exit 1
	if [ -n "$v6" ]; then
		echo 1 >$proc/ipv6/conf/all/forwarding || exit 1
	fi
	firewalls -I "$device"
	;;
off)
	left=
	for d in $devices; do
		[ "$d" = "$device" ] || left="${left:+$left }$d"
	done
	[ -n "$device" ] || left=
	for d in ${device:-juist0 juist1 juist2 juist3 juist4 juist5 juist6 juist7 juist8 juist9}; do
		firewalls -D "$d"
	done
	if [ -n "$left" ]; then
		write "$left"
		exit $?
	fi
	[ -f "$conf" ] || exit 0
	set -- $was
	[ "${1:-}" = 0 ] && echo 0 >$proc/ipv4/ip_forward
	[ "${2:-}" = 0 ] && [ -n "$v6" ] && echo 0 >$proc/ipv6/conf/all/forwarding
	for i in $ra; do
		p=$proc/ipv6/conf/$i/accept_ra
		[ -e "$p" ] && [ "$(cat "$p")" = 2 ] && echo 1 >"$p"
	done
	rm -f "$conf"
	;;
esac
exit 0
