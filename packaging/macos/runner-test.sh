#!/bin/sh
# runner-test.sh: M29's exit criterion (1) on a Mac with passwordless sudo,
# as GitHub's macOS runners are. Installs the kit built here, joins a network
# whose other member is a netstack juistd on the same Mac, reaches it through
# utun100 by name, checks the guard, and removes everything again.
set -eu
kit=$(pwd)/build/macos-kit/juist
peer=$(mktemp -d)
dump() {
	echo "== diagnostics"
	sudo tail -n 200 /var/log/juistd.log || true
	ifconfig utun100 || true
	netstat -rn | head -n 60 || true
	sudo pfctl -s rules || true
	sudo pfctl -a com.apple/juist.utun100_in -s rules || true
	sudo pfctl -a com.apple/juist.daemon_utun100 -s rules || true
	sudo lsof -nP -iTCP -sTCP:LISTEN -iUDP | grep -i juist || true
	scutil --dns | head -n 60 || true
	ls -l /etc/resolver || true
	tail -n 50 "$peer/invite.log" || true
	tail -n 100 "$peer/peer.log" || true
	juist status || true
	juist --socket "$peer/juistd.sock" status || true
	cat /etc/resolver/ci-net.juist || true
	juist health || true
	sudo pfctl -s info || true
	sudo pfctl -a com.apple/juist.utun100_in -vv -s rules || true
	own6=$(ifconfig utun100 | awk '/inet6 fd/ { print $2; exit }')
	peer6=$(netstat -rn -f inet6 | awk '$NF == "utun100" && $3 ~ /H/ && $1 ~ /^fd/ && $1 != own { print $1; exit }' own="$own6")
	echo "== own $own6, peer $peer6"
	ndp -an || true
	route -n get -inet6 "$peer6" || true
	stats >"$peer/stats.0"
	probe
	stats >"$peer/stats.1"
	echo "== counters the probe moved"
	diff "$peer/stats.0" "$peer/stats.1" || true
	echo "== with checksum offload off"
	sudo sysctl net.link.generic.system.hwcksum_tx=0 net.link.generic.system.hwcksum_rx=0 || true
	stats >"$peer/stats.2"
	probe
	stats >"$peer/stats.3"
	diff "$peer/stats.2" "$peer/stats.3" || true
	sudo pkill tcpdump || true
	echo "== utun100"
	grep -c 'bad .*cksum\|incorrect' "$peer/utun100.txt" || true
	head -n 120 "$peer/utun100.txt" || true
	echo "== lo0"
	head -n 60 "$peer/lo0.txt" || true
}
# stats are the kernel's counters a dropped packet moves.
stats() {
	netstat -s -p ip6 2>/dev/null
	netstat -s -p icmp6 2>/dev/null
	netstat -s -p tcp 2>/dev/null
	netstat -s -p udp 2>/dev/null
}
# probe asks this Mac's own overlay addresses for what members and the
# host's resolver ask them.
probe() {
	own6=$(ifconfig utun100 | awk '/inet6 fd/ { print $2; exit }')
	route -n get -inet6 "$own6" | grep interface || true
	for a in 10.111.0.1 "$own6"; do
		nc -z -G 2 "$a" 41644 && echo "tcp $a 41644 answers" || echo "tcp $a 41644 does not answer"
	done
	dig +time=2 +tries=1 +short @"$own6" peer.ci-net.juist AAAA || true
	dig +time=2 +tries=1 +short @"$own6" mac.ci-net.juist || true
	dscacheutil -q host -a name peer.ci-net.juist || true
	ping -c 1 -t 2 10.111.0.2 >/dev/null && echo "the peer answers ping" || echo "the peer answers no ping"
}
watchdog=
trap 'status=$?; [ -z "$watchdog" ] || kill "$watchdog" 2>/dev/null; [ $status -eq 0 ] || dump; exit $status' EXIT
# Whatever hangs, the run ends with diagnostics.
trap 'echo "runner test: no end in 15 minutes"; exit 124' TERM
# The shell takes TERM once its command ends: the children go too.
(sleep 900 && kill -TERM $$ && pkill -TERM -P $$) >/dev/null 2>&1 &
watchdog=$!

rm -rf "$kit" && mkdir -p "$kit"
# As make macos builds the release's.
CGO_ENABLED=0 go build -trimpath -o "$kit/juist" ./cmd/juist
CGO_ENABLED=0 go build -trimpath -o "$kit/juistd" ./cmd/juistd
cp packaging/macos/setup.sh packaging/macos/juistd-launch packaging/macos/io.nning.juist.juistd.plist \
	README.md LICENSE THIRD_PARTY_LICENSES "$kit/"
sudo sh "$kit/setup.sh" install "$kit"

for _ in $(seq 60); do [ -S /var/run/juist/juistd.sock ] && break; sleep 1; done
juist status
ps -axo user,command | grep '[j]uistd --home' | tee "$peer/ps"
grep -q '^root ' "$peer/ps" && grep -q '^_juist ' "$peer/ps"

# As a user does: the admin key belongs in the user's keystore, not root's.
sudo juist set --operator="$(id -un)"
juist create ci-net --device mac --ipv4 10.111.0.0/24
# -vv checks each packet's checksums.
sudo tcpdump -vvnli utun100 >"$peer/utun100.txt" 2>&1 &
sudo tcpdump -nli lo0 ip6 >"$peer/lo0.txt" 2>&1 &
juist invite ci-net peer --yes --no-dht --no-lan >"$peer/invite.log" 2>&1 &
invite=$!
for _ in $(seq 60); do grep -q "juist join '" "$peer/invite.log" && break; sleep 1; done
link=$(sed -n "s/.*juist join '\(.*\)'.*/\1/p" "$peer/invite.log" | head -n 1)
[ -n "$link" ] || { cat "$peer/invite.log"; exit 1; }
"$kit/juistd" --verbose --home "$peer/home" --socket "$peer/juistd.sock" --port 41700 --gossip-port 41701 \
	--relay-port 41702 --serve status=status-page --join "$link" >"$peer/peer.log" 2>&1 &
sleep 2
kill -0 $! || { echo "the netstack peer did not start"; exit 1; }
# The invite ends once the peer joined; it waits an hour otherwise.
for _ in $(seq 120); do kill -0 "$invite" 2>/dev/null || break; sleep 1; done
if kill -0 "$invite" 2>/dev/null; then
	kill "$invite"
	echo "the peer did not join in two minutes"
	juist --socket "$peer/juistd.sock" status || true
	exit 1
fi
wait "$invite"

# The peer, a service member, has a network stack of its own, which
# answers pings at its overlay addresses; without --serve it has none.
end=$(($(date +%s) + 60))
addr=
while [ "$(date +%s)" -lt "$end" ]; do
	addr=$(dscacheutil -q host -a name peer.ci-net.juist | awk '/ip_address/ { print $2; exit }')
	[ -n "$addr" ] && ping -c 1 -t 2 "$addr" >/dev/null 2>&1 && break
	sleep 1
done
[ -n "$addr" ] || { echo "peer.ci-net.juist did not resolve in a minute"; exit 1; }
echo "peer.ci-net.juist is $addr"
route -n get "$addr" | grep -q 'interface: utun100'
ping -c 3 "$addr"
sudo juist status
# Another network's instance, as juist starts one.
sudo /Library/juist/setup.sh instance start juist1
for _ in $(seq 60); do [ -S /var/run/juist1/juistd.sock ] && break; sleep 1; done
ps -axo user,command | grep -q '^_juist1 .*juistd --home /var/db/juist1'
[ -n "$(sudo pfctl -a com.apple/juist.utun100_in -s rules)" ]
[ -n "$(sudo pfctl -a com.apple/juist.daemon_utun100 -s rules)" ]
for f in /var/log/juistd.log /var/log/juistd.juist1.log; do
	[ "$(stat -f %Lp "$f")" = 600 ] || { echo "$f can be read by others"; exit 1; }
done
# A log launchd opens anew, once deleted, is root's alone too.
sudo rm /var/log/juistd.juist1.log
sudo launchctl kickstart -k system/io.nning.juist.juistd.juist1
for _ in $(seq 30); do [ -e /var/log/juistd.juist1.log ] && break; sleep 1; done
[ "$(stat -f %Lp /var/log/juistd.juist1.log)" = 600 ] || { echo "a log launchd made anew can be read by others"; exit 1; }
sudo pfctl -s info | grep -q 'Status: Enabled'
token=$(sudo sed -n 's/^token //p' /var/run/juistd.pf)
sudo pfctl -s References | grep -qw "$token"

sudo pkill tcpdump || true
sudo /Library/juist/setup.sh remove --keys
for f in /Library/juist /Library/LaunchDaemons/io.nning.juist.juistd.plist /Library/LaunchDaemons/io.nning.juist.juistd.juist1.plist \
	/var/db/juist /var/db/juist1 /usr/local/bin/juist /var/run/juist /var/run/juist1 /var/log/juistd.log /var/log/juistd.juist1.log; do
	[ ! -e "$f" ] || { echo "$f left"; exit 1; }
done
# Not "! cmd": set -e ignores what such a line returns.
for u in _juist _juist1; do
	if dscl . -read "/Users/$u" >/dev/null 2>&1; then echo "$u left"; exit 1; fi
done
if ifconfig utun100 >/dev/null 2>&1; then echo "utun100 left"; exit 1; fi
if pgrep -f 'juistd --home /var/db/juist' >/dev/null; then echo "juistd left running"; exit 1; fi
if grep -rl '^# juistd ' /etc/resolver 2>/dev/null; then echo "resolver files left"; exit 1; fi
if ls /var/run/juistd.* 2>/dev/null; then echo "run files left"; exit 1; fi
if sudo pfctl -s References | grep -qw "$token"; then echo "pf reference $token left"; exit 1; fi
# pf on macOS lists an anchor once named, emptied or not, until a reboot:
# what must go is what juist's anchors hold.
for a in $(sudo pfctl -a com.apple -s Anchors 2>/dev/null | grep 'juist\.' || true); do
	held=$(sudo pfctl -a "$a" -s rules 2>/dev/null; sudo pfctl -a "$a" -s nat 2>/dev/null; sudo pfctl -a "$a" -s Tables 2>/dev/null)
	[ -z "$held" ] || { echo "pf anchor $a still holds: $held"; exit 1; }
done
kill "$watchdog" 2>/dev/null || true
echo "macOS runner test passed"
