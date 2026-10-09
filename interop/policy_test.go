//go:build interop && linux

package interop

import (
	"strings"
	"testing"
	"time"
)

// accessPolicy has east and west, devices in namespaces on lx, kept apart by
// a policy: they exchange no packet and learn no address of each other's,
// east opens on lx the port passed alone, and west uses lx as its exit node
// where east is refused.
func accessPolicy(t *testing.T, fb, lx *vm, lx4 string) {
	east := walled{name: "east", ns: "east", dev: "ea", net: "10.86.0", home: "/tmp/east", sock: "/tmp/east/juistd.sock"}
	west := walled{name: "west", ns: "west", dev: "we", net: "10.87.0", home: "/tmp/west", sock: "/tmp/west/juistd.sock"}
	t.Cleanup(func() {
		if t.Failed() {
			for _, w := range []walled{east, west} {
				out, _ := lx.try(w.juist("status")+"; "+w.juist("devices")+"; tail -40 "+w.home+"/juistd.log", time.Minute)
				t.Logf("%s:\n%s", w.name, out)
			}
			out, _ := fb.try("juist policy; juist status", time.Minute)
			t.Logf("fb:\n%s", out)
			hold(t, fb, lx)
		}
		// What follows runs as without a policy.
		lx.try("juist exit serve --stop", 3*time.Minute)
		fb.try(`printf 'pass from any to { any, internet, `+fbSide.subnet+` }\n' > /tmp/open.conf
juist policy set --yes /tmp/open.conf; juist remove east --yes; juist remove west --yes; juist revoke lx exit --yes`,
			3*time.Minute)
		lx.try(`pkill -f '[j]uistd --home /tmp/east'; pkill -f '[j]uistd --home /tmp/west'
pkill -f '[t]cpdump -i ea0'; pkill -f '[p]robe serve lx-alt'; pkill -f '[p]robe serve lx-other'
ip netns del east; ip netns del west; rm -rf /etc/netns/east /etc/netns/west
iptables -t nat -D POSTROUTING -s 10.86.0.0/24 -j MASQUERADE; iptables -t nat -D POSTROUTING -s 10.87.0.0/24 -j MASQUERADE
iptables -D FORWARD -i ea0 -j ACCEPT; iptables -D FORWARD -o ea0 -j ACCEPT
iptables -D FORWARD -i we0 -j ACCEPT; iptables -D FORWARD -o we0 -j ACCEPT
sysctl -qw net.ipv4.ip_forward=0`, 3*time.Minute)
	})

	lx.run(t, `set -e
command -v tcpdump >/dev/null || { apt-get update -q >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -q tcpdump >/dev/null; }
sysctl -qw net.ipv4.ip_forward=1
for w in east:ea:10.86.0 west:we:10.87.0; do
	ns=${w%%:*}; rest=${w#*:}; dev=${rest%%:*}; net=${rest#*:}
	ip netns add $ns; ip link add ${dev}0 type veth peer name ${dev}1 netns $ns
	ip addr add $net.1/24 dev ${dev}0; ip link set ${dev}0 up
	ip -n $ns addr add $net.2/24 dev ${dev}1; ip -n $ns link set ${dev}1 up; ip -n $ns link set lo up
	ip -n $ns route add default via $net.1
	mkdir -p /etc/netns/$ns; echo "nameserver 10.77.0.1" > /etc/netns/$ns/resolv.conf
	install -d -m 700 -o juist -g juist /tmp/$ns
	iptables -t nat -A POSTROUTING -s $net.0/24 -j MASQUERADE
	iptables -I FORWARD -i ${dev}0 -j ACCEPT; iptables -I FORWARD -o ${dev}0 -j ACCEPT
done
setsid -f /tmp/probe serve lx-alt 8080 >/dev/null 2>&1 < /dev/null
setsid -f /tmp/probe serve lx-other 8081 >/dev/null 2>&1 < /dev/null
sleep 2`)
	for _, w := range []walled{east, west} {
		// As the packaged service runs it: juistd of root may use no exit node.
		lx.run(t, w.in(`setsid -f env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent `+
			`setpriv --reuid=juist --regid=juist --init-groups --inh-caps=+net_admin --ambient-caps=+net_admin `+
			`/usr/bin/juistd --home `+w.home+` --socket `+w.sock+` --verbose >>`+w.home+`/juistd.log 2>&1 < /dev/null`))
		lx.eventually(t, w.name+"'s juistd answering", time.Minute, w.juist("status"), func(string) bool { return true })
		invite(t, fb, lx, w.juist("join '%s' --name "+w.name))
	}
	for _, w := range []walled{east, west} {
		lx.eventually(t, w.name+" reaching lx before any policy", 3*time.Minute, w.in("ping -c1 -W2 "+lx4),
			func(string) bool { return true })
	}

	fb.run(t, `cat > /tmp/policy.conf <<'EOF'
pass from { fb, lx } to any
pass from east to lx proto tcp port 8080
pass from west to { lx, internet via lx }
test block from east to west
test block from west to east
test pass from east to lx proto tcp port 8080
test block from east to internet via lx
EOF
juist grant lx exit && juist policy set --yes /tmp/policy.conf`)
	lx.eventually(t, "serving as exit node", 3*time.Minute, "juist exit serve", func(string) bool { return true })
	for _, w := range []walled{east, west} {
		lx.eventually(t, w.name+" holding the policy", 3*time.Minute, w.juist("devices"),
			func(out string) bool { return strings.Contains(out, "keeps apart") })
	}
	// Whatever passes between east and west on the underlay from here, the
	// way they would reach each other, once the tunnel they had is gone.
	time.Sleep(10 * time.Second)
	lx.run(t, "setsid -f tcpdump -i ea0 -U -s 0 -w /tmp/east-west.pcap host 10.87.0.2 >/tmp/tcpdump-east.log 2>&1 < /dev/null")

	// (1): east opens on lx what the policy passes alone.
	lx.eventually(t, "east reaching lx on the port passed", 2*time.Minute, east.in("/tmp/probe get "+lx4+":8080"),
		has("lx-alt from"))
	if out, err := lx.try(east.in("timeout 10 /tmp/probe get "+lx4+":8081"), time.Minute); err == nil {
		t.Errorf("east opened lx's port 8081, which the policy does not pass:\n%s", out)
	}
	lx.eventually(t, "west reaching lx on any port", 2*time.Minute, west.in("/tmp/probe get "+lx4+":8081"), has("lx-other from"))

	// lx carries west's internet traffic, which the policy passes it, and
	// not east's.
	lx.eventually(t, "west hearing lx serves", 3*time.Minute, west.juist("exit"), func(out string) bool {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "lx ") && strings.Contains(l, "serving") && !strings.Contains(l, "not serving") {
				return true
			}
		}
		return false
	})
	lx.run(t, west.juist("exit use lx")+" && "+east.juist("exit use lx --force"))
	lx.eventually(t, "west reaching the internet through lx", 2*time.Minute, west.in("/tmp/probe get "+lxSide.target+":80"),
		has("lx-target from "+lxSide.nat))
	lx.eventually(t, "east refused lx", time.Minute, east.juist("exit"), has("access policy"))
	if out, err := lx.try(east.in("timeout 10 /tmp/probe get "+lxSide.target+":80"), time.Minute); err == nil {
		t.Errorf("east reached the internet the policy does not pass it through lx:\n%s", out)
	}
	lx.run(t, west.juist("exit off")+"; "+east.juist("exit off"))

	// (4): east and west, kept apart, list each other not, exchange no
	// packet, and hold no address of the other's in the clear.
	for _, pair := range [][2]walled{{east, west}, {west, east}} {
		if out := lx.run(t, pair[0].juist("devices")); strings.Contains(out, pair[1].name) {
			t.Errorf("%s lists %s:\n%s", pair[0].name, pair[1].name, out)
		}
	}
	time.Sleep(30 * time.Second)
	lx.run(t, "pkill -f '[t]cpdump -i ea0'; sleep 1")
	if out := lx.run(t, "tcpdump -nr /tmp/east-west.pcap 2>/dev/null"); strings.TrimSpace(out) != "" {
		t.Errorf("east and west, kept apart, exchanged:\n%s", out)
	}
	// 10.87.0.2 and 10.86.0.2, as an announcement holds them.
	lx.run(t, `! grep -rqaP '\x0a\x57\x00\x02' /tmp/east && ! grep -rqaP '\x0a\x56\x00\x02' /tmp/west`)
}
