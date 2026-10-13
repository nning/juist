//go:build interop && linux

package interop

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The relays' public names, and where the lab's DNS sends them.
const (
	relayFB = "relay-fb.example.org"
	relayLX = "relay-lx.example.org"
)

// A walled device runs on lx in a namespace of its own, whose one way out is
// to: TCP to 443 and DNS, or a proxy.
type walled struct {
	name, ns, dev, net string
	home, sock         string
}

func (w walled) juist(args string) string { return "juist --socket " + w.sock + " " + args }

func (w walled) in(script string) string { return "ip netns exec " + w.ns + " " + script }

// httpsAlone is M13's exit criteria. On lx, hotel is a device whose network
// passes nothing but TCP to 443 and DNS, and office one whose network passes
// nothing but TCP to a CONNECT proxy. Both join by a link, reach fb and lx
// through their relays on 443 under public names, by Pebble's certificates,
// keep reaching fb once fb's home relay moves, and do again after a restart
// (1, 5); hotel's underlay carries TLS and DNS alone, as nDPI classifies it,
// every ClientHello naming a relay (2, 3); fb, the ingress, serves its relay
// on 443 beside the names it publishes (4).
func httpsAlone(t *testing.T, fb, lx *vm, work, fb4, lx4 string) {
	hotel := walled{name: "hotel", ns: "hotel", dev: "ht", net: "10.88.0", home: "/tmp/hotel", sock: "/tmp/hotel/juistd.sock"}
	office := walled{name: "office", ns: "office", dev: "of", net: "10.89.0", home: "/tmp/office", sock: "/tmp/office/juistd.sock"}
	t.Cleanup(func() {
		if t.Failed() {
			for _, w := range []walled{hotel, office} {
				out, _ := lx.try(w.juist("status")+"; tail -60 "+w.home+"/juistd.log; grep -E "+
					"'preshared key with|newly given a preshared key|keyed:|log sync|gossip' "+w.home+"/juistd.log | tail -60",
					time.Minute)
				t.Logf("%s:\n%s", w.name, out)
			}
			out, _ := lx.try("juist status; iptables -L -v -n | head -40; /tmp/probe pcap /tmp/hotel.pcap | sort | uniq -c | head -40; "+
				"cat /tmp/proxy.log | sort | uniq -c; journalctl -u juistd -n 40 --no-pager", 2*time.Minute)
			t.Logf("lx:\n%s", out)
			out, _ = fb.try("juist status; tail -40 /var/log/juistd.log; tail -20 /tmp/pebble.log; "+
				"tail -30 /var/log/juist-ingress.log; ls -la /var/run/juist; sockstat -u | grep juist; id juist-ingress",
				time.Minute)
			t.Logf("fb:\n%s", out)
			hold(t, fb, lx)
		}
		lx.try(`pkill -f '[j]uistd --home /tmp/hotel'; pkill -f '[j]uistd --home /tmp/office'
pkill -f '[t]cpdump -i ht0'; pkill -f '[p]robe answer 10.88.0.1'; pkill -f '[p]robe proxy'
ip netns del hotel; ip netns del office; rm -rf /etc/netns/hotel /etc/netns/office
iptables -D INPUT -i ht0 -j HOTEL; iptables -D FORWARD -i ht0 -j HOTEL
iptables -D INPUT -i of0 -j OFFICE; iptables -D FORWARD -i of0 -j OFFICE
iptables -F HOTEL; iptables -X HOTEL; iptables -F OFFICE; iptables -X OFFICE
iptables -t nat -D POSTROUTING -s 10.88.0.0/24 -j MASQUERADE
sysctl -qw net.ipv4.ip_forward=0
juist set --relay-name ""
rm -f /etc/systemd/system/juistd.service.d/pebble.conf; systemctl daemon-reload; systemctl restart juistd`, 3*time.Minute)
		fb.try(`juist set --relay-name ""; sysrc -q -x juistd_env juistd_args; service juistd restart
pkill -f '[p]robe answer'; daemon -f /tmp/probe answer 127.0.0.1:5399 127.0.0.1`, 3*time.Minute)
		// The subtests after this one start from a tunnel up again.
		lx.try("for i in $(seq 60); do ping -c1 -W2 "+fb4+" >/dev/null && break; sleep 3; done", 4*time.Minute)
	})

	// Pebble finds lx's relay by its name; the rest of its names are fb's.
	fb.run(t, `pkill -f '[p]robe answer'
daemon -f /tmp/probe answer 127.0.0.1:5399 127.0.0.1 `+relayLX+`=`+lx.lanAddr+`
sysrc -q juistd_env=SSL_CERT_FILE=/tmp/ca.pem juistd_args="--acme https://`+fb.lanAddr+`:14000/dir"
service juistd restart >/dev/null`)
	lx.run(t, `set -e
mkdir -p /etc/systemd/system/juistd.service.d
printf '%s\n' '[Service]' 'Environment=SSL_CERT_FILE=/etc/juist-test-ca.pem' 'ExecStart=' \
  'ExecStart=/usr/bin/juistd --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0 --acme https://`+
		fb.lanAddr+`:14000/dir' > /etc/systemd/system/juistd.service.d/pebble.conf
systemctl daemon-reload; systemctl restart juistd`)
	for _, v := range []*vm{fb, lx} {
		v.eventually(t, "juistd answering again", 2*time.Minute, "juist status", has("connected"))
	}
	fb.run(t, "juist grant fb relay && juist grant lx relay")
	mustHave(t, fb.run(t, "juist set --relay-name "+relayFB), "relay name "+relayFB)
	mustHave(t, lx.run(t, "juist set --relay-name "+relayLX), "relay name "+relayLX)
	mustHave(t, lx.run(t, "cat /etc/systemd/system/juistd.service.d/juist-relay-443.conf"), "CAP_NET_BIND_SERVICE")
	fb.eventually(t, "serving its relay on 443 through the ingress", 4*time.Minute, "juist status",
		has(relayFB+", on 443 through the ingress"))
	lx.eventually(t, "serving its relay on 443", 4*time.Minute, "juist status", has(relayLX+", on 443"))

	root := fb.run(t, "cat /tmp/root.pem")
	if err := os.WriteFile(filepath.Join(work, "pebble-root.pem"), []byte(root), 0o644); err != nil {
		t.Fatal(err)
	}
	lx.put(t, filepath.Join(work, "pebble-root.pem"), "/tmp/pebble-root.pem", 0o644)

	// (4) and (3)'s certificate: each relay's name is Pebble's, fb's beside
	// what fb's ingress passes on for the names published.
	for _, r := range []struct{ name, at string }{{relayFB, fb.lanAddr}, {relayLX, lx.lanAddr}} {
		// Over TLS 1.3 with X25519MLKEM768, which a relay requires and
		// Debian 12's curl and openssl do not offer.
		lx.eventually(t, "answering for "+r.name+" by Pebble's certificate", 2*time.Minute,
			"/tmp/probe pqget "+r.at+":443 "+r.name+" /tmp/pebble-root.pem /derp/probe", func(out string) bool {
				return strings.HasPrefix(out, "200 ") && strings.Contains(out, "Pebble")
			})
	}
	fb.eventually(t, "passing on a name it publishes beside", 3*time.Minute,
		"/tmp/probe hello 127.0.0.1:443 fbweb.pub.example.org /tmp/root.pem", has("fb-web from"))

	// The two walled networks, the capture of hotel's, its DNS and office's
	// proxy.
	lx.run(t, `set -e
command -v tcpdump >/dev/null && command -v ndpiReader >/dev/null || {
	apt-get update -q >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -q tcpdump libndpi-bin >/dev/null; }
lan=$(ip -br link | awk '$3 == "52:54:00:77:00:03" {print $1}')
sysctl -qw net.ipv4.ip_forward=1
for w in hotel:ht:10.88.0 office:of:10.89.0; do
	ns=${w%%:*}; rest=${w#*:}; dev=${rest%%:*}; net=${rest#*:}
	ip netns add $ns; ip link add ${dev}0 type veth peer name ${dev}1 netns $ns
	ip addr add $net.1/24 dev ${dev}0; ip link set ${dev}0 up
	sysctl -qw net.ipv6.conf.${dev}0.disable_ipv6=1
	ip netns exec $ns sysctl -qw net.ipv6.conf.${dev}1.disable_ipv6=1
	ip -n $ns addr add $net.2/24 dev ${dev}1; ip -n $ns link set ${dev}1 up; ip -n $ns link set lo up
	ip -n $ns route add default via $net.1
	# The overlay's, while no tunnel routes it: a ping then leaves by no wire.
	ip -n $ns route add blackhole 198.16.0.0/12; ip -n $ns route add blackhole 100.0.0.0/8
	mkdir -p /etc/netns/$ns; echo "nameserver $net.1" > /etc/netns/$ns/resolv.conf
	install -d -m 700 /tmp/$ns
done
iptables -N HOTEL
iptables -A HOTEL -p tcp --dport 443 -j ACCEPT
iptables -A HOTEL -d 10.88.0.1 -p udp --dport 53 -j ACCEPT
iptables -A HOTEL -d 10.88.0.1 -p tcp --dport 53 -j ACCEPT
iptables -A HOTEL -j DROP
iptables -I INPUT -i ht0 -j HOTEL; iptables -I FORWARD -i ht0 -j HOTEL
iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o $lan -j MASQUERADE
iptables -N OFFICE
iptables -A OFFICE -d 10.89.0.1 -p tcp --dport 3128 -j ACCEPT
iptables -A OFFICE -j DROP
iptables -I INPUT -i of0 -j OFFICE; iptables -I FORWARD -i of0 -j OFFICE
# Nothing comes in unasked, as through a NAT, though peers try the local
# addresses a walled device's magicsock still names in call-me-maybe.
iptables -N INWARD
iptables -A INWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INWARD -j DROP
for dev in ht0 of0; do iptables -I OUTPUT -o $dev -j INWARD; iptables -I FORWARD -o $dev -j INWARD; done
setsid -f /tmp/probe answer 10.88.0.1:53 - `+relayFB+`=`+fb.lanAddr+` `+relayLX+`=`+lx.lanAddr+` >/dev/null 2>&1 < /dev/null
setsid -f /tmp/probe proxy 10.89.0.1:3128 walled:secret /tmp/proxy.log `+relayFB+`=`+fb.lanAddr+` `+relayLX+`=`+lx.lanAddr+
		` >/dev/null 2>&1 < /dev/null
# What each sends: the host's own chatter on the link is none of its doing.
setsid -f tcpdump -i ht0 -U -s 0 -w /tmp/hotel.pcap src host 10.88.0.2 >/tmp/tcpdump.log 2>&1 < /dev/null
setsid -f tcpdump -i of0 -U -s 0 -w /tmp/office.pcap src host 10.89.0.2 >/tmp/tcpdump-office.log 2>&1 < /dev/null
sleep 2`)

	start := func(w walled) {
		// No system bus: the host's resolver would take the namespace's
		// device for the host's link of the same index.
		lx.run(t, w.in(`setsid -f env SSL_CERT_FILE=/tmp/pebble-root.pem DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent `+
			`/usr/bin/juistd --home `+w.home+
			` --socket `+w.sock+` --verbose >>`+w.home+`/juistd.log 2>&1 < /dev/null`))
		lx.eventually(t, w.name+"'s juistd answering", time.Minute, w.juist("status"), func(string) bool { return true })
	}
	for _, w := range []walled{hotel, office} {
		start(w)
	}
	mustHave(t, lx.run(t, hotel.juist("set --https-only")), "https only")
	mustHave(t, lx.run(t, office.juist("set --https-only --proxy http://walled:secret@10.89.0.1:3128")), "https only",
		"proxy http://walled:xxxxx@10.89.0.1:3128")
	for _, w := range []walled{hotel, office} {
		invite(t, fb, lx, w.juist("join '%s' --name "+w.name))
	}
	reach := func(what string) {
		for _, w := range []walled{hotel, office} {
			for _, peer := range []string{fb4, lx4} {
				lx.eventually(t, w.name+" reaching "+peer+" "+what, 3*time.Minute, w.in("ping -c1 -W2 "+peer),
					func(string) bool { return true })
			}
		}
	}
	reach("through the relays on 443")
	for _, w := range []walled{hotel, office} {
		mustHave(t, lx.run(t, w.juist("status")), "HTTPS", "only, by "+relayFB+", "+relayLX)
	}
	mustHave(t, lx.run(t, office.juist("status")), "through http://walled:xxxxx@10.89.0.1:3128")

	// fb's relay goes, and with it fb's home: the walled devices learn its
	// next home from the relay left, at lx.
	fb.run(t, "juist revoke fb relay")
	fb.eventually(t, "homed at lx's relay", 3*time.Minute, "juist status", has("via lx"))
	reach("once fb's home relay moved")

	for _, w := range []walled{hotel, office} {
		lx.run(t, "pkill -f '[j]uistd --home "+w.home+"'; while pgrep -f '[j]uistd --home "+w.home+"' >/dev/null; do sleep 0.5; done")
		start(w)
	}
	reach("after a restart")

	lx.run(t, "pkill -f '[t]cpdump -i ht0'; pkill -f '[t]cpdump -i of0'; sleep 1")
	// (2) and (3): TLS and DNS alone, each TLS flow asking for a relay by
	// its public name.
	flows := lx.run(t, "/tmp/probe pcap /tmp/hotel.pcap")
	tls := 0
	for _, l := range strings.Split(strings.TrimSpace(flows), "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 0 || f[0] == "dns" && strings.HasSuffix(l, "> 10.88.0.1"):
		case f[0] == "tls" && slices.Contains([]string{relayFB, relayLX}, f[len(f)-1]):
			tls++
		default:
			t.Errorf("hotel sent %q", l)
		}
	}
	if tls == 0 {
		t.Errorf("no TLS from hotel:\n%s", flows)
	}
	ndpi := lx.run(t, "ndpiReader -i /tmp/hotel.pcap 2>&1")
	protocols := detected(ndpi)
	for _, p := range protocols {
		if p != "TLS" && p != "DNS" {
			t.Errorf("nDPI found %s in hotel's capture:\n%s", p, ndpi)
		}
	}
	if !slices.Contains(protocols, "TLS") {
		t.Errorf("nDPI found no TLS in hotel's capture:\n%s", ndpi)
	}
	// (5): office reached nothing but the proxy, and asked it for the
	// relays' names on 443 alone.
	if other := lx.run(t, "tcpdump -nr /tmp/office.pcap 'ip and not (dst host 10.89.0.1 and tcp dst port 3128)' "+
		"2>/dev/null"); strings.TrimSpace(other) != "" {
		t.Errorf("office sent besides the proxy:\n%s", other)
	}
	for _, l := range strings.Split(strings.TrimSpace(lx.run(t, "sort -u /tmp/proxy.log")), "\n") {
		if l != "CONNECT "+relayFB+":443" && l != "CONNECT "+relayLX+":443" {
			t.Errorf("the proxy was asked %q", l)
		}
	}
	fb.run(t, "juist remove hotel --yes && juist remove office --yes")
}

// detected is the protocols nDPI's summary of a capture lists.
func detected(out string) []string {
	var got []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(l), "Detected protocols:"):
			in = true
		case in && strings.TrimSpace(l) == "":
			return got
		case in:
			if f := strings.Fields(l); len(f) > 0 {
				got = append(got, f[0])
			}
		}
	}
	return got
}
