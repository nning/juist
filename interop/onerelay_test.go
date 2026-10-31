//go:build interop && linux

package interop

import (
	"strings"
	"testing"
	"time"
)

// relayIngress is the name fb's relay takes on 443 as the ingress's, with no
// name set.
const relayIngress = "relay.pub.example.org"

// oneRelayOn443 is M22's exit criteria, on hotel as httpsAlone leaves it,
// joined and on HTTPS alone. fb, the ingress, relays as relay.DOMAIN with no
// name set (5); lx relays under no name, homed at its own relay, where hotel
// does not reach. They meet at fb's relay: each reaches the other, with
// --https-only and without it, and hotel reaches lx first after three
// minutes without traffic (1, 2, 5); with lx's juistd stopped, hotel's
// health names it as not at fb's relay (6); and lx, started again after
// hotel restarted, learns hotel's new announcement without a tunnel to it,
// and reaches it (3). Beside a STUN server that answers it, hotel leaves
// the STUN servers out to be homed and reach lx; once every relay name it
// holds moved, it finds the new ones at relay.DOMAIN (M24).
func oneRelayOn443(t *testing.T, fb, lx *vm, hotel walled, fb4, lx4 string) {
	ok := func(string) bool { return true }
	// Apart: the script naming the answerer would match its own pkill.
	lx.run(t, `pkill -f '[p]robe answer 10.88.0.1'; true`)
	names := relayFB + `=` + fb.lanAddr + ` ` + relayLX + `=` + lx.lanAddr + ` ` + relayIngress + `=` + fb.lanAddr
	// And at resolved's stub in hotel's namespace: resolved rewrites the
	// file the namespace's resolv.conf is mounted over as lx's juistd
	// restarts, which hotel's juistd then reads.
	t.Cleanup(func() { lx.try(`pkill -f '[p]robe answer 127.0.0.53'`, time.Minute) })
	lx.run(t, `setsid -f /tmp/probe answer 10.88.0.1:53 - `+names+` >/dev/null 2>&1 < /dev/null`)
	lx.run(t, hotel.in(`setsid -f /tmp/probe answer 127.0.0.53:53 - `+names+` >/dev/null 2>&1 < /dev/null`))
	fb.run(t, "juist grant fb relay")
	mustHave(t, fb.run(t, `juist set --relay-name ""`), "relay name "+relayIngress+", the ingress's")
	fb.eventually(t, "serving its relay as the ingress's on 443", 4*time.Minute, "juist status",
		has(relayIngress+", on 443 through the ingress"))
	// hotel learns the new name through lx's relay, before that goes off
	// 443: it learns nothing once no relay it knows of is named there.
	lx.eventually(t, "hotel knowing fb's relay by its name", 3*time.Minute, hotel.juist("status"), has(relayIngress))
	mustHave(t, lx.run(t, `juist set --relay-name ""`), "relay name cleared")
	hotel4 := strings.TrimSpace(lx.run(t, hotel.in(`ip -4 -br addr | awk '$1 ~ /juist/ {print $3}' | cut -d/ -f1`)))
	if hotel4 == "" {
		t.Fatal("hotel has no overlay IPv4 address")
	}
	meet := func(what string) {
		t.Helper()
		lx.eventually(t, "hotel reaching lx "+what, 3*time.Minute, hotel.in("ping -c1 -W2 "+lx4), ok)
		lx.eventually(t, "lx reaching hotel "+what, 3*time.Minute, "ping -c1 -W2 "+hotel4, ok)
	}
	meet("at fb's relay")
	mustHave(t, lx.run(t, hotel.juist("status")), "only, by "+relayIngress)
	lx.eventually(t, "hotel saying it meets lx at fb's relay", 2*time.Minute, hotel.juist("status --verbose"),
		has("lx via fb"))
	// lx is homed at the relay hotel's walls name, not at fb's.
	walls := lx.run(t, `grep -o 'conn: walled: relays \[[0-9]*\]' `+hotel.home+`/juistd.log | tail -1 | tr -dc 0-9`)
	if walls == "" {
		t.Fatal("hotel says no relay is out of its reach")
	}
	// netcheck keeps a home a few milliseconds behind the nearest, so lx,
	// homed at fb's relay while its own restarted on losing its name, may
	// stay there: once restarted, it takes its own.
	home := "journalctl -u juistd --no-pager | grep -o 'home is now derp-[0-9]*' | tail -1"
	deadline := time.Now().Add(90 * time.Second)
	for {
		if out, _ := lx.try(home, time.Minute); strings.Contains(out, "derp-"+walls) {
			break
		}
		if time.Now().After(deadline) {
			t.Logf("lab: lx homed at fb's relay; restarting its juistd")
			lx.run(t, "systemctl restart juistd")
			lx.eventually(t, "homed at the relay hotel does not reach", 3*time.Minute, home, has("derp-"+walls))
			break
		}
		time.Sleep(5 * time.Second)
	}
	time.Sleep(3 * time.Minute)
	lx.run(t, hotel.in("ping -c3 -W3 "+lx4))

	// hotel's log carries no time: a tick every 5 s says where the time goes,
	// and how lx sees hotel then; fb's log is marked as it starts.
	lx.run(t, `setsid -f sh -c 'for i in $(seq 48); do echo "lab: tick $(date +%T)"; `+
		`juist status --verbose 2>/dev/null | grep -i hotel | sed "s/^/lab: lx sees /"; sleep 5; done >> `+
		hotel.home+`/juistd.log' </dev/null >/dev/null 2>&1`)
	fb.try(`echo "lab: hotel leaves HTTPS alone $(date +%T)" >> /var/log/juistd.log`, time.Minute)
	since := strings.TrimSpace(lx.run(t, "date '+%Y-%m-%d %H:%M:%S'"))
	mustHave(t, lx.run(t, hotel.juist("set --https-only=false")), "https only off")
	lx.eventually(t, "hotel's juistd answering", time.Minute, hotel.juist("status"), has("connected"))
	meet("without HTTPS alone")
	t.Logf("hotel, meeting lx without HTTPS alone:\n%s", lx.run(t, `sed -n '/lab: tick/,$p' `+hotel.home+`/juistd.log | `+
		`grep -E "lab: |conn: |home is now|report: |ReSTUN|UDP is blocked|dht: " | cut -c1-160 | head -120`))
	if out, err := fb.try(`sed -n '/lab: hotel leaves HTTPS alone/,$p' /var/log/juistd.log | `+
		`grep -E "lab: |discovered|pushed|gossip: " | cut -c1-160 | head -40`, time.Minute); err == nil {
		t.Logf("fb, as hotel met lx:\n%s", out)
	}
	t.Logf("lx, as hotel met it:\n%s", lx.run(t, `journalctl -u juistd --no-pager -o short-precise --since '`+since+`' | `+
		`grep -E "conn: |home is now|adding connection to derp|discovered|derp-[0-9]+ does not know" | cut -c1-200 | head -60`))
	time.Sleep(3 * time.Minute)
	lx.run(t, hotel.in("ping -c3 -W3 "+lx4))

	lx.run(t, "systemctl stop juistd")
	lx.run(t, "! "+hotel.in("ping -c3 -W2 "+lx4))
	lx.eventually(t, "hotel saying lx is not at fb's relay", 3*time.Minute, hotel.juist("health"),
		has("no answer from lx: not at the relay on fb"))
	lx.run(t, "pkill -f '[j]uistd --home "+hotel.home+"'; while pgrep -f '[j]uistd --home "+hotel.home+"' >/dev/null; do sleep 0.5; done")
	lx.run(t, hotel.in(`setsid -f env SSL_CERT_FILE=/tmp/pebble-root.pem DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent `+
		`/usr/bin/juistd --home `+hotel.home+` --socket `+hotel.sock+` --verbose >>`+hotel.home+`/juistd.log 2>&1 < /dev/null`))
	lx.eventually(t, "hotel's juistd answering", time.Minute, hotel.juist("status"), has("connected"))
	lx.run(t, "systemctl start juistd")
	lx.eventually(t, "lx reaching hotel after both restarted", 4*time.Minute, "ping -c1 -W2 "+hotel4, ok)

	// A STUN server answers hotel and no relay's port does: netcheck then
	// measures no relay by HTTPS, until hotel leaves the STUN servers out.
	t.Cleanup(func() {
		lx.try(`iptables -D HOTEL -d 10.88.0.1 -p udp --dport 3478 -j ACCEPT 2>/dev/null; pkill -f '[p]robe stun'`, time.Minute)
	})
	lx.run(t, `setsid -f /tmp/probe stun 10.88.0.1:3478 >/dev/null 2>&1 < /dev/null
iptables -I HOTEL 1 -d 10.88.0.1 -p udp --dport 3478 -j ACCEPT`)
	lx.run(t, "pkill -f '[j]uistd --home "+hotel.home+"'; while pgrep -f '[j]uistd --home "+hotel.home+"' >/dev/null; do sleep 0.5; done")
	lx.run(t, hotel.in(`setsid -f env SSL_CERT_FILE=/tmp/pebble-root.pem DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent `+
		`/usr/bin/juistd --home `+hotel.home+` --socket `+hotel.sock+` --stun 10.88.0.1:3478 --verbose >>`+hotel.home+`/juistd.log 2>&1 < /dev/null`))
	lx.eventually(t, "hotel's juistd answering", time.Minute, hotel.juist("status"), has("connected"))
	lx.eventually(t, "hotel reaching lx beside a STUN server answering", 3*time.Minute, hotel.in("ping -c1 -W2 "+lx4), ok)
	mustHave(t, lx.run(t, `grep -q 'STUN servers answered and no relay did' `+hotel.home+`/juistd.log && echo aside`), "aside")

	// Every name hotel, on HTTPS alone again, holds on 443 moves: lx's
	// relay takes a name and gives it up again, fb's takes relayFB, hotel
	// hearing of each through the other, and fb's goes back to the
	// ingress's. hotel then finds the members at relay.DOMAIN, which its
	// log says the ingress serves.
	lx.run(t, `iptables -D HOTEL -d 10.88.0.1 -p udp --dport 3478 -j ACCEPT`)
	mustHave(t, lx.run(t, hotel.juist("set --https-only")), "https only")
	lx.eventually(t, "hotel's juistd answering on HTTPS alone", time.Minute, hotel.juist("status"), has("only, by"))
	mustHave(t, lx.run(t, "juist set --relay-name "+relayLX), "relay name "+relayLX)
	lx.eventually(t, "hotel knowing lx's relay by its name", 4*time.Minute, hotel.juist("status"), has(relayLX))
	mustHave(t, fb.run(t, "juist set --relay-name "+relayFB), "relay name "+relayFB)
	lx.eventually(t, "hotel knowing fb's relay by its own name", 4*time.Minute, hotel.juist("status"), has(relayFB))
	mustHave(t, lx.run(t, `juist set --relay-name ""`), "relay name cleared")
	lx.eventually(t, "hotel knowing lx's relay without a name", 4*time.Minute, hotel.juist("status"),
		func(out string) bool { return !strings.Contains(out, relayLX) })
	mustHave(t, fb.run(t, `juist set --relay-name ""`), "relay name "+relayIngress+", the ingress's")
	// Its certificate may be ordered anew, which takes the lab's CA minutes.
	fb.eventually(t, "serving its relay as the ingress's on 443 again", 4*time.Minute, "juist status",
		has(relayIngress+", on 443 through the ingress"))
	lx.eventually(t, "hotel finding fb's relay under the ingress's name", 5*time.Minute, hotel.juist("status"), has(relayIngress))
	lx.eventually(t, "hotel reaching lx after every name it held moved", 3*time.Minute, hotel.in("ping -c1 -W2 "+lx4), ok)

	fb.run(t, "juist revoke fb relay")
}
