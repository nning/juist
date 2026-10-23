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
// and reaches it (3).
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
	lx.eventually(t, "homed at the relay hotel does not reach", 3*time.Minute,
		"journalctl -u juistd --no-pager | grep -o 'home is now derp-[0-9]*' | tail -1", has("derp-"+walls))
	time.Sleep(3 * time.Minute)
	lx.run(t, hotel.in("ping -c3 -W3 "+lx4))

	// hotel's log carries no time: a tick every 5 s says where the time goes,
	// and how lx sees hotel then; fb's log is marked as it starts.
	lx.run(t, `setsid -f sh -c 'for i in $(seq 48); do echo "lab: tick $(date +%T)"; `+
		`juist status --verbose 2>/dev/null | grep -i hotel | sed "s/^/lab: lx sees /"; sleep 5; done >> `+
		hotel.home+`/juistd.log' </dev/null >/dev/null 2>&1`)
	fb.try(`echo "lab: hotel leaves HTTPS alone $(date +%T)" >> /var/log/juistd.log`, time.Minute)
	mustHave(t, lx.run(t, hotel.juist("set --https-only=false")), "https only off")
	lx.eventually(t, "hotel's juistd answering", time.Minute, hotel.juist("status"), has("connected"))
	meet("without HTTPS alone")
	t.Logf("hotel, meeting lx without HTTPS alone:\n%s", lx.run(t, `sed -n '/lab: tick/,$p' `+hotel.home+`/juistd.log | `+
		`grep -E "lab: |conn: |home is now|report: |ReSTUN|UDP is blocked|dht: " | cut -c1-160 | head -120`))
	if out, err := fb.try(`sed -n '/lab: hotel leaves HTTPS alone/,$p' /var/log/juistd.log | `+
		`grep -E "lab: |discovered|pushed|gossip: " | cut -c1-160 | head -40`, time.Minute); err == nil {
		t.Logf("fb, as hotel met lx:\n%s", out)
	}
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
	fb.run(t, "juist revoke fb relay")
}
