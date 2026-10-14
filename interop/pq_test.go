//go:build interop && linux

package interop

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// previousRelease is exit criterion (4) of M15 and (3) of M18: on the
// previous release lx creates a network, fb joins, and the two reach each
// other. fb, made an admin and upgraded while lx is stopped, and lx, back on
// the previous release, reach each other; upgraded, lx reaches fb on a pair
// key, and an epoch bump leaves no gap in a ping. The network then goes,
// failed or not, so the lab's own starts from nothing; a keystore of its own
// keeps its admin keys out of the lab's.
func previousRelease(t *testing.T, fb, lx *vm) {
	const env = "HOME=/tmp/previous "
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{fb, lx} {
				out, _ := v.try(diagnose(v), 2*time.Minute)
				t.Logf("%s:\n%s", v.name, out)
				out, _ = v.try(previousDump(v), 2*time.Minute)
				t.Logf("%s, since lx's juistd stopped for the upgrade:\n%s", v.name, out)
			}
			hold(t, fb, lx)
		}
		for _, v := range []*vm{fb, lx} {
			v.try(env+"juist reset --force --yes", 2*time.Minute)
		}
		fb.try("pkill -f '[t]cpdump -n -tt -l -c 400'; sysrc -q -x juistd_args; service juistd restart", 2*time.Minute)
		lx.try("pkill -f '[t]cpdump -n -tt -l -c 400'; rm -f "+verboseDropIn+
			"; systemctl daemon-reload; systemctl restart juistd", 2*time.Minute)
	})
	ok := func(string) bool { return true }
	// Both log verbosely, so that a failure shows what each heard of the other.
	fb.run(t, "sysrc -q juistd_args=--verbose >/dev/null && service juistd restart >/dev/null")
	lx.run(t, "mkdir -p /etc/systemd/system/juistd.service.d && printf '%s\\n' '[Service]' 'ExecStart=' "+
		"'ExecStart=/usr/bin/juistd --verbose --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0' > "+
		verboseDropIn+" && systemctl daemon-reload && systemctl restart juistd")
	for _, v := range []*vm{fb, lx} {
		v.run(t, "mkdir -p /tmp/previous")
		v.eventually(t, "juistd answers", 2*time.Minute, "juist status", ok)
	}
	lx.run(t, env+"juist create previous --device lx")
	inviteAs(t, lx, fb, env, env+"juist join '%s'")
	fb4 := strings.TrimSpace(fb.run(t, `ifconfig juist0 inet | awk '/inet / {print $2; exit}'`))
	lx4 := strings.TrimSpace(lx.run(t, `ip -4 -br addr show juist0 | awk '{print $3}' | cut -d/ -f1`))
	lx.eventually(t, "reaching fb, on the previous release", 3*time.Minute, "ping -c1 -W2 "+fb4, ok)
	fb.eventually(t, "reaching lx on the previous release", time.Minute, "ping -c1 -t2 "+lx4, ok)
	if out := fb.run(t, "juist devices"); strings.Contains(out, "outdated") {
		t.Fatalf("a network of the previous release calls a device outdated:\n%s", out)
	}
	// The same ping across an epoch bump, on the previous release.
	out, bump := pingAcrossBump(t, lx, fb4, func() { lx.run(t, env+"juist rotate group-secret") })
	lost, gap := lostPings(out, 900)
	t.Logf("on the previous release, across the bump at %s: lost %d%s %s", bump, len(lost),
		map[bool]string{true: ", a gap", false: ""}[gap], strings.Join(lost, ", "))

	key := regexp.MustCompile(`juist admins add fb (nid:\S+)`).FindStringSubmatch(fb.run(t, env+"juist admins new fb"))
	if key == nil {
		t.Fatal("juist admins new printed no key to add")
	}
	lx.run(t, env+"juist admins add fb "+key[1])
	fb.eventually(t, "holding its admin key's addition", 2*time.Minute, env+"juist admins", has("fb"))
	lx.run(t, "systemctl stop juistd")
	// The data plane between the two on their LAN from here, for a failure.
	fb.run(t, "daemon -f sh -c 'exec tcpdump -n -tt -l -c 400 -i vtnet1 udp port 41643 > /tmp/pq.udp 2>/dev/null'")
	lx.run(t, "date +%s > /tmp/pq.restart; setsid -f sh -c 'exec tcpdump -n -tt -l -c 400 -i any udp port 41643 "+
		"and host 10.77.0.1 > /tmp/pq.udp 2>/dev/null' >/dev/null 2>&1 < /dev/null")
	fb.run(t, "pkg add -f /tmp/juist.pkg >/dev/null && service juistd restart >/dev/null")
	fb.eventually(t, "juistd answers, upgraded", 2*time.Minute, "juist status", ok)
	lx.run(t, "systemctl start juistd")
	lx.eventually(t, "reaching fb, upgraded, from the previous release", 3*time.Minute, "ping -c1 -W2 "+fb4, ok)
	fb.eventually(t, "reaching lx on the previous release, upgraded", time.Minute, "ping -c1 -t2 "+lx4, ok)
	if out := fb.run(t, "juist health"); strings.Contains(out, "older juist") || strings.Contains(out, "firewall") {
		t.Fatalf("an upgraded device blames the previous release:\n%s", out)
	}

	lx.run(t, "dpkg -i /tmp/juist.deb >/dev/null && systemctl is-active juistd >/dev/null")
	lx.eventually(t, "juistd answers, upgraded", 2*time.Minute, "juist status", ok)
	lx.eventually(t, "the tunnel on a pair key", 3*time.Minute, pairsCmd, newer(0))
	lx.eventually(t, "reaching fb on a pair key", time.Minute, "ping -c1 -W2 "+fb4, ok)
	fb.eventually(t, "reaching lx on a pair key", time.Minute, "ping -c1 -t2 "+lx4, ok)
	out, bump = pingAcrossBump(t, lx, fb4, func() { fb.run(t, env+"juist rotate group-secret") })
	if lost, gap := lostPings(out, 900); gap {
		t.Fatalf("a gap across the bump at %s, both upgraded: lost %s\n%s", bump, strings.Join(lost, ", "),
			out[max(0, len(out)-300):])
	} else if len(lost) > 0 {
		t.Logf("lost alone across the bump at %s, as the lab's network does: %s", bump, strings.Join(lost, ", "))
	}
	for _, v := range []*vm{fb, lx} {
		v.run(t, env+"juist reset --force --yes")
		v.eventually(t, "in no network", 2*time.Minute, "juist status", has("no network"))
	}
}

// verboseDropIn has Debian's juistd log verbosely, the previous release's too.
const verboseDropIn = "/etc/systemd/system/juistd.service.d/verbose.conf"

// previousDump is the devices v holds, the datagrams between fb and lx on
// their LAN since lx's juistd stopped for fb's upgrade, and the last of what
// v's juistd logged.
func previousDump(v *vm) string {
	logs := "tail -600 /var/log/juistd.log"
	if !v.freebsd {
		logs = "journalctl -u juistd --no-pager -o short-unix --since @$(cat /tmp/pq.restart) | tail -600"
	}
	return "juist devices; echo '== udp/41643 between fb and lx'; head -150 /tmp/pq.udp; echo '== juistd'; " + logs
}

// postQuantum is exit criterion (2) of M15: an epoch bump moves the two to a
// new pair key while a ping every 200 ms across the tunnel, for three
// minutes, past the session's next rekey, which takes the new key up, has
// no gap: a key one side held alone would fail the handshake, retried after
// 5 s. The lab's own network loses an echo now and then, without a bump too,
// so a single one lost alone is said and not counted. And Debian, its juistd
// stopped across two bumps, reaches FreeBSD again and moves on to a new pair
// key.
func postQuantum(t *testing.T, fb, lx *vm, fb4, lx4 string) {
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{fb, lx} {
				out, _ := v.try(diagnose(v), 2*time.Minute)
				t.Logf("%s:\n%s", v.name, out)
			}
			hold(t, fb, lx)
		}
		lx.try("systemctl start juistd", time.Minute)
	})
	lx.eventually(t, "the tunnel on a pair key", 3*time.Minute, pairsCmd, newer(0))
	before := generation(t, lx)
	var moved string
	out, bump := pingAcrossBump(t, lx, fb4, func() {
		fb.run(t, "juist rotate group-secret")
		lx.eventually(t, "a new pair key with fb", 2*time.Minute, pairsCmd, newer(before))
		moved = strings.TrimSpace(lx.run(t, "date +%s.%N"))
	})
	if lost, gap := lostPings(out, 900); gap {
		t.Fatalf("a gap across the epoch bump at %s, the new key in place by %s: lost %s\n%s", bump, moved,
			strings.Join(lost, ", "), out[max(0, len(out)-300):])
	} else if len(lost) > 0 {
		t.Logf("lost alone, as the lab's network does (the bump at %s, the new key by %s): %s", bump, moved,
			strings.Join(lost, ", "))
	}

	asleep := generation(t, lx)
	lx.run(t, "systemctl stop juistd")
	fb.run(t, "juist rotate group-secret && juist rotate group-secret")
	lx.run(t, "systemctl start juistd")
	ok := func(string) bool { return true }
	lx.eventually(t, "reaching fb again", 3*time.Minute, "ping -c1 -W2 "+fb4, ok)
	fb.eventually(t, "reaching lx again", time.Minute, "ping -c1 -t2 "+lx4, ok)
	lx.eventually(t, "a pair key past the bumps", 3*time.Minute, pairsCmd, newer(asleep))
}

// pingAcrossBump pings fb4 from lx every 200 ms for three minutes, bump
// running 5 s in, and returns what ping -D wrote and when bump began. The
// WireGuard handshakes lx sees meanwhile are logged, as what a lost echo
// is set against.
func pingAcrossBump(t *testing.T, lx *vm, fb4 string, bump func()) (out, at string) {
	t.Helper()
	lx.run(t, "rm -f /tmp/pq.ping /tmp/pq.hs; setsid -f tcpdump -n -tt -l -i any "+
		"'udp port 41643 and (udp[8] = 1 or udp[8] = 2)' > /tmp/pq.hs 2>/dev/null < /dev/null; sleep 1; "+
		"setsid -f sh -c 'ping -D -i 0.2 -c 900 -W 1 "+fb4+" > /tmp/pq.ping 2>&1' >/dev/null 2>&1 < /dev/null")
	defer func() {
		hs, _ := lx.try("pkill -f '[t]cpdump -n -tt -l'; cat /tmp/pq.hs", time.Minute)
		t.Logf("handshakes lx saw: %s", strings.Join(strings.Fields(strings.ReplaceAll(hs, "\n", " ; ")), " "))
	}()
	time.Sleep(5 * time.Second)
	at = strings.TrimSpace(lx.run(t, "date +%s.%N"))
	bump()
	out = lx.eventually(t, "the ping across the bump to end", 5*time.Minute, "cat /tmp/pq.ping",
		has("packets transmitted"))
	if strings.Count(out, "icmp_seq=") < 2 {
		t.Fatalf("the ping did not run:\n%s", out)
	}
	return out, at
}

// pairsCmd prints the newest generation of a pair key Debian's juistd
// holds.
const pairsCmd = "/tmp/probe pairs /var/lib/juist/pairs.secret"

func generation(t *testing.T, lx *vm) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(lx.run(t, pairsCmd)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// newer takes what pairsCmd printed past gen.
func newer(gen int) func(string) bool {
	return func(out string) bool {
		n, err := strconv.Atoi(strings.TrimSpace(out))
		return err == nil && n > gen
	}
}

// lostPings names the echoes of count that out, ping -D's, holds no reply
// to, each with the time of the reply before it, and reports a gap: two in a
// row lost, or more than three.
func lostPings(out string, count int) (lost []string, gap bool) {
	at := map[int]string{}
	re := regexp.MustCompile(`^\[([0-9.]+)\].*icmp_seq=(\d+) `)
	for _, l := range strings.Split(out, "\n") {
		if m := re.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[2])
			at[n] = m[1]
		}
	}
	last := "-"
	for n := 1; n <= count; n++ {
		if t, ok := at[n]; ok {
			last = t
			continue
		}
		lost = append(lost, fmt.Sprintf("%d (after %s)", n, last))
		if _, ok := at[n-1]; n > 1 && !ok {
			gap = true
		}
	}
	return lost, gap || len(lost) > 3
}
