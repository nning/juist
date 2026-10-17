//go:build interop && linux

package interop

import (
	"encoding/binary"
	"encoding/hex"
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
	out, bump, _ := pingAcrossBump(t, lx, fb4, false, func() string {
		lx.run(t, env+"juist rotate group-secret")
		return strings.TrimSpace(lx.run(t, "date +%s.%N"))
	})
	lost, gap := lostPings(out)
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
	before := generation(t, lx)
	out, bump, _ = pingAcrossBump(t, lx, fb4, true, func() string {
		fb.run(t, env+"juist rotate group-secret")
		lx.eventually(t, "a new pair key with fb", 2*time.Minute, pairsCmd, newer(before))
		return strings.TrimSpace(lx.run(t, "date +%s.%N"))
	})
	if lost, gap := lostPings(out); gap {
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
// new pair key while a ping every 200 ms across the tunnel, past the next
// handshake, which takes the new key up, has no gap: a key one side held
// alone would fail the handshake, retried after 5 s. The lab's own network
// loses an echo now and then, without a bump too, so a single one lost alone
// is said and not counted. And Debian, its juistd stopped across two bumps,
// reaches FreeBSD again and moves on to a new pair key.
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
	out, bump, _ := pingAcrossBump(t, lx, fb4, true, func() string {
		fb.run(t, "juist rotate group-secret")
		lx.eventually(t, "a new pair key with fb", 2*time.Minute, pairsCmd, newer(before))
		moved = strings.TrimSpace(lx.run(t, "date +%s.%N"))
		return moved
	})
	if lost, gap := lostPings(out); gap {
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

// epochBumps has fb bump the epoch three times, lx asleep across the last
// two, and the two reach each other on a pair key past them.
func epochBumps(t *testing.T, fb, lx *vm, fb4, lx4 string) {
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
	ok := func(string) bool { return true }
	lx.eventually(t, "the tunnel on a pair key", 3*time.Minute, pairsCmd, newer(0))
	before := generation(t, lx)
	fb.run(t, "juist rotate group-secret")
	lx.eventually(t, "a new pair key with fb", 2*time.Minute, pairsCmd, newer(before))
	asleep := generation(t, lx)
	lx.run(t, "systemctl stop juistd")
	fb.run(t, "juist rotate group-secret && juist rotate group-secret")
	lx.run(t, "systemctl start juistd")
	lx.eventually(t, "reaching fb again", 3*time.Minute, "ping -c1 -W2 "+fb4, ok)
	fb.eventually(t, "reaching lx again", time.Minute, "ping -c1 -t2 "+lx4, ok)
	lx.eventually(t, "a pair key past the bumps", 3*time.Minute, pairsCmd, newer(asleep))
}

// pingAcrossBump pings fb4 from lx every 200 ms, bump running 5 s in, until
// 20 s past the first WireGuard session that a handshake 5 s or more after
// the moment bump returns, on lx's clock, made and data then used: the
// device has the new key by then. It pings five minutes at most. It returns
// what ping -D wrote, when bump began and that session's handshake, failing
// t where session is set and no such session came. The handshakes lx saw
// are logged, as what a lost echo is set against.
func pingAcrossBump(t *testing.T, lx *vm, fb4 string, session bool, bump func() string) (out, at, made string) {
	t.Helper()
	lx.run(t, "rm -f /tmp/pq.ping /tmp/pq.wg; setsid -f tcpdump -n -tt -l -x -s 128 -i any "+
		"'udp port 41643 and (udp[8] = 1 or udp[8] = 2 or udp[8] = 4)' > /tmp/pq.wg 2>/dev/null < /dev/null; sleep 1; "+
		"setsid -f sh -c 'ping -D -i 0.2 -c 1500 -W 1 "+fb4+" > /tmp/pq.ping 2>&1' >/dev/null 2>&1 < /dev/null")
	var capture strings.Builder
	defer func() {
		lx.try("pkill -f '[t]cpdump -n -tt -l -x'", time.Minute)
		var hs []string
		for _, h := range wgHandshakes(capture.String()) {
			hs = append(hs, h.String())
		}
		t.Logf("handshakes lx saw: %s", strings.Join(hs, " ; "))
	}()
	time.Sleep(5 * time.Second)
	at = strings.TrimSpace(lx.run(t, "date +%s.%N"))
	since, err := strconv.ParseFloat(bump(), 64)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(6 * time.Minute); ; {
		if time.Now().After(deadline) {
			t.Fatalf("the ping across the bump did not end in 6 minutes")
		}
		// An error's output is none of the capture's bytes.
		if more, err := lx.try(fmt.Sprintf("tail -c +%d /tmp/pq.wg", capture.Len()+1), time.Minute); err == nil {
			capture.WriteString(more)
		}
		if made == "" {
			for _, h := range wgHandshakes(capture.String()) {
				if h.response > since+5 && h.used > 0 {
					made = h.String()
					t.Logf("lab: lx: a session made after the bump at %.3f, used at %.3f", h.response, h.used)
					time.Sleep(20 * time.Second)
					lx.try("pkill -INT -f '[p]ing -D -i 0.2'", time.Minute)
					break
				}
			}
		}
		if o, _ := lx.try("cat /tmp/pq.ping", time.Minute); strings.Contains(o, "packets transmitted") {
			out = o
			break
		}
		time.Sleep(2 * time.Second)
	}
	if strings.Count(out, "icmp_seq=") < 2 {
		t.Fatalf("the ping did not run:\n%s", out)
	}
	if session && made == "" {
		t.Fatalf("no session made after the bump carried data in five minutes")
	}
	return out, at, made
}

// A handshake is a WireGuard response and the first data its initiator
// sent on the session it made, at lx's time.
type handshake struct {
	initiation, response, used float64
}

func (h handshake) String() string {
	return fmt.Sprintf("init %.3f resp %.3f used %.3f", h.initiation, h.response, h.used)
}

// wgHandshakes reads what tcpdump -tt -x wrote of WireGuard's messages and
// returns each response, with the initiation it answers and the first data
// sent to its sender's index: proof the initiator took it.
func wgHandshakes(capture string) []handshake {
	type packet struct {
		at float64
		b  []byte
	}
	var pkts []packet
	for _, l := range strings.Split(capture, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 0:
		case !strings.HasPrefix(l, "\t") && !strings.HasPrefix(l, " "):
			at, err := strconv.ParseFloat(f[0], 64)
			if err == nil {
				pkts = append(pkts, packet{at: at})
			}
		case len(pkts) > 0 && strings.HasPrefix(f[0], "0x"):
			for _, w := range f[1:] {
				b, err := hex.DecodeString(w)
				if err != nil {
					break
				}
				pkts[len(pkts)-1].b = append(pkts[len(pkts)-1].b, b...)
			}
		}
	}
	// The WireGuard message in an IP packet: its type, and the indexes
	// after it.
	message := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		n := 40
		if b[0]>>4 == 4 {
			n = int(b[0]&0xf) * 4
		}
		if len(b) < n+8+12 {
			return nil
		}
		return b[n+8:]
	}
	var hs []handshake
	inits := map[uint32]float64{}
	open := map[uint32]int{} // a response's sender, waiting for data
	for _, p := range pkts {
		m := message(p.b)
		if m == nil {
			continue
		}
		switch m[0] {
		case 1:
			inits[binary.LittleEndian.Uint32(m[4:])] = p.at
		case 2:
			sender, receiver := binary.LittleEndian.Uint32(m[4:]), binary.LittleEndian.Uint32(m[8:])
			hs = append(hs, handshake{initiation: inits[receiver], response: p.at})
			open[sender] = len(hs) - 1
		case 4:
			if i, ok := open[binary.LittleEndian.Uint32(m[4:])]; ok {
				hs[i].used = p.at
				delete(open, binary.LittleEndian.Uint32(m[4:]))
			}
		}
	}
	return hs
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

// lostPings names the echoes out, ping -D's, holds no reply to, each with
// the time of the reply before it, and reports a gap: two in a row lost, or
// more than three. The last echo sent, which an interrupt may have cut
// short of its reply, is not counted.
func lostPings(out string) (lost []string, gap bool) {
	count := 0
	if m := regexp.MustCompile(`(\d+) packets transmitted`).FindStringSubmatch(out); m != nil {
		count, _ = strconv.Atoi(m[1])
		count--
	}
	at := map[int]string{}
	re := regexp.MustCompile(`^\[([0-9.]+)\] \d+ bytes from .*icmp_seq=(\d+) `)
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

// A response proves a session where data then reaches its sender's index;
// one whose session no data used, as a key one side held alone leaves it,
// proves none.
func TestAResponseIsProvedByTheDataItsSessionCarries(t *testing.T) {
	// An IPv4 and UDP header, then a WireGuard message of type typ whose
	// indexes follow, little-endian.
	pkt := func(at string, typ byte, idx ...uint32) string {
		b := make([]byte, 28, 28+16)
		b[0] = 0x45
		b = append(b, typ, 0, 0, 0)
		for _, i := range idx {
			b = binary.LittleEndian.AppendUint32(b, i)
		}
		for len(b) < 28+16 {
			b = append(b, 0)
		}
		// As tcpdump -x prints it: sixteen bytes a row, in groups of two.
		s := at + " eth1  Out IP 10.77.0.3.41643 > 10.77.0.1.41643: UDP, length 148\n"
		for o := 0; o < len(b); o += 16 {
			s += fmt.Sprintf("\t0x%04x: ", o)
			for g := o; g < min(o+16, len(b)); g += 2 {
				s += " " + hex.EncodeToString(b[g:min(g+2, len(b))])
			}
			s += "\n"
		}
		return s
	}
	capture := pkt("100.0", 1, 7) + pkt("100.1", 2, 9, 7) + pkt("100.2", 4, 9) + // proved
		pkt("200.0", 1, 11) + pkt("200.1", 2, 13, 11) + pkt("200.2", 4, 9) // data to the old index
	hs := wgHandshakes(capture)
	if len(hs) != 2 {
		t.Fatalf("%d handshakes: %v", len(hs), hs)
	}
	if hs[0].initiation != 100.0 || hs[0].response != 100.1 || hs[0].used != 100.2 {
		t.Errorf("the first: %v", hs[0])
	}
	if hs[1].response != 200.1 || hs[1].used != 0 {
		t.Errorf("a session no data used: %v", hs[1])
	}
}

func TestLostPingsCountsWhatWasSent(t *testing.T) {
	out := "[1.0] 64 bytes from 1.1.1.1: icmp_seq=1 ttl=64\n[1.2] 64 bytes from 1.1.1.1: icmp_seq=2 ttl=64\n" +
		"[1.4] From 10.77.0.1 icmp_seq=3 Destination Host Unreachable\n" +
		"[1.8] 64 bytes from 1.1.1.1: icmp_seq=5 ttl=64\n6 packets transmitted, 3 received\n"
	lost, gap := lostPings(out)
	if len(lost) != 2 || !gap {
		t.Errorf("lost %v, gap %v; want 3 and 4, a gap, the 6th not counted", lost, gap)
	}
}
