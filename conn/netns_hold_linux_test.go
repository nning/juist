//go:build linux

package conn

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"
)

// command sends cmd to the node's helper and returns its answer, a line
// starting with want.
func (n *netnsNode) command(cmd, want string) string {
	t := n.lab.t
	t.Helper()
	if _, err := io.WriteString(n.stdin, cmd+"\n"); err != nil {
		t.Fatalf("node %s: sending %s: %v", n.name, cmd, err)
	}
	return n.expect(want, 30*time.Second)
}

// A streamStat is what a held stream reports.
type streamStat struct {
	echoed int64
	gap    time.Duration
	err    string
}

func (n *netnsNode) streamStat(name string) streamStat {
	t := n.lab.t
	t.Helper()
	f := strings.Fields(n.command("STREAMSTAT "+name, "STREAM "))
	if len(f) != 4 {
		t.Fatalf("node %s: a stream stat of %q", n.name, f)
	}
	echoed, _ := strconv.ParseInt(f[1], 10, 64)
	ms, _ := strconv.ParseInt(f[2], 10, 64)
	return streamStat{echoed: echoed, gap: time.Duration(ms) * time.Millisecond, err: f[3]}
}

// setSelf gives n's running data plane its key and addresses, and each of
// peers n as it is now.
func (n *netnsNode) setSelf(peers ...*netnsNode) {
	n.command("SELF "+rawHex(n.nodeKey.Raw32())+" "+joinPrefixes(n.addrs), "OK")
	for _, p := range peers {
		p.command("PEERSET "+encodePeers([]*netnsNode{n}), "OK")
	}
}

// maxStall is the longest a held stream may wait across a change: a
// handshake, retried after WireGuard's RekeyTimeout and its jitter when two
// initiations cross.
const maxStall = 6 * time.Second

// Exit criterion (6) of M15: a TCP stream across the tunnel survives what
// changes on a running device, with no reset and no stall longer than a
// handshake. Each change is made while the streams run, and they are checked
// after it; the IPv4 one ends with the address it was opened from.
func TestNetnsAStreamSurvivesChanges(t *testing.T) {
	lab := newNetnsLab(t)
	a := lab.addNode("a", 1)
	b := lab.addNode("b", 2)
	a.start([]*netnsNode{b}, tcpEchoPort)
	b.start([]*netnsNode{a}, 0)
	if err := b.pingUntil(a.addrs[0].Addr(), 60*time.Second); err != nil {
		t.Fatalf("b cannot reach a: %v", err)
	}
	// Keys first: a peer newly keyed passes nothing for a moment, by design.
	k1 := hex.EncodeToString(make([]byte, 31)) + "01"
	a.command("PSK "+k1, "OK")
	b.command("PSK "+k1, "OK")
	if err := b.pingUntil(a.addrs[0].Addr(), 30*time.Second); err != nil {
		t.Fatalf("b cannot reach a under a preshared key: %v", err)
	}

	v4, v6 := a.addrs[0].Addr(), a.addrs[1].Addr()
	b.command("STREAM v4 "+netip.AddrPortFrom(v4, tcpEchoPort).String(), "OK")
	b.command("STREAM v6 "+netip.AddrPortFrom(v6, tcpEchoPort).String(), "OK")
	last := map[string]streamStat{}
	check := func(what string, names ...string) {
		t.Helper()
		time.Sleep(3 * time.Second)
		for _, name := range names {
			s := b.streamStat(name)
			for deadline := time.Now().Add(maxStall); s.err == "-" && s.echoed <= last[name].echoed && time.Now().Before(deadline); {
				time.Sleep(250 * time.Millisecond)
				s = b.streamStat(name)
			}
			switch {
			case s.err != "-":
				t.Fatalf("%s: the %s stream ended: %s", what, name, s.err)
			case s.echoed <= last[name].echoed:
				t.Fatalf("%s: nothing came back on the %s stream since (%d bytes)", what, name, s.echoed)
			case s.gap > maxStall:
				t.Errorf("%s: the %s stream stalled for %v", what, name, s.gap)
			}
			t.Logf("%s: %d bytes echoed on %s, the longest stall %v", what, s.echoed, name, s.gap)
			last[name] = s
		}
	}
	check("streaming", "v4", "v6")

	k2 := hex.EncodeToString(make([]byte, 31)) + "02"
	a.command("PSK "+k2, "OK")
	b.command("PSK "+k2, "OK")
	if r := b.command("REKEY", "REKEYED "); r == "REKEYED none" {
		t.Fatal("no handshake under the new preshared key")
	}
	check("a new preshared key", "v4", "v6")

	b.command("EGRESS "+EgressRefused.String(), "OK")
	b.command("EGRESS "+EgressDirect.String(), "OK")
	check("egress refused and back", "v4", "v6")

	lab.forwardBoth(a)
	a.command("SERVE 100.64.0.0/24,fd7a:115c:a1e0::/48", "OK")
	a.command("SERVE none", "OK")
	check("serving as an exit node and not", "v4", "v6")

	a.nodeKey = key.NewNode()
	a.setSelf(b)
	check("a new key", "v4", "v6")

	// A renumbering as the daemon gives it: the retiring address first,
	// until it goes.
	moved := func(n *netnsNode) netip.Prefix { return netip.MustParsePrefix(fmt.Sprintf("10.7.0.%d/32", n.id)) }
	for _, n := range []*netnsNode{a, b} {
		n.addrs = []netip.Prefix{n.addrs[1], n.addrs[0], moved(n)}
	}
	a.setSelf(b)
	b.setSelf(a)
	check("a renumbering under way", "v4", "v6")
	if err := b.pingUntil(moved(a).Addr(), 10*time.Second); err != nil {
		t.Errorf("b cannot reach a at its new address: %v", err)
	}
	for _, n := range []*netnsNode{a, b} {
		n.addrs = []netip.Prefix{n.addrs[0], moved(n)}
	}
	a.setSelf(b)
	b.setSelf(a)
	check("a renumbering done", "v6")
	if err := b.pingUntil(moved(a).Addr(), 10*time.Second); err != nil {
		t.Errorf("b cannot reach a at its new address: %v", err)
	}
}
