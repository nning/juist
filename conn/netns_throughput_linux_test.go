//go:build linux

package conn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"testing"
	"time"
)

const (
	iperfPort = 5201
	proxyPort = 5202
)

// TestNetnsThroughput measures with iperf3 what each path through the tunnel
// carries: the tunnel itself, to a confined peer, through an exit node, to a
// service member's network stack, and through a proxy on the host. It runs
// where JUIST_THROUGHPUT is set, as make throughput sets it, and logs one
// THROUGHPUT line a path, for docs/12-validating.md.
func TestNetnsThroughput(t *testing.T) {
	if os.Getenv("JUIST_THROUGHPUT") == "" {
		t.Skip("JUIST_THROUGHPUT is not set; make throughput sets it")
	}
	if _, err := exec.LookPath("iperf3"); err != nil {
		t.Fatal("no iperf3")
	}
	// once is one iperf3 run of 5 seconds, what arrived in Mbit/s; extra
	// flags go to the client.
	once := func(t *testing.T, lab *netnsLab, server, client *netnsNode, to netip.Addr, port int, extra ...string) float64 {
		t.Helper()
		var said bytes.Buffer
		srvArgs := []string{"iperf3", "-s", "-1", "--forceflush", "-p", strconv.Itoa(iperfPort)}
		if port == iperfPort {
			// Its answers come from the address asked, as a server's on
			// the internet do, not from where the host would send.
			srvArgs = append(srvArgs, "-B", to.String())
		}
		srv := lab.exec(server, srvArgs...)
		srv.Stdout, srv.Stderr = &said, &said
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			srv.Process.Kill()
			srv.Wait()
		}()
		for i := 0; ; i++ {
			ss, _ := lab.exec(server, "ss", "-ltnH", "sport", "= :"+strconv.Itoa(iperfPort)).Output()
			if len(bytes.TrimSpace(ss)) > 0 {
				break
			}
			if i == 100 {
				t.Fatalf("iperf3 is not listening:\n%s", said.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
		args := append([]string{"iperf3", "-c", to.String(), "-p", strconv.Itoa(port), "-t", "5", "-J"}, extra...)
		out, err := lab.exec(client, args...).Output()
		if err != nil {
			ss, _ := lab.exec(server, "ss", "-ltnp").CombinedOutput()
			t.Fatalf("iperf3 to %v: %v\n%s\nthe server said:\n%s\nlistening there:\n%s", to, err, out, said.String(), ss)
		}
		var r struct {
			End struct {
				Received struct {
					BitsPerSecond float64 `json:"bits_per_second"`
				} `json:"sum_received"`
				Sum struct {
					BitsPerSecond float64 `json:"bits_per_second"`
					LostPercent   float64 `json:"lost_percent"`
				} `json:"sum"`
			} `json:"end"`
		}
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("iperf3's report: %v", err)
		}
		if r.End.Received.BitsPerSecond == 0 { // UDP
			return r.End.Sum.BitsPerSecond * (1 - r.End.Sum.LostPercent/100) / 1e6
		}
		return r.End.Received.BitsPerSecond / 1e6
	}
	// measure logs the median of three runs, and the least and most.
	measure := func(t *testing.T, path string, lab *netnsLab, server, client *netnsNode, to netip.Addr, port int, extra ...string) {
		t.Helper()
		var runs []float64
		for range 3 {
			runs = append(runs, once(t, lab, server, client, to, port, extra...))
		}
		slices.Sort(runs)
		t.Logf("THROUGHPUT %-12s %6.0f Mbit/s (%.0f to %.0f)", path, runs[1], runs[0], runs[2])
	}

	t.Run("tunnel", func(t *testing.T) {
		lab := newNetnsLab(t)
		a, b := lab.addNode("a", 1), lab.addNode("b", 2)
		a.start([]*netnsNode{b}, 0)
		b.start([]*netnsNode{a}, 0)
		if err := b.pingUntil(a.addrs[0].Addr(), 60*time.Second); err != nil {
			t.Fatal(err)
		}
		measure(t, "tunnel", lab, a, b, a.addrs[0].Addr(), iperfPort)
		a.command("ACCESS "+strconv.Itoa(iperfPort), "OK")
		measure(t, "confined", lab, a, b, a.addrs[0].Addr(), iperfPort)
		a.command(fmt.Sprintf("PROXY %v 127.0.0.1:%d", netip.AddrPortFrom(a.addrs[0].Addr(), proxyPort), iperfPort), "OK")
		a.command("ACCESS "+strconv.Itoa(proxyPort), "OK")
		measure(t, "proxy", lab, a, b, a.addrs[0].Addr(), proxyPort)
		// The proxy alone, the tunnel out of the way.
		a.command(fmt.Sprintf("PROXY 127.0.0.1:%d 127.0.0.1:%d", proxyPort+1, iperfPort), "OK")
		measure(t, "proxy alone", lab, a, a, netip.MustParseAddr("127.0.0.1"), proxyPort+1)
	})

	t.Run("exit node", func(t *testing.T) {
		lab := newNetnsLab(t)
		client, exit, web := lab.addNode("c", 1), lab.addNode("x", 2), lab.addNode("w", 9)
		internet := netip.MustParseAddr("1.1.1.1")
		lab.runIn(web, "addr", "add", internet.String()+"/32", "dev", "lo")
		lab.runIn(exit, "route", "add", internet.String()+"/32", "via", web.underlay.String(), "dev", exit.veth)
		lab.forwardBoth(exit)
		exit.carries = Internet(true, true, nil)
		exit.env = append(exit.env, envServe+"=100.64.0.0/24,fd7a:115c:a1e0::/48")
		client.env = append(client.env, envEgress+"="+EgressTunnel.String())
		exit.start([]*netnsNode{client}, 0)
		client.start([]*netnsNode{exit}, 0)
		if err := client.pingUntil(internet, 60*time.Second); err != nil {
			t.Fatal(err)
		}
		measure(t, "exit node", lab, web, client, internet, iperfPort)
		// What the internet sends back, by UDP, as QUIC does: what UDP GRO
		// forwarding on the exit node's uplink is for.
		measure(t, "exit UDP", lab, web, client, internet, iperfPort, "-u", "-b", "4G", "-l", "1200", "-R")
	})

	t.Run("netstack", func(t *testing.T) {
		lab := newNetnsLab(t)
		a, b := lab.addNode("a", 1), lab.addNode("b", 2)
		a.env = append(a.env, fmt.Sprintf("%s=%d>127.0.0.1:%d", envNetstack, proxyPort, iperfPort))
		a.start([]*netnsNode{b}, 0)
		b.start([]*netnsNode{a}, 0)
		measure(t, "netstack", lab, a, b, a.addrs[0].Addr(), proxyPort)
	})
}
