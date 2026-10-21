package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// homeAndVPS is a network of laptop, which founded it, and vps.
func homeAndVPS(t *testing.T) (laptop, vps *daemonDevice) {
	t.Helper()
	laptop = newDaemonDevice(t, nil)
	laptop.mgr.mu.Lock()
	laptop.mgr.answers = true
	laptop.mgr.mu.Unlock()
	laptop.mustRun("create", "home", "--device", "laptop")
	vps = newDaemonDevice(t, nil)
	inv := laptop.start("invite", "--no-lan", "--port", "0", "--yes")
	vps.mustRun("join", inv.waitFor(t, linkRE)[1], "--name", "vps")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	return laptop, vps
}

func (m *peersManager) onlyPeerRoutes(t *testing.T) []netip.Prefix {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.peers) != 1 {
		t.Fatalf("%d peers, want 1", len(m.peers))
	}
	return m.peers[0].Routes
}

func statusOfDaemon(t *testing.T, d *daemonDevice) *ipc.Status {
	t.Helper()
	resp, err := ipc.Call(d.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil || resp.Status == nil {
		t.Fatalf("status: %v", err)
	}
	return resp.Status
}

// daemonLog is the log d's juistd holds.
func daemonLog(t *testing.T, d *daemonDevice) *log.Authority {
	t.Helper()
	resp, err := ipc.Call(d.sock, ipc.Request{Command: ipc.CmdLog})
	if err != nil {
		t.Fatal(err)
	}
	var records []types.AUM
	for _, b := range resp.Records {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, aum)
	}
	auth, err := log.FromRecords(log.NewMemStorage(), records)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

// exitNodesHere skips where there are no exit nodes and subnet routers.
func exitNodesHere(t *testing.T) {
	t.Helper()
	if !servesHere {
		t.Skip("no exit nodes and subnet routers here")
	}
}

func carries(ps []netip.Prefix, a string) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) })
}

// An exit node takes an admin's grant and its operator's word; a device then
// chooses it, sends the internet through it alone, and goes direct again.
func TestAnExitNodeFromGrantToOff(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("a juistd running as root cannot use an exit node")
	}
	laptop, vps := homeAndVPS(t)

	mustContain(t, laptop.mustRun("exit"), "no exit nodes", "juist grant DEVICE exit")
	out, err := laptop.run("exit", "use", "vps")
	if err == nil {
		t.Fatal("chose a device that is no exit node")
	}
	mustContain(t, out+err.Error(), "vps is not an exit node", "juist grant vps exit")

	mustContain(t, laptop.mustRun("grant", "vps", "exit"), "vps: roles exit")
	n, err := resolveDevice(daemonLog(t, laptop).State(), "vps")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(n.Routes, netip.MustParsePrefix("0.0.0.0/0")) || !slices.Contains(n.Routes, netip.MustParsePrefix("::/0")) {
		t.Fatalf("the grant gave vps the routes %v", n.Routes)
	}
	mustContain(t, laptop.mustRun("grant", "vps", "exit"), "vps: unchanged")
	eventually(t, "vps hears of its grant", func() bool {
		return slices.ContainsFunc(statusOfDaemon(t, vps).Devices, func(d ipc.Device) bool {
			return d.Name == "vps" && slices.Contains(d.Roles, types.RoleExit)
		})
	})

	out, err = laptop.run("exit", "use", "vps")
	if err == nil {
		t.Fatal("chose an exit node whose operator has not agreed to serve")
	}
	mustContain(t, out+err.Error(), "vps does not serve as an exit node", "juist exit serve")
	if e, _ := laptop.mgr.exitState(); e != conn.EgressDirect {
		t.Fatalf("a refused choice left egress %v", e)
	}

	eventually(t, "vps serves", func() bool {
		out, err := vps.run("exit", "serve")
		return err == nil && strings.Contains(out, "serving as an exit node")
	})
	if _, s := vps.mgr.exitState(); !carries(s.Routes, "8.8.8.8") || carries(s.Routes, "192.168.1.1") {
		t.Fatalf("vps serves %v", s.Routes)
	}
	mustContain(t, vps.mustRun("status"), "Exit node", "this device serves")
	eventually(t, "laptop hears vps serves", func() bool {
		ex := statusOfDaemon(t, laptop).Exit
		return ex != nil && slices.Contains(ex.Offering, n.Identity)
	})
	// The list says how the last tunnel check found vps, however soon it ran.
	eventually(t, "laptop checks its tunnel to vps", func() bool {
		return slices.ContainsFunc(statusOfDaemon(t, laptop).Reach, func(r ipc.PeerReach) bool { return r.Identity == n.Identity })
	})
	if out := laptop.mustRun("exit"); !regexp.MustCompile(`(?m)^vps +\S+ +serving$`).MatchString(out) {
		t.Fatalf("the list:\n%s", out)
	}

	// Over ssh from the internet, isolated, the session's answers would
	// leave through vps; not isolated, they leave the way they came.
	laptop.cli.env = map[string]string{"SSH_CONNECTION": "8.8.4.4 51022 192.168.1.20 22"}
	out, err = laptop.run("exit", "use", "vps", "--isolate")
	if err == nil {
		t.Fatal("chose an exit node, isolated, that ends this ssh session")
	}
	mustContain(t, out+err.Error(), "this ssh session, from 8.8.4.4, would end: isolated", "--force")
	if e, _ := laptop.mgr.exitState(); e != conn.EgressDirect {
		t.Fatalf("a choice stopped for ssh left egress %v", e)
	}
	// Where the host's own firewall keeps answers from leaving the way they
	// came, as FreeBSD's pf rules of its own, the session would end as well.
	laptop.mgr.mu.Lock()
	laptop.mgr.through = "the host's own pf rules pass what comes in"
	laptop.mgr.mu.Unlock()
	eventually(t, "the status says why answers go through", func() bool {
		ex := statusOfDaemon(t, laptop).Exit
		return ex != nil && ex.AnswersThrough != ""
	})
	out, err = laptop.run("exit", "use", "vps")
	if err == nil {
		t.Fatal("chose an exit node that ends this ssh session by the host's own rules")
	}
	mustContain(t, out+err.Error(), "would end: the host's own pf rules pass what comes in")
	laptop.mgr.mu.Lock()
	laptop.mgr.through = ""
	laptop.mgr.mu.Unlock()
	eventually(t, "the status says answers leave the way they came", func() bool {
		ex := statusOfDaemon(t, laptop).Exit
		return ex != nil && ex.AnswersThrough == ""
	})

	laptop.cli.system = map[string]string{"/etc/resolv.conf": "nameserver 192.168.1.1\nnameserver 9.9.9.9\n"}
	out = laptop.mustRun("exit", "use", "vps")
	mustContain(t, out, "internet via vps", "warning: DNS goes to 192.168.1.1, outside the tunnel")
	if strings.Contains(out, "9.9.9.9") {
		t.Errorf("a resolver the exit node carries was named:\n%s", out)
	}
	mustContain(t, laptop.mustRun("health"), "DNS goes to 192.168.1.1")
	if e, _ := laptop.mgr.exitState(); e != conn.EgressTunnel {
		t.Fatalf("egress %v, want the tunnel", e)
	}
	routes := laptop.mgr.onlyPeerRoutes(t)
	if !carries(routes, "8.8.8.8") || carries(routes, "192.168.1.1") || carries(routes, "10.0.0.1") {
		t.Fatalf("vps carries %v", routes)
	}
	mustContain(t, laptop.mustRun("status"), "Exit node", "vps")
	mustContain(t, laptop.mustRun("exit"), "in use")
	mustContain(t, laptop.mustRun("exit", "use", "vps"), "unchanged: internet via vps")
	laptop.cli.env = map[string]string{"SSH_CONNECTION": "192.168.1.5 51022 192.168.1.20 22"}
	mustContain(t, laptop.mustRun("exit", "use", "vps", "--isolate"), "internet via vps, isolated",
		"warning: answers to connections from the internet go through vps too")
	mustContain(t, laptop.mustRun("status"), "vps, isolated")
	out = laptop.mustRun("exit", "use", "vps")
	mustContain(t, out, "internet via vps")
	if strings.Contains(out, "isolated") || strings.Contains(out, "unchanged") {
		t.Errorf("the isolated choice was not given up:\n%s", out)
	}
	if b, err := os.ReadFile(filepath.Join(laptop.state, statedir.ExitFile)); err != nil ||
		strings.TrimSpace(string(b)) != n.Identity.String() {
		t.Fatalf("the choice kept is %q, %v", b, err)
	}
	if _, err := vps.run("exit", "use", "laptop"); err == nil {
		t.Fatal("vps chose laptop, which is no exit node")
	}

	laptop.mustRun("revoke", "vps", "exit")
	if e, _ := laptop.mgr.exitState(); e != conn.EgressRefused {
		t.Fatalf("after the revoke, egress %v; want refused, not direct", e)
	}
	if r := laptop.mgr.onlyPeerRoutes(t); len(r) != 0 {
		t.Fatalf("vps still carries %d routes", len(r))
	}
	mustContain(t, laptop.mustRun("status"), "internet refused", "has not made it an exit node")
	mustContain(t, laptop.mustRun("exit"), "no exit nodes", "internet traffic refused: vps is in use",
		"juist exit off")
	eventually(t, "vps stops serving", func() bool {
		_, s := vps.mgr.exitState()
		return len(s.Routes) == 0
	})

	mustContain(t, laptop.mustRun("exit", "off"), "internet direct")
	if e, _ := laptop.mgr.exitState(); e != conn.EgressDirect {
		t.Fatalf("after off, egress %v", e)
	}
	mustContain(t, laptop.mustRun("exit", "off"), "unchanged: internet direct")
	mustContain(t, vps.mustRun("exit", "serve", "--stop"), "stopped serving")
	if strings.Contains(vps.mustRun("status"), "Exit node") {
		t.Error("the status speaks of exit nodes with none chosen or served")
	}
}

// Serving can be agreed to before the grant, and starts with it.
func TestServingWaitsForTheGrant(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	out := vps.mustRun("exit", "serve")
	mustContain(t, out, "will serve once an admin makes this device an exit node", "juist grant vps exit")
	mustContain(t, vps.mustRun("status"), "does not serve", "has not made this device an exit node")
	laptop.mustRun("grant", "vps", "exit")
	eventually(t, "vps serves once granted", func() bool {
		_, s := vps.mgr.exitState()
		return len(s.Routes) > 0
	})
}

// DNS to a resolver the exit node does not carry is named; to one it does, or
// on this host, it is not.
func TestDNSOutsideTheTunnel(t *testing.T) {
	files := map[string]string{}
	read := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	overlay := []netip.Prefix{netip.MustParsePrefix("198.18.4.0/22"), netip.MustParsePrefix("fd12:3456:789a::/48")}
	for _, tc := range []struct {
		resolv, resolved string
		want             []string
	}{
		{"nameserver 192.168.1.1\nnameserver 9.9.9.9\n", "", []string{"192.168.1.1"}},
		{"# comment\nnameserver 8.8.8.8\nsearch lan\n", "", nil},
		{"nameserver 127.0.0.53\noptions edns0\n", "nameserver 10.0.0.1\nnameserver fe80::1%eth0\n",
			[]string{"10.0.0.1", "fe80::1%eth0"}},
		{"nameserver 127.0.0.53\n", "nameserver 1.1.1.1\n", nil},
		{"nameserver 127.0.0.1\n", "", nil},
		{"nameserver 198.18.4.1\nnameserver fd12:3456:789a::1\n", "", nil},
		{"nameserver 100.100.100.100\n", "", []string{"100.100.100.100"}},
	} {
		files["/etc/resolv.conf"], files["/run/systemd/resolve/resolv.conf"] = tc.resolv, tc.resolved
		var got []string
		for _, a := range dnsOutside(read, overlay) {
			got = append(got, a.String())
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v, want %v", tc.resolv, got, tc.want)
		}
	}
}

// The setup script's sysctl file says for which devices it was kept.
func TestExitSetUpReadsTheDevices(t *testing.T) {
	read := func(string) ([]byte, error) {
		return []byte("# Kept by juist's exit-node.sh\n# for: juist0 juist2\n# was: 0 0\nnet.ipv4.ip_forward = 1\n"), nil
	}
	if !exitSetUp(read, "juist2") || exitSetUp(read, "juist1") || exitSetUp(read, "juist") {
		t.Error("the devices were misread")
	}
	if exitSetUp(func(string) ([]byte, error) { return nil, os.ErrNotExist }, "juist0") {
		t.Error("a missing file said the host was set up")
	}
}

// On a host in two networks, one uses an exit node at a time, and the hint
// names the other network as the command takes it.
func TestOneNetworkAHostUsesAnExitNodeThrough(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.mustRun("create", "work", "--device", "laptop")
	k, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id := k.Public()
	if _, err := ipc.Call(h.layout.socket(0), ipc.Request{Command: ipc.CmdExit, ExitNode: id}); err != nil {
		t.Fatal(err)
	}
	_, err = h.run("--network", "work", "exit", "use", "vps")
	if err == nil || !strings.Contains(err.Error(), "home (juist0) uses an exit node already") ||
		!strings.Contains(err.Error(), "hint: juist exit off home") {
		t.Fatalf("use in a second network: %v", err)
	}
	mustContain(t, h.mustRun("exit", "off", "home"), "internet direct")
}

// A device that serves and uses another stops serving, and says so; one
// that uses another is not set up to serve.
func TestServingAndUsingExcludeEachOther(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	laptop.mustRun("grant", "vps", "exit")
	laptop.mustRun("grant", "laptop", "exit")
	mustContain(t, laptop.mustRun("__complete", "exit", "use", ""), "vps\n")
	if out := laptop.mustRun("__complete", "exit", "use", ""); strings.Contains(out, "laptop") {
		t.Errorf("completion offers this device:\n%s", out)
	}
	mustContain(t, vps.mustRun("exit", "serve", "--stop"), "unchanged: not serving")
	mustContain(t, vps.mustRun("exit", "off"), "unchanged: internet direct")
	eventually(t, "both serve", func() bool {
		a, errA := laptop.run("exit", "serve")
		b, errB := vps.run("exit", "serve")
		return errA == nil && errB == nil && strings.Contains(a, "serving as") && strings.Contains(b, "serving as")
	})
	eventually(t, "vps hears laptop serves", func() bool {
		ex := statusOfDaemon(t, vps).Exit
		return ex != nil && len(ex.Offering) == 1
	})
	mustContain(t, vps.mustRun("exit", "use", "laptop"), "internet via laptop",
		"warning: this device stops serving as an exit node")
	if _, s := vps.mgr.exitState(); len(s.Routes) > 0 {
		t.Error("vps serves on while it uses laptop")
	}
	out, err := vps.run("exit", "serve")
	if err == nil || !strings.Contains(err.Error(), "this device uses an exit node itself") ||
		!strings.Contains(err.Error(), "juist exit off") {
		t.Fatalf("serve while using one (%v):\n%s", err, out)
	}
}

// --force chooses an exit node that does not serve: the outcome is the
// choice, and the internet is refused, which is said.
func TestForceChoosesAnExitNodeThatDoesNotServe(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	laptop, _ := homeAndVPS(t)
	laptop.mustRun("grant", "vps", "exit")
	out := laptop.mustRun("exit", "use", "vps", "--force")
	mustContain(t, out, "chose vps", "warning: internet traffic refused: its operator has not agreed to serve")
	if strings.Contains(out, "internet via") {
		t.Errorf("a refused choice reads as in force:\n%s", out)
	}
	if e, _ := laptop.mgr.exitState(); e != conn.EgressRefused {
		t.Errorf("egress %v, want refused", e)
	}
	mustContain(t, laptop.mustRun("exit", "off"), "internet direct")
}

// The status says where the exit node in use does not answer.
func TestTheStatusSaysAnExitNodeIsOffline(t *testing.T) {
	id := types.Identity{1}
	for _, tc := range []struct {
		reach ipc.PeerReach
		want  string
	}{
		{ipc.PeerReach{Identity: id, Absent: true}, "vps, offline"},
		{ipc.PeerReach{Identity: id}, "vps, not answering"},
	} {
		st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Exit: &ipc.Exit{Node: id, Name: "vps"}},
			Tunnels: ipc.Tunnels{TunnelsChecked: true, Reach: []ipc.PeerReach{tc.reach}}}
		v := statusOf(st, time.Now(), func(_, s string) string { return s })
		found := false
		for _, l := range v.head {
			found = found || l.label == "Exit node" && l.text == tc.want
		}
		if !found {
			t.Errorf("%+v: the head is %+v, want %q", tc.reach, v.head, tc.want)
		}
	}
}

// Forwarding is on where the host forwards IPv4, and IPv6 where it has it.
func TestForwardingIsReadFromTheKernel(t *testing.T) {
	for _, tc := range []struct {
		v4, v6 string
		want   bool
	}{{"1\n", "1\n", true}, {"1\n", "", true}, {"0\n", "1\n", false}, {"1\n", "0\n", false}, {"", "1\n", false}} {
		read := func(p string) ([]byte, error) {
			v := map[bool]string{true: tc.v6, false: tc.v4}[strings.Contains(p, "ipv6")]
			if v == "" {
				return nil, os.ErrNotExist
			}
			return []byte(v), nil
		}
		if got := forwarding(read); got != tc.want {
			t.Errorf("v4 %q v6 %q: %v", tc.v4, tc.v6, got)
		}
	}
}

// On a host in two networks that both serve, one that stops takes its device
// out of the setup, which keeps forwarding for the other; one network serving
// keeps the other from using an exit node, and one using keeps the other from
// serving.
func TestTwoNetworksServingAndUsing(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.mustRun("create", "work", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.exitScript = filepath.Join(t.TempDir(), "exit-node.sh")
	if err := os.WriteFile(h.layout.exitScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.cli.system = map[string]string{exitSysctl: "# for: juist0 juist1\n",
		"/proc/sys/net/ipv4/conf/all/forwarding": "1\n", "/proc/sys/net/ipv6/conf/all/forwarding": "1\n"}
	on := true
	for n := range 2 {
		if _, err := ipc.Call(h.layout.socket(n), ipc.Request{Command: ipc.CmdExit, Serve: &on}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := h.run("--network", "work", "exit", "use", "vps")
	if err == nil || !strings.Contains(err.Error(), "home (juist0) serves as an exit node") ||
		!strings.Contains(err.Error(), "hint: juist exit serve --stop home") {
		t.Fatalf("use beside a network that serves: %v", err)
	}
	mustContain(t, h.mustRun("exit", "serve", "--stop", "home"), "stopped serving")
	if b, _ := os.ReadFile(calls); !helperSetsUpHost && string(b) != "off juist0\n" {
		t.Errorf("the setup script ran %q, want off juist0", b)
	}
	k, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(h.layout.socket(0), ipc.Request{Command: ipc.CmdExit, ExitNode: k.Public()}); err != nil {
		t.Fatal(err)
	}
	_, err = h.run("--network", "work", "exit", "serve")
	if err == nil || !strings.Contains(err.Error(), "home (juist0) uses an exit node") ||
		!strings.Contains(err.Error(), "hint: juist exit off home") {
		t.Fatalf("serve beside a network that uses one: %v", err)
	}
}

// Strict reverse-path filtering is the higher of all's and the interface's
// own being 1; loopback and juist's devices do not count.
func TestStrictReversePathFiltering(t *testing.T) {
	for _, tc := range []struct {
		files map[string]string
		want  []string
	}{
		{map[string]string{"all": "2", "eth0": "0"}, nil},
		{map[string]string{"all": "1", "eth0": "0"}, []string{"eth0", "wlan0"}},
		{map[string]string{"all": "1", "eth0": "2"}, []string{"wlan0"}},
		{map[string]string{"all": "0", "wlan0": "1"}, []string{"wlan0"}},
		{map[string]string{"all": "1", "lo": "1", "juist0": "1"}, []string{"eth0", "wlan0"}},
	} {
		read := func(p string) ([]byte, error) {
			for n, v := range tc.files {
				if p == "/proc/sys/net/ipv4/conf/"+n+"/rp_filter" {
					return []byte(v + "\n"), nil
				}
			}
			return nil, os.ErrNotExist
		}
		if got := strictRP(read, []string{"lo", "eth0", "wlan0", "juist0"}); !slices.Equal(got, tc.want) {
			t.Errorf("%v: %v, want %v", tc.files, got, tc.want)
		}
	}
}

// The warning of firewalld's strict IPv6 reverse-path filter follows juistd,
// which reads the ruleset: firewalld's configuration is root's alone, and
// unread says nothing.
func TestFirewalldStrictReversePath(t *testing.T) {
	c := newCLI(t)
	for _, strict := range []bool{false, true} {
		out := &syncBuffer{}
		a := c.app(out, "")
		a.emit(a.strictRPNotes(&ipc.Exit{Name: "vps", StrictRP6: strict}))
		if got := strings.Contains(out.String(), "firewalld's strict IPv6 reverse-path filter"); got != strict {
			t.Errorf("strict %v, warned:\n%s", strict, out.String())
		}
	}
}

// A change approved from its file is handed on as proposed by the one other
// admin whose signature on it holds, and by nobody where it does not.
func TestAFileIsHandedOnByItsSigner(t *testing.T) {
	t.Parallel()
	alice := newCLI(t)
	alice.mustRun("create", "home", "--device", "laptop")
	auth := openLog(t, alice)
	keys, err := alice.home2().adminKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("alice's keys: %v", err)
	}
	aum, err := auth.Builder().RenameNetwork("office")
	if err != nil {
		t.Fatal(err)
	}
	if err := aum.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	bobCLI := newCLI(t)
	bob := bobCLI.app(&syncBuffer{}, "")
	bob.home = bobCLI.home2()
	own := alice.app(&syncBuffer{}, "")
	own.home = alice.home2()
	if got := bob.handedOn(auth.State(), &aum); got != keys[0].Public() {
		t.Errorf("handed on by %v, want alice's key", got)
	}
	if got := own.handedOn(auth.State(), &aum); !got.IsZero() {
		t.Errorf("alice's own file is handed on by %v", got)
	}
	aum.Signatures[0].PQ[0] ^= 1
	if got := bob.handedOn(auth.State(), &aum); !got.IsZero() {
		t.Errorf("a forged signature made %v the proposer", got)
	}
}

// The role is "exit", however it is cased.
func TestTheExitRoleByName(t *testing.T) {
	for _, name := range []string{"exit", "Exit"} {
		if r, err := parseRole(name); err != nil || r != types.RoleExit {
			t.Errorf("%q: %v, %v", name, r, err)
		}
	}
	if got := describeRoles([]types.Role{types.RoleExit}); got != "exit" {
		t.Errorf("the role reads %q", got)
	}
}
