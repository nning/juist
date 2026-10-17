package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// Names are published under the network's domain, one label on one device
// each, and the domain goes only once none is published under it.
func TestPublishAddAndRemove(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	if out, err := admin.run("publish", "add", "nas", "immich"); err == nil ||
		!strings.Contains(err.Error(), "hint: juist network domain") {
		t.Fatalf("a name published without a domain: %v\n%s", err, out)
	}
	mustContain(t, admin.mustRun("network", "domain", "Pub.Example.org"), "domain pub.example.org",
		"warning: every member then resolves pub.example.org through juistd, names on or not, with DNSSEC off for it")
	mustContain(t, admin.mustRun("network", "domain", "pub.example.org"), "unchanged")
	mustContain(t, admin.mustRun("network"), "pub.example.org")

	mustContain(t, admin.mustRun("publish", "add", "nas", "immich"), "nas: publishes immich.pub.example.org:443",
		"hint: on nas, juist publish serve")
	mustContain(t, admin.mustRun("publish", "add", "nas", "photos.pub.example.org", "2283", "--proxy"),
		"immich.pub.example.org:443, photos.pub.example.org:2283")
	mustContain(t, admin.mustRun("publish"), "photos.pub.example.org", "2283 (proxy protocol)")
	if out := admin.mustRun("devices"); !strings.Contains(out, "publishes") || strings.Contains(out, "immich") {
		t.Errorf("devices does not say nas publishes, or names what, which juist publish lists:\n%s", out)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"publish", "add", "laptop", "immich"}, "hint: juist publish remove nas immich"},
		{[]string{"publish", "add", "nas", "a.b"}, "one label"},
		{[]string{"publish", "add", "nas", "Im_mich"}, "no name to publish"},
		{[]string{"publish", "add", "nas", "web", "0"}, "no port"},
		{[]string{"publish", "remove", "laptop", "immich"}, "does not publish immich"},
		{[]string{"network", "domain", "off"}, "hint: juist publish remove nas"},
	} {
		if out, err := admin.run(tc.args...); err == nil || !strings.Contains(out+err.Error(), tc.want) {
			t.Errorf("juist %q: %v\n%s", tc.args, err, out)
		}
	}
	mustContain(t, admin.mustRun("network", "domain", "pub.example.net"), "domain pub.example.net")
	mustContain(t, admin.mustRun("publish"), "immich.pub.example.net")
	mustContain(t, admin.mustRun("publish", "rm", "nas", "immich"), "nas: publishes photos.pub.example.net:2283")
	mustContain(t, admin.mustRun("publish", "rm", "nas", "photos"), "nas: publishes nothing")
	mustContain(t, admin.mustRun("network", "domain", "off"), "no domain")
}

// An ingress is a role of its own, beside no voucher and no exit, and its
// operator is told what to run.
func TestGrantAnIngress(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop", "--voucher")
	enrollDevice(t, admin, "vps")
	mustContain(t, admin.mustRun("grant", "vps", "ingress"), "vps: roles ingress", "hint: on vps, juist ingress serve")
	if out := admin.mustRun("grant", "vps", "relay"); !strings.Contains(out, "vps: roles ingress, relay") ||
		strings.Contains(out, "hint:") {
		t.Errorf("a role granted beside the ingress hints again:\n%s", out)
	}
	for args, want := range map[[3]string]string{
		{"grant", "vps", "exit"}:       "vps holds the role ingress, which the role exit excludes\nhint: juist revoke vps ingress",
		{"grant", "laptop", "ingress"}: "laptop holds the role voucher, which the role ingress excludes",
	} {
		if out, err := admin.run(args[:]...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("juist %q: %v\n%s", args, err, out)
		}
	}
	// Withdrawn, the role no longer confines the device.
	mustContain(t, admin.mustRun("revoke", "vps", "ingress"), "vps: roles relay",
		"warning: vps is confined no more, now a member like any other",
		"hint: one that may be compromised goes by juist remove vps", "hint: on vps, juist ingress serve --stop")
}

// An approver reads a change of published names as what the internet then
// reaches.
func TestAPublishChangeSaysWhatItPublishes(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	c.mustRun("network", "domain", "pub.example.org")
	c.mustRun("publish", "add", "laptop", "immich")
	auth := openLog(t, c)
	self := nodeKeysOf(t, c).Identity.Public()
	aum, err := auth.Builder().SetPublished(self, []types.PublishedName{{Label: "photos", Port: 2283, Proxy: true}})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"),
		"publishes photos.pub.example.org on port 2283 of laptop", "with PROXY protocol",
		"no longer publishes immich.pub.example.org")
}

// A device serves what is published on it once its operator agrees, and the
// status says what it serves, or why not.
func TestPublishServe(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	mustContain(t, vps.mustRun("publish", "serve"), "will serve once an admin publishes", "hint: juist publish add vps NAME")
	mustContain(t, vps.mustRun("publish", "serve", "--stop"), "stopped serving")
	laptop.mustRun("network", "domain", "pub.example.org")
	mustContain(t, laptop.mustRun("publish", "add", "vps", "immich"), "hint: on vps, juist publish serve")
	eventually(t, "the vps learns what it publishes", func() bool {
		return strings.Contains(vps.mustRun("status"), "not served here: not agreed to on this device")
	})
	mustContain(t, vps.mustRun("publish", "serve"), "serving immich.pub.example.org")
	mustContain(t, vps.mustRun("status"), "this device serves immich.pub.example.org")
	eventually(t, "the laptop hears the vps serves", func() bool {
		return slices.ContainsFunc(statusOfDaemon(t, laptop).Devices, func(d ipc.Device) bool { return d.Serving })
	})
	if out := laptop.mustRun("publish", "add", "vps", "photos"); strings.Contains(out, "hint:") {
		t.Errorf("a name published on a device that serves hints:\n%s", out)
	}
	mustContain(t, vps.mustRun("publish", "serve", "--stop"), "stopped serving")
	mustContain(t, vps.mustRun("publish", "serve", "--stop"), "unchanged: not serving")
}

// A name an admin publishes on their own device is served at once, the
// admin being its operator.
func TestPublishingOnThisDeviceServesIt(t *testing.T) {
	t.Parallel()
	laptop, _ := homeAndVPS(t)
	laptop.mustRun("network", "domain", "pub.example.org")
	mustContain(t, laptop.mustRun("publish", "add", "laptop", "immich"), "laptop: publishes immich.pub.example.org:443",
		"serving immich.pub.example.org", "warning: a server published from this device")
	mustContain(t, laptop.mustRun("status"), "this device serves immich.pub.example.org")
	if out := laptop.mustRun("publish", "add", "laptop", "photos"); strings.Contains(out, "warning:") {
		t.Errorf("a second name warns again:\n%s", out)
	}
}

// A name published on a service member asks nothing more of its operator,
// whose juistd --serve agreed already.
func TestPublishingOnAServiceMemberHintsNothing(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "svc")
	admin.mustRun("grant", "svc", "service")
	admin.mustRun("network", "domain", "pub.example.org")
	if out := admin.mustRun("publish", "add", "svc", "web"); strings.Contains(out, "hint:") {
		t.Errorf("publishing on a service member hints:\n%s", out)
	}
}

// juist invite --service admits a service member publishing its name, in
// one step, which the approval says.
func TestInviteAServiceMember(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	if _, err := admin.run("invite", "--service", "web"); err == nil || !strings.Contains(err.Error(), "no domain") {
		t.Fatalf("a service member invited with no domain: %v", err)
	}
	admin.mustRun("network", "domain", "pub.example.org")
	if _, err := admin.run("invite", "--service", "web", "--relay"); err == nil || !strings.Contains(err.Error(), "no other role") {
		t.Fatalf("a service member invited as a relay too: %v", err)
	}
	inv, link := startInvite(t, admin, "--service", "web.pub.example.org")
	inv.waitFor(t, regexp.MustCompile(`invite to "home" as service`))
	newCLI(t).mustRun("join", link, "--name", "svc")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	mustContain(t, admin.mustRun("devices"), "svc", "service")
	mustContain(t, admin.mustRun("publish"), "web.pub.example.org", "svc")

	auth := openLog(t, admin)
	n := types.NodeRecord{Name: "svc2", Published: []types.PublishedName{{Label: "blog", Port: 443}}}
	aum := types.AUM{Kind: types.KindAddNode, Node: &n}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"), "publishing blog.pub.example.org on port 443 of it")
}

// What the terminator says decides whether juist ends TLS where a name is
// published: where it listens, it does; where another program holds the
// port, it says so.
func TestTheTerminatorsWordDecides(t *testing.T) {
	at := "100.64.0.1:443"
	for _, tc := range []struct {
		t         *ipc.Terminator
		listening bool
		err       string
	}{
		{nil, false, ""},
		{&ipc.Terminator{Listening: []string{at}}, false, ""},
		{&ipc.Terminator{Running: true}, false, ""},
		{&ipc.Terminator{Running: true, Listening: []string{at}}, true, ""},
		{&ipc.Terminator{Running: true, Unbound: []string{at}}, false, "another program holds port 443 on 100.64.0.1"},
	} {
		if tc.t != nil && len(tc.t.Unbound) > 0 {
			_, err := terminatorAt(tc.t, at, ipc.PublishedTarget{Name: "mc.pub.example.org", Public: 25565})
			if err == nil || !strings.Contains(err.Error(), "where juist would pass mc.pub.example.org by TCP") {
				t.Errorf("a name by TCP: %v", err)
			}
		}
		listening, err := terminatorAt(tc.t, at, ipc.PublishedTarget{Name: "immich.pub.example.org"})
		if listening != tc.listening || (err == nil) != (tc.err == "") || err != nil && !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%+v: %v, %v", tc.t, listening, err)
		}
	}
}

// A label another device holds is refused before anything is asked of
// anyone: an invite says so before its guest joins, and publishing says
// whose it is.
func TestATakenLabelIsSaidAtOnce(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	admin.mustRun("network", "domain", "pub.example.org")
	admin.mustRun("publish", "add", "nas", "web")
	if _, err := admin.run("invite", "--service", "web"); err == nil || !strings.Contains(err.Error(), "web.pub.example.org is published on nas already") {
		t.Errorf("an invite for a taken label: %v", err)
	}
	admin.mustRun("grant", "laptop", "publish")
	if _, err := admin.run("publish", "add", "nas", "laptop"); err == nil || !strings.Contains(err.Error(), "laptop.pub.example.org is laptop's own name") {
		t.Errorf("publishing a share holder's label: %v", err)
	}
}

// The domain itself is published spelled out, by one device, which the
// approval says; its own address records are hinted at, and it is removed
// as any name is.
func TestPublishTheDomainItself(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	admin.mustRun("network", "domain", "pub.example.org")
	mustContain(t, admin.mustRun("publish", "add", "nas", "pub.example.org"), "nas: publishes pub.example.org:443",
		"hint: pub.example.org needs A and AAAA records of its own")
	mustContain(t, admin.mustRun("publish"), "pub.example.org")
	if _, err := admin.run("publish", "add", "laptop", "pub.example.org", "8443"); err == nil ||
		!strings.Contains(err.Error(), "pub.example.org is published on nas already") {
		t.Errorf("the domain published twice: %v", err)
	}
	if _, err := admin.run("names", "add", "laptop", "pub.example.org"); err == nil {
		t.Error("a name pointed at a member is the domain published")
	}
	auth := openLog(t, admin)
	nas, _ := resolveDevice(auth.State(), "nas")
	aum, err := auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Port: 8443}})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"), "publishes the domain pub.example.org itself on port 8443")
	moved, err := auth.Builder().SetDomain("pub.example.net")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&moved, auth.State(), 0), "\n"), "publishes the domain pub.example.net itself on nas",
		"has every member resolve pub.example.net through juistd", "turns DNSSEC off for pub.example.net on members")
	admin.mustRun("publish", "remove", "nas", "pub.example.org")
	if out := admin.mustRun("publish"); strings.Contains(out, "nas") {
		t.Errorf("the domain is still published:\n%s", out)
	}
}

// The Names line names this device's own names, under the network's domain
// and the public ones pointed at it, nothing of the others' nor of why they
// are not resolved.
func TestTheNamesLineNamesThisDevice(t *testing.T) {
	plain := func(_, s string) string { return s }
	o := []ipc.NameOverride{{Name: "mail.example.org", Device: "laptop"}, {Name: "www.example.org", Device: "nas"}}
	for n, want := range map[*ipc.Names]string{
		{Domain: "home.juist", Public: "pub.example.org", Resolved: true}:    "laptop.home.juist",
		{Domain: "home.juist", Resolved: true, Accepted: true, Overrides: o}: "laptop.home.juist, mail.example.org",
		{Domain: "home.juist", Overrides: o}:                                 "laptop.home.juist, mail.example.org",
		{Domain: "home.juist", Not: "juistd does not answer them"}:           "laptop.home.juist",
		{Public: "pub.example.org", Resolved: true}:                          "",
		{Domain: "home.juist", Off: true, Not: "DNS is off on this device"}:  "laptop.home.juist (DNS off)",
	} {
		if text := namesLine(n, "laptop", plain); text != want {
			t.Errorf("%+v is said as %q, want %q", *n, text, want)
		}
	}
}

// A terminator just started is waited for by what juistd says now, not by
// the status read before it ran.
func TestAStartedTerminatorIsWaitedFor(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	at := netip.MustParseAddrPort("[fd00::1]:443")
	var asked atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := ipc.ReadMessage(c, 1<<20)
			req, derr := ipc.DecodeRequest(b)
			if err == nil && derr == nil {
				var resp ipc.Response
				switch req.Command {
				case ipc.CmdServing:
					resp.Serving = &ipc.Published{Names: []ipc.PublishedTarget{{Name: "laptop.pub.example.org",
						Addrs: []netip.Addr{at.Addr()}, Port: at.Port()}}}
				case ipc.CmdStatus:
					resp.Status = &ipc.Status{InNetwork: true}
					if asked.Add(1) > 1 {
						resp.Status.Terminator = &ipc.Terminator{Running: true, Listening: []string{at.String()}}
					}
				}
				_ = ipc.WriteMessage(c, resp, 1<<20)
			}
			c.Close()
		}
	}()
	out := &syncBuffer{}
	a := newCLI(t).app(out, "")
	script := filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.host = &hostLayout{serveScript: script, terminatorWait: 5 * time.Second,
		answersTLS: func(context.Context, string) error { return nil }}
	a.asRoot = func() bool { return true }
	a.node = &daemonNode{sock: sock, st: &ipc.Status{InNetwork: true}}
	if err := a.startTerminator(""); err != nil {
		t.Fatalf("waiting for the terminator: %v\n%s", err, out)
	}
}

// A name is published for members alone on 443, by TLS, and stays so where
// a later command leaves it out, until --members=false makes it public.
func TestPublishANameForMembersAlone(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	admin.mustRun("network", "domain", "pub.example.org")
	mustContain(t, admin.mustRun("publish", "add", "nas", "photos", "--members"), "nas: publishes photos.pub.example.org:443 (members)")
	mustContain(t, admin.mustRun("publish"), "photos.pub.example.org", "443 (members)")
	members := func() bool {
		t.Helper()
		for _, n := range openLog(t, admin).State().Nodes() {
			for _, p := range n.Published {
				if p.Label == "photos" {
					return p.Members
				}
			}
		}
		t.Fatal("photos is published nowhere")
		return false
	}
	admin.mustRun("publish", "add", "nas", "photos")
	if !members() {
		t.Fatal("a command leaving --members out made the name public")
	}
	for _, args := range [][]string{
		{"publish", "add", "nas", "wiki", "--members", "--tcp=2222", "22"},
		{"publish", "add", "nas", "wiki", "--members", "--proxy"},
		{"publish", "add", "nas", "wiki", "8443", "--members"},
		{"publish", "add", "nas", "photos", "--proxy"},
	} {
		if out, err := admin.run(args...); err == nil {
			t.Errorf("juist %q taken:\n%s", args, out)
		}
	}
	auth := openLog(t, admin)
	var nas types.NodeRecord
	for _, n := range auth.State().Nodes() {
		if n.Name == "nas" {
			nas = n
		}
	}
	aum, err := auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "photos", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"),
		"makes photos.pub.example.org public, for the internet: it was for members alone")
	if out := admin.mustRun("publish", "add", "nas", "photos", "--members=false"); strings.Contains(out, "(members)") ||
		!strings.Contains(out, "nas: publishes photos.pub.example.org:443") {
		t.Errorf("made public, it says:\n%s", out)
	}
	if members() {
		t.Fatal("--members=false left the name for members")
	}
}

// A name for members alone not served for sharing its service is warned of
// in the status, and what to do is a hint of its own.
func TestTheStatusWarnsOfANameSharingItsService(t *testing.T) {
	t.Parallel()
	s := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 1,
		Publish: &ipc.Publish{Shared: []string{"photos.pub.example.org with web.pub.example.org"}}}}
	v := statusOf(s, time.Unix(1_000_000, 0), noPaint)
	for _, want := range []line{
		{kind: lineWarn, text: "not serving photos.pub.example.org, which is for members alone: web.pub.example.org " +
			"reaches its service as it is, whose clients could ask it for photos.pub.example.org by Host"},
		{kind: lineHint, text: sharedHint},
	} {
		if !slices.Contains(v.head, want) && !slices.Contains(v.notes, want) {
			t.Errorf("status %v %v lacks %v", v.head, v.notes, want)
		}
	}
}
