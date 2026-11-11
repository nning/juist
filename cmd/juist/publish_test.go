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
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// Names are published under the network's domain, one label on one device
// each, and the domain goes only once none is published under it.
func TestPublishAndStop(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	if out, err := admin.run("publish", "immich", "--on", "nas"); err == nil ||
		!strings.Contains(err.Error(), "hint: juist network domain") {
		t.Fatalf("a name published without a domain: %v\n%s", err, out)
	}
	mustContain(t, admin.mustRun("network", "domain", "Pub.Example.org"), "domain pub.example.org",
		"warning: every member resolves pub.example.org through juistd without DNSSEC, even with names off")
	mustContain(t, admin.mustRun("network", "domain", "pub.example.org"), "unchanged")
	mustContain(t, admin.mustRun("network"), "pub.example.org")

	mustContain(t, admin.mustRun("publish", "immich", "--on", "nas"), "nas: publishes immich.pub.example.org:443",
		"hint: on nas, juist publish immich")
	mustContain(t, admin.mustRun("publish", "photos.pub.example.org", "2283", "--proxy", "--on", "nas"),
		"immich.pub.example.org:443, photos.pub.example.org:2283")
	// The domain's own row keeps its cells, so that the header aligns with the rows.
	mustContain(t, admin.mustRun("publish"), "NAME             DEVICE  PORT\n"+
		"pub.example.org\n"+
		"  immich         nas     443\n"+
		"  photos         nas     2283 (proxy protocol)\n")
	if out := admin.mustRun("devices"); !strings.Contains(out, "publishes") || strings.Contains(out, "immich") {
		t.Errorf("devices does not say nas publishes, or names what, which juist publish lists:\n%s", out)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"publish", "immich", "--on", "laptop"}, "hint: juist publish --stop immich --on nas"},
		{[]string{"publish", "a.b.pub.example.org", "--on", "nas"}, "name under pub.example.org cannot contain a dot"},
		{[]string{"publish", "Im_mich", "--on", "nas"}, "name can only contain letters, digits and inner hyphens: \"Im_mich\"\nusage: juist publish"},
		{[]string{"publish", "web", "0", "--on", "nas"}, `"0" is not a port`},
		{[]string{"publish", "--stop", "immich", "--on", "laptop"}, "does not publish immich"},
		{[]string{"publish", "--stop", "--on", "laptop"}, "missing NAME"},
		{[]string{"publish", "--stop", "immich", "--members"}, "--members cannot be used with --stop"},
		{[]string{"publish", "--members"}, "--members cannot be used with juist publish alone"},
		{[]string{"publish", "immich", "--for", "2h"}, "--for cannot be used with juist publish NAME"},
		{[]string{"publish", "immich", "--public", "all"}, "--public only works with status-page"},
		{[]string{"publish", "8080", "--members"}, "--members cannot be used with juist publish PORT"},
		{[]string{"publish", "immich", "8080", "9090"}, "unexpected argument"},
		{[]string{"publish", "immich", "x"}, `"x" is not a port, HOST:PORT or status-page`},
		{[]string{"publish", "8080", "--on", "nas"}, "name cannot be only digits: 8080"},
		{[]string{"publish", "8080.pub.example.org", "--on", "nas"}, "name cannot be only digits: 8080"},
		{[]string{"network", "domain", "off"}, "hint: juist publish --stop immich.pub.example.org --on nas"},
	} {
		if out, err := admin.run(tc.args...); err == nil || !strings.Contains(out+err.Error(), tc.want) {
			t.Errorf("juist %q: %v\n%s", tc.args, err, out)
		}
	}
	mustContain(t, admin.mustRun("network", "domain", "pub.example.net"), "domain pub.example.net")
	mustContain(t, admin.mustRun("publish"), "pub.example.net\n  immich")
	mustContain(t, admin.mustRun("publish", "--stop", "immich", "--on", "nas"), "nas: publishes photos.pub.example.net:2283")
	mustContain(t, admin.mustRun("publish", "--stop", "photos", "--on", "nas"), "nas: publishes nothing")
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
		{"grant", "vps", "exit"}:       "vps cannot be ingress and exit at once\nhint: juist revoke vps ingress",
		{"grant", "laptop", "ingress"}: "laptop cannot be voucher and ingress at once",
	} {
		if out, err := admin.run(args[:]...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("juist %q: %v\n%s", args, err, out)
		}
	}
	// Withdrawn, the role no longer confines the device.
	mustContain(t, admin.mustRun("revoke", "vps", "ingress"), "vps: roles relay",
		"warning: vps is no longer confined: it is now an ordinary member",
		"hint: if it may be compromised: juist remove vps", "hint: on vps: juist ingress serve --stop")
}

// An approver reads a change of published names as what the internet then
// reaches.
func TestAPublishChangeSaysWhatItPublishes(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	c.mustRun("network", "domain", "pub.example.org")
	c.mustRun("publish", "immich", "--on", "laptop")
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
func TestServingANamePublishedHere(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	laptop.mustRun("network", "domain", "pub.example.org")
	eventually(t, "the vps learns the domain", func() bool {
		_, err := vps.run("publish", "immich")
		return err != nil && strings.Contains(err.Error(), "immich.pub.example.org is not published on this device")
	})
	mustContain(t, vps.mustRun("publish", "--stop"), "unchanged: not serving")
	mustContain(t, laptop.mustRun("publish", "immich", "--on", "vps"), "hint: on vps, juist publish immich")
	eventually(t, "the vps learns what it publishes", func() bool {
		return strings.Contains(vps.mustRun("status"), "immich.pub.example.org (not served)")
	})
	mustContain(t, vps.mustRun("health"), "warning: not serving immich.pub.example.org: not agreed to on this device",
		"hint: juist publish immich")
	mustContain(t, vps.mustRun("publish", "immich"), "serving immich.pub.example.org")
	mustContain(t, vps.mustRun("status"), "this device serves immich.pub.example.org")
	if out := vps.mustRun("publish", "immich"); strings.Contains(out, "warning: a compromised server") {
		t.Errorf("serving again warns again:\n%s", out)
	}
	eventually(t, "the laptop hears the vps serves", func() bool {
		return slices.ContainsFunc(statusOfDaemon(t, laptop).Devices, func(d ipc.Device) bool { return d.Serving })
	})
	if out := laptop.mustRun("publish", "photos", "--on", "vps"); strings.Contains(out, "hint:") {
		t.Errorf("a name published on a device that serves hints:\n%s", out)
	}
	mustContain(t, vps.mustRun("publish", "--stop"), "stopped serving")
	mustContain(t, vps.mustRun("publish", "--stop"), "unchanged: not serving")
}

// A name an admin publishes on their own device is served at once, the
// admin being its operator.
func TestPublishingOnThisDeviceServesIt(t *testing.T) {
	t.Parallel()
	laptop, _ := homeAndVPS(t)
	laptop.mustRun("network", "domain", "pub.example.org")
	mustContain(t, laptop.mustRun("publish", "immich", "--on", "laptop"), "laptop: publishes immich.pub.example.org:443",
		"serving immich.pub.example.org", "warning: a compromised server published from this device")
	mustContain(t, laptop.mustRun("status"), "this device serves immich.pub.example.org")
	if out := laptop.mustRun("publish", "photos", "--on", "laptop"); strings.Contains(out, "warning:") {
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
	if out := admin.mustRun("publish", "web", "--on", "svc"); strings.Contains(out, "hint:") {
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
	if _, err := admin.run("invite", "--service", "web", "--relay"); err == nil || !strings.Contains(err.Error(), "--service cannot be used with --relay") {
		t.Fatalf("a service member invited as a relay too: %v", err)
	}
	inv, link := startInvite(t, admin, "--service", "web.pub.example.org")
	inv.waitFor(t, regexp.MustCompile(`invite to "home" as service`))
	newCLI(t).mustRun("join", link, "--name", "svc")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	mustContain(t, admin.mustRun("devices"), "svc", "service")
	mustContain(t, admin.mustRun("publish"), "pub.example.org\n  web            svc     443\n")

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
			if err == nil || !strings.Contains(err.Error(), "needed for mc.pub.example.org") {
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
	admin.mustRun("publish", "web", "--on", "nas")
	if _, err := admin.run("invite", "--service", "web"); err == nil || !strings.Contains(err.Error(), "web.pub.example.org is published on nas already") {
		t.Errorf("an invite for a taken label: %v", err)
	}
	admin.mustRun("grant", "laptop", "publish")
	if _, err := admin.run("publish", "laptop", "--on", "nas"); err == nil || !strings.Contains(err.Error(), "laptop.pub.example.org is taken: laptop shares under it") {
		t.Errorf("publishing a share holder's label: %v", err)
	}
}

// relay.DOMAIN is the name of the relay of an ingress that relays, and no
// name to publish while there is one.
func TestTheIngressRelaysNameIsNotPublished(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	enrollDevice(t, admin, "vps")
	admin.mustRun("network", "domain", "pub.example.org")
	admin.mustRun("grant", "vps", "ingress")
	admin.mustRun("publish", "relay", "--on", "nas")
	admin.mustRun("publish", "--stop", "relay", "--on", "nas")
	admin.mustRun("grant", "vps", "relay")
	if _, err := admin.run("publish", "relay", "--on", "nas"); err == nil ||
		!strings.Contains(err.Error(), "relay.pub.example.org is taken by the relay on vps") {
		t.Errorf("publishing the ingress's relay's name: %v", err)
	}
}

// Granting the roles that make the first ingress that relays warns where
// relay.DOMAIN, which its relay takes, is published already.
func TestAnIngressRelayTakingAPublishedNameIsWarned(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	enrollDevice(t, admin, "vps")
	admin.mustRun("network", "domain", "pub.example.org")
	admin.mustRun("publish", "relay", "--on", "nas")
	if out := admin.mustRun("grant", "vps", "ingress"); strings.Contains(out, "warning:") {
		t.Errorf("an ingress that does not relay warned: %s", out)
	}
	mustContain(t, admin.mustRun("grant", "vps", "relay"),
		"warning: relay.pub.example.org is published on nas already; vps takes it for its relay unless juist set --relay-name names another")
}

// A grant that waits for another admin's vote warns as one applied does.
func TestAnIngressRelayGrantWaitingIsWarned(t *testing.T) {
	t.Parallel()
	alice := newCLI(t)
	alice.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	enrollDevice(t, alice, "nas")
	enrollDevice(t, alice, "vps")
	alice.mustRun("network", "domain", "pub.example.org")
	alice.mustRun("publish", "relay", "--on", "nas")
	alice.mustRun("grant", "vps", "ingress")
	_, bob := adminKeyOf(t, "bob")
	alice.mustRun("admins", "add", "bob", bob)
	alice.mustRun("admins", "quorum", "2", "--yes")
	mustContain(t, alice.mustRun("grant", "vps", "relay"), "needs 1 more vote",
		"warning: relay.pub.example.org is published on nas already")
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
	mustContain(t, admin.mustRun("publish", "pub.example.org", "--on", "nas"), "nas: publishes pub.example.org:443",
		"hint: point A and AAAA records of pub.example.org at the ingress; *.pub.example.org does not cover it")
	mustContain(t, admin.mustRun("publish"), "pub.example.org")
	if _, err := admin.run("publish", "pub.example.org", "8443", "--on", "laptop"); err == nil ||
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
		"has every member resolve pub.example.net through juistd, with DNSSEC off for it")
	admin.mustRun("publish", "--stop", "pub.example.org", "--on", "nas")
	if out := admin.mustRun("publish"); strings.Contains(out, "nas") {
		t.Errorf("the domain is still published:\n%s", out)
	}
}

// A name of its own is published as it is, outside the network's domain,
// public alone; an approval says that members resolve it to its device.
func TestPublishANameOfItsOwn(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	admin.mustRun("network", "domain", "pub.example.org")
	mustContain(t, admin.mustRun("publish", "IMG.example.net.", "--proxy", "--on", "nas"),
		"nas: publishes img.example.net:443", "hint: point A and AAAA records of img.example.net at the ingress")
	mustContain(t, admin.mustRun("publish"), "img.example.net")
	for _, bad := range [][]string{
		{"publish", "img.example.net", "--on", "laptop"},
		{"publish", "wiki.example.net", "--members", "--on", "nas"},
		{"publish", "a.b.pub.example.org", "--on", "nas"},
		{"publish", "img.local", "--on", "nas"},
		{"names", "add", "laptop", "img.example.net"},
	} {
		if _, err := admin.run(bad...); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	auth := openLog(t, admin)
	nas, _ := resolveDevice(auth.State(), "nas")
	for proxy, want := range map[bool]bool{false: true, true: false} {
		aum, err := auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "photos.example.net", Port: 443, Proxy: proxy}})
		if err != nil {
			t.Fatal(err)
		}
		said := strings.Contains(strings.Join(effect(&aum, auth.State(), 0), "\n"),
			"so every member resolves photos.example.net to nas (")
		if said != want {
			t.Errorf("with proxy %v, the approval says members resolve it: %v", proxy, said)
		}
	}
	admin.mustRun("publish", "--stop", "img.example.net", "--on", "nas")
	if out := admin.mustRun("publish"); strings.Contains(out, "img.example.net") {
		t.Errorf("the name is still published:\n%s", out)
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
	mustContain(t, admin.mustRun("publish", "photos", "--members", "--on", "nas"), "nas: publishes photos.pub.example.org:443 (members)")
	mustContain(t, admin.mustRun("publish"), "pub.example.org\n  photos         nas     443 (members)\n")
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
	admin.mustRun("publish", "photos", "--on", "nas")
	if !members() {
		t.Fatal("a command leaving --members out made the name public")
	}
	for _, args := range [][]string{
		{"publish", "wiki", "22", "--members", "--tcp=2222", "--on", "nas"},
		{"publish", "wiki", "--members", "--proxy", "--on", "nas"},
		{"publish", "wiki", "8443", "--members", "--on", "nas"},
		{"publish", "photos", "--proxy", "--on", "nas"},
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
		"makes photos.pub.example.org public on the internet: it was for members only")
	if out := admin.mustRun("publish", "photos", "--members=false", "--on", "nas"); strings.Contains(out, "(members)") ||
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
		{kind: lineWarn, text: "not serving photos.pub.example.org, which is for members only: web.pub.example.org " +
			"reaches the same service, whose clients could ask it for photos.pub.example.org by Host"},
		{kind: lineHint, text: sharedHint},
	} {
		if !slices.Contains(v.head, want) && !slices.Contains(v.notes, want) {
			t.Errorf("status %v %v lacks %v", v.head, v.notes, want)
		}
	}
}

// juist publish says each name's state in a word: this device's own as it
// serves them, another's as its announcement and reach say.
func TestAPublishedNamesStateIsOneWord(t *testing.T) {
	t.Parallel()
	self, other := types.Identity{1}, types.Identity{2}
	here := types.NodeRecord{Identity: self, Name: "nas"}
	there := types.NodeRecord{Identity: other, Name: "vps"}
	docs := types.PublishedName{Label: "docs", Port: 443}
	name := "docs.pub.example.org"
	for _, tc := range []struct {
		what string
		st   ipc.Status
		on   types.NodeRecord
		want string
	}{
		{"served here", ipc.Status{Derived: ipc.Derived{Publish: &ipc.Publish{Serving: []string{name}}}}, here, stateServing},
		{"not agreed to", ipc.Status{Derived: ipc.Derived{Publish: &ipc.Publish{}}}, here, stateUnserved},
		{"withheld", ipc.Status{Derived: ipc.Derived{Publish: &ipc.Publish{Serving: []string{name}, Withheld: []string{name}}}}, here, stateUnserved},
		{"no terminator", ipc.Status{Derived: ipc.Derived{Publish: &ipc.Publish{Serving: []string{name},
			Ending: []string{name + " to 127.0.0.1:80"}, TerminatorSilent: true}}}, here, stateUnserved},
		{"no certificate", ipc.Status{Derived: ipc.Derived{Publish: &ipc.Publish{Serving: []string{name}},
			Terminator: &ipc.Terminator{Running: true, NoCert: []ipc.NoCert{{Name: name, Why: "CAA"}}}}}, here, stateFailing},
		{"port held", ipc.Status{Derived: ipc.Derived{Publish: &ipc.Publish{Serving: []string{name}},
			Terminator: &ipc.Terminator{Running: true, Unbound: []string{"10.0.0.1:443"}}}}, here, stateFailing},
		{"another's, served", ipc.Status{Derived: ipc.Derived{Devices: []ipc.Device{{Identity: other, Serving: true}}}}, there, stateServing},
		{"another's, not served", ipc.Status{Derived: ipc.Derived{Devices: []ipc.Device{{Identity: other}}}}, there, stateUnserved},
		{"another's, offline", ipc.Status{Derived: ipc.Derived{Devices: []ipc.Device{{Identity: other, Serving: true}}},
			Tunnels: ipc.Tunnels{Reach: []ipc.PeerReach{{Identity: other, Absent: true}}}}, there, stateOffline},
		{"another's, unknown", ipc.Status{}, there, ""},
		{"another's, not heard from", ipc.Status{Derived: ipc.Derived{Silent: []string{"vps"},
			Devices: []ipc.Device{{Identity: other, Serving: true}}}}, there, stateOffline},
	} {
		st := tc.st
		st.Self = self
		if got := publishedState(&st, tc.on, docs, "pub.example.org"); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.what, got, tc.want)
		}
	}
}

// A label of digits alone is spelled out where a command names it, so that
// juist publish does not take it for a port.
func TestALabelOfDigitsIsSpelledOut(t *testing.T) {
	t.Parallel()
	if got := labelArg("8080", "pub.example.org"); got != "8080.pub.example.org" {
		t.Errorf("labelArg: %q", got)
	}
	if got := labelArg("docs", "pub.example.org"); got != "docs" {
		t.Errorf("labelArg: %q", got)
	}
	notes := publishNotes(&ipc.Publish{Consent: false}, []string{"8080.pub.example.org"}, "vps", "pub.example.org")
	if len(notes) != 2 || notes[1].text != "juist publish 8080.pub.example.org" {
		t.Errorf("the hint to serve it: %+v", notes)
	}
}

// publishedBefore puts names into the log as a build without today's checks
// on new names would have: through a change file an admin approves.
func publishedBefore(t *testing.T, admin *daemonDevice, device string, ps ...types.PublishedName) {
	t.Helper()
	publishedBeforeAt(t, filepath.Join(admin.state, logDir), admin.mustRun, device, ps...)
}

// publishedBeforeAt is [publishedBefore] for the log in dir, approved by run.
func publishedBeforeAt(t *testing.T, dir string, run func(...string) string, device string, ps ...types.PublishedName) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := log.Open(st)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolveDevice(auth.State(), device)
	if err != nil {
		t.Fatal(err)
	}
	aum, err := auth.Builder().SetPublished(target.Identity, ps)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "old.rec")
	if err := writeNewRecordFile(path, &aum); err != nil {
		t.Fatal(err)
	}
	run("approve", path, "--yes")
}

// juist publish --stop PORT, where the device shares another port and
// publishes a name of PORT's digits, names that name.
func TestStoppingAPortNamesANameOfItsDigits(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	publishedBeforeAt(t, filepath.Join(h.layout.home(0), logDir), h.mustRun, "laptop", types.PublishedName{Label: "8080", Port: 443})
	r := h.cli.start("share", t.TempDir())
	r.waitFor(t, regexp.MustCompile(`sharing .* until Ctrl-C`))
	if _, err := h.run("publish", "--stop", "8080"); err == nil || err.Error() !=
		"8080 is not shared\nhint: to stop the name 8080.pub.example.org: juist publish --stop 8080.pub.example.org" {
		t.Errorf("--stop 8080: %v", err)
	}
	r.cancel()
	if _, err := r.wait(t); err != nil {
		t.Fatal(err)
	}
}

// A name of digits alone, published before juist publish refused such
// names, is still served, named and stopped, spelled out as its hints
// spell it.
func TestAnOldNameOfDigitsStaysUsable(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	laptop.mustRun("network", "domain", "pub.example.org")
	publishedBefore(t, laptop, "vps", types.PublishedName{Label: "8080", Port: 443})
	mustContain(t, laptop.mustRun("publish"), "  8080 ")
	eventually(t, "the vps learns its name", func() bool { return strings.Contains(vps.mustRun("status"), "8080.pub.example.org") })
	mustContain(t, vps.mustRun("health"), "hint: juist publish 8080.pub.example.org")
	mustContain(t, vps.mustRun("publish", "8080.pub.example.org"), "serving 8080.pub.example.org")
	mustContain(t, laptop.mustRun("publish", "8080.pub.example.org", "--members", "--on", "vps"), "8080.pub.example.org:443 (members)")
	if _, err := laptop.run("publish", "8080.pub.example.org", "--on", "laptop"); err == nil ||
		!strings.Contains(err.Error(), "8080.pub.example.org is published on vps already\nhint: juist publish --stop 8080.pub.example.org --on vps") {
		t.Errorf("8080 on another device: %v", err)
	}
	mustContain(t, vps.mustRun("publish", "--stop", "8080"), "hint: to stop the name 8080.pub.example.org: juist publish --stop 8080.pub.example.org")
	mustContain(t, laptop.mustRun("publish", "--stop", "8080.pub.example.org", "--on", "vps"), "vps: publishes nothing")
	// Gone from the log, it is not offered again.
	eventually(t, "the vps forgets it", func() bool { return !strings.Contains(vps.mustRun("status"), "8080.pub.example.org") })
	if _, err := vps.run("publish", "8080.pub.example.org"); err == nil || strings.Contains(err.Error(), "hint:") {
		t.Errorf("a name no command publishes anew is offered: %v", err)
	}
	if _, err := laptop.run("publish", "8-0", "--on", "vps"); err != nil {
		t.Errorf("a name with a hyphen among digits: %v", err)
	}
}

// --stop's hint needs no operator: stopping a share asks for one once, the
// hint nothing more.
func TestStoppingAPortAsksForTheOperatorOnce(t *testing.T) {
	t.Parallel()
	run := func(args ...string) string {
		var out syncBuffer
		a := newApp(strings.NewReader("n\n"), &out, &out)
		a.interactive = true
		a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
		_ = a.main(append([]string{"publish"}, args...))
		return out.String()
	}
	if out := run("--stop", "8080"); strings.Count(out, "not the operator") != 1 {
		t.Errorf("juist publish --stop 8080 asks %d times:\n%s", strings.Count(out, "not the operator"), out)
	}
}
