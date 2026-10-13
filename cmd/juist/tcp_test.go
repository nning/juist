package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// A name published by TCP has a public port of every ingress, its device's
// port unless given, which no other name has, nor an ingress's TLS or
// juist's own; it stays published by TCP until removed.
func TestPublishByTCP(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	admin.mustRun("network", "domain", "pub.example.org")
	mustContain(t, admin.mustRun("publish", "add", "nas", "mc", "25565", "--tcp"),
		"nas: publishes mc.pub.example.org:25565/tcp", "hint: on nas, juist publish serve")
	mustContain(t, admin.mustRun("publish", "add", "nas", "ssh", "22", "--tcp=2222", "--proxy"),
		"mc.pub.example.org:25565/tcp, ssh.pub.example.org:2222/tcp to 22")
	mustContain(t, admin.mustRun("publish", "add", "nas", "immich"), "immich.pub.example.org:443")
	mustContain(t, admin.mustRun("publish"), "25565/tcp", "2222/tcp to 22 (proxy protocol)")
	mustContain(t, admin.mustRun("publish", "add", "nas", "mc", "25565", "-T"), "nas: unchanged")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"nas", "mc2", "25566", "--tcp=25565"}, "mc.pub.example.org is published on port 25565 already"},
		{[]string{"laptop", "game", "25565", "--tcp"}, "mc.pub.example.org is published on port 25565 already"},
		{[]string{"nas", "web", "8443", "--tcp=443"}, "a name is not published by TCP on port 443"},
		{[]string{"nas", "web", "8080", "--tcp=80"}, "port 80"},
		{[]string{"nas", "x", "1", "--tcp=41643"}, "one of juist's own"},
		{[]string{"nas", "web", "--tcp"}, "needs the device's port\nhint: juist publish add nas web PORT --tcp"},
		{[]string{"nas", "mc", "25565"}, "mc.pub.example.org is published by TCP on port 25565\nhint: juist publish add nas mc.pub.example.org 25565 --tcp"},
		{[]string{"nas", "ssh", "22", "--tcp", "2222"}, "hint: a public port goes with the option: --tcp=2222"},
		{[]string{"nas", "x", "1", "--tcp=0"}, "want a port"},
		{[]string{"nas", "x", "1", "--tcp=y"}, "want a port"},
		{[]string{"x", "127.0.0.1:1", "--tcp", "--http2"}, "--http2 is for a name whose TLS juist ends"},
		{[]string{"nas", "web", "22", "--tcp=2223"}, "both go to port 22"},
	} {
		if out, err := admin.run(append([]string{"publish", "add"}, tc.args...)...); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("add %q: %v\n%s", tc.args, err, out)
		}
	}
	mustContain(t, admin.mustRun("publish", "rm", "nas", "mc"), "nas: publishes immich.pub.example.org:443, ssh.pub.example.org:2222/tcp to 22")
	mustContain(t, admin.mustRun("publish", "add", "nas", "mc", "25565"), "mc.pub.example.org:25565,")

	// An ingress holds every public port: none of its own names goes to one.
	enrollDevice(t, admin, "vps")
	admin.mustRun("grant", "vps", "ingress")
	if out, err := admin.run("publish", "add", "vps", "web", "2222"); err == nil || !strings.Contains(err.Error(), "port 2222") {
		t.Errorf("an ingress's name on a public port: %v\n%s", err, out)
	}
}

// An approver reads a name published by TCP as the port it opens on every
// ingress.
func TestATCPChangeSaysWhatItOpens(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	c.mustRun("network", "domain", "pub.example.org")
	auth := openLog(t, c)
	self := nodeKeysOf(t, c).Identity.Public()
	aum, err := auth.Builder().SetPublished(self, []types.PublishedName{{Label: "ssh", Port: 22, Proxy: true, Public: 2222}})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), 0), "\n"),
		"publishes ssh.pub.example.org by TCP on port 2222 of every ingress, to port 22 of laptop (", "), with PROXY protocol")
}

// juist publish add NAME HOST:PORT --tcp publishes NAME on this device by TCP,
// on the public port, which the device takes too, and has juist pass it on
// to HOST:PORT as it is; it says so, and no CAA record.
func TestPublishAddPassesTCP(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	out := h.mustRun("publish", "add", "mc", "127.0.0.1:25565", "--tcp")
	mustContain(t, out, "laptop: publishes mc.pub.example.org:25565/tcp", "serving mc.pub.example.org",
		"passing mc.pub.example.org to 127.0.0.1:25565")
	if strings.Contains(out, "ending TLS") || strings.Contains(out, "CAA") {
		t.Errorf("TLS said for a name passed by TCP:\n%s", out)
	}
	mustContain(t, h.mustRun("publish", "add", "ssh", "127.0.0.1:22", "--tcp=2222"),
		"ssh.pub.example.org:2222/tcp", "passing ssh.pub.example.org to 127.0.0.1:22")
	if out := h.mustRun("publish", "add", "ssh", "127.0.0.1:2022", "--tcp=2222"); strings.Contains(out, "publishes") ||
		!strings.Contains(out, "passing ssh.pub.example.org to 127.0.0.1:2022") {
		t.Errorf("a name passed elsewhere:\n%s", out)
	}
	if _, err := h.run("publish", "add", "mc", "127.0.0.1:25566"); err == nil ||
		!strings.Contains(err.Error(), "is published by TCP on port 25565\nhint: juist publish add mc 127.0.0.1:25566 --tcp,") {
		t.Errorf("a name by TCP turned to TLS: %v", err)
	}
	if _, err := h.run("publish", "add", "mc", "127.0.0.1:25565", "--tcp", "2222"); err == nil ||
		!strings.Contains(err.Error(), "hint: a public port goes with the option: --tcp=2222") {
		t.Errorf("a public port apart from --tcp: %v", err)
	}
	mustContain(t, h.mustRun("publish", "serve"), "passing mc.pub.example.org to 127.0.0.1:25565",
		"passing ssh.pub.example.org to 127.0.0.1:2022")
	mustContain(t, h.mustRun("publish"), "mc.pub.example.org", "25565/tcp", "127.0.0.1:25565")
	mustContain(t, h.mustRun("publish", "rm", "mc"), "mc.pub.example.org no longer goes to 127.0.0.1:25565")
}

// An ingress lists the names it passes by TCP with their public port, and
// says it serves them.
func TestAnIngressListsWhatItPassesByTCP(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.ingressScript = filepath.Join(t.TempDir(), "ingress.sh")
	if err := os.WriteFile(h.layout.ingressScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("revoke", "laptop", "voucher", "--yes")
	h.mustRun("grant", "laptop", "ingress")
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("publish", "add", "laptop", "mc", "2283", "--tcp=25565")
	eventually(t, "the ingress is told the name", func() bool {
		return strings.Contains(h.mustRun("ingress"), "mc.pub.example.org")
	})
	mustContain(t, h.mustRun("ingress"), "PORT", "25565/tcp", ":2283")
	mustContain(t, h.mustRun("ingress", "serve"), "serving 1 name on 443, 443/udp, 80 and by TCP on 25565")
}

// The status line of an ingress names the ports it passes by TCP, and those
// another program holds, 443/udp among them.
func TestTheIngressSummaryNamesItsPorts(t *testing.T) {
	plain := func(_, s string) string { return s }
	for _, tc := range []struct {
		in   ipc.Ingress
		want string
	}{
		{ipc.Ingress{Running: true}, "serving 0 names on 443, 443/udp and 80"},
		{ipc.Ingress{Running: true, Names: []string{"a", "b"}, Ports: []uint16{25565}}, "serving a, b on 443, 443/udp, 80 and by TCP on 25565"},
		{ipc.Ingress{Running: true, Names: []string{"a", "b", "c"}, Ports: []uint16{2222, 25565}, Unbound: []uint16{22}},
			"serving 3 names on 443, 443/udp, 80 and by TCP on 2222, 25565; another program holds port 22"},
		{ipc.Ingress{Running: true, Unbound: []uint16{22, 25}}, "serving 0 names on 443, 443/udp and 80; another program holds ports 22, 25"},
		{ipc.Ingress{Running: true, NoQUIC: true}, "serving 0 names on 443 and 80; another program holds port 443/udp"},
	} {
		if got := ingressSummary(&tc.in, plain); got != tc.want {
			t.Errorf("%+v: %q", tc.in, got)
		}
	}
}

// An operator with no admin key says where a name an admin published on
// this device by TCP goes, on the ports it is published on, which changes
// nothing in the log.
func TestAnOperatorPassesWhatAnAdminPublishedByTCP(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	layout := *noHost
	layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	vps.cli.host, vps.cli.root = &layout, true
	laptop.mustRun("network", "domain", "pub.example.org")
	laptop.mustRun("publish", "add", "vps", "pp", "2222", "--tcp", "--proxy")
	eventually(t, "the vps learns what it publishes", func() bool {
		return strings.Contains(vps.mustRun("publish"), "2222/tcp")
	})
	out := vps.mustRun("publish", "add", "pp", "127.0.0.1:7002", "--tcp", "--proxy")
	if strings.Contains(out, "hint: an admin publishes it") || strings.Contains(out, "publishes pp") {
		t.Errorf("the ports published were changed:\n%s", out)
	}
	mustContain(t, out, "pp.pub.example.org")
	if _, err := vps.run("publish", "add", "pp", "127.0.0.1:7002", "--tcp=2223", "--proxy"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, vps.mustRun("publish", "add", "pp", "127.0.0.1:7002", "--tcp=2223", "--proxy"),
		"hint: an admin publishes it: juist publish add vps pp.pub.example.org 2223 --tcp --proxy")

	// By TLS in the log, juist ends TLS for it until an admin says otherwise.
	laptop.mustRun("publish", "add", "vps", "web")
	eventually(t, "the vps learns web", func() bool { return strings.Contains(vps.mustRun("publish"), "web.pub.example.org") })
	mustContain(t, vps.mustRun("publish", "add", "web", "127.0.0.1:8080", "--tcp"),
		"warning: until an admin publishes it by TCP, juist ends TLS for web.pub.example.org",
		"hint: an admin publishes it: juist publish add vps web.pub.example.org 8080 --tcp")
}

// The terminator is waited for where the name just published is served, by
// TCP too, not where the first is.
func TestTheNameJustPublishedIsWaitedFor(t *testing.T) {
	p := &ipc.Published{Names: []ipc.PublishedTarget{{Name: "a.pub.example.org", Port: 443}},
		TCP: []ipc.PublishedTarget{{Name: "mc.pub.example.org", Port: 25565, Public: 25565}}}
	if got := servedAs(p, "mc.pub.example.org"); got.Port != 25565 {
		t.Errorf("waited for %+v", got)
	}
	if got := servedAs(p, ""); got.Name != "a.pub.example.org" {
		t.Errorf("with no name, waited for %+v", got)
	}
	if got := servedAs(&ipc.Published{}, "x"); got.Name != "" {
		t.Errorf("with nothing served, waited for %+v", got)
	}
}

// A device passing names by TCP alone, whose terminator does not run, is
// said to pass none on, not to end TLS for none.
func TestASilentTerminatorPassesNone(t *testing.T) {
	plain := func(_, s string) string { return s }
	got := publishSummary(&ipc.Publish{Consent: true, Serving: []string{"mc.pub.example.org"}, TerminatorSilent: true,
		Passing: []string{"mc.pub.example.org to 127.0.0.1:25565"}}, plain)
	if !strings.Contains(got, "but passes none on: the terminator does not run") {
		t.Errorf("passing alone: %q", got)
	}
	got = publishSummary(&ipc.Publish{Consent: true, Serving: []string{"a", "b"}, TerminatorSilent: true,
		Ending: []string{"a to 127.0.0.1:1"}, Passing: []string{"b to 127.0.0.1:2"}}, plain)
	if !strings.Contains(got, "but ends TLS for none") {
		t.Errorf("ending TLS too: %q", got)
	}
}

// A port the terminator cannot listen on, another program holding it, is
// warned of, port 80 apart, with a hint for a service on every address.
func TestAPortTheTerminatorCannotHoldIsSaid(t *testing.T) {
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2}}
	st.Terminator = &ipc.Terminator{Running: true, Unbound: []string{"100.64.0.1:25565", "[fd00::1]:25565", "100.64.0.1:80"}}
	notes := statusNotes(st, false)
	want := line{kind: lineWarn, text: "another program holds port 25565 on 100.64.0.1, fd00::1, where juist would serve what is published here"}
	i := slices.Index(notes, want)
	if i < 0 || !slices.ContainsFunc(notes[i:], func(l line) bool {
		return l.kind == lineHint && strings.Contains(l.text, "publish its port: juist publish add DEVICE NAME PORT")
	}) {
		t.Errorf("notes %v", notes)
	}
}

// A service meant for members alone goes to no name the log has public:
// juistd holds it back, also when said again without --members, until
// --members=false; once the log has the name for members, it is served.
func TestAServiceForMembersGoesToNoPublicName(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	layout := *noHost
	layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	vps.cli.host, vps.cli.root = &layout, true
	laptop.mustRun("network", "domain", "pub.example.org")
	var wiki string
	eventually(t, "the vps learns the domain", func() bool {
		out, err := vps.run("publish", "add", "wiki", "127.0.0.1:2343", "--members")
		wiki = out
		return err == nil
	})
	mustContain(t, wiki, "wiki.pub.example.org goes to 127.0.0.1:2343 once published on this device for members alone")
	laptop.mustRun("publish", "add", "vps", "photos")
	eventually(t, "the vps learns photos", func() bool { return strings.Contains(vps.mustRun("publish"), "photos.pub.example.org") })
	withheld := "warning: not serving photos.pub.example.org, its service meant for members alone: the log has the name public"
	mustContain(t, vps.mustRun("publish", "add", "photos", "127.0.0.1:2342", "--members"), withheld,
		"hint: an admin publishes it: juist publish add vps photos.pub.example.org --members")
	mustContain(t, vps.mustRun("status"), withheld)
	mustContain(t, vps.mustRun("publish", "add", "photos", "127.0.0.1:2342"), withheld)
	if out := vps.mustRun("publish", "add", "photos", "127.0.0.1:2342", "--members=false"); strings.Contains(out, withheld) {
		t.Errorf("--members=false still held it back:\n%s", out)
	}
	vps.mustRun("publish", "add", "photos", "127.0.0.1:2342", "--members")
	mustContain(t, vps.mustRun("publish"), "127.0.0.1:2342 (members)")
	laptop.mustRun("publish", "add", "vps", "photos", "--members")
	eventually(t, "the vps serves photos for members", func() bool { return !strings.Contains(vps.mustRun("status"), withheld) })

	// On an admin's device, the mark changes nothing in the log by itself.
	admin := layout
	admin.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(admin.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	laptop.cli.host, laptop.cli.root = &admin, true
	laptop.mustRun("publish", "add", "blog", "127.0.0.1:9", "--members")
	laptop.mustRun("publish", "add", "laptop", "blog", "--members=false")
	mustContain(t, laptop.mustRun("publish", "add", "blog", "127.0.0.1:9"),
		"warning: not serving blog.pub.example.org, its service meant for members alone: the log has the name public",
		"hint: an admin publishes it: juist publish add laptop blog.pub.example.org --members")
	for _, l := range strings.Split(laptop.mustRun("publish"), "\n") {
		if strings.HasPrefix(l, "blog.") && (strings.Contains(l, "443 (members)") || !strings.Contains(l, "127.0.0.1:9 (members)")) {
			t.Errorf("the device's mark changed the log, or went: %q", l)
		}
	}
}
