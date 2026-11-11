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
	mustContain(t, admin.mustRun("publish", "mc", "25589", "--tcp=25565", "--on", "nas"),
		"nas: publishes mc.pub.example.org:25565/tcp", "hint: on nas, juist publish mc")
	mustContain(t, admin.mustRun("publish", "ssh", "22", "--tcp=2222", "--proxy", "--on", "nas"),
		"mc.pub.example.org:25565/tcp to 25589, ssh.pub.example.org:2222/tcp to 22")
	mustContain(t, admin.mustRun("publish", "immich", "--on", "nas"), "immich.pub.example.org:443")
	listed := admin.mustRun("publish")
	for _, want := range []struct {
		name, port, to string
	}{
		{"  mc ", "25565/tcp", "nas:25589"},
		{"  ssh ", "2222/tcp (proxy protocol)", "nas:22"},
	} {
		var line string
		for _, candidate := range strings.Split(listed, "\n") {
			if strings.HasPrefix(candidate, want.name) {
				line = candidate
				break
			}
		}
		if !strings.Contains(line, want.port) || !strings.Contains(line, want.to) ||
			strings.Contains(line, "to 25589") || strings.Contains(line, "to 22") {
			t.Errorf("juist publish row for %s does not separate public port and target: %q\n%s",
				want.name, line, listed)
		}
	}
	mustContain(t, admin.mustRun("publish", "mc", "25589", "--tcp=25565", "--on", "nas"), "nas: unchanged")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"mc2", "25566", "--tcp=25565", "--on", "nas"}, "mc.pub.example.org is published on port 25565 already"},
		{[]string{"game", "25565", "--tcp", "--on", "laptop"}, "mc.pub.example.org is published on port 25565 already"},
		{[]string{"web", "8443", "--tcp=443", "--on", "nas"}, "cannot publish by TCP on port 443"},
		{[]string{"web", "8080", "--tcp=80", "--on", "nas"}, "port 80"},
		{[]string{"x", "1", "--tcp=41643", "--on", "nas"}, "one of juist's own"},
		{[]string{"web", "--tcp", "--on", "nas"}, "--tcp with --on needs PORT\nusage: juist publish"},
		{[]string{"mc", "25565", "--on", "nas"}, "mc.pub.example.org is published by TCP on port 25565\nhint: juist publish mc 25589 --tcp=25565 --on nas"},
		{[]string{"ssh", "22", "--tcp", "2222", "--on", "nas"}, "unexpected argument \"2222\": the public port goes in --tcp=2222\nusage: juist publish"},
		{[]string{"x", "1", "--tcp=0", "--on", "nas"}, "not a port"},
		{[]string{"x", "1", "--tcp=y", "--on", "nas"}, "not a port"},
		{[]string{"x", "127.0.0.1:1", "--tcp", "--http2"}, "--http2 cannot be used with --tcp"},
		{[]string{"web", "22", "--tcp=2223", "--on", "nas"}, "both go to port 22"},
	} {
		if out, err := admin.run(append([]string{"publish"}, tc.args...)...); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("publish %q: %v\n%s", tc.args, err, out)
		}
	}
	mustContain(t, admin.mustRun("publish", "--stop", "mc", "--on", "nas"), "nas: publishes immich.pub.example.org:443, ssh.pub.example.org:2222/tcp to 22")
	mustContain(t, admin.mustRun("publish", "mc", "25565", "--on", "nas"), "mc.pub.example.org:25565,")

	// An ingress holds every public port: none of its own names goes to one.
	enrollDevice(t, admin, "vps")
	admin.mustRun("grant", "vps", "ingress")
	if out, err := admin.run("publish", "web", "2222", "--on", "vps"); err == nil || !strings.Contains(err.Error(), "port 2222") {
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

// juist publish NAME HOST:PORT --tcp publishes NAME on this device by TCP,
// on the public port, which the device takes too, and has juist pass it on
// to HOST:PORT as it is; it says so, and no CAA record.
func TestPublishingPassesTCP(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	out := h.mustRun("publish", "mc", "127.0.0.1:25565", "--tcp")
	mustContain(t, out, "laptop: publishes mc.pub.example.org:25565/tcp", "serving mc.pub.example.org",
		"passing mc.pub.example.org to 127.0.0.1:25565")
	if strings.Contains(out, "ending TLS") || strings.Contains(out, "CAA") {
		t.Errorf("TLS said for a name passed by TCP:\n%s", out)
	}
	mustContain(t, h.mustRun("publish", "ssh", "127.0.0.1:22", "--tcp=2222"),
		"ssh.pub.example.org:2222/tcp", "passing ssh.pub.example.org to 127.0.0.1:22")
	if out := h.mustRun("publish", "ssh", "127.0.0.1:2022", "--tcp=2222"); strings.Contains(out, "publishes") ||
		!strings.Contains(out, "passing ssh.pub.example.org to 127.0.0.1:2022") {
		t.Errorf("a name passed elsewhere:\n%s", out)
	}
	if _, err := h.run("publish", "mc", "127.0.0.1:25566"); err == nil ||
		!strings.Contains(err.Error(), "is published by TCP on port 25565\nhint: juist publish mc 127.0.0.1:25566 --tcp, or juist publish --stop mc first") {
		t.Errorf("a name by TCP turned to TLS: %v", err)
	}
	if _, err := h.run("publish", "mc", "127.0.0.1:25565", "--tcp", "2222"); err == nil ||
		!strings.Contains(err.Error(), "the public port goes in --tcp=2222") {
		t.Errorf("a public port apart from --tcp: %v", err)
	}
	mustContain(t, h.mustRun("publish", "mc"), "passing mc.pub.example.org to 127.0.0.1:25565",
		"passing ssh.pub.example.org to 127.0.0.1:2022")
	mustContain(t, h.mustRun("publish"), "pub.example.org\n  mc ", "25565/tcp", "laptop:25565")
	mustContain(t, h.mustRun("publish", "--stop", "mc"), "mc.pub.example.org no longer goes to 127.0.0.1:25565")
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
	h.mustRun("publish", "mc", "2283", "--tcp=25565", "--on", "laptop")
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
	laptop.mustRun("publish", "pp", "2222", "--tcp", "--proxy", "--on", "vps")
	eventually(t, "the vps learns what it publishes", func() bool {
		return strings.Contains(vps.mustRun("publish"), "2222/tcp")
	})
	out := vps.mustRun("publish", "pp", "127.0.0.1:7002", "--tcp", "--proxy")
	if strings.Contains(out, "hint: an admin publishes it") || strings.Contains(out, "publishes pp") {
		t.Errorf("the ports published were changed:\n%s", out)
	}
	mustContain(t, out, "pp.pub.example.org")
	if _, err := vps.run("publish", "pp", "127.0.0.1:7002", "--tcp=2223", "--proxy"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, vps.mustRun("publish", "pp", "127.0.0.1:7002", "--tcp=2223", "--proxy"),
		"hint: an admin publishes it: juist publish pp 2223 --tcp --proxy --on vps")

	// By TLS in the log, juist ends TLS for it until an admin says otherwise.
	laptop.mustRun("publish", "web", "--on", "vps")
	eventually(t, "the vps learns web", func() bool { return strings.Contains(vps.mustRun("publish"), "  web ") })
	mustContain(t, vps.mustRun("publish", "web", "127.0.0.1:8080", "--tcp"),
		"warning: until an admin publishes it by TCP, juist ends TLS for web.pub.example.org",
		"hint: an admin publishes it: juist publish web 8080 --tcp --on vps")
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

// A device whose terminator does not run says so, whether it passes names
// by TCP alone or ends TLS for some.
func TestASilentTerminatorIsSaid(t *testing.T) {
	plain := func(_, s string) string { return s }
	got := publishSummary(&ipc.Publish{Consent: true, Serving: []string{"mc.pub.example.org"}, TerminatorSilent: true,
		Passing: []string{"mc.pub.example.org to 127.0.0.1:25565"}}, nil, plain)
	if want := "this device serves mc.pub.example.org, but the terminator does not run (juist publish mc.pub.example.org)"; got != want {
		t.Errorf("passing alone: %q", got)
	}
	got = publishSummary(&ipc.Publish{Consent: true, Serving: []string{"a", "b"}, TerminatorSilent: true,
		Ending: []string{"a to 127.0.0.1:1"}, Passing: []string{"b to 127.0.0.1:2"}}, nil, plain)
	if !strings.Contains(got, "but the terminator does not run") {
		t.Errorf("ending TLS too: %q", got)
	}
}

// A port the terminator cannot listen on, another program holding it, is
// warned of, port 80 apart, with a hint for a service on every address.
func TestAPortTheTerminatorCannotHoldIsSaid(t *testing.T) {
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2}}
	st.Terminator = &ipc.Terminator{Running: true, Unbound: []string{"100.64.0.1:25565", "[fd00::1]:25565", "100.64.0.1:80"}}
	notes := statusNotes(st, false)
	want := line{kind: lineWarn, text: "another program holds port 25565 on 100.64.0.1, fd00::1, needed for what is published here"}
	i := slices.Index(notes, want)
	if i < 0 || !slices.ContainsFunc(notes[i:], func(l line) bool {
		return l.kind == lineHint && strings.Contains(l.text, "publish its port: juist publish NAME PORT --on DEVICE")
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
		out, err := vps.run("publish", "wiki", "127.0.0.1:2343", "--members")
		wiki = out
		return err == nil
	})
	mustContain(t, wiki, "wiki.pub.example.org goes to 127.0.0.1:2343 once published on this device for members only")
	// Named alone, it is not published by this device's guess at how.
	if _, err := vps.run("publish", "wiki"); err == nil ||
		!strings.Contains(err.Error(), "wiki.pub.example.org goes to 127.0.0.1:2343 but is not published\n"+
			"hint: an admin publishes it: juist publish wiki --members --on vps") {
		t.Errorf("publish wiki: %v", err)
	}
	mustContain(t, vps.mustRun("health"), "warning: wiki.pub.example.org goes to 127.0.0.1:2343 but is not published",
		"hint: an admin publishes it: juist publish wiki --members --on vps")
	mustContain(t, vps.mustRun("publish"), "NAME             DEVICE  PORT  TO                        STATE\n"+
		"pub.example.org\n"+
		"  wiki           vps     -     127.0.0.1:2343 (members)  unpublished\n")
	// One meant by TCP is not asked for as TLS on 443.
	mustContain(t, vps.mustRun("publish", "mc", "127.0.0.1:25565", "--tcp", "--proxy"),
		"hint: an admin publishes it: juist publish mc 25565 --tcp --proxy --on vps")
	mustContain(t, vps.mustRun("health"), "hint: an admin publishes it: juist publish mc --on vps (add PORT and --tcp or --proxy if the service needs them)")
	if _, err := vps.run("publish", "mc"); err == nil || !strings.Contains(err.Error(), "(add PORT and --tcp or --proxy if the service needs them)") {
		t.Errorf("publish mc: %v", err)
	}
	laptop.mustRun("publish", "photos", "--on", "vps")
	eventually(t, "the vps learns photos", func() bool { return strings.Contains(vps.mustRun("publish"), "  photos ") })
	withheld := "warning: not serving photos.pub.example.org: its service is for members only, but the name is public"
	mustContain(t, vps.mustRun("publish", "photos", "127.0.0.1:2342", "--members"), withheld,
		"hint: an admin publishes it: juist publish photos --members --on vps")
	mustContain(t, vps.mustRun("health"), withheld)
	mustContain(t, vps.mustRun("publish", "photos", "127.0.0.1:2342"), withheld)
	if out := vps.mustRun("publish", "photos", "127.0.0.1:2342", "--members=false"); strings.Contains(out, withheld) {
		t.Errorf("--members=false still held it back:\n%s", out)
	}
	vps.mustRun("publish", "photos", "127.0.0.1:2342", "--members")
	mustContain(t, vps.mustRun("publish"), "127.0.0.1:2342 (members)")
	laptop.mustRun("publish", "photos", "--members", "--on", "vps")
	eventually(t, "the vps serves photos for members", func() bool { return !strings.Contains(vps.mustRun("status"), withheld) })

	// On an admin's device, the mark changes nothing in the log by itself.
	admin := layout
	admin.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(admin.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	laptop.cli.host, laptop.cli.root = &admin, true
	laptop.mustRun("publish", "blog", "127.0.0.1:9", "--members")
	laptop.mustRun("publish", "blog", "--members=false", "--on", "laptop")
	mustContain(t, laptop.mustRun("publish", "blog", "127.0.0.1:9"),
		"warning: not serving blog.pub.example.org: its service is for members only, but the name is public",
		"hint: an admin publishes it: juist publish blog --members --on laptop")
	for _, l := range strings.Split(laptop.mustRun("publish"), "\n") {
		if strings.HasPrefix(l, "  blog ") && (strings.Contains(l, "443 (members)") || !strings.Contains(l, "127.0.0.1:9 (members)")) {
			t.Errorf("the device's mark changed the log, or went: %q", l)
		}
	}
}
