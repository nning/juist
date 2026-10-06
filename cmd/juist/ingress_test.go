package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
)

// A device the network made its ingress serves as one, by the package's
// script, and lists what it serves; one that is not is told so.
func TestIngressServe(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.ingressScript = filepath.Join(t.TempDir(), "ingress.sh")
	if err := os.WriteFile(h.layout.ingressScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("ingress", "serve"); err == nil || !strings.Contains(err.Error(), "hint: an admin grants it: juist grant laptop ingress") {
		t.Fatalf("a device that is no ingress served: %v", err)
	}
	mustContain(t, h.mustRun("ingress"), "this device is no ingress")
	h.mustRun("revoke", "laptop", "voucher", "--yes")
	mustContain(t, h.mustRun("grant", "laptop", "ingress"), "laptop: roles ingress", "serving 0 names on 443, 443/udp and 80")
	mustContain(t, h.mustRun("status"), "Ingress", "not running on this device (juist ingress serve)")
	h.layout.answers = func(context.Context, string) error { return errors.New("connection refused") }
	if _, err := h.run("ingress", "serve"); err == nil || !strings.Contains(err.Error(), "does not answer on 443") ||
		!strings.Contains(err.Error(), "hint: "+helperLog("juist-ingress")) {
		t.Fatalf("an ingress that does not answer: %v", err)
	}
	h.layout.answers = nil
	mustContain(t, h.mustRun("ingress", "serve"), "serving 0 names on 443, 443/udp and 80")
	mustContain(t, h.mustRun("ingress"), "nothing to serve")
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("publish", "add", "laptop", "immich", "2283")
	eventually(t, "the ingress is told the name its target serves", func() bool {
		return strings.Contains(h.mustRun("ingress"), "immich.pub.example.org")
	})
	mustContain(t, h.mustRun("ingress"), ":2283")
	mustContain(t, h.mustRun("ingress", "serve", "--stop"), "stopped serving")
	if b, _ := os.ReadFile(calls); string(b) != "on\non\non\noff\n" {
		t.Errorf("the script ran %q", b)
	}
}

// juist publish add NAME HOST:PORT publishes NAME on this device, has juist
// end its TLS and send it on to HOST:PORT, and adds to what was said before;
// the terminator starts by the package's script and stops with serving,
// which keeps where names go, or with the last of them.
func TestPublishAddEndsTLS(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"immich"}, "missing HOST:PORT"},
		{[]string{"immich", "127.0.0.1:0"}, "no HOST:PORT"},
		{[]string{"a.b", "127.0.0.1:2283"}, "one label"},
		{[]string{"laptop", "immich", "127.0.0.1:x"}, "no HOST:PORT"},
	} {
		if _, err := h.run(append([]string{"publish", "add"}, tc.args...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("add %q: %v", tc.args, err)
		}
	}
	if _, err := h.run("publish", "serve", "immich=127.0.0.1:2283"); err == nil ||
		!strings.Contains(err.Error(), "hint: juist publish add immich 127.0.0.1:2283") {
		t.Errorf("serve NAME=ADDR: %v", err)
	}
	out := h.mustRun("publish", "add", "immich.pub.example.org", "127.0.0.1:2283")
	mustContain(t, out, "laptop: publishes immich.pub.example.org:443", "serving immich.pub.example.org",
		"ending TLS for immich.pub.example.org to 127.0.0.1:2283", "warning: a server published from this device reaches the network")
	if strings.Contains(out, "CAA") {
		t.Errorf("CAA records before the terminator has an account:\n%s", out)
	}
	out = h.mustRun("publish", "add", "docs", "127.0.0.1:8181")
	mustContain(t, out, "laptop: publishes docs.pub.example.org:443, immich.pub.example.org:443",
		"ending TLS for docs.pub.example.org to 127.0.0.1:8181")
	if strings.Contains(out, "immich.pub.example.org to") || strings.Contains(out, "warning:") {
		t.Errorf("a second name repeats the first:\n%s", out)
	}
	if out := h.mustRun("publish", "add", "docs", "127.0.0.1:8282"); strings.Contains(out, "publishes") ||
		!strings.Contains(out, "ending TLS for docs.pub.example.org to 127.0.0.1:8282") {
		t.Errorf("a name sent elsewhere:\n%s", out)
	}
	mustContain(t, h.mustRun("publish"), "TO", "127.0.0.1:8282", "127.0.0.1:2283")
	mustContain(t, h.mustRun("publish", "add", "docs", "127.0.0.1:8282", "--http2"),
		"ending TLS for docs.pub.example.org to 127.0.0.1:8282 over HTTP/2")
	mustContain(t, h.mustRun("publish"), "127.0.0.1:8282 over HTTP/2")
	if _, err := h.run("publish", "add", "laptop", "docs", "--http2"); err == nil || !strings.Contains(err.Error(), "--http2 is for") {
		t.Errorf("--http2 for a service ending TLS itself: %v", err)
	}
	mustContain(t, h.mustRun("publish", "add", "docs", "127.0.0.1:8282"), "ending TLS for docs.pub.example.org to 127.0.0.1:8282")
	// The terminator says its account, as it does once the CA answers.
	if _, err := ipc.Call(h.layout.socket(0), ipc.Request{Command: ipc.CmdServing,
		Account: &ipc.ACMEAccount{URI: "https://ca.example/acct/7", Issuers: []string{"ca.example"}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the CAA record", func() bool {
		return strings.Contains(h.mustRun("publish", "add", "docs", "127.0.0.1:8282"),
			`docs.pub.example.org. CAA 0 issue "ca.example; accounturi=https://ca.example/acct/7"`)
	})
	out = h.mustRun("publish", "add", "docs", "127.0.0.1:8282")
	if strings.Contains(out, "immich.pub.example.org. CAA") {
		t.Errorf("a name's CAA record with another's:\n%s", out)
	}
	if strings.Count(out, "gets no address from a wildcard") != 1 {
		t.Errorf("a name's own records, said not once:\n%s", out)
	}
	mustContain(t, h.mustRun("status"), "this device serves docs.pub.example.org, immich.pub.example.org")

	mustContain(t, h.mustRun("publish", "serve", "--stop"), "stopped serving")
	mustContain(t, h.mustRun("status"), "not agreed to on this device")
	mustContain(t, h.mustRun("publish", "serve"), "ending TLS for docs.pub.example.org to 127.0.0.1:8282",
		"ending TLS for immich.pub.example.org to 127.0.0.1:2283", "immich.pub.example.org. CAA")
	mustContain(t, h.mustRun("publish", "rm", "docs"), "laptop: publishes immich.pub.example.org:443",
		"docs.pub.example.org no longer goes to 127.0.0.1:8282")
	if out := h.mustRun("publish"); strings.Contains(out, "docs") {
		t.Errorf("a name removed is listed:\n%s", out)
	}
	mustContain(t, h.mustRun("publish", "remove", "laptop", "immich"), "laptop: publishes nothing",
		"immich.pub.example.org no longer goes to 127.0.0.1:2283")
	if _, err := h.run("publish", "rm", "immich"); err == nil || !strings.Contains(err.Error(), "laptop does not publish immich") {
		t.Errorf("removed twice: %v", err)
	}
	if b, _ := os.ReadFile(calls); !strings.HasPrefix(string(b), "on\non\n") || !strings.HasSuffix(string(b), "on\noff\non\noff\n") {
		t.Errorf("the script ran %q", b)
	}
}

// juist invite --ingress admits the device as the network's ingress, and
// refuses to make it a voucher too.
func TestInviteAnIngress(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	if _, err := admin.run("invite", "--ingress", "--voucher"); err == nil || !strings.Contains(err.Error(), "an ingress is no voucher") {
		t.Fatalf("an ingress invited as a voucher: %v", err)
	}
	inv, link := startInvite(t, admin, "--ingress")
	inv.waitFor(t, regexp.MustCompile(`invite to "home" as ingress`))
	newCLI(t).mustRun("join", link, "--name", "vps")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	mustContain(t, admin.mustRun("devices"), "vps", "ingress")
}

// An operator with no admin key says where a name goes before an admin
// publishes it: juist starts the terminator at once, so that it serves the
// name once published, says what is the admins' to do, and stops it with the
// last name.
func TestTheTerminatorStartsBeforeTheName(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	calls := filepath.Join(t.TempDir(), "calls")
	layout := *noHost
	layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(layout.serveScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	vps.cli.host, vps.cli.root = &layout, true
	laptop.mustRun("network", "domain", "pub.example.org")
	eventually(t, "the vps learns the domain", func() bool {
		_, err := vps.run("publish", "add", "docs", "127.0.0.1:8181", "--proxy")
		return err == nil
	})
	if b, _ := os.ReadFile(calls); string(b) != "on\n" {
		t.Fatalf("the script ran %q", b)
	}
	out := vps.mustRun("publish", "add", "docs", "127.0.0.1:8181")
	mustContain(t, out, "docs.pub.example.org goes to 127.0.0.1:8181 once published on this device",
		"hint: an admin publishes it: juist publish add vps docs")
	mustContain(t, vps.mustRun("publish"), "docs.pub.example.org", "vps", "not published", "127.0.0.1:8181")
	mustContain(t, vps.mustRun("status"), "not served here: the network publishes nothing on this device")
	laptop.mustRun("publish", "add", "vps", "docs")
	eventually(t, "the status saying the terminator does not run", func() bool {
		return strings.Contains(vps.mustRun("status"), "ends TLS for none: the terminator does not run")
	})
	mustContain(t, vps.mustRun("publish", "rm", "docs"), "docs.pub.example.org no longer goes to 127.0.0.1:8181",
		"hint: an admin stops publishing it: juist publish remove vps docs")
	if _, err := vps.run("publish", "rm", "docs"); err == nil || !strings.Contains(err.Error(), "no admin key") {
		t.Errorf("removed with nothing to remove here: %v", err)
	}
	if b, _ := os.ReadFile(calls); !strings.HasSuffix(string(b), "on\noff\n") {
		t.Errorf("the last name left the terminator: the script ran %q", b)
	}
	if _, err := laptop.run("publish", "add", "vps", "web", "127.0.0.1:1"); err == nil ||
		!strings.Contains(err.Error(), "hint: on vps, juist publish add web 127.0.0.1:1") {
		t.Errorf("TLS ended on another device: %v", err)
	}
	mustContain(t, vps.mustRun("publish", "add", "pub.example.org", "127.0.0.1:80"),
		"hint: an admin publishes it: juist publish add vps pub.example.org")
}

// An operator who is not root, with no terminal to ask sudo by, publishes a
// name while the terminator runs already: nothing is started, so nothing
// needs root.
func TestARunningTerminatorNeedsNoRoot(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	calls := filepath.Join(t.TempDir(), "calls")
	layout := *noHost
	layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(layout.serveScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	layout.terminatorOn = func(context.Context) bool { return true }
	vps.cli.host, vps.cli.root = &layout, false
	laptop.mustRun("network", "domain", "pub.example.org")
	var err error
	eventually(t, "the vps learns the domain", func() bool {
		_, err = vps.run("publish", "add", "docs", "127.0.0.1:8181")
		return err == nil || !strings.Contains(err.Error(), "no domain")
	})
	if err != nil {
		t.Fatalf("publishing beside a running terminator: %v", err)
	}
	if b, err := os.ReadFile(calls); err == nil {
		t.Errorf("the script ran %q", b)
	}
}

// What answers on the published port must end TLS, not be another program
// holding it.
func TestTheTerminatorMustEndTLS(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.layout.answersTLS = func(context.Context, string) error {
		return errors.New("a service there speaks no TLS; another program holds the port")
	}
	h.mustRun("network", "domain", "pub.example.org")
	if _, err := h.run("publish", "add", "immich", "127.0.0.1:2283"); err == nil ||
		!strings.Contains(err.Error(), "another program holds the port") {
		t.Errorf("a port another program holds: %v", err)
	}
}

// A plain service on a port reads as none that ends TLS; a TLS server, even
// one refusing the name, as one.
func TestEndsTLSTellsTLSFromPlain(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	if err := endsTLS(context.Background(), plain.Addr().String()); err == nil {
		t.Error("a plain service reads as ending TLS")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	if err := endsTLS(context.Background(), srv.Listener.Addr().String()); err != nil {
		t.Errorf("a TLS server: %v", err)
	}
}

// An ingress and a terminator serve the default network's instance alone.
func TestHelpersServeTheDefaultInstanceAlone(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.mustRun("create", "work", "--device", "laptop")
	h.layout.ingressScript = filepath.Join(t.TempDir(), "ingress.sh")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	for _, f := range []string{h.layout.ingressScript, h.layout.serveScript} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"--network", "work", "ingress", "serve"},
		{"--network", "work", "publish", "add", "immich", "127.0.0.1:2283"}} {
		if _, err := h.run(args...); err == nil || !strings.Contains(err.Error(), "the default network's instance alone") {
			t.Errorf("juist %q: %v", args, err)
		}
	}
}

// An ingress serving nothing because this device's view is stale is told
// why.
func TestAStaleIngressIsToldWhy(t *testing.T) {
	t.Parallel()
	out := &syncBuffer{}
	newCLI(t).app(out, "").sayServing(0, nil, true)
	mustContain(t, out.String(), "serving 0 names on 443, 443/udp and 80", "hint: this device's view of the network is stale")
}

// juist publish status-page serves the status page as a name whose TLS juist
// ends, says what the public sees, and says it again where told otherwise.
func TestPublishTheStatusPage(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "missing NAME"},
		{[]string{"status", "--public", "everyone"}, `"everyone" is none, services, network or all`},
		{[]string{"status", "127.0.0.1:80"}, "unexpected argument"},
	} {
		if _, err := h.run(append([]string{"publish", "status-page"}, tc.args...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status-page %q: %v", tc.args, err)
		}
	}
	mustContain(t, h.mustRun("publish", "status-page", "status"), "laptop: publishes status.pub.example.org:443",
		"ending TLS for status.pub.example.org to the status page, public: services")
	mustContain(t, h.mustRun("publish", "status-page", "status", "--public", "all"),
		"ending TLS for status.pub.example.org to the status page, public: all")
	mustContain(t, h.mustRun("publish"), "status.pub.example.org", "the status page, public: all")
	p, err := ipc.Call(h.layout.socket(0), ipc.Request{Command: ipc.CmdStatusPage})
	if err != nil || p.StatusPage == nil || p.StatusPage.Status.NetworkName != "home" {
		t.Fatalf("juistd's status page: %+v, %v", p, err)
	}
	mustContain(t, h.mustRun("publish", "rm", "status"), "status.pub.example.org no longer goes to the status page, public: all")
	if _, err := ipc.Call(h.layout.socket(0), ipc.Request{Command: ipc.CmdStatusPage}); err == nil {
		t.Error("juistd answers for a status page no longer served")
	}
}
