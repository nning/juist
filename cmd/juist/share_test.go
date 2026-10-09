package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/ipc"
)

// A shared directory is read under its token alone: anywhere else is 404 and
// lists nothing, a link out of it reaches nothing, nothing is written, and
// no link out takes the token along.
func TestAShareIsReadUnderItsTokenAlone(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	h, under, err := shareHandler(dir, info, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if under != "/tok/" {
		t.Errorf("shared under %q", under)
	}
	get := func(method, path string) (int, string, http.Header) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		b, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(b), w.Result().Header
	}
	if code, body, hdr := get("GET", "/tok/a.txt"); code != 200 || body != "shared" || hdr.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("the file: %d %q %v", code, body, hdr)
	}
	if code, body, _ := get("GET", "/tok/"); code != 200 || !strings.Contains(body, "a.txt") {
		t.Errorf("the directory: %d %q", code, body)
	}
	for _, path := range []string{"/", "/a.txt", "/tok", "/other/a.txt", "/tok/../a.txt"} {
		if code, body, _ := get("GET", path); code != 404 || strings.Contains(body, "a.txt") {
			t.Errorf("%s: %d %q", path, code, body)
		}
	}
	if code, body, _ := get("GET", "/tok/link"); code == 200 || strings.Contains(body, "secret") {
		t.Errorf("a link out of the share: %d %q", code, body)
	}
	if code, _, _ := get("PUT", "/tok/a.txt"); code != http.StatusMethodNotAllowed {
		t.Errorf("a write: %d", code)
	}

	file := filepath.Join(dir, "a.txt")
	info, _ = os.Stat(file)
	h, under, err = shareHandler(file, info, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if code, body, _ := get("GET", under); under != "/tok/a.txt" || code != 200 || body != "shared" {
		t.Errorf("a shared file at %s: %d %q", under, code, body)
	}
	for _, path := range []string{"/tok/", "/tok/link"} {
		if code, _, _ := get("GET", path); code != 404 {
			t.Errorf("beside a shared file, %s: %d", path, code)
		}
	}
}

// juist share holds the share open until Ctrl-C: the device needs the
// publish role and a domain, the terminator starts, the status says what is
// shared, and once stopped nothing is.
func TestShareUntilStopped(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop", "--voucher")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := h.run("share", dir); err == nil || !strings.Contains(err.Error(), "hint: an admin grants it: juist grant laptop publish") {
		t.Fatalf("sharing without the role: %v", err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	mustContain(t, h.mustRun("grant", "laptop", "publish"), "laptop: roles voucher, publish",
		"hint: on laptop, juist share FILE or juist publish PORT")
	r := h.cli.start("share", dir, "--for", "1h")
	link := regexp.MustCompile(`sharing \S+ at (https://laptop\.pub\.example\.org/[A-Za-z0-9_-]{22}/), until`)
	r.waitFor(t, link)
	mustContain(t, r.out.String(), "warning: the network has no ingress")
	shared, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.mustRun("status"), "Sharing", shared+" at "+link.FindStringSubmatch(r.out.String())[1]+", until")
	if _, err := h.run("publish", "8000"); err == nil || !strings.Contains(err.Error(), "shares already") {
		t.Errorf("a second share: %v", err)
	}
	r.cancel()
	if out, err := r.wait(t); err != nil || !strings.Contains(out, "stopped sharing") {
		t.Errorf("stopping: %v\n%s", err, out)
	}
	eventually(t, "the share's end", func() bool { return !strings.Contains(h.mustRun("status"), "Sharing") })
	if b, _ := os.ReadFile(calls); !strings.HasPrefix(string(b), "on\n") {
		t.Errorf("the terminator was not started: %q", b)
	}
}

// Where systemd starts the terminator once juistd needs it, sharing runs no
// script, so asks for no root.
func TestAShareWhereSystemdStartsTheTerminatorTakesNoRoot(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.layout.terminatorStarts = func(context.Context) bool { return true }
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	r := h.cli.start("share", t.TempDir(), "--for", "1h")
	r.waitFor(t, regexp.MustCompile(`sharing \S+ at https://laptop\.pub\.example\.org/`))
	r.cancel()
	if out, err := r.wait(t); err != nil || !strings.Contains(out, "stopped sharing") {
		t.Errorf("stopping: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(calls); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("serve.sh ran: %q", b)
	}
}

// The words the CLI knows juistd's refusals by are juistd's own.
func TestTheShareWordsAreJuistds(t *testing.T) {
	for got, want := range map[string]string{
		errNoPublishRole:     daemon.ErrNoPublishRole.Error(),
		errNoDomain:          daemon.ErrNoDomain.Error(),
		terminatorNotRunning: daemon.TerminatorNotRunning,
		errSharing:           daemon.ErrSharing.Error(),
		errNotSharing:        daemon.ErrNotSharing.Error(),
	} {
		if got != want {
			t.Errorf("the CLI knows %q, juistd says %q", got, want)
		}
	}
}

// A share serves what it names, however it is named or linked, and hides
// the dot-entries a directory keeps for itself; nothing shared runs as the
// name's origin.
func TestAShareServesWhatItNames(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"index.html": "<p>page", "report #3.pdf": "pdf", ".env": "secret"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "x.pdf"), []byte("linked"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "x.pdf")
	if err := os.Symlink(filepath.Join(elsewhere, "x.pdf"), link); err != nil {
		t.Fatal(err)
	}
	get := func(h http.Handler, path string) (int, string, http.Header) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		b, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(b), w.Result().Header
	}
	share := func(arg string) (http.Handler, string) {
		t.Helper()
		p, info, err := sharedPath(arg)
		if err != nil {
			t.Fatal(err)
		}
		h, under, err := shareHandler(p, info, "tok")
		if err != nil {
			t.Fatal(err)
		}
		return h, under
	}
	for arg, want := range map[string]string{link: "linked", filepath.Join(dir, "index.html"): "<p>page",
		filepath.Join(dir, "report #3.pdf"): "pdf"} {
		h, under := share(arg)
		if code, body, hdr := get(h, under); code != 200 || body != want ||
			hdr.Get("Content-Security-Policy") != "sandbox" || hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s at %s: %d %q %v", filepath.Base(arg), under, code, body, hdr)
		}
	}
	if _, under := share(filepath.Join(dir, "report #3.pdf")); under != "/tok/report%20%233.pdf" {
		t.Errorf("the path is printed as %s", under)
	}
	h, _ := share(dir)
	if code, body, _ := get(h, "/tok/"); code != 200 || strings.Contains(body, ".env") {
		t.Errorf("the listing: %d %q", code, body)
	}
	if code, _, _ := get(h, "/tok/.env"); code != 404 {
		t.Errorf("a dot-entry: %d", code)
	}
	outside := t.TempDir()
	if err := os.Symlink(filepath.Join(elsewhere, "x.pdf"), filepath.Join(outside, "out")); err != nil {
		t.Fatal(err)
	}
	h, _ = share(outside)
	if code, _, _ := get(h, "/tok/out"); code != 404 {
		t.Errorf("a link out of the share: %d", code)
	}
}

// juist publish takes its port past --for, refuses one that is none, and
// takes IPv6's loopback where only it answers.
func TestPublishAPort(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("publish", "--for", "2h", "8000"); err == nil || !strings.Contains(err.Error(), "holds no publish role") {
		t.Errorf("publish --for 2h 8000: %v", err)
	}
	if _, err := h.run("publish", "99999"); err == nil || !strings.Contains(err.Error(), "is no port") {
		t.Errorf("publish 99999: %v", err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback here")
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	r := h.cli.start("publish", port)
	r.waitFor(t, regexp.MustCompile(`publishing \[::1\]:`+port+` at https://laptop\.pub\.example\.org, until Ctrl-C`))
	r.cancel()
	if out, err := r.wait(t); err != nil || !strings.Contains(out, "stopped sharing") {
		t.Errorf("stopping: %v\n%s", err, out)
	}
}

// A share whose juistd goes says so, and the share ends.
func TestAShareEndsWithJuistd(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	r := h.cli.start("share", t.TempDir())
	r.waitFor(t, regexp.MustCompile(`sharing .* until Ctrl-C`))
	h.stops[0]()
	if _, err := r.wait(t); err == nil || err.Error() != "the share ended with juistd" {
		t.Errorf("juistd gone: %v", err)
	}
}

// A share keeps the terminator it needs: stopping what is published leaves
// it running while the share lasts.
func TestAShareKeepsItsTerminator(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	h.mustRun("publish", "add", "docs", "127.0.0.1:8181")
	r := h.cli.start("share", t.TempDir())
	r.waitFor(t, regexp.MustCompile(`sharing .* until Ctrl-C`))
	mustContain(t, h.mustRun("publish", "serve", "--stop"), "stopped serving")
	h.mustRun("publish", "remove", "docs")
	if b, _ := os.ReadFile(calls); strings.Contains(string(b), "off") {
		t.Errorf("the terminator was stopped under a share: %q", b)
	}
}

// A share said again, as after a rename, warns of no ingress once.
func TestAShareSaidAgainWarnsOnce(t *testing.T) {
	out := &syncBuffer{}
	a := newCLI(t).app(out, "")
	st := &ipc.Status{}
	a.sayShare(st, "sharing x at https://laptop.pub.example.org/a/", time.Time{}, true)
	a.sayShare(st, "sharing x at https://desk.pub.example.org/a/", time.Time{}, false)
	if n := strings.Count(out.String(), "no ingress"); n != 1 {
		t.Errorf("warned %d times:\n%s", n, out)
	}
	mustContain(t, out.String(), "https://desk.pub.example.org/a/, until Ctrl-C")
}

// A firewall that keeps out the port this device serves on is said, by a
// share and by publishing alike, with how to let the device in; one that
// lets it in is not.
func TestAFirewallKeepingOutWhatIsServedIsSaid(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var blocked, unsure atomic.Bool
	blocked.Store(true)
	h.layout.firewalled = func(_ context.Context, dev string, port uint16) (bool, bool) {
		return dev == "juist0" && port == 443 && blocked.Load(), unsure.Load()
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	r := h.cli.start("share", t.TempDir())
	r.waitFor(t, regexp.MustCompile(`hint: sudo firewall-cmd --permanent --zone=trusted --change-interface=juist0`))
	mustContain(t, r.out.String(), "warning: firewalld blocks tcp/443 on juist0")
	r.cancel()
	if _, err := r.wait(t); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.mustRun("publish", "add", "docs", "127.0.0.1:8181"), "ending TLS for docs.pub.example.org",
		"warning: firewalld blocks tcp/443 on juist0", "--change-interface=juist0")
	unsure.Store(true)
	mustContain(t, h.mustRun("publish", "serve"), "warning: firewalld may block tcp/443 on juist0: its zone is not trusted")
	blocked.Store(false)
	if out := h.mustRun("publish", "serve"); strings.Contains(out, "firewall") {
		t.Errorf("a firewall letting the port in is said:\n%s", out)
	}
}

// A share in the background serves on once the command has returned, until
// juist share --stop, which a share in the foreground heeds too; a second
// share is refused, and stopping none says so.
func TestAShareInTheBackground(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := h.mustRun("share", "--background", dir)
	m := regexp.MustCompile(`https://laptop\.pub\.example\.org(/[^/]+/), until juist share --stop`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("a background share says:\n%s", out)
	}
	get := func() (int, error) {
		st := hostStatus(t, h)
		if st.Share == nil {
			return 0, errors.New("no share")
		}
		resp, err := http.Get("http://" + st.Share.To + m[1] + "a.txt")
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get(); code != 200 {
		t.Fatalf("the background share, once the command returned: %d, %v", code, err)
	}
	if out, err := h.run("share", "--background", dir); err == nil || !strings.Contains(out, "this device shares already") {
		t.Errorf("a second share: %v\n%s", err, out)
	}
	mustContain(t, h.mustRun("share", "--stop"), "stopped sharing")
	if code, err := get(); err == nil {
		t.Errorf("a stopped share still serves: %d", code)
	}
	mustContain(t, h.mustRun("share", "--stop"), "unchanged: not sharing")

	r := h.cli.start("share", dir)
	r.waitFor(t, regexp.MustCompile(`sharing .* until Ctrl-C`))
	mustContain(t, h.mustRun("share", "--stop"), "stopped sharing")
	if out, err := r.wait(t); err != nil || !strings.Contains(out, "stopped sharing") {
		t.Errorf("a share in the foreground, stopped: %v\n%s", err, out)
	}
}

// A share in the background outlives a restart of juistd, under its path.
func TestABackgroundShareOutlivesJuistd(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	h.mustRun("grant", "laptop", "publish")
	h.mustRun("share", "--background", "--for", "1h", t.TempDir())
	before := hostStatus(t, h).Share
	if before == nil {
		t.Fatal("no share")
	}
	h.stops[0]()
	h.stops[0] = startInstanceService(t, h.layout.home(0), h.layout.socket(0), 0)
	eventually(t, "the share is taken up again", func() bool {
		st := hostStatus(t, h)
		return st.Share != nil && st.Share.To == before.To
	})
	mustContain(t, h.mustRun("share", "--stop"), "stopped sharing")
}

// hostStatus is the default instance's status on h, empty while it does not
// answer.
func hostStatus(t *testing.T, h *testHost) *ipc.Status {
	t.Helper()
	resp, err := ipc.Call(h.layout.socket(0), ipc.Request{Command: ipc.CmdStatus})
	if err != nil || resp.Status == nil {
		return &ipc.Status{}
	}
	return resp.Status
}

// A shared directory is listed folders first, sorted as asked, with links
// that stay under the token whatever a name holds, and dot-entries left out;
// the listing runs nothing and may download, while what is shared stays
// sandboxed; a directory with an index.html is that page.
func TestASharedDirectoryIsListed(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"small.txt": "a", "big.bin": strings.Repeat("b", 2500),
		"a:b.txt": "c", "<x>.txt": "d", ".env": "secret", "sub/inner.txt": "e", "site/index.html": "<p>site"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	info, _ := os.Stat(dir)
	h, _, err := shareHandler(dir, info, "tok")
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) (int, string, http.Header) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Code, w.Body.String(), w.Result().Header
	}
	code, body, hdr := get("/tok/?sort=size&order=desc")
	if code != 200 || hdr.Get("Content-Security-Policy") != shareListCSP {
		t.Fatalf("the listing: %d %v", code, hdr)
	}
	order := []string{`href="./sub/"`, `href="./site/"`, `href="./big.bin"`, `href="./a:b.txt"`}
	last := -1
	for _, want := range order {
		i := strings.Index(body, want)
		if i < 0 || i < last {
			t.Errorf("%s not in order %v in:\n%s", want, order, body)
		}
		last = i
	}
	for _, want := range []string{"2.5 kB", "&lt;x&gt;.txt", `href="./sub/?zip"`, `href="?zip"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the listing lacks %s", want)
		}
	}
	if strings.Contains(body, ".env") || strings.Contains(body, "<script") || strings.Contains(body, "<x>") {
		t.Errorf("the listing shows what it should not:\n%s", body)
	}
	if code, body, _ := get("/tok/sub/"); code != 200 || !strings.Contains(body, `href="../"`) || !strings.Contains(body, "inner.txt") {
		t.Errorf("a folder: %d\n%s", code, body)
	}
	if code, body, hdr := get("/tok/site/"); code != 200 || body != "<p>site" || hdr.Get("Content-Security-Policy") != "sandbox" {
		t.Errorf("a folder with an index.html: %d %q %v", code, body, hdr)
	}
	if _, _, hdr := get("/tok/small.txt"); hdr.Get("Content-Security-Policy") != "sandbox" {
		t.Errorf("a shared file: %v", hdr)
	}
}

// A directory is sent whole as a ZIP, under its own name, its dot-entries
// and what a link reaches outside the share left out.
func TestASharedDirectoryIsZipped(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"a.txt": "a", "sub/b.txt": "b", ".git/config": "secret", "sub/.env": "secret"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "in")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	h, _, err := shareHandler(dir, info, "tok")
	if err != nil {
		t.Fatal(err)
	}
	zipped := func(path string) map[string]string {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
			t.Fatalf("%s: %d %v", path, w.Code, w.Header())
		}
		zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		got := map[string]string{}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			got[f.Name] = string(b)
		}
		return got
	}
	top := filepath.Base(dir)
	want := map[string]string{top + "/a.txt": "a", top + "/in": "a", top + "/sub/b.txt": "b"}
	if got := zipped("/tok/?zip"); !maps.Equal(got, want) {
		t.Errorf("the share as a ZIP: %v, want %v", got, want)
	}
	if got := zipped("/tok/sub/?zip"); !maps.Equal(got, map[string]string{"sub/b.txt": "b"}) {
		t.Errorf("a folder as a ZIP: %v", got)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/tok/sub/?zip", nil))
	if cd := w.Header().Get("Content-Disposition"); cd != "attachment; filename=sub.zip" {
		t.Errorf("named %q", cd)
	}
	for _, path := range []string{"/?zip", "/tok/.git/?zip", "/tok/a.txt?zip"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Header().Get("Content-Type") == "application/zip" {
			t.Errorf("%s is zipped", path)
		}
	}
}

// The listing's fonts are reached under the token alone, and not beside a
// shared file.
func TestTheListingsFontsAreUnderTheToken(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	h, _, err := shareHandler(dir, info, "tok")
	if err != nil {
		t.Fatal(err)
	}
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if w := get(h, "/tok/.juist/plex-sans-400.woff2"); w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" || w.Body.Len() < 1000 {
		t.Errorf("a font: %d %v", w.Code, w.Header())
	}
	if w := get(h, "/tok/.juist/icon.svg"); w.Code != 200 || w.Header().Get("Content-Type") != "image/svg+xml" {
		t.Errorf("the icon: %d %v", w.Code, w.Header())
	}
	for _, path := range []string{"/.juist/plex-sans-400.woff2", "/tok/.juist/sharelist.html", "/tok/.juist/"} {
		if w := get(h, path); w.Code != 404 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	if w := get(h, "/tok/"); !strings.Contains(w.Body.String(), "/tok/.juist/plex-sans-400.woff2") {
		t.Error("the listing does not load its font from under the token")
	} else if !strings.Contains(w.Body.String(), `href="/tok/.juist/icon.svg"`) ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Error("the listing does not load its icon from under the token")
	}
	file := filepath.Join(dir, "a.txt")
	info, _ = os.Stat(file)
	h, _, err = shareHandler(file, info, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if w := get(h, "/tok/.juist/plex-sans-400.woff2"); w.Code != 404 {
		t.Errorf("a font beside a shared file: %d", w.Code)
	}
}

// The listing takes the website's look from webstyle.
func TestTheListingLooksAsTheWebsiteDoes(t *testing.T) {
	var b strings.Builder
	if err := shareListTmpl.Execute(&b, shareList{Name: "x", Assets: "/tok/.juist/"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--accent: #46d1bf;", "url(/tok/.juist/plex-sans-400.woff2)", `viewBox="80 -770 2860 980"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the listing lacks %s", want)
		}
	}
}
