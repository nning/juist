//go:build interop && linux

package interop

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// share is M9c in the lab: lx, granted the publish role, shares a directory
// under its own name, which a client on the LAN fetches through fb, the
// ingress, with its token and a certificate from Pebble, and finds nothing
// without it; fb serves the name no longer once the share is stopped, or
// past its end, which ends the command too: exit criteria (5) and (6).
func share(t *testing.T, fb, lx *vm, work string) {
	t.Cleanup(func() {
		lx.try("pkill -f '[j]uist share'", time.Minute)
		if t.Failed() {
			out, _ := lx.try("cat /tmp/share.log; juist status; juist health; journalctl -u juist-serve --no-pager | tail -20", time.Minute)
			t.Logf("lx:\n%s", out)
			hold(t, fb, lx)
		}
	})
	root := filepath.Join(work, "pebble-root.pem")
	if err := os.WriteFile(root, []byte(fb.run(t, "cat /tmp/root.pem")), 0o644); err != nil {
		t.Fatal(err)
	}
	lx.put(t, root, "/tmp/pebble-root.pem", 0o644)
	fb.run(t, "juist grant lx publish")
	// Shared before lx holds the grant, juist share refuses at once.
	lx.eventually(t, "holding the publish role", 2*time.Minute, "juist devices", func(s string) bool {
		return regexp.MustCompile(`(?m)^lx \(this device\).*\bpublish\b`).MatchString(s)
	})
	url := regexp.MustCompile(`https://lx\.pub\.example\.org/[A-Za-z0-9_-]{22}/`)
	start := func(args string) string {
		lx.run(t, `set -e
rm -f /tmp/share.log
setsid -f sh -c 'juist share /tmp/shared `+args+` >/tmp/share.log 2>&1' </dev/null >/dev/null 2>&1`)
		out := lx.eventually(t, "sharing", 2*time.Minute, "cat /tmp/share.log", func(s string) bool { return url.MatchString(s) })
		return url.FindString(out)
	}
	fetch := func(u string) string {
		return "curl -fsS --max-time 10 --cacert /tmp/pebble-root.pem --resolve lx.pub.example.org:443:" + fb.lanAddr + " " + u
	}
	served := func(s string) bool { return strings.Contains(s, "lx.pub.example.org") }
	lx.run(t, "mkdir -p /tmp/shared && echo shared-file > /tmp/shared/a.txt")
	u := start("")
	fb.eventually(t, "serving lx's share", 2*time.Minute, "juist ingress", served)
	lx.eventually(t, "fetching the shared file through fb", 3*time.Minute, fetch(u+"a.txt"), has("shared-file"))
	for _, path := range []string{"a.txt", ""} {
		out, _ := lx.try(fetch("https://lx.pub.example.org/"+path), time.Minute)
		if !strings.Contains(out, "404") || strings.Contains(out, "a.txt") || strings.Contains(out, "shared-file") {
			t.Errorf("without the token, /%s: %s", path, out)
		}
	}
	lx.run(t, "pkill -INT -f '[j]uist share'")
	lx.eventually(t, "saying it stopped", time.Minute, "cat /tmp/share.log", has("stopped sharing"))
	fb.eventually(t, "serving the stopped share no longer", 2*time.Minute, "juist ingress", func(s string) bool { return !served(s) })
	lx.run(t, "! "+fetch(u+"a.txt"))

	u = start("--for 90s")
	fb.eventually(t, "serving the share that ends", 2*time.Minute, "juist ingress", served)
	lx.eventually(t, "fetching the share that ends", 3*time.Minute, fetch(u+"a.txt"), has("shared-file"))
	lx.eventually(t, "the command ending with its share", 3*time.Minute, "cat /tmp/share.log; pgrep -f '[j]uist share' || echo ended",
		func(s string) bool { return strings.Contains(s, "stopped sharing") && strings.Contains(s, "ended") })
	fb.eventually(t, "serving the share past its end no longer", 2*time.Minute, "juist ingress", func(s string) bool { return !served(s) })
}
