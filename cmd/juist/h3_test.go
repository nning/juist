package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// juist publish NAME HOST:PORT --http3 has juist proxy the service's
// HTTP and offer HTTP/3, says so, and prints the DNS record that has
// browsers try it at once; with --http2 the service is asked by h2c.
func TestPublishingOffersHTTP3(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.layout.serveScript = filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(h.layout.serveScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.mustRun("network", "domain", "pub.example.org")
	mustContain(t, h.mustRun("publish", "docs", "127.0.0.1:8181", "--http3"),
		"ending TLS for docs.pub.example.org to 127.0.0.1:8181, with HTTP/3",
		`docs.pub.example.org. HTTPS 1 . alpn="h3,h2"`, "hint: add this record at the domain's DNS so that browsers try HTTP/3 at once",
		"hint: a name with its own records gets no address from a wildcard")
	mustContain(t, h.mustRun("publish", "docs", "127.0.0.1:8181", "-3", "-2"),
		"to 127.0.0.1:8181 over HTTP/2, with HTTP/3")
	mustContain(t, h.mustRun("publish"), "127.0.0.1:8181 over HTTP/2, with HTTP/3")
	if out := h.mustRun("publish", "docs", "127.0.0.1:8181"); strings.Contains(out, "HTTPS 1") ||
		strings.Contains(out, "HTTP/3") {
		t.Errorf("without --http3:\n%s", out)
	}
	for _, args := range [][]string{{"docs", "--http3", "--on", "laptop"}, {"docs", "127.0.0.1:1", "--http3", "--tcp"}} {
		if _, err := h.run(append([]string{"publish"}, args...)...); err == nil || !strings.Contains(err.Error(), "--http3 cannot be used with") {
			t.Errorf("publish %q: %v", args, err)
		}
	}
	mustContain(t, h.mustRun("publish", "docs", "127.0.0.1:8181", "--http3"), "with HTTP/3")
	mustContain(t, h.mustRun("publish", "docs"), "ending TLS for docs.pub.example.org to 127.0.0.1:8181, with HTTP/3",
		`docs.pub.example.org. HTTPS 1 . alpn="h3,h2"`)
}
