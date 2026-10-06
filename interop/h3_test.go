//go:build interop && linux

package interop

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// http3 is M11b in the lab, exit criterion (1): fb, the ingress, passes QUIC
// by the name a client's Initials ask for to lx, whose terminator ends
// HTTP/3 with a certificate from Pebble and proxies the requests to a web
// server; headless Chrome on the host fetches the page over HTTP/3, which
// the page's own script reports, and over HTTP/2 by a port that forwards
// no UDP. Chrome uses Alt-Svc for a known root alone, so here it is told
// QUIC is there; that a browser finds it by Alt-Svc is shown by hand.
func http3(t *testing.T, fb, lx *vm, work, chrome string) {
	t.Cleanup(func() {
		lx.try("pkill -f '[p]robe web'", time.Minute)
		if t.Failed() {
			for _, port := range []int{fb.https, fb.tcpOnly} {
				b, _ := os.ReadFile(filepath.Join(work, fmt.Sprintf("chrome-%d.log", port)))
				t.Logf("Chrome by %d:\n%s", port, b)
			}
			out, _ := fb.try("juist ingress; sockstat -46l -p 443; tail -30 /var/log/juist-ingress.log", time.Minute)
			t.Logf("fb:\n%s", out)
			out, _ = lx.try("juist publish; cat /tmp/beacons.log; journalctl -u juist-serve --no-pager | tail -20", time.Minute)
			t.Logf("lx:\n%s", out)
			hold(t, fb, lx)
		}
	})
	lx.run(t, "setsid -f sh -c '/tmp/probe web 8090 >/tmp/beacons.log 2>&1' </dev/null >/dev/null 2>&1")
	fb.run(t, "juist publish add lx h3")
	lx.eventually(t, "ending TLS for the name and offering HTTP/3", 3*time.Minute,
		"juist publish add h3 127.0.0.1:8090 --http3", has("ending TLS for h3.pub.example.org to 127.0.0.1:8090, with HTTP/3"))
	lx.eventually(t, "Alt-Svc on its answers over TCP, by Pebble's certificate", 3*time.Minute,
		"curl -fsS -D - -o /dev/null --max-time 10 --cacert /tmp/pebble-root.pem --resolve h3.pub.example.org:443:"+fb.lanAddr+
			" https://h3.pub.example.org/", has(`alt-svc: h3=":443"; ma=86400`))

	// The chain's keys, which Chrome takes the certificate by: over QUIC
	// it asks the issuer's too.
	c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fb.tcpOnly), &tls.Config{ServerName: "h3.pub.example.org",
		InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, cert := range c.ConnectionState().PeerCertificates {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		keys = append(keys, base64.StdEncoding.EncodeToString(sum[:]))
	}
	c.Close()
	spki := strings.Join(keys, ",")

	visit := func(port int, flags ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := append([]string{"--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
			"--no-first-run", "--remote-debugging-port=0", "--user-data-dir=" + t.TempDir(), "--enable-logging=stderr", "--v=0",
			"--host-resolver-rules=MAP h3.pub.example.org 127.0.0.1", "--ignore-certificate-errors-spki-list=" + spki},
			flags...)
		args = append(args, fmt.Sprintf("https://h3.pub.example.org:%d/", port))
		cmd := exec.CommandContext(ctx, chrome, args...)
		log, _ := os.Create(filepath.Join(work, fmt.Sprintf("chrome-%d.log", port)))
		defer log.Close()
		cmd.Stdout, cmd.Stderr = log, log
		_ = cmd.Run() // it stays until the context ends it
	}
	visit(fb.https, fmt.Sprintf("--origin-to-force-quic-on=h3.pub.example.org:%d", fb.https))
	lx.eventually(t, "Chrome saying it came by HTTP/3", time.Minute, "cat /tmp/beacons.log", has("proto=h3"))
	visit(fb.tcpOnly)
	lx.eventually(t, "Chrome saying it came by HTTP/2 where no UDP reaches 443", time.Minute, "cat /tmp/beacons.log",
		has("proto=h2"))
	fb.run(t, "juist publish rm lx h3")
}
