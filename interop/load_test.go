//go:build interop && linux

package interop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLoad loads the website along the whole path it is published by:
// visitors from 100 addresses, an ingress on fb, the tunnel, and lx's
// terminator and the site's server behind it, over HTTP/1.1, HTTP/2 and
// then HTTP/3. It fails where a visitor is lost, or where HTTP/2 does not
// hold fewer connections. make load-lab runs it, at LOAD_RATE visitors a second
// for LOAD_FOR.
func TestLoad(t *testing.T) {
	site := os.Getenv("JUIST_LOAD_SITE")
	if site == "" {
		t.Skip("JUIST_LOAD_SITE is not set; make load-lab sets it")
	}
	server := need(t, "JUIST_LOAD_SERVER")
	rate, dur := env("JUIST_LOAD_RATE", "20"), env("JUIST_LOAD_FOR", "90s")
	pebble := buildPebble(t)
	fb, lx := labPair(t, "fb", "lx")
	work := need(t, "JUIST_INTEROP_WORK")
	probe := filepath.Join(work, "probe-freebsd")
	cmd := exec.Command(env("GO", "go"), "build", "-trimpath", "-o", probe, "./probe")
	cmd.Env = append(os.Environ(), "GOOS=freebsd", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("juist publish; journalctl -u juist-serve --no-pager | tail -30; tail -20 /tmp/site.log", time.Minute)
			t.Logf("lx:\n%s", out)
			out, _ = fb.try("juist ingress; tail -30 /var/log/juist-ingress.log; tail -20 /tmp/pebble.log", time.Minute)
			t.Logf("fb:\n%s", out)
			hold(t, fb, lx)
		}
	})

	lx.run(t, "juist create home --device lx")
	invite(t, lx, fb, "juist join '%s'")
	testCA(t, work, fb.lanAddr, "127.0.0.1")
	if err := os.WriteFile(filepath.Join(work, "pebble.json"), []byte(pebbleConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	fb.put(t, pebble, "/tmp/pebble", 0o755)
	fb.put(t, probe, "/tmp/probe", 0o755)
	for _, f := range []string{"ca.pem", "cert.pem", "key.pem", "pebble.json"} {
		fb.put(t, filepath.Join(work, f), "/tmp/"+f, 0o644)
	}
	lx.put(t, filepath.Join(work, "ca.pem"), "/tmp/ca.pem", 0o644)
	lx.put(t, site, "/tmp/site.tgz", 0o644)
	lx.put(t, server, "/tmp/site-server", 0o755)

	// lx, at home, publishes the site through fb, the VPS.
	lx.run(t, `set -e
juist network domain pub.example.org
juist grant fb ingress
juist publish add lx docs 443`)
	var sources []string
	for i := 1; i <= 100; i++ {
		sources = append(sources, fmt.Sprintf("10.78.%d.1", i))
	}
	fb.run(t, `set -e
juist ingress serve
daemon -f /tmp/probe answer 127.0.0.1:5399 127.0.0.1
env PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 daemon -f -o /tmp/pebble.log /tmp/pebble -config /tmp/pebble.json -dnsserver 127.0.0.1:5399
for a in `+strings.Join(sources, " ")+`; do ifconfig lo0 inet $a/32 alias; done`)
	lx.run(t, `set -e
install -m 644 /tmp/ca.pem /etc/juist-test-ca.pem
mkdir -p /etc/systemd/system/juist-serve.service.d
printf '%s\n' '[Service]' 'Environment=SSL_CERT_FILE=/etc/juist-test-ca.pem' 'ExecStart=' \
  'ExecStart=/usr/bin/juistd --helper tls --home /var/lib/juist-serve --socket /run/juist/juistd.sock --acme https://`+
		fb.lanAddr+`:14000/dir' > /etc/systemd/system/juist-serve.service.d/pebble.conf
systemctl daemon-reload
rm -rf /tmp/site; tar -xzf /tmp/site.tgz -C /tmp`)
	lx.run(t, "setsid -f /tmp/site-server -root /tmp/site -addr 127.0.0.1:8181 >/tmp/site.log 2>&1 < /dev/null")
	lx.eventually(t, "ending TLS for the site", 3*time.Minute, "juist publish add docs 127.0.0.1:8181",
		has("ending TLS for docs.pub.example.org to 127.0.0.1:8181"))
	fb.eventually(t, "taking Pebble's root", time.Minute,
		"fetch -q --ca-cert=/tmp/ca.pem -o /tmp/root.pem https://127.0.0.1:15000/roots/0 && grep -q CERTIFICATE /tmp/root.pem",
		func(string) bool { return true })
	visit := "/tmp/probe visitors -to " + fb.lanAddr + ":443 -ca /tmp/root.pem -from " + strings.Join(sources, ",")
	page := " https://docs.pub.example.org/en/"
	fb.eventually(t, "a visitor reaching the site", 3*time.Minute, visit+" -rate 1 -for 1s"+page, has("failed=0"))

	refused := regexp.MustCompile(`refused`)
	peak := regexp.MustCompile(`(?m)^done .* failed=(\d+) .* peak=(\d+) `)
	load := func(how string) (failed, open int) {
		time.Sleep(15 * time.Second) // the last load's connections close
		before := len(refused.FindAllString(fb.run(t, "cat /var/log/juist-ingress.log"), -1))
		out := fb.run(t, visit+" -rate "+rate+" -for "+dur+page)
		after := len(refused.FindAllString(fb.run(t, "cat /var/log/juist-ingress.log"), -1))
		t.Logf("%s, %s visitors a second for %s; the ingress refused %d connections:\n%s", how, rate, dur, after-before, out)
		m := peak.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("%s: no summary", how)
		}
		failed, _ = strconv.Atoi(m[1])
		open, _ = strconv.Atoi(m[2])
		return failed, open
	}
	failed1, open1 := load("HTTP/1.1")
	lx.eventually(t, "offering HTTP/2", time.Minute, "juist publish add docs 127.0.0.1:8181 --http2",
		has("to 127.0.0.1:8181 over HTTP/2"))
	failed2, open2 := load("HTTP/2")
	lx.eventually(t, "offering HTTP/3", time.Minute, "juist publish add docs 127.0.0.1:8181 --http2 --http3",
		has("to 127.0.0.1:8181 over HTTP/2, with HTTP/3"))
	visit += " -h3"
	failed3, _ := load("HTTP/3")
	if failed1 > 0 || failed2 > 0 || failed3 > 0 {
		t.Errorf("visitors were lost: %d over HTTP/1.1, %d over HTTP/2, %d over HTTP/3", failed1, failed2, failed3)
	}
	if open2*3 > open1 {
		t.Errorf("HTTP/2 held %d connections at most, HTTP/1.1 %d", open2, open1)
	}
}
