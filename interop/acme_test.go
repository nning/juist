//go:build interop && linux

package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pebbleVersion is the release of Let's Encrypt's test CA the lab runs.
const pebbleVersion = "v2.10.1"

// buildPebble builds Pebble for FreeBSD and says where it is.
func buildPebble(t *testing.T) string {
	t.Helper()
	goBin := env("GO", "go")
	cmd := exec.Command(goBin, "install", "github.com/letsencrypt/pebble/v2/cmd/pebble@"+pebbleVersion)
	cmd.Env = append(os.Environ(), "GOOS=freebsd", "GOARCH=amd64", "CGO_ENABLED=0", "GOBIN=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building pebble: %v\n%s", err, out)
	}
	gopath := strings.TrimSpace(sh(t, goBin, "env", "GOPATH"))
	return filepath.Join(strings.Split(gopath, string(os.PathListSeparator))[0], "bin", "freebsd_amd64", "pebble")
}

// testCA writes ca.pem, and cert.pem and key.pem for the given addresses,
// into dir.
func testCA(t *testing.T, dir string, ips ...string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Named, as OpenSSL finds an issuer by its name.
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "juist interop CA"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pebble"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]*pem.Block{"ca.pem": {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: der}, "key.pem": {Type: "EC PRIVATE KEY", Bytes: kder}} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// pebbleConfig is Pebble's on fb: its challenges go to port 443, the
// ingress's.
const pebbleConfig = `{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "127.0.0.1:15000",
 "certificate": "/tmp/cert.pem", "privateKey": "/tmp/key.pem", "httpPort": 5002, "tlsPort": 443}}`

// tlsAtTheTarget is M9b's exit criterion (1): with Pebble as the CA, a client
// outside the network fetches a name lx publishes through fb, now the
// ingress, with a certificate lx's terminator took by TLS-ALPN-01 through fb,
// and trusts it by Pebble's root alone. Pebble runs on fb, where its
// challenge reaches the ingress, and lx asks it over the LAN.
func tlsAtTheTarget(t *testing.T, fb, lx *vm, work, pebble string) {
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{fb, lx} {
				out, _ := v.try(diagnose(v)+"; juist devices; juist publish; juist ingress", 2*time.Minute)
				t.Logf("%s:\n%s", v.name, out)
			}
			out, _ := lx.try("systemctl status juist-serve --no-pager; journalctl -u juist-serve --no-pager | tail -30", time.Minute)
			t.Logf("lx's terminator:\n%s", out)
			out, _ = fb.try("tail -30 /tmp/pebble.log; tail -20 /var/log/juist-ingress.log; tail -20 /var/log/juist-serve.log", time.Minute)
			t.Logf("fb's pebble and ingress:\n%s", out)
			hold(t, fb, lx)
		}
	})
	testCA(t, work, fb.lanAddr, "127.0.0.1")
	if err := os.WriteFile(filepath.Join(work, "pebble.json"), []byte(pebbleConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	fb.put(t, pebble, "/tmp/pebble", 0o755)
	for _, f := range []string{"ca.pem", "cert.pem", "key.pem", "pebble.json"} {
		fb.put(t, filepath.Join(work, f), "/tmp/"+f, 0o644)
	}
	lx.put(t, filepath.Join(work, "ca.pem"), "/tmp/ca.pem", 0o644)

	// fb takes the ingress's role, which no voucher or exit node holds.
	// The probe holding fb's port 80 goes, which the ingress takes.
	fb.run(t, `juist exit serve --stop; juist subnet serve --stop; pkill -f '[p]robe serve fb-host'; true`)
	fb.run(t, `set -e
juist revoke lx ingress
juist revoke fb exit voucher --yes
juist subnet remove fb `+fbSide.subnet+`
juist grant fb ingress
juist ingress serve
juist publish add lx web 443
daemon -f /tmp/probe answer 127.0.0.1:5399 127.0.0.1  # not 5353, which mDNS holds
env PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 daemon -f -o /tmp/pebble.log /tmp/pebble -config /tmp/pebble.json -dnsserver 127.0.0.1:5399`)

	// lx's terminator takes its certificates from Pebble, whose own it trusts
	// by the lab's CA.
	lx.run(t, `set -e
install -m 644 /tmp/ca.pem /etc/juist-test-ca.pem
mkdir -p /etc/systemd/system/juist-serve.service.d
printf '%s\n' '[Service]' 'Environment=SSL_CERT_FILE=/etc/juist-test-ca.pem' 'ExecStart=' \
  'ExecStart=/usr/bin/juistd --helper tls --home /var/lib/juist-serve --socket /run/juist/juistd.sock --acme https://`+
		fb.lanAddr+`:14000/dir' > /etc/systemd/system/juist-serve.service.d/pebble.conf
systemctl daemon-reload
setsid -f /tmp/probe serve lx-web >/dev/null 2>&1 < /dev/null`)
	lx.eventually(t, "ending TLS for what fb published on it", 3*time.Minute, "juist publish add web 127.0.0.1:80",
		has("ending TLS for web.pub.example.org to 127.0.0.1:80"))
	lx.eventually(t, "printing the CAA record", time.Minute, "juist publish serve",
		has(`web.pub.example.org. CAA 0 issue "pebble.letsencrypt.org; accounturi=https://`+fb.lanAddr+`:14000/`))
	fb.eventually(t, "taking Pebble's root", time.Minute,
		"fetch -q --ca-cert=/tmp/ca.pem -o /tmp/root.pem https://127.0.0.1:15000/roots/0 && grep -q CERTIFICATE /tmp/root.pem",
		func(string) bool { return true })
	fb.eventually(t, "fetching lx's name through itself, by Pebble's certificate", 3*time.Minute,
		"/tmp/probe hello "+fb.lanAddr+":443 web.pub.example.org /tmp/root.pem", has("lx-web from 127.0.0.1"))

	// fb ends TLS too, by its package's terminator, for a name of its own on
	// another port than the ingress's.
	// The probe from the ingress's test holds *:8443, which root's binder
	// says so of rather than binding over it.
	fb.run(t, `set -e
daemon -f /tmp/probe serve fb-web 8081
sysrc juist_serve_env=SSL_CERT_FILE=/tmp/ca.pem juist_serve_args="--acme https://`+fb.lanAddr+`:14000/dir"
juist publish add fb fbweb 8443`)
	fb.eventually(t, "saying another program holds 8443", 3*time.Minute, "juist publish add fbweb 127.0.0.1:8081 2>&1; true",
		has("another program holds port 8443"))
	fb.run(t, "pkill -f '[p]robe tls fb-tls'")
	fb.eventually(t, "ending TLS for its own name", 3*time.Minute, "juist publish add fbweb 127.0.0.1:8081",
		has("ending TLS for fbweb.pub.example.org to 127.0.0.1:8081"))
	fb.eventually(t, "fetching its own name through itself", 3*time.Minute,
		"/tmp/probe hello "+fb.lanAddr+":443 fbweb.pub.example.org /tmp/root.pem", has("fb-web from 127.0.0.1"))
	// Each serves as its own user, beside a parent that stays root to bind.
	fb.run(t, "pgrep -U juist-ingress -f '[j]uistd --helper ingress' >/dev/null")
	fb.run(t, "pgrep -U juist-serve -f '[j]uistd --helper tls' >/dev/null")
}

// serviceMember is M9b's service member, beside lx's own juistd: a juistd
// as nobody, with no device and no capability, joins, is granted the role,
// and serves a name through fb with a certificate from Pebble, while its
// overlay address answers no port but the one it publishes and log sync's,
// exit criterion (4).
func serviceMember(t *testing.T, fb, lx *vm) {
	t.Cleanup(func() { lx.try("pkill -f '[j]uistd --serve'", time.Minute) })
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("tail -40 /tmp/svc/juistd.log; juist --socket /tmp/svc/juistd.sock status", time.Minute)
			t.Logf("the service member:\n%s", out)
			out, _ = fb.try("juist devices; tail -20 /tmp/ingress.log", time.Minute)
			t.Logf("fb:\n%s", out)
			hold(t, fb, lx)
		}
	})
	lx.run(t, `set -e
install -d -o nobody -g nogroup -m 700 /tmp/svc
setsid -f setpriv --reuid=nobody --regid=nogroup --clear-groups --inh-caps=-all \
  env SSL_CERT_FILE=/etc/juist-test-ca.pem /usr/bin/juistd --serve svc=127.0.0.1:80 --home /tmp/svc \
  --socket /tmp/svc/juistd.sock --port 41700 --gossip-port 41701 --relay-port 41702 --no-dht \
  --acme https://`+fb.lanAddr+`:14000/dir >/tmp/svc/juistd.log 2>&1 < /dev/null`)
	lx.eventually(t, "the service member answering", time.Minute, "juist --socket /tmp/svc/juistd.sock status",
		func(string) bool { return true })
	invite(t, fb, lx, "juist --socket /tmp/svc/juistd.sock join '%s' --name svc")
	fb.run(t, `set -e
juist grant svc service
juist publish add svc svc 443`)
	fb.eventually(t, "fetching the service member's name through itself", 4*time.Minute,
		"/tmp/probe hello "+fb.lanAddr+":443 svc.pub.example.org /tmp/root.pem", has("lx-web from 127.0.0.1"))
	svc4 := strings.TrimSpace(fb.run(t, `juist devices | awk '$1 == "svc" {print $2}'`))
	fb.run(t, "! /tmp/probe get "+svc4+":80")
}
