//go:build interop && linux

package interop

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// membersAlone is M16's exit criterion (1), after TLS at the target: lx
// serves secret for members alone, which fb, the ingress, passes nothing but
// the CA's validation; neither lx itself, whose own programs a client could make
// ask, nor fb, the ingress, is taken at lx, even through the tunnel, as a
// compromised one would not be. A member opens it in the access policy's
// part.
func membersAlone(t *testing.T, fb, lx *vm, work, lx4 string) {
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("juist publish; juist status; journalctl -u juist-serve --no-pager | tail -30", time.Minute)
			t.Logf("lx:\n%s", out)
			out, _ = fb.try("juist publish; tail -20 /var/log/juist-ingress.log; tail -20 /tmp/pebble.log", time.Minute)
			t.Logf("fb:\n%s", out)
			hold(t, fb, lx)
		}
	})
	root := filepath.Join(work, "pebble-root.pem")
	if err := os.WriteFile(root, []byte(fb.run(t, "cat /tmp/root.pem")), 0o644); err != nil {
		t.Fatal(err)
	}
	lx.put(t, root, "/tmp/root.pem", 0o644)
	// A service of its own: web's, which the internet reaches, would answer
	// its clients for secret by Host.
	lx.run(t, "setsid -f /tmp/probe serve lx-secret 8082 >/dev/null 2>&1 < /dev/null")
	fb.run(t, "juist publish add lx secret --members")
	if out, _ := lx.try("juist publish add secret 127.0.0.1:80", time.Minute); !has("its service as it is")(out) {
		t.Errorf("sharing web's service, the name for members was not refused:\n%s", out)
	}
	lx.eventually(t, "ending TLS for the name for members", 3*time.Minute, "juist publish add secret 127.0.0.1:8082",
		has("ending TLS for secret.pub.example.org to 127.0.0.1:8082"))
	if out := fb.run(t, "juist publish"); !has("(members)")(out) {
		t.Errorf("juist publish does not mark the name for members:\n%s", out)
	}
	if out, err := lx.try("timeout 10 /tmp/probe hello "+lx4+":443 secret.pub.example.org /tmp/root.pem", time.Minute); err == nil {
		t.Errorf("lx itself opened its name for members:\n%s", out)
	}
	// (1): not from the internet through the ingress, which says why, and
	// not from the ingress itself through the tunnel.
	// Asked again until the ingress, which learns the name a poll later,
	// says why.
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(2 * time.Second) {
		if out, err := fb.try("timeout 10 /tmp/probe hello "+fb.lanAddr+":443 secret.pub.example.org /tmp/root.pem", time.Minute); err == nil {
			t.Fatalf("the internet opened the name for members through the ingress:\n%s", out)
		}
		out, _ := fb.try("grep -h 'secret.pub.example.org' /var/log/juist-ingress.log", time.Minute)
		if has(`"secret.pub.example.org" members only`)(out) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ingress never said the name is for members alone:\n%s", out)
		}
	}
	if out, err := fb.try("timeout 10 /tmp/probe hello "+lx4+":443 secret.pub.example.org /tmp/root.pem", time.Minute); err == nil {
		t.Errorf("the ingress opened the name for members at lx through the tunnel:\n%s", out)
	}
	// A certificate is ordered on a hello lx takes, as for any name, so
	// none of those it refused had it ordered; the access policy's part has
	// one issued through the ingress.
	if out, err := lx.try("test -e "+membersCert, time.Minute); err == nil {
		t.Errorf("a hello refused had the name's certificate ordered:\n%s", out)
	}
}

const membersCert = "/var/lib/juist-serve/certs/secret.pub.example.org"
