//go:build linux || freebsd

package main

import (
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rootsCue is the test binary's cue to say whether it trusts any root.
const rootsCue = "JUIST_TEST_ROOTS"

func init() {
	if os.Getenv(rootsCue) != "" {
		pool, err := x509.SystemCertPool()
		switch {
		case err != nil:
			println(err.Error())
		case pool.Equal(x509.NewCertPool()):
			println("none")
		default:
			println("some")
		}
		os.Exit(0)
	}
}

// On a host without a CA bundle juistd still trusts the public roots, which
// relays on 443 and the ACME CA are verified by.
func TestRootsWithoutTheHostsBundle(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), rootsCue+"=1",
		"SSL_CERT_FILE="+filepath.Join(t.TempDir(), "none"), "SSL_CERT_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "some" {
		t.Errorf("roots without the host's bundle: %s, want some", got)
	}
}
