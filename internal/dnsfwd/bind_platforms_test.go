package dnsfwd

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The resolver may listen at a device's addresses wherever a device of
// juist's carries names: Linux binds to it, FreeBSD and macOS need not.
func TestEveryDevicePlatformBindsTheResolver(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	for _, goos := range []string{"linux", "freebsd", "darwin"} {
		cmd := exec.Command("go", "list", "-f", "{{join .GoFiles \" \"}}", ".")
		cmd.Env = append(cmd.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list for %s: %v", goos, err)
		}
		if slices.Contains(strings.Fields(string(out)), "bind_other.go") {
			t.Errorf("on %s the resolver refuses a device: %s", goos, out)
		}
	}
}
