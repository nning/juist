//go:build interop && linux

package interop

import (
	"strings"
	"testing"
	"time"
)

// rename is M9e in the lab: fb, renamed on fb, is resolved on lx by its new
// name, at the addresses it had, and no longer by its old one.
func rename(t *testing.T, fb, lx *vm, fb4, fb6 string) {
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("juist devices; juist log | tail -6; resolvectl status juist0", time.Minute)
			t.Logf("lx:\n%s", out)
			hold(t, fb, lx)
		}
	})
	mustHave(t, fb.run(t, "juist rename fb bsd"), "renamed fb to bsd")
	lx.eventually(t, "resolving fb by its new name", 2*time.Minute, "getent ahosts bsd.interop.juist", func(out string) bool {
		return strings.Contains(out, fb4) && strings.Contains(out, fb6)
	})
	lx.eventually(t, "no longer by its old one", time.Minute, "getent ahosts fb.interop.juist || echo gone", has("gone"))
	mustHave(t, lx.run(t, "juist devices"), "bsd", fb4)
	mustHave(t, lx.run(t, "juist log"), `renaming of a device: fb to "bsd"`)
	lx.eventually(t, "reaching fb by its new name", time.Minute, "ping -c1 -W2 bsd.interop.juist", func(string) bool { return true })
}
