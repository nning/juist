//go:build interop && linux

package interop

import (
	"regexp"
	"testing"
	"time"
)

var breakGlassLine = regexp.MustCompile(`juist-break-glass-1\.\S+`)

// disable is M12 in the lab: fb ends the network with the break-glass line
// juist create showed, and lx, told by fb's juistd, says so, which its juistd
// does once it has dropped every peer.
func disable(t *testing.T, fb, lx *vm, fb4, glass string) {
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{fb, lx} {
				logs := "journalctl -u juistd -n 40 --no-pager"
				if v.freebsd {
					logs = "tail -40 /var/log/juistd.log"
				}
				out, _ := v.try("juist status; juist log | tail -4; "+logs, time.Minute)
				t.Logf("%s:\n%s", v.name, out)
			}
			hold(t, fb, lx)
		}
	})
	lx.eventually(t, "reaching fb", time.Minute, "ping -c1 -W2 "+fb4, func(string) bool { return true })
	mustHave(t, fb.run(t, "printf '%s\\n' "+glass+" | juist network disable --yes"), `disabled "interop"`)
	lx.eventually(t, "hearing the network ended", 2*time.Minute, "juist status", has("disabled"))
	mustHave(t, lx.run(t, "juist log"), "ended with a break-glass secret")
	mustHave(t, fb.run(t, "juist status"), "disabled")
}
