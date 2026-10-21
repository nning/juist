package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// EtcHosts is the hosts file resolved answers names from itself.
var EtcHosts = "/etc/hosts"

var etcHosts struct {
	mu    sync.Mutex
	path  string
	mod   time.Time
	size  int64
	names map[string]bool
}

// inEtcHosts reports whether resolved answers name from the hosts file: a
// name it lists, or the reverse name of an address it lists.
func inEtcHosts(name string) bool {
	path := EtcHosts
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	etcHosts.mu.Lock()
	defer etcHosts.mu.Unlock()
	if etcHosts.names == nil || etcHosts.path != path || !fi.ModTime().Equal(etcHosts.mod) || fi.Size() != etcHosts.size {
		b, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		etcHosts.path, etcHosts.mod, etcHosts.size, etcHosts.names = path, fi.ModTime(), fi.Size(), hostsNames(string(b))
	}
	return etcHosts.names[name]
}

// hostsNames are the names a hosts file lists, lowercase without a final
// dot, and its addresses' reverse names.
func hostsNames(text string) map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		l, _, _ = strings.Cut(l, "#")
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		if !a.IsUnspecified() {
			out[reverseName(a.Unmap())] = true
		}
		for _, n := range f[1:] {
			out[strings.ToLower(strings.TrimSuffix(n, "."))] = true
		}
	}
	return out
}

// reverseName is a's name under in-addr.arpa or ip6.arpa.
func reverseName(a netip.Addr) string {
	var b strings.Builder
	s := a.AsSlice()
	if a.Is4() {
		for i := 3; i >= 0; i-- {
			fmt.Fprintf(&b, "%d.", s[i])
		}
		return b.String() + "in-addr.arpa"
	}
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", s[i]&0x0f, s[i]>>4)
	}
	return b.String() + "ip6.arpa"
}
