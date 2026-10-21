package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// The settings of 443 kept in the home are what the mesh runs with.
func TestTheMeshRunsOnTheKeptSettingsOf443(t *testing.T) {
	nw := newNetwork(t, 2)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	st, err := store.Open(filepath.Join(home, keys.LogDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.FromRecords(st, []types.AUM{nw.genesis}); err != nil {
		t.Fatal(err)
	}
	const proxy, name = "http://proxy.example:3128", "relay.example.org"
	for file, v := range map[string]string{statedir.HTTPSOnlyFile: "", statedir.ProxyFile: proxy, statedir.RelayNameFile: name} {
		if err := os.WriteFile(filepath.Join(home, file), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := startServiceWith(t, nw, home, inTunnel)
	m := f.s.Mesh()
	if m == nil {
		t.Fatal("no mesh runs")
	}
	if !m.httpsOnly || m.proxy != proxy || m.relayName != name {
		t.Errorf("the mesh runs with HTTPS alone %v, proxy %q, relay name %q; want true, %q, %q",
			m.httpsOnly, m.proxy, m.relayName, proxy, name)
	}
}
