package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
)

// juist set --port-mapping=false is kept in the device's state and taken by
// the mesh it starts again; the mesh starts with it on by default.
func TestPortMappingIsKeptAndTaken(t *testing.T) {
	var seen connectsSeen
	f := newServiceFixtureWith(t, func(o *Options) { seen.wrap(o) })
	seen.last(t, "mapping a port", func(o conn.Options) bool { return !o.PortMapOff })

	off := false
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, PortMapping: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.PortMapOffFile)); err != nil {
		t.Errorf("port mapping off was not kept: %v", err)
	}
	seen.last(t, "mapping no port", func(o conn.Options) bool { return o.PortMapOff })
	if resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus}); err != nil || resp.Status == nil || !resp.Status.PortMapOff {
		t.Errorf("the status does not say port mapping is off: %v", err)
	}
	if !LoadPrefs(f.home, t.Logf).PortMapOff {
		t.Error("a juistd started again maps a port")
	}

	on := true
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, PortMapping: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.PortMapOffFile)); !os.IsNotExist(err) {
		t.Errorf("port mapping on, the word stays: %v", err)
	}
	seen.last(t, "mapping a port again", func(o conn.Options) bool { return !o.PortMapOff })
}

// The status says what the data plane measured beneath, and nothing before
// it measured.
func TestUnderlayStatusIsTheMeasurement(t *testing.T) {
	if s := underlayStatus(conn.Underlay{PortMapOff: true}); s != nil {
		t.Errorf("nothing measured, the status says %+v", s)
	}
	got := underlayStatus(conn.Underlay{Measured: true, UDP: true, IPv4: true, Mapping: true, PortPerPeer: true,
		Offered: []string{"UPnP"}})
	if got == nil || !got.UDP || !got.IPv4 || !got.Mapping || !got.PortPerPeer || len(got.Offered) != 1 || got.Mapped != "" {
		t.Errorf("the status says %+v", got)
	}
	got = underlayStatus(conn.Underlay{Measured: true, UDP: true, Mapped: netip.MustParseAddrPort("203.0.113.7:41641")})
	if got == nil || got.Mapped != "203.0.113.7:41641" {
		t.Errorf("a port the router maps, the status says %+v", got)
	}
}
