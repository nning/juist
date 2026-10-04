package daemon

import (
	"testing"

	"github.com/nning/juist/conn"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
)

// On a network stack of its own, the data plane's sockets are bound to no
// interface, which would keep them from LANs off the default route.
func TestANetstackNodeBindsItsSocketsToNoInterface(t *testing.T) {
	t.Cleanup(func() { netns.SetEnabled(true) })
	d := &Daemon{}
	connect := d.onNetstack(func(conn.Options) (conn.Manager, error) { return nil, nil })
	if _, err := connect(conn.Options{}); err != nil {
		t.Fatal(err)
	}
	if netns.Listener(t.Logf, netmon.NewStatic()).Control != nil {
		t.Error("the data plane's sockets are still bound by netns")
	}
}
