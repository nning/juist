package daemon

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// The terminator is told what the status page shows where its operator
// serves one, and its members leave the ingress out, which brings the
// public; nobody but the terminator and the operator is told.
func TestTheTerminatorIsToldTheStatusPage(t *testing.T) {
	nw := newNetworkMutated(t, 3, func(nw *network) { nw.devices[2].record.Roles = []types.Role{types.RoleIngress} })
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	serve, reader := caller{uid: 4244, known: true}, caller{uid: 4245, known: true}
	if f.s.selfUID == serve.uid || f.s.selfUID == reader.uid {
		t.Skip("the test user happens to have the terminator's uid")
	}
	f.s.serveUID = serve.uid
	ask := func(who caller) ipc.Response {
		return f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdStatusPage}, who, func(*ipc.Event) error { return nil }, nil)
	}
	if resp := ask(serve); resp.Err != errNoStatusPage.Error() {
		t.Errorf("with no status page served: %+v", resp)
	}
	on := true
	if err := f.s.setPublish(&ipc.Request{ServePublished: &on,
		ServeTo: []ipc.ServeTo{{Label: "status", To: ipc.StatusPageTo(ipc.ShowAll)}}}); err != nil {
		t.Fatal(err)
	}
	var p *ipc.StatusPage
	waitFor(t, 10*time.Second, "the status page's members", func() bool {
		resp := ask(serve)
		p = resp.StatusPage
		return resp.Err == "" && p != nil && len(p.Members) > 0
	})
	for addr, want := range map[string]bool{"198.18.0.1": true, "198.18.0.2": true, "198.18.0.3": false} {
		if got := slices.Contains(p.Members, netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s a member's: %v", addr, got)
		}
	}
	if p.Total != 1 || len(p.Changes) != 1 || p.Changes[0].What != "network creation" || p.Status.SelfName != "n0" {
		t.Errorf("the page: %d changes, %+v, %q", p.Total, p.Changes, p.Status.SelfName)
	}
	if resp := ask(reader); resp.Err != ipc.ErrNotOperator || resp.StatusPage != nil {
		t.Errorf("a reader got %+v", resp)
	}
}
