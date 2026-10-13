package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// A device holding the publish role shares under its own name: it announces
// the share with an end at most a lease ahead, or the share's own, its
// terminator ends TLS for the name without the word published names need,
// and an ingress may open its port while the view is fresh; one share of a
// port at a time, and none without the role.
func TestADeviceSharesUnderItsName(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
		nw.devices[1].record.Roles = []types.Role{types.RoleIngress}
	}, nil)
	f.learnOthers(t)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	name, sh, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{})
	if err != nil || name != "n0.pub.example.org" {
		t.Fatalf("sharing as %q: %v", name, err)
	}
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8001"}, time.Time{}); !errors.Is(err, ErrPortShared) {
		t.Errorf("a second share: %v", err)
	}
	now := f.d.now()
	e, ok := f.d.announce(0)
	if !ok || e.Share == nil || e.Share.Port != 443 ||
		e.Share.Until <= now.Add(shareLease/2).Unix()-1 || e.Share.Until > now.Add(shareLease).Unix() {
		t.Fatalf("the announcement shares %+v", e.Share)
	}
	got := f.d.Serving(nil)
	if i := slices.IndexFunc(got.Names, func(n ipc.PublishedTarget) bool { return n.Name == name }); i < 0 ||
		got.Names[i].To != "127.0.0.1:8000" || got.Names[i].Port != 443 {
		t.Errorf("the terminator is told %+v", got.Names)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if ports := f.mgr.ingressPortsNow(); !slices.Contains(ports, 443) {
		t.Errorf("an ingress may open %v", ports)
	}
	if st := f.d.sharesStatus(f.auth.State(), true, now); len(st) != 1 || st[0].Name != name || st[0].NotShared != "" {
		t.Errorf("the status says %+v", st)
	}

	f.d.EndShare(sh)
	if e, _ := f.d.announce(0); e.Share != nil {
		t.Errorf("an ended share is announced: %+v", e.Share)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if ports := f.mgr.ingressPortsNow(); slices.Contains(ports, 443) {
		t.Errorf("after the share an ingress may open %v", ports)
	}

	end := now.Add(time.Minute)
	_, sh, err = f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, end)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := f.d.announce(0); e.Share == nil || e.Share.Until != end.Unix() {
		t.Errorf("a share ending sooner than a lease is announced as %+v", e.Share)
	}
	f.d.EndShare(sh)

	g := exitFixtureWith(t, func(nw *network) { nw.domain = "pub.example.org" }, nil)
	if _, _, err := g.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); !errors.Is(err, ErrNoPublishRole) {
		t.Errorf("sharing without the role: %v", err)
	}
}

// A device holds several shares under its one name: a file's under its own
// path, and one port's beside them, which takes what no path does, else the
// first path's server does; announced to the last end, each stopped by its
// path alone, and no more than maxShares.
func TestADeviceHoldsSeveralShares(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	}, nil)
	f.learnOthers(t)
	now := f.d.now()
	served := func() ipc.PublishedTarget {
		t.Helper()
		got := f.d.Serving(nil)
		i := slices.IndexFunc(got.Names, func(n ipc.PublishedTarget) bool { return n.Name == "n0.pub.example.org" })
		if i < 0 {
			t.Fatalf("the terminator is told %+v", got.Names)
		}
		return got.Names[i]
	}
	shared := func() []string {
		var out []string
		for _, sh := range f.d.sharesStatus(f.auth.State(), true, f.d.now()) {
			out = append(out, sh.To)
		}
		return out
	}
	a := &ipc.ShareRequest{To: "127.0.0.1:9001", What: "/srv/a", Path: "/tokA/"}
	b := &ipc.ShareRequest{To: "127.0.0.1:9002", What: "/srv/b.pdf", Path: "/tokB/b.pdf"}
	if _, _, err := f.d.StartShare(a, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.d.StartShare(b, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	paths := []ipc.PathTarget{{Prefix: "/tokA/", To: "127.0.0.1:9001"}, {Prefix: "/tokB/", To: "127.0.0.1:9002"}}
	if n := served(); n.To != "127.0.0.1:9001" || !slices.Equal(n.Paths, paths) {
		t.Errorf("without a port, the terminator is told %+v", n)
	}
	if e, _ := f.d.announce(0); e.Share == nil || e.Share.Until != now.Add(2*time.Minute).Unix() {
		t.Errorf("two shares are announced as %+v", e.Share)
	}
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:9003", Path: "/tokA/x"}, time.Time{}); !errors.Is(err, ErrPathShared) {
		t.Errorf("a second share under a path: %v", err)
	}
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n := served(); n.To != "127.0.0.1:8000" || !slices.Equal(n.Paths, paths) {
		t.Errorf("beside a port, the terminator is told %+v", n)
	}
	if e, _ := f.d.announce(0); e.Share == nil || e.Share.Until > now.Add(shareLease).Unix() {
		t.Errorf("shares one of which has no end are announced as %+v", e.Share)
	}
	if got := shared(); !slices.Equal(got, []string{"127.0.0.1:9001", "127.0.0.1:9002", "127.0.0.1:8000"}) {
		t.Errorf("the status lists %v", got)
	}

	if err := f.d.StopShare("/tokB/b.pdf", false); err != nil {
		t.Fatal(err)
	}
	if err := f.d.StopShare("", false); err != nil {
		t.Fatal(err)
	}
	if got := shared(); !slices.Equal(got, []string{"127.0.0.1:9001"}) {
		t.Errorf("stopped by path, the status lists %v", got)
	}
	if err := f.d.StopShare("/tokB/b.pdf", false); !errors.Is(err, ErrNotSharing) {
		t.Errorf("stopping a stopped share: %v", err)
	}

	for i := len(shared()); i < maxShares; i++ {
		if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:9100", Path: fmt.Sprintf("/t%d/", i)}, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:9100", Path: "/more/"}, time.Time{}); !errors.Is(err, ErrTooManyShares) {
		t.Errorf("a share past %d: %v", maxShares, err)
	}
}

// juistd stops the share an unshare request names by its path, and every
// share for one that names none.
func TestAnUnshareStopsTheShareItNames(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	for _, req := range []*ipc.ShareRequest{{To: "127.0.0.1:9001", Path: "/tokA/"}, {To: "127.0.0.1:9002", Path: "/tokB/"},
		{To: "127.0.0.1:8000"}} {
		if _, _, err := f.s.Mesh().StartShare(req, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnshare, Share: &ipc.ShareRequest{Path: "/tokA/"}}); err != nil {
		t.Fatal(err)
	}
	if st := f.s.Status(); len(st.Shares) != 2 || st.Shares[0].Path != "/tokB/" || st.Shares[1].To != "127.0.0.1:8000" {
		t.Errorf("one stopped, the status lists %+v", st.Shares)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnshare}); err != nil {
		t.Fatal(err)
	}
	if st := f.s.Status(); len(st.Shares) != 0 {
		t.Errorf("all stopped, the status lists %+v", st.Shares)
	}
}

// An ingress serves a member's share under the member's name while the
// member holds the role and its announcement holds, and not past its end.
func TestAnIngressServesMembersShares(t *testing.T) {
	published := func(roles []types.Role, until time.Duration) *ipc.Published {
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
			nw.devices[1].record.Roles = roles
		}, nil)
		e, err := endpointFor(f.nw.devices[1], 7001)
		if err != nil {
			t.Fatal(err)
		}
		e.Share = &gossip.Share{Port: 443, Until: f.d.now().Add(until).Unix()}
		if err := e.SignPQ(f.nw.devices[1].identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
		return f.d.Published()
	}
	got := published([]types.Role{types.RolePublish}, time.Minute)
	if len(got.Names) != 1 || got.Names[0].Name != "n1.pub.example.org" || got.Names[0].Port != 443 ||
		len(got.Names[0].Addrs) != 2 {
		t.Fatalf("an ingress serves %+v", got.Names)
	}
	if got := published(nil, time.Minute); len(got.Names) != 0 {
		t.Errorf("an ingress serves a share of a member without the role: %+v", got.Names)
	}
	if got := published([]types.Role{types.RolePublish}, -time.Second); len(got.Names) != 0 {
		t.Errorf("an ingress serves a share past its end: %+v", got.Names)
	}
}

// Over the socket a share lasts as long as the call: the caller hears the
// name, and once it hangs up the device shares nothing.
func TestAShareLastsAsLongAsTheCall(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	ctx, cancel := context.WithCancel(context.Background())
	named := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := ipc.Converse(ctx, f.sock, ipc.Request{Command: ipc.CmdShare, Share: &ipc.ShareRequest{To: "127.0.0.1:8000"}},
			func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
				if e.Kind == ipc.EventSharing {
					named <- e.Name
				}
				return nil
			})
		done <- err
	}()
	select {
	case name := <-named:
		if name != "n0.pub.example.org" {
			t.Errorf("sharing as %q", name)
		}
	case err := <-done:
		t.Fatalf("the share ended at once: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no word of the share")
	}
	if st := f.s.Status(); len(st.Shares) != 1 || st.Shares[0].To != "127.0.0.1:8000" {
		t.Errorf("sharing, the status says %+v", st.Shares)
	}
	cancel()
	<-done
	waitFor(t, 10*time.Second, "the share's end", func() bool { return len(f.s.Status().Shares) == 0 })
}

// A share is stopped from another call: the call holding it ends without
// error, and a second stop finds nothing to stop.
func TestAShareIsStoppedFromAnotherCall(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnshare}); err == nil || err.Error() != ErrNotSharing.Error() {
		t.Fatalf("stopping no share: %v", err)
	}
	named := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, err := ipc.Converse(context.Background(), f.sock, ipc.Request{Command: ipc.CmdShare,
			Share: &ipc.ShareRequest{To: "127.0.0.1:8000"}},
			func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
				if e.Kind == ipc.EventSharing {
					named <- struct{}{}
				}
				return nil
			})
		done <- err
	}()
	select {
	case <-named:
	case err := <-done:
		t.Fatalf("the share ended at once: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no word of the share")
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnshare}); err != nil {
		t.Fatalf("stopping the share: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the stopped share's call: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call holding a stopped share goes on")
	}
	if st := f.s.Status(); len(st.Shares) != 0 {
		t.Errorf("stopped, the status says %+v", st.Shares)
	}
}

// A share is announced while this device can serve it alone: not once the
// role is withdrawn, nor while the view is stale, which the status says.
func TestAShareIsAnnouncedWhileItCanBeServed(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	}, nil)
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if st := f.d.sharesStatus(f.auth.State(), true, f.d.now()); len(st) != 1 || st[0].NotShared != "the terminator does not run" {
		t.Errorf("before the terminator asked, the status says %+v", st)
	}
	rec, err := f.auth.Builder().SetNodeRoutes(f.nw.devices[0].record.Identity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(f.nw.admin, f.auth.State().Schema()); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.d.announce(0); e.Share != nil {
		t.Errorf("a share without the role is announced: %+v", e.Share)
	}

	g := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
		nw.devices[2].record.Roles = []types.Role{types.RoleAdmin} // a voucher who vouched nothing
	}, nil)
	if _, _, err := g.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if e, _ := g.d.announce(0); e.Share != nil {
		t.Errorf("a share is announced while the view is stale: %+v", e.Share)
	}
}

// A running share has its announcement go out once its end moves, once each
// half lease, and not otherwise.
func TestAShareIsRenewedAsItsEndMoves(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	}, func(o *Options) { o.Clock = c.get })
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	var last int64
	if !f.d.renewShare(&last) {
		t.Fatal("a new share is not announced")
	}
	c.set(c.get().Add(time.Minute))
	if f.d.renewShare(&last) {
		t.Error("a share renewed with its end where it was")
	}
	c.set(c.get().Add(shareLease / 2))
	if !f.d.renewShare(&last) {
		t.Error("a share whose end moved is not renewed")
	}
}

// An ingress takes no share that ends further ahead than a lease, so one
// whose device is gone ends with it.
func TestAnIngressTakesNoShareEndingFarAhead(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
		nw.devices[1].record.Roles = []types.Role{types.RolePublish}
	}, nil)
	e, err := endpointFor(f.nw.devices[1], 7001)
	if err != nil {
		t.Fatal(err)
	}
	e.Share = &gossip.Share{Port: 443, Until: f.d.now().Add(time.Hour).Unix()}
	if err := e.SignPQ(f.nw.devices[1].identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if got := f.d.Published(); len(got.Names) != 0 {
		t.Errorf("an ingress takes a share ending an hour ahead: %+v", got.Names)
	}
}

// A share outlives a restart of the network beneath it, taken up again by
// the new one.
func TestAShareOutlivesARestart(t *testing.T) {
	defer func(d time.Duration) { shareCheck = d }(shareCheck)
	shareCheck = 20 * time.Millisecond
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	named := make(chan string, 2)
	go ipc.Converse(ctx, f.sock, ipc.Request{Command: ipc.CmdShare, Share: &ipc.ShareRequest{To: "127.0.0.1:8000"}},
		func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
			named <- e.Name
			return nil
		})
	<-named
	before := f.s.Mesh()
	f.s.mu.Lock()
	f.s.restartMeshLocked(nil, "a test")
	f.s.mu.Unlock()
	waitFor(t, 10*time.Second, "the share in the restarted network", func() bool {
		m := f.s.Mesh()
		return m != nil && m != before && len(m.sharesNow(time.Now())) == 1
	})
}

// A share whose device is renamed is said again under its new name.
func TestARenamedShareIsSaidAgain(t *testing.T) {
	defer func(d time.Duration) { shareCheck = d }(shareCheck)
	shareCheck = 20 * time.Millisecond
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	named := make(chan string, 2)
	go ipc.Converse(ctx, f.sock, ipc.Request{Command: ipc.CmdShare, Share: &ipc.ShareRequest{To: "127.0.0.1:8000"}},
		func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
			named <- e.Name
			return nil
		})
	if got := <-named; got != "n0.pub.example.org" {
		t.Fatalf("shares under %s", got)
	}
	m := f.s.Mesh()
	m.authMu.Lock()
	rec, err := m.authority.Builder().RenameNode(nw.devices[0].record.Identity, "desk")
	m.authMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(nw.admin, m.authority.State().Schema()); err != nil {
		t.Fatal(err)
	}
	if err := m.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-named:
		if got != "desk.pub.example.org" {
			t.Errorf("renamed, shares under %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Error("renamed, the share was not said again")
	}
}

// A share ends, saying why, once its device holds the publish role no more.
func TestAShareEndsWithItsRole(t *testing.T) {
	defer func(d time.Duration) { shareCheck = d }(shareCheck)
	shareCheck = 20 * time.Millisecond
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	named := make(chan string, 1)
	ended := make(chan string, 1)
	go func() {
		resp, err := ipc.Converse(context.Background(), f.sock, ipc.Request{Command: ipc.CmdShare,
			Share: &ipc.ShareRequest{To: "127.0.0.1:8000"}},
			func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
				named <- e.Name
				return nil
			})
		if err != nil {
			resp.Err = err.Error()
		}
		ended <- resp.Err
	}()
	<-named
	m := f.s.Mesh()
	m.authMu.Lock()
	rec, err := m.authority.Builder().SetNodeRoutes(nw.devices[0].record.Identity, nil, nil)
	m.authMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(nw.admin, m.authority.State().Schema()); err != nil {
		t.Fatal(err)
	}
	if err := m.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	select {
	case why := <-ended:
		if why != ErrNoPublishRole.Error() {
			t.Errorf("the share ended with %q", why)
		}
	case <-time.After(10 * time.Second):
		t.Error("the share outlived its role")
	}
}

// A share's end ends that share alone, never one started after it.
func TestAShareEndsItselfAlone(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	}, nil)
	_, first, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	f.d.EndShare(first)
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8001"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.d.EndShare(first)
	if shs := f.d.sharesNow(f.d.now()); len(shs) != 1 || shs[0].to != "127.0.0.1:8001" {
		t.Errorf("an ended share's end ended the next: %+v", shs)
	}
}

// A share restarted with its network leaves one another call made in the
// new network meanwhile, and ends.
func TestARestartedShareLeavesAnothers(t *testing.T) {
	defer func(d time.Duration) { shareCheck = d }(shareCheck)
	shareCheck = 50 * time.Millisecond
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	})
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	waitFor(t, 10*time.Second, "the mesh", func() bool { return f.s.Mesh() != nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	named, done := make(chan string, 2), make(chan error, 1)
	go func() {
		_, err := ipc.Converse(ctx, f.sock, ipc.Request{Command: ipc.CmdShare, Share: &ipc.ShareRequest{To: "127.0.0.1:8000"}},
			func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
				named <- e.Name
				return nil
			})
		done <- err
	}()
	<-named
	f.s.mu.Lock()
	f.s.restartMeshLocked(nil, "a test")
	f.s.mu.Unlock()
	if _, _, err := f.s.Mesh().StartShare(&ipc.ShareRequest{To: "127.0.0.1:9000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the restarted share does not end beside another's")
	}
	if shs := f.s.Mesh().sharesNow(time.Now()); len(shs) != 1 || shs[0].to != "127.0.0.1:9000" {
		t.Errorf("the other share is %+v", shs)
	}
}

// An ingress's look at what is published leaves the daemon as it was, and a
// device whose membership has run out tells its helpers nothing.
func TestPublishedHasNoSideEffectsAndExpiryEndsServing(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
	}, nil)
	f.d.mu.Lock()
	f.d.v4 = nil
	f.d.mu.Unlock()
	f.d.Published()
	f.d.mu.Lock()
	v4 := f.d.v4
	f.d.mu.Unlock()
	if v4 != nil {
		t.Errorf("a look at what is published set the ranges to %v", v4)
	}

	g := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
		nw.devices[0].record.Expiry = uint64(time.Now().Add(-time.Hour).Unix())
	}, nil)
	if _, _, err := g.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := g.d.Serving(nil); len(got.Names) != 0 {
		t.Errorf("an expired device's terminator is told %+v", got.Names)
	}
}

// The status says where the terminator listens and where another program
// holds the port, as the terminator last said; a look by the operator
// changes nothing of it.
// juistd keeps the terminator's file while a share or a name whose TLS juist
// ends needs it, and tells the terminator when nothing does.
func TestJuistdSaysWhenTheTerminatorIsNeeded(t *testing.T) {
	wanted := filepath.Join(t.TempDir(), "serve-wanted")
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RolePublish}
	}, func(o *Options) { o.TerminatorWanted = wanted })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	needed := func(want bool) {
		t.Helper()
		_, err := os.Stat(wanted)
		if exists := err == nil; exists != want {
			t.Fatalf("the file exists: %v, want %v", exists, want)
		}
		if idle := f.d.Serving(&ipc.TerminatorReport{}).Idle; idle == want {
			t.Fatalf("the terminator is told it is idle: %v", idle)
		}
	}
	needed(false)
	_, sh, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	needed(true)
	f.d.EndShare(sh)
	needed(false)
	f.d.SetPublishConsent(true, map[string]string{"immich": "127.0.0.1:2283"}, nil)
	needed(true)
	f.d.SetPublishConsent(true, nil, nil)
	needed(false)
	if _, _, err := f.d.StartShare(&ipc.ShareRequest{To: "127.0.0.1:8000"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.StopShare("", true); err != nil {
		t.Fatal(err)
	}
	needed(false)

	other := exitFixtureWith(t, func(nw *network) { nw.domain = "pub.example.org" }, nil)
	if p := other.d.Serving(&ipc.TerminatorReport{}); p.Idle {
		t.Error("a juistd that keeps no file told its terminator it is idle")
	}
}

func TestTheStatusSaysWhereTheTerminatorListens(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) { nw.domain = "pub.example.org" }, nil)
	if st := f.d.terminatorStatus(); st != nil {
		t.Fatalf("before the terminator asked: %+v", st)
	}
	noCert := []ipc.NoCert{{Name: "immich.pub.example.org", Why: "no viable challenge type found"}}
	f.d.Serving(&ipc.TerminatorReport{Listening: []string{"100.64.0.1:443"}, Unbound: []string{"100.64.0.1:8443"},
		NoCert: noCert})
	f.d.serving(&ipc.TerminatorReport{}, false)
	st := f.d.terminatorStatus()
	if st == nil || !st.Running || !slices.Equal(st.Listening, []string{"100.64.0.1:443"}) ||
		!slices.Equal(st.Unbound, []string{"100.64.0.1:8443"}) || !slices.Equal(st.NoCert, noCert) {
		t.Errorf("the status says %+v", st)
	}
	if p := f.d.Serving(&ipc.TerminatorReport{Stopping: true}); len(p.Names) != 0 {
		t.Errorf("a terminator that stops is told %+v", p)
	}
	if st := f.d.terminatorStatus(); st != nil {
		t.Errorf("once the terminator said it stops, the status says %+v", st)
	}
}
