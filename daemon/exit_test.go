package daemon

import (
	"cmp"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

var defaultRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// exitFixture is a network of three in which device exit (1) is an exit
// node, and the daemon runs as device self, with opts adjusted.
func exitFixture(t *testing.T, exit, admin int, mutate func(*Options)) *reconcileFixture {
	t.Helper()
	return exitFixtureWith(t, func(nw *network) {
		nw.devices[exit].record.Roles = []types.Role{types.RoleExit}
		nw.devices[exit].record.Routes = defaultRoutes
		if admin >= 0 {
			nw.devices[admin].record.Roles = append(nw.devices[admin].record.Roles, types.RoleAdmin)
			slices.Sort(nw.devices[admin].record.Roles)
		}
	}, mutate)
}

// exitFixtureWith is a network of three that network adjusts before genesis,
// and the daemon, run as device 0, with opts adjusted.
func exitFixtureWith(t *testing.T, network func(*network), mutate func(*Options)) *reconcileFixture {
	t.Helper()
	nw := newNetworkMutated(t, 3, network)
	auth, st := nw.authorityFor(t)
	mgr := &fakeManager{}
	self := nw.devices[0]
	opts := Options{
		Authority: auth, Storage: st,
		Identity: self.identity, Recipient: self.recipient, WireGuard: self.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true, DisableDHT: true,
		Logf:       safeLogf(t, ""),
		EgressUser: func() string { return "" },
		ResolvConf: stubResolvConf(t),
	}
	if mutate != nil {
		mutate(&opts)
	}
	d, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return &reconcileFixture{nw: nw, d: d, mgr: mgr, auth: auth, storage: st, self: self}
}

// learnExit hands the daemon dev's announcement, saying it serves or not.
func (f *reconcileFixture) learnExit(t *testing.T, dev *device, port uint16, serving bool) {
	t.Helper()
	e, err := endpointFor(dev, port)
	if err != nil {
		t.Fatal(err)
	}
	e.Exit, e.Seq = serving, e.Seq+1
	if err := e.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
}

// learnOld hands the daemon dev's announcement as a build before schema 14
// makes it, naming no epoch, saying it serves as an exit node and router or
// not.
func (f *reconcileFixture) learnOld(t *testing.T, dev *device, port uint16, serving bool) {
	t.Helper()
	e, err := endpointFor(dev, port)
	if err != nil {
		t.Fatal(err)
	}
	e.Exit, e.Subnets, e.Epoch, e.PairStore, e.Seq = serving, serving, 0, 0, e.Seq+1
	if err := e.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
}

func (f *reconcileFixture) peerRoutes(t *testing.T, dev *device) []netip.Prefix {
	t.Helper()
	f.mgr.mu.Lock()
	defer f.mgr.mu.Unlock()
	for _, p := range f.mgr.peers {
		if p.NodeKey == conn.NodePublicFromRaw32(dev.record.WireGuard) {
			return p.Routes
		}
	}
	return nil
}

func contains(ps []netip.Prefix, a string) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) })
}

// A client routes the internet, and only the internet, through the exit node
// it chose, and gives no other peer a route.
func TestAClientRoutesThroughItsExitNode(t *testing.T) {
	f := exitFixture(t, 1, -1, nil)
	exit, other := f.nw.devices[1], f.nw.devices[2]
	f.learnExit(t, exit, 7001, true)
	f.learn(t, other, 7002)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.mgr.exitState(); e != conn.EgressTunnel {
		t.Fatalf("egress %v, want the tunnel", e)
	}
	routes := f.peerRoutes(t, exit)
	for _, a := range []string{"8.8.8.8", "2606:4700::1111"} {
		if !contains(routes, a) {
			t.Errorf("the exit node does not carry %s", a)
		}
	}
	state := f.auth.State()
	for _, a := range []string{"10.1.2.3", "192.168.1.1", state.Addr6(other.record.Identity).String(),
		other.record.V4.String()} {
		if contains(routes, a) {
			t.Errorf("the exit node carries %s", a)
		}
	}
	if r := f.peerRoutes(t, other); len(r) != 0 {
		t.Errorf("a member that is no exit node carries %v", r)
	}
	if st := f.d.Status().Exit; st == nil || st.Name != exit.record.Name || st.Refused != "" {
		t.Errorf("the status says %+v", st)
	}
}

// Wherever the chosen exit node cannot carry the traffic, it is refused, not
// sent out directly, and the status says why.
func TestAChosenExitNodeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin int
		setup func(t *testing.T, f *reconcileFixture)
		want  string
	}{
		{"not serving", -1, func(t *testing.T, f *reconcileFixture) { f.learnExit(t, f.nw.devices[1], 7001, false) },
			"has not agreed to serve"},
		{"not reachable", -1, func(*testing.T, *reconcileFixture) {}, "cannot be reached"},
		{"an older build", -1, func(t *testing.T, f *reconcileFixture) { f.learnOld(t, f.nw.devices[1], 7001, true) },
			"it runs an older juist, or has yet to catch up"},
		{"stale", 2, func(t *testing.T, f *reconcileFixture) { f.learnExit(t, f.nw.devices[1], 7001, true) },
			"view of the network is stale"},
		{"withdrawn", -1, func(t *testing.T, f *reconcileFixture) {
			f.learnExit(t, f.nw.devices[1], 7001, true)
			rec, err := f.auth.Builder().SetNodeRoutes(f.nw.devices[1].record.Identity, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := rec.Sign(f.nw.admin); err != nil {
				t.Fatal(err)
			}
			if err := f.d.Inform([]types.AUM{rec}); err != nil {
				t.Fatal(err)
			}
		}, "has not made it an exit node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := exitFixture(t, 1, tc.admin, nil)
			f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
			tc.setup(t, f)
			if err := f.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if e, _ := f.mgr.exitState(); e != conn.EgressRefused {
				t.Errorf("egress %v, want refused", e)
			}
			if r := f.peerRoutes(t, f.nw.devices[1]); len(r) != 0 {
				t.Errorf("the exit node carries %d routes", len(r))
			}
			if st := f.d.Status().Exit; st == nil || !strings.Contains(st.Refused, tc.want) {
				t.Errorf("the status says %+v, want %q", st, tc.want)
			}
		})
	}
}

// With no choice, or off, the host routes by itself.
func TestNoExitNodeGoesDirect(t *testing.T) {
	f := exitFixture(t, 1, -1, nil)
	f.learnExit(t, f.nw.devices[1], 7001, true)
	for _, c := range []ExitChoice{{}, {Chosen: true}} {
		f.d.SetExitChoice(c)
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if e, _ := f.mgr.exitState(); e != conn.EgressDirect {
			t.Errorf("%+v: egress %v, want direct", c, e)
		}
		if r := f.peerRoutes(t, f.nw.devices[1]); len(r) != 0 {
			t.Errorf("%+v: the exit node carries %d routes", c, len(r))
		}
	}
}

// An exit node serves while the network makes it one, its operator agreed
// and its view is fresh, masquerading the overlay, and says so in its
// announcement; without any of them it serves nothing.
func TestAnExitNodeServesWhenGrantedAndAgreed(t *testing.T) {
	f := exitFixture(t, 0, -1, nil)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, s := f.mgr.exitState(); len(s.Routes) > 0 {
		t.Fatal("an exit node serves without its operator's word")
	}
	f.d.SetServeConsent(true)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	_, s := f.mgr.exitState()
	if !contains(s.Routes, "8.8.8.8") || contains(s.Routes, "192.168.1.1") {
		t.Fatalf("it serves %v", s.Routes)
	}
	state := f.auth.State()
	for _, p := range append(state.V4Ranges(), state.ULA()) {
		if !slices.Contains(s.Sources, p) {
			t.Errorf("it does not masquerade %v", p)
		}
	}
	if a, ok := f.d.Announcement(); !ok || !a.Exit {
		t.Error("its announcement does not say it serves")
	}
	if st := f.d.Status().Exit; st == nil || !st.Serving {
		t.Errorf("the status says %+v", st)
	}

	rec, err := f.auth.Builder().SetNodeRoutes(f.self.record.Identity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if _, s := f.mgr.exitState(); len(s.Routes) > 0 {
		t.Error("it serves on after the role was withdrawn")
	}
	if a, _ := f.d.Announcement(); a.Exit {
		t.Error("its announcement still says it serves")
	}
	if st := f.d.Status().Exit; st == nil || !strings.Contains(st.NotServing, "has not made this device") {
		t.Errorf("the status says %+v", st)
	}
}

// A stale exit node serves nothing, so that a withdrawal it has not heard of
// ends its serving at the TTL.
func TestAStaleExitNodeServesNothing(t *testing.T) {
	f := exitFixture(t, 0, 2, func(o *Options) { o.ServeExit = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, s := f.mgr.exitState(); len(s.Routes) > 0 {
		t.Fatal("a stale exit node serves")
	}
	if st := f.d.Status().Exit; st == nil || !strings.Contains(st.NotServing, "stale") {
		t.Errorf("the status says %+v", st)
	}
}

// The owner's choice survives a restart, as three states, a node isolated
// or not.
func TestTheExitChoiceIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exit-node")
	id := newDevice(t, "vps", netip.Addr{}).record.Identity
	for _, c := range []ExitChoice{{}, {Chosen: true}, {Chosen: true, Node: id}, {Chosen: true, Node: id, Isolate: true}} {
		if err := SaveExitChoice(path, c); err != nil {
			t.Fatal(err)
		}
		got, err := LoadExitChoice(path)
		if err != nil || got != c {
			t.Errorf("kept %+v, read %+v, %v", c, got, err)
		}
	}
}

// Isolated, answers to what came in by another device go through the exit
// node too, as the data plane is told; not isolated, the status says why
// they would all the same, where the data plane knows.
func TestAnIsolatedChoiceSendsAnswersThrough(t *testing.T) {
	f := exitFixture(t, 1, -1, nil)
	exit := f.nw.devices[1]
	f.learnExit(t, exit, 7001, true)
	f.mgr.mu.Lock()
	f.mgr.through = "the host's own pf rules"
	f.mgr.mu.Unlock()
	for _, isolate := range []bool{false, true} {
		f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity, Isolate: isolate})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		f.mgr.mu.Lock()
		got := f.mgr.isolate
		f.mgr.mu.Unlock()
		st := f.d.Status().Exit
		if got != isolate || st == nil || st.Isolated != isolate || (st.AnswersThrough != "") == isolate {
			t.Errorf("isolate %v: the data plane was told %v, the status says %+v", isolate, got, st)
		}
	}
}

// A juistd that runs as root or as a person's user uses no exit node: its
// own traffic, which goes around it, is that user's.
func TestAnExitNodeNeedsASystemUser(t *testing.T) {
	defs := func(s string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(s), nil }
	}
	for _, uid := range []int{0, 1000, 1500} {
		why := egressUser(uid, defs(""))
		f := exitFixture(t, 1, -1, func(o *Options) { o.EgressUser = func() string { return why } })
		f.learnExit(t, f.nw.devices[1], 7001, true)
		f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if e, _ := f.mgr.exitState(); e != conn.EgressRefused {
			t.Errorf("uid %d: egress %v, want refused", uid, e)
		}
		if st := f.d.Status().Exit; st == nil || why == "" || st.Refused != why {
			t.Errorf("uid %d: the status says %+v", uid, st)
		}
	}
	if egressUser(900, defs("")) != "" {
		t.Error("a system user is refused")
	}
	for _, tc := range []struct {
		uid  int
		defs string
		want bool
	}{
		{999, "", true}, {1000, "", false}, {0, "", false},
		{499, "# comment\nUID_MIN 500\n", true}, {500, "UID_MIN\t500\n", false}, {900, "UID_MIN x\n", true},
	} {
		if got := systemUser(tc.uid, defs(tc.defs)); got != tc.want {
			t.Errorf("uid %d with %q: %v", tc.uid, tc.defs, got)
		}
	}
}

// A chosen exit node that rotates its identity stays the choice, and the new
// identity is kept.
func TestTheChoiceFollowsARotatedExitNode(t *testing.T) {
	moved := make(chan [2]types.Identity, 1)
	f := exitFixture(t, 1, -1, func(o *Options) {
		o.OnExitMoved = func(from, to types.Identity) { moved <- [2]types.Identity{from, to} }
	})
	exit := f.nw.devices[1]
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := f.auth.Builder().RotateIdentity(exit.record.Identity, fresh.Public(), f.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []types.PrivateIdentity{exit.identity, fresh, f.nw.admin} {
		if err := rec.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	rotated := *exit
	rotated.identity, rotated.record.Identity = fresh, fresh.Public()
	f.learnExit(t, &rotated, 7001, true)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Exit; st == nil || st.Node != fresh.Public() || st.Refused != "" {
		t.Fatalf("the status says %+v", st)
	}
	if e, _ := f.mgr.exitState(); e != conn.EgressTunnel {
		t.Errorf("egress %v, want the tunnel", e)
	}
	select {
	case m := <-moved:
		if m != [2]types.Identity{exit.record.Identity, fresh.Public()} {
			t.Errorf("told of a move %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Error("the service was not told to keep the new identity")
	}
}

// A data plane that refuses the relay set serves nothing and routes nothing
// through an exit node, as one refusing the peer set does.
func TestARefusedRelaySetEndsServing(t *testing.T) {
	f := exitFixture(t, 0, -1, func(o *Options) { o.ServeExit = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, s := f.mgr.exitState(); len(s.Routes) == 0 {
		t.Fatal("it does not serve to begin with")
	}
	f.mgr.mu.Lock()
	f.mgr.relayErr = errors.New("no relays today")
	f.mgr.mu.Unlock()
	rec, err := f.auth.Builder().SetNodeRoutes(f.nw.devices[2].record.Identity, []types.Role{types.RoleRelayCapable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	_ = f.d.Inform([]types.AUM{rec})
	if _, s := f.mgr.exitState(); len(s.Routes) > 0 {
		t.Error("it serves on beside a refused relay set")
	}
}

// Where the data plane cannot even refuse, the status says the traffic may
// leave directly, not that it is refused.
func TestAnEgressThatFailsIsNotCalledRefused(t *testing.T) {
	f := exitFixture(t, 1, -1, nil)
	f.learnExit(t, f.nw.devices[1], 7001, true)
	fail := errors.New("no nftables")
	for _, tc := range []struct {
		fails           []conn.Egress
		choice          ExitChoice
		refused, failed bool
	}{
		{[]conn.Egress{conn.EgressTunnel}, ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity}, true, false},
		{[]conn.Egress{conn.EgressTunnel, conn.EgressRefused}, ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity}, false, true},
		{[]conn.Egress{conn.EgressDirect}, ExitChoice{Chosen: true}, false, false},
		{nil, ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity}, true, false},
	} {
		f.mgr.mu.Lock()
		f.mgr.egressErr = map[conn.Egress]error{}
		for _, e := range tc.fails {
			f.mgr.egressErr[e] = fail
		}
		if tc.fails == nil {
			f.mgr.egressErr[conn.EgressTunnel] = conn.ErrEgressTaken
			f.mgr.egressErr[conn.EgressRefused] = conn.ErrEgressTaken
		}
		f.mgr.mu.Unlock()
		f.d.SetExitChoice(tc.choice)
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		ex := cmp.Or(f.d.Status().Exit, &ipc.Exit{})
		if (ex.Refused != "") != tc.refused || (ex.Failed != "") != tc.failed {
			t.Errorf("%v failing: the status says %+v", tc.fails, ex)
		}
	}
}

// The service keeps the choice the mesh holds after a rotation, and not a
// rotation's step the mesh has gone past.
func TestTheServiceKeepsTheMeshsFollowedChoice(t *testing.T) {
	nw := newNetwork(t, 3)
	f := serviceWithChoice(t, nw, nw.devices[0], nw.devices[1].record.Identity.String()+"\n")
	a, b, c := nw.devices[1].record.Identity, nw.devices[2].record.Identity, newDevice(t, "c", netip.Addr{}).record.Identity
	f.s.Mesh().SetExitChoice(ExitChoice{Chosen: true, Node: c})
	f.s.followExit(a, b)
	if got, _ := LoadExitChoice(filepath.Join(f.home, statedir.ExitFile)); got.Node != a {
		t.Errorf("a step the mesh went past was kept: %v", got.Node)
	}
	f.s.followExit(b, c)
	if got, _ := LoadExitChoice(filepath.Join(f.home, statedir.ExitFile)); got.Node != c {
		t.Errorf("kept %v, want the mesh's %v", got.Node, c)
	}
}

// serviceWithChoice is a service over nw's log, as device self, whose home
// holds exit-node file contents choice, if any.
func serviceWithChoice(t *testing.T, nw *network, self *device, choice string, mutate ...func(*Options)) *serviceFixture {
	t.Helper()
	home := socketDir(t)
	writeDevice(t, home, self)
	st, err := store.Open(filepath.Join(home, keys.LogDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.FromRecords(st, []types.AUM{nw.genesis}); err != nil {
		t.Fatal(err)
	}
	if choice != "" {
		if err := os.WriteFile(filepath.Join(home, statedir.ExitFile), []byte(choice), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return startServiceWith(t, nw, home, func(o *Options) {
		o.EgressUser = func() string { return "" }
		for _, m := range mutate {
			m(o)
		}
	})
}

func (f *serviceFixture) exitStatus(t *testing.T) *ipc.Exit {
	t.Helper()
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status.Exit
}

// A choice kept that cannot be read is refused, not taken for none, and
// isolated, as it may have been.
func TestAnUnreadableChoiceIsRefused(t *testing.T) {
	nw := newNetwork(t, 2)
	f := serviceWithChoice(t, nw, nw.devices[0], "nid:garbage\n")
	waitFor(t, 10*time.Second, "the refusal", func() bool {
		ex := f.exitStatus(t)
		e, _ := f.mgr.exitState()
		f.mgr.mu.Lock()
		isolated := f.mgr.isolate
		f.mgr.mu.Unlock()
		return ex != nil && strings.Contains(ex.Refused, "cannot be read") && e == conn.EgressRefused && isolated
	})
}

// Without a mesh, as on a device the network removed, the choice is still
// refused, and the status says so.
func TestAChoiceWithoutAMeshIsRefused(t *testing.T) {
	nw := newNetwork(t, 2)
	stranger := newDevice(t, "stranger", netip.Addr{})
	f := serviceWithChoice(t, nw, stranger, nw.devices[1].record.Identity.String()+"\n")
	ex := f.exitStatus(t)
	if ex == nil || ex.Node != nw.devices[1].record.Identity || !strings.Contains(ex.Refused, "no member") {
		t.Fatalf("the status says %+v", ex)
	}
}

// A reset forgets the choice and the consent with the network, and a choice
// that cannot be kept is not taken.
func TestAResetForgetsTheExitChoice(t *testing.T) {
	nw := newNetwork(t, 2)
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	if err := os.Mkdir(filepath.Join(f.home, statedir.ExitFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdExit, ExitNode: nw.devices[1].record.Identity}); err == nil {
		t.Fatal("a choice that could not be kept was taken")
	}
	f.s.mu.Lock()
	held := f.s.exit
	f.s.mu.Unlock()
	if held != (ExitChoice{}) {
		t.Fatalf("a choice not kept is held: %+v", held)
	}
	if err := os.Remove(filepath.Join(f.home, statedir.ExitFile)); err != nil {
		t.Fatal(err)
	}
	on := true
	for _, req := range []ipc.Request{{Command: ipc.CmdExit, ExitNode: nw.devices[1].record.Identity},
		{Command: ipc.CmdExit, Serve: &on}} {
		if _, err := ipc.Call(f.sock, req); err != nil {
			t.Fatal(err)
		}
	}
	if ex := f.exitStatus(t); ex == nil || !ex.Consent || ex.Node.IsZero() {
		t.Fatalf("before the reset: %+v", ex)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdReset, Force: true}); err != nil {
		t.Fatal(err)
	}
	if ex := f.exitStatus(t); ex != nil {
		t.Errorf("after the reset: %+v", ex)
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.exit != (ExitChoice{}) || f.s.serve {
		t.Errorf("the service holds on to %+v, serving %v", f.s.exit, f.s.serve)
	}
}

// The exit node in use carries in the status what the host's reverse-path
// filter makes of its IPv6 answers.
func TestTheStatusSaysAStrictReversePathFilter(t *testing.T) {
	for _, strict := range []bool{false, true} {
		f := exitFixture(t, 1, -1, func(o *Options) { o.StrictRP6 = func() bool { return strict } })
		f.learnExit(t, f.nw.devices[1], 7001, true)
		f.d.SetExitChoice(ExitChoice{Chosen: true, Node: f.nw.devices[1].record.Identity})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if st := f.d.Status().Exit; st == nil || st.StrictRP6 != strict {
			t.Errorf("strict %v, the status says %+v", strict, st)
		}
	}
}

// A reverse-path filter that cannot be read is logged, not taken for loose
// unsaid.
func TestAnUnreadableReversePathFilterIsLogged(t *testing.T) {
	f := exitFixture(t, 1, -1, nil)
	strict := f.d.loggedStrictRP6(func() (bool, error) { return false, errors.New("operation not permitted") })
	if strict() {
		t.Error("an unread filter is taken for strict")
	}
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	if !f.d.logged["daemon: reading the host's reverse-path filter: operation not permitted"] {
		t.Errorf("not logged: %v", f.d.logged)
	}
}
