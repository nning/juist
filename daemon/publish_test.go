package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// publishFixture is a network of three under pub.example.org, publishing
// immich on device 0, where the daemon runs, with device 1 an ingress.
func publishFixture(t *testing.T, mutate func(*Options)) *reconcileFixture {
	t.Helper()
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Published = []types.PublishedName{{Label: "immich", Port: 2283}}
		nw.devices[1].record.Roles = []types.Role{types.RoleIngress}
	}, mutate)
	f.learnOthers(t)
	return f
}

// learnOthers hands the daemon every other device's announcement.
func (f *reconcileFixture) learnOthers(t *testing.T) {
	t.Helper()
	for i, dev := range f.nw.devices[1:] {
		e, err := endpointFor(dev, uint16(7001+i))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *reconcileFixture) peerOf(t *testing.T, dev *device) conn.Peer {
	t.Helper()
	f.mgr.mu.Lock()
	defer f.mgr.mu.Unlock()
	for _, p := range f.mgr.peers {
		if p.NodeKey == conn.NodePublicFromRaw32(dev.record.WireGuard) {
			return p
		}
	}
	t.Fatalf("%s is no peer", dev.record.Name)
	return conn.Peer{}
}

// An ingress is confined, and reaches log sync alone until the operator
// agrees to serve what is published here; then the published port too, while
// the view is fresh.
func TestAnIngressReachesWhatIsServedAlone(t *testing.T) {
	f := publishFixture(t, nil)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerOf(t, f.nw.devices[1]).Access; got == nil {
		t.Error("the ingress is not confined")
	}
	if got := f.peerOf(t, f.nw.devices[2]).Access; got != nil {
		t.Errorf("a member is confined to %+v", got)
	}
	gossip := f.d.gossipPort
	if got := f.mgr.ingressPortsNow(); !slices.Equal(got, []uint16{gossip}) {
		t.Errorf("not agreed, an ingress may open %v", got)
	}
	if st := f.d.Status().Publish; st == nil || st.Consent || len(st.Serving) > 0 {
		t.Errorf("not agreed, the status says %+v", st)
	}

	f.d.SetPublishConsent(true, nil)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.mgr.ingressPortsNow(); !slices.Equal(got, slices.Sorted(slices.Values([]uint16{gossip, 2283}))) {
		t.Errorf("agreed, an ingress may open %v", got)
	}
	if st := f.d.Status().Publish; st == nil || !slices.Equal(st.Serving, []string{"immich.pub.example.org"}) {
		t.Errorf("agreed, the status says %+v", st)
	}
	if got := f.d.planPublish(f.d.snapshotOf(f.auth.State()), false); !slices.Equal(got.TCP, []uint16{gossip}) || len(got.UDP) > 0 {
		t.Errorf("stale, an ingress may open %v", got)
	}
	if st := f.d.publishNow(); st == nil || st.NotServing != "this device's view of the network is stale" {
		t.Errorf("stale, the status says %+v", st)
	}
	f.mgr.mu.Lock()
	f.mgr.relayErr = errors.New("no relays today")
	f.mgr.mu.Unlock()
	if err := f.d.Reconcile(); err == nil {
		t.Fatal("a refused relay set went unsaid")
	}
	if got := f.mgr.ingressPortsNow(); !slices.Equal(got, []uint16{gossip}) {
		t.Errorf("beside a refused relay set, an ingress may open %v", got)
	}
}

// The operator's word is kept, and goes with the network.
func TestThePublishWordIsKept(t *testing.T) {
	nw := newNetwork(t, 2)
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	on := true
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdPublish, ServePublished: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.PublishServeFile)); err != nil {
		t.Errorf("%s is not kept: %v", statedir.PublishServeFile, err)
	}
	st, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil || st.Status.Publish == nil || !st.Status.Publish.Consent {
		t.Fatalf("the status says %+v, %v", st.Status.Publish, err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdReset, Force: true}); err != nil {
		t.Fatal(err)
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.servePublished {
		t.Error("the service holds on to the word after a reset")
	}
}

// The ingress may ask what is published, and nothing else, the status
// included; no other caller but an operator may ask that.
func TestTheIngressAsksWhatIsPublishedAlone(t *testing.T) {
	f := newServiceFixture(t, true)
	ingress, stranger := caller{uid: 4242, known: true}, caller{uid: 4343, known: true}
	if f.s.selfUID == ingress.uid || f.s.selfUID == stranger.uid {
		t.Skip("the test user happens to have one of the callers' uids")
	}
	f.s.ingressUID = ingress.uid
	ask := func(who caller, cmd ipc.Command) ipc.Response {
		return f.s.handle(context.Background(), &ipc.Request{Command: cmd}, who, func(*ipc.Event) error { return nil }, nil)
	}
	if resp := ask(ingress, ipc.CmdPublished); resp.Err != "" || resp.Published == nil {
		t.Errorf("the ingress asked what is published: %+v", resp)
	}
	for _, cmd := range []ipc.Command{ipc.CmdStatus, ipc.CmdLog, ipc.CmdSelf, ipc.CmdBootstrap} {
		if resp := ask(ingress, cmd); resp.Err == "" {
			t.Errorf("the ingress's %v call got %+v", cmd, resp)
		}
	}
	if resp := ask(stranger, ipc.CmdPublished); resp.Err != ipc.ErrNotOperator {
		t.Errorf("a stranger asked what is published: %+v", resp)
	}
	root := caller{uid: 0, known: true}
	for who, want := range map[caller]tier{ingress: tierIngress, stranger: tierReader, root: tierOperator} {
		if got := f.s.tierOf(who); got != want {
			t.Errorf("uid %d is of tier %v, want %v", who.uid, got, want)
		}
	}
	if resp := ask(root, ipc.CmdPublished); resp.Published == nil {
		t.Errorf("root asked what is published: %+v", resp)
	}
	if got, err := ipc.CallPublished(context.Background(), f.sock, nil); err != nil || len(got.Names) != 0 {
		t.Errorf("over the socket, a device that is no ingress serves %+v, %v", got, err)
	}
	// What the ingress says it listens on passes the socket's checks.
	report := &ipc.IngressReport{Listening: []uint16{2222, 25565}, Unbound: []uint16{22}, NoQUIC: true}
	if _, err := ipc.CallPublished(context.Background(), f.sock, report); err != nil {
		t.Errorf("over the socket, with the ingress's report: %v", err)
	}
	for p := range uint16(2000) {
		report.Listening = append(report.Listening, 1+p)
	}
	if _, err := ipc.CallPublished(context.Background(), f.sock, report); err != nil {
		t.Errorf("over the socket, with a report of more ports than a request carries: %v", err)
	}
}

// Readers filling their pool leave the ingress its own.
func TestReadersCannotCrowdOutTheIngress(t *testing.T) {
	s := newIPCTestServer()
	for uid := uint32(5000); ; uid++ {
		if _, ok := s.admit(caller{uid: uid, known: true}, tierReader); !ok {
			break
		}
	}
	if _, ok := s.admit(caller{uid: 4242, known: true}, tierIngress); !ok {
		t.Fatal("the readers took the ingress's slots")
	}
}

// The ingress holding every slot it may leaves the terminator its own.
func TestOneHelperCannotCrowdOutTheOther(t *testing.T) {
	s := newIPCTestServer()
	for {
		if _, ok := s.admit(caller{uid: 4242, known: true}, tierIngress); !ok {
			break
		}
	}
	if _, ok := s.admit(caller{uid: 4243, known: true}, tierIngress); !ok {
		t.Fatal("the ingress took the terminator's slot")
	}
}

func newIPCTestServer() *ipcServer {
	return &ipcServer{readers: newPool(maxReaderClients, maxClientsPerUser),
		ingress: newPool(maxIngressClients, maxIngressPerUser)}
}

// An ingress serves every name published in the network whose target serves
// it, with where it goes, and nothing once it is no ingress or its view is
// stale.
func TestAnIngressServesWhatIsPublishedWhileFresh(t *testing.T) {
	published := func(roles []types.Role, voucher, served bool) *ipc.Published {
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Roles = roles
			nw.devices[1].record.Published = []types.PublishedName{{Label: "immich", Port: 2283, Proxy: true}}
			if voucher {
				nw.devices[2].record.Roles = []types.Role{types.RoleAdmin}
			}
		}, nil)
		e, err := endpointFor(f.nw.devices[1], 7001)
		if err != nil {
			t.Fatal(err)
		}
		e.Published = served
		if err := e.Sign(f.nw.devices[1].identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
		return f.d.Published()
	}
	got := published([]types.Role{types.RoleIngress}, false, true)
	if len(got.Names) != 1 || got.Names[0].Name != "immich.pub.example.org" || got.Names[0].Port != 2283 ||
		!got.Names[0].Proxy || len(got.Names[0].Addrs) != 2 {
		t.Fatalf("an ingress serves %+v", got)
	}
	if got := published([]types.Role{types.RoleIngress}, false, false); len(got.Names) != 0 {
		t.Errorf("an ingress serves a name its target does not: %+v", got)
	}
	if got := published(nil, false, true); len(got.Names) != 0 {
		t.Errorf("a device that is no ingress serves %+v", got)
	}
	if got := published([]types.Role{types.RoleIngress}, true, true); len(got.Names) != 0 {
		t.Errorf("a stale ingress serves %+v", got)
	}
}

// A terminator is told the names published here that the operator said
// where to send, on this device's addresses, and nothing without the word or
// while the view is stale; the status says where each goes.
func TestATerminatorIsToldWhereNamesGo(t *testing.T) {
	serving := func(consent bool, voucher bool) (*ipc.Published, *ipc.Publish) {
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Published = []types.PublishedName{{Label: "immich", Port: 443}, {Label: "raw", Port: 8022}}
			if voucher {
				nw.devices[2].record.Roles = []types.Role{types.RoleAdmin}
			}
		}, func(o *Options) { o.ServePublished, o.ServeTo = consent, map[string]string{"immich": "127.0.0.1:2283"} })
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		return f.d.Serving(nil), f.d.Status().Publish
	}
	got, st := serving(true, false)
	if len(got.Names) != 1 || got.Names[0].Name != "immich.pub.example.org" || got.Names[0].To != "127.0.0.1:2283" ||
		got.Names[0].Port != 443 || len(got.Names[0].Addrs) != 2 {
		t.Fatalf("the terminator is told %+v", got)
	}
	if st == nil || !slices.Equal(st.Ending, []string{"immich.pub.example.org to 127.0.0.1:2283"}) {
		t.Errorf("the status says %+v", st)
	}
	if got, _ := serving(false, false); len(got.Names) != 0 {
		t.Errorf("without the word, the terminator is told %+v", got)
	}
	if got, _ := serving(true, true); len(got.Names) != 0 {
		t.Errorf("stale, the terminator is told %+v", got)
	}
}

// Where names go is added to and taken from one name at a time, kept apart
// from the word, which a stop withdraws while where they go stays; the
// status says it.
func TestWhereToServeIsKept(t *testing.T) {
	nw := newNetwork(t, 2)
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	on, off := true, false
	call := func(req ipc.Request) *ipc.Status {
		t.Helper()
		resp, err := ipc.Call(f.sock, req)
		if err != nil {
			t.Fatalf("%v: %v", resp, err)
		}
		return resp.Status
	}
	kept := func(want string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(f.home, statedir.PublishToFile))
		if want == "" && !os.IsNotExist(err) || want != "" && (err != nil || string(b) != want) {
			t.Errorf("kept %q, %v; want %q", b, err, want)
		}
	}
	call(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on, ServeTo: []ipc.ServeTo{{Label: "immich", To: "127.0.0.1:2283"}}})
	call(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on, ServeTo: []ipc.ServeTo{{Label: "docs", To: "127.0.0.1:8181"}}})
	st := call(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on})
	kept("docs 127.0.0.1:8181\nimmich 127.0.0.1:2283\n")
	if want := []ipc.ServeTo{{Label: "docs", To: "127.0.0.1:8181"}, {Label: "immich", To: "127.0.0.1:2283"}}; st.Publish == nil ||
		!slices.Equal(st.Publish.To, want) {
		t.Errorf("the status says %+v", st.Publish)
	}
	call(ipc.Request{Command: ipc.CmdPublish, Unserve: []string{"docs"}})
	kept("immich 127.0.0.1:2283\n")

	st = call(ipc.Request{Command: ipc.CmdPublish, ServePublished: &off})
	if _, err := os.Stat(filepath.Join(f.home, statedir.PublishServeFile)); !os.IsNotExist(err) {
		t.Errorf("stopping kept the word: %v", err)
	}
	kept("immich 127.0.0.1:2283\n")
	if st.Publish == nil || st.Publish.Consent || len(st.Publish.To) != 1 || st.Publish.NotServing == "" {
		t.Errorf("stopped, the status says %+v", st.Publish)
	}
	if consent, to := loadServeTo(f.home, t.Logf); consent || to["immich"] != "127.0.0.1:2283" {
		t.Errorf("read back %v %v", consent, to)
	}
	call(ipc.Request{Command: ipc.CmdPublish, Unserve: []string{"immich"}})
	kept("")
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.servePublished || f.s.serveTo != nil {
		t.Errorf("kept %v %v", f.s.servePublished, f.s.serveTo)
	}
}

// Where names go, as an older version kept it in the word's file, is read
// from there, and goes from there once written anew.
func TestWhereToServeMovesOutOfTheWord(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, statedir.PublishServeFile), []byte("immich 127.0.0.1:2283\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if consent, to := loadServeTo(home, t.Logf); !consent || to["immich"] != "127.0.0.1:2283" {
		t.Fatalf("read %v %v", consent, to)
	}
	s := &Service{opts: ServiceOptions{Home: home}, servePublished: true, serveTo: map[string]string{"immich": "127.0.0.1:2283"}}
	if err := s.setPublish(&ipc.Request{Unserve: []string{"immich"}}); err != nil {
		t.Fatal(err)
	}
	if consent, to := loadServeTo(home, t.Logf); !consent || len(to) != 0 {
		t.Errorf("the older lines came back: %v %v", consent, to)
	}
}

// The terminator asks what this device serves, and nothing else.
func TestTheTerminatorAsksWhatItServesAlone(t *testing.T) {
	f := newServiceFixture(t, true)
	serve := caller{uid: 4244, known: true}
	if f.s.selfUID == serve.uid {
		t.Skip("the test user happens to have the terminator's uid")
	}
	f.s.serveUID = serve.uid
	ask := func(cmd ipc.Command) ipc.Response {
		return f.s.handle(context.Background(), &ipc.Request{Command: cmd}, serve, func(*ipc.Event) error { return nil }, nil)
	}
	if resp := ask(ipc.CmdServing); resp.Err != "" || resp.Serving == nil {
		t.Errorf("the terminator asked what it serves: %+v", resp)
	}
	for _, cmd := range []ipc.Command{ipc.CmdStatus, ipc.CmdPublished, ipc.CmdLog} {
		if resp := ask(cmd); resp.Err == "" {
			t.Errorf("the terminator's %v call got %+v", cmd, resp)
		}
	}
	if got := f.s.tierOf(serve); got != tierIngress {
		t.Errorf("the terminator is of tier %v", got)
	}
}

// A member resolves a name published on 443 to its target, as a name pointed
// at it, where the target serves it; a name on another port or behind
// --proxy, or one its target does not serve, it resolves publicly.
func TestMembersReachAPublishedNameDirectly(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[1].record.Published = []types.PublishedName{{Label: "docs", Port: 443, Proxy: true},
			{Label: "immich", Port: 443}, {Label: "ssh", Port: 22}}
	}, nil)
	state := f.auth.State()
	target := f.nw.devices[1].record.Identity
	now := time.Now().Unix()
	z, _, _ := f.d.namesZone(state, policy.View{}, log.Freshness{}, true, now, func(id types.Identity) bool { return id == target })
	if o, ok := z.Overrides["immich.pub.example.org"]; !ok || o.Target != target.String() || len(o.Addrs) != 2 {
		t.Errorf("the published name resolves to %+v, %v", o, ok)
	}
	if _, ok := z.Overrides["ssh.pub.example.org"]; ok {
		t.Error("a name published on another port resolves to its target")
	}
	if _, ok := z.Overrides["docs.pub.example.org"]; ok {
		t.Error("a name published behind --proxy resolves to its target")
	}
	z, _, _ = f.d.namesZone(state, policy.View{}, log.Freshness{}, true, now, func(types.Identity) bool { return false })
	if _, ok := z.Overrides["immich.pub.example.org"]; ok {
		t.Error("a name its target does not serve resolves to it")
	}
}

// An ingress's status says whether the ingress asked lately what is
// published; a device that is no ingress says nothing of it.
func TestTheStatusSaysWhetherTheIngressRuns(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) { nw.devices[0].record.Roles = []types.Role{types.RoleIngress} })
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	ingress := caller{uid: 4242, known: true}
	if f.s.selfUID == ingress.uid {
		t.Skip("the test user happens to have the ingress's uid")
	}
	f.s.ingressUID = ingress.uid
	waitFor(t, 10*time.Second, "the ingress's status", func() bool {
		in := f.s.Status().Ingress
		return in != nil && !in.Running
	})
	f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdPublished}, ingress, func(*ipc.Event) error { return nil }, nil)
	if in := f.s.Status().Ingress; in == nil || !in.Running {
		t.Errorf("an ingress that asked: %+v", in)
	}
	f.s.ingressAsked.Store(f.s.now().Add(-ingressSilence - time.Second).Unix())
	if in := f.s.Status().Ingress; in == nil || in.Running {
		t.Errorf("an ingress silent for longer than it may be: %+v", in)
	}
	other := serviceWithChoice(t, nw, nw.devices[1], "")
	waitFor(t, 10*time.Second, "the other device's mesh", func() bool { return other.s.Status().Members > 0 })
	if in := other.s.Status().Ingress; in != nil {
		t.Errorf("a device that is no ingress: %+v", in)
	}
}

// The status lists a member as serving what it publishes where its
// announcement says so, and this device where it does.
func TestTheStatusSaysWhoServesWhatTheyPublish(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		for i, label := range []string{"a", "b", "c"} {
			nw.devices[i].record.Published = []types.PublishedName{{Label: label, Port: 443}}
		}
	}, func(o *Options) { o.ServePublished = true })
	for i, served := range map[int]bool{1: true, 2: false} {
		e, err := endpointFor(f.nw.devices[i], uint16(7000+i))
		if err != nil {
			t.Fatal(err)
		}
		e.Published = served
		if err := e.Sign(f.nw.devices[i].identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, d := range f.d.Status().Devices {
		if want := d.Identity != f.nw.devices[2].record.Identity; d.Serving != want {
			t.Errorf("%s serving: %v, want %v", d.Name, d.Serving, want)
		}
	}
}

// On a network stack of its own the daemon hands the data plane a device,
// syncs the log in the tunnel alone, and listens on its overlay addresses
// there, not on the host's.
func TestADaemonOnANetworkStack(t *testing.T) {
	var gotTun bool
	f := exitFixtureWith(t, func(*network) {}, func(o *Options) {
		inner := o.Connect
		o.Netstack = true
		o.Connect = func(co conn.Options) (conn.Manager, error) {
			gotTun = co.Tun != nil
			return inner(co)
		}
	})
	if !gotTun {
		t.Fatal("the data plane got no device")
	}
	if !f.d.Status().SyncInTunnel {
		t.Error("log sync is not in the tunnel")
	}
	addr := f.d.startAddrs[0].Addr()
	ln, err := f.d.ListenOverlay(netip.AddrPortFrom(addr, 8443).String())
	if err != nil {
		t.Fatalf("listening on an overlay address: %v", err)
	}
	ln.Close()
	if c, err := net.DialTimeout("tcp", netip.AddrPortFrom(addr, f.d.gossipPort).String(), time.Second); err == nil {
		c.Close()
		t.Error("log sync is reached from the host")
	}
}

// Once the terminator says its account, the status holds a CAA record for
// each name whose TLS it ends, and none for the others.
func TestTheStatusHoldsTheCAARecords(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Published = []types.PublishedName{{Label: "immich", Port: 443}, {Label: "raw", Port: 8022}}
	}, func(o *Options) { o.ServePublished, o.ServeTo = true, map[string]string{"immich": "127.0.0.1:2283"} })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Publish; st == nil || len(st.CAA) != 0 {
		t.Fatalf("before the terminator has an account, the status says %+v", st)
	}
	f.d.Serving(&ipc.TerminatorReport{Account: &ipc.ACMEAccount{URI: "https://ca.example/acct/7", Issuers: []string{"ca.example"}}})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{`immich.pub.example.org. CAA 0 issue "ca.example; accounturi=https://ca.example/acct/7"`}
	if st := f.d.Status().Publish; st == nil || !slices.Equal(st.CAA, want) {
		t.Errorf("the status says %+v", st)
	}
}

// The network's own domain goes to juistd whole on every member, whether it
// turned names on or not: the domain itself and its names published on 443
// resolve to their target, a name pointed at a member only where names are
// on, and the rest goes on upstream.
func TestTheDomainGoesToJuistdWhole(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[1].record.Published = []types.PublishedName{{Port: 443}, {Label: "immich", Port: 443}}
		nw.devices[2].record.Names = []string{"mx.example.net"}
	}, nil)
	state := f.auth.State()
	target := f.nw.devices[1].record.Identity
	now := time.Now().Unix()
	f.d.reachable.Store(&map[types.Identity]bool{target: true})
	z, _, _ := f.d.namesZone(state, policy.View{}, log.Freshness{}, false, now, func(id types.Identity) bool { return id == target })
	for _, name := range []string{"pub.example.org", "immich.pub.example.org"} {
		if o, ok := z.Overrides[name]; !ok || o.Target != target.String() {
			t.Errorf("without names on, %s resolves to %+v, %v", name, o, ok)
		}
	}
	if _, ok := z.Overrides["mx.example.net"]; ok {
		t.Error("without names on, a name pointed at a member resolves to it")
	}
	if got := routedDomains(z); !slices.Contains(got, "pub.example.org") || slices.Contains(got, "immich.pub.example.org") {
		t.Errorf("the routed domains are %v", got)
	}
	q := func(name string) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		m, _ := b.Finish()
		return m
	}
	var m dnsmessage.Message
	if err := m.Unpack(z.Answer(q("pub.example.org"))); err != nil || len(m.Answers) != 1 ||
		netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A) != *f.nw.devices[1].record.V4 {
		t.Errorf("the domain itself is answered %+v, %v", m.Answers, err)
	}
	if z.Answer(q("www.pub.example.org")) != nil {
		t.Error("a name of the domain published nowhere is answered, not passed on")
	}
}

// Where the domain itself goes, its label empty, is kept as a line of its
// own and read back.
func TestWhereTheDomainItselfGoesIsKept(t *testing.T) {
	home := t.TempDir()
	s := &Service{opts: ServiceOptions{Home: home}}
	on := true
	if err := s.setPublish(&ipc.Request{ServePublished: &on, ServeTo: []ipc.ServeTo{{To: "127.0.0.1:80"},
		{Label: "immich", To: "127.0.0.1:2283"}}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, statedir.PublishToFile)); string(b) != "@ 127.0.0.1:80\nimmich 127.0.0.1:2283\n" {
		t.Errorf("kept %q", b)
	}
	if _, to := loadServeTo(home, t.Logf); to[""] != "127.0.0.1:80" || to["immich"] != "127.0.0.1:2283" {
		t.Errorf("read back %v", to)
	}
}
