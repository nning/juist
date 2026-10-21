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
	"tailscale.com/types/ipproto"

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

	f.d.changePrefs(func(p *Prefs) { p.ServePublished, p.ServeTo, p.ServeMembers = true, nil, nil })
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
	if f.s.prefs.ServePublished {
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
	for _, cmd := range []ipc.Command{ipc.CmdStatus, ipc.CmdLog, ipc.CmdSelf} {
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
		if err := e.SignPQ(f.nw.devices[1].identity); err != nil {
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
	if consent, to, _ := loadServeTo(f.home, t.Logf); consent || to["immich"] != "127.0.0.1:2283" {
		t.Errorf("read back %v %v", consent, to)
	}
	call(ipc.Request{Command: ipc.CmdPublish, Unserve: []string{"immich"}})
	kept("")
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.prefs.ServePublished || f.s.prefs.ServeTo != nil {
		t.Errorf("kept %v %v", f.s.prefs.ServePublished, f.s.prefs.ServeTo)
	}
}

// Where names go, as an older version kept it in the word's file, is read
// from there, and goes from there once written anew.
func TestWhereToServeMovesOutOfTheWord(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, statedir.PublishServeFile), []byte("immich 127.0.0.1:2283\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if consent, to, _ := loadServeTo(home, t.Logf); !consent || to["immich"] != "127.0.0.1:2283" {
		t.Fatalf("read %v %v", consent, to)
	}
	s := &Service{opts: ServiceOptions{Home: home}, prefs: Prefs{ServePublished: true, ServeTo: map[string]string{"immich": "127.0.0.1:2283"}}}
	if err := s.setPublish(&ipc.Request{Unserve: []string{"immich"}}); err != nil {
		t.Fatal(err)
	}
	if consent, to, _ := loadServeTo(home, t.Logf); !consent || len(to) != 0 {
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

// A name for members alone resolves to its device for a member the policy
// names it for, or every member without one, never for the device itself;
// for anyone else as the internet resolves it.
func TestANameForMembersResolvesForThoseItIsFor(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Published = []types.PublishedName{{Label: "own", Port: 443, Members: true}}
		nw.devices[1].record.Published = []types.PublishedName{{Label: "photos", Port: 443, Members: true}}
	}, nil)
	state := f.auth.State()
	self, target := f.nw.devices[0].record.Identity, f.nw.devices[1].record.Identity
	now := time.Now().Unix()
	serves := func(types.Identity) bool { return true }
	resolves := func(v policy.View) (photos, own bool, held []heldOverride) {
		z, held, _ := f.d.namesZone(state, v, log.Freshness{}, true, now, serves)
		_, photos = z.Overrides["photos.pub.example.org"]
		_, own = z.Overrides["own.pub.example.org"]
		return photos, own, held
	}
	photos, own, held := resolves(policy.View{})
	if !photos || own {
		t.Errorf("without a policy: photos %v, the device's own %v", photos, own)
	}
	if !slices.ContainsFunc(held, func(h heldOverride) bool { return h.name == "photos.pub.example.org" && h.members }) {
		t.Errorf("photos is not held as for members: %+v", held)
	}
	peers := map[types.Identity]bool{target: true}
	for _, c := range []struct {
		names []string
		want  bool
	}{{[]string{"photos"}, true}, {nil, false}, {[]string{"other"}, false}} {
		v := policy.View{Restricted: true, Peers: peers, Out: map[types.Identity]policy.Access{target: {Names: c.names}}, In: map[types.Identity]policy.Access{self: {}}}
		if photos, own, _ := resolves(v); photos != c.want || own {
			t.Errorf("names %q: photos %v, the device's own %v", c.names, photos, own)
		}
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
		if err := e.SignPQ(f.nw.devices[i].identity); err != nil {
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
	addr := f.d.heldAddrs()[0].Addr()
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
	if _, to, _ := loadServeTo(home, t.Logf); to[""] != "127.0.0.1:80" || to["immich"] != "127.0.0.1:2283" {
		t.Errorf("read back %v", to)
	}
}

// A name for members alone goes to the terminator apart from the others,
// with the addresses of the members it is for: without a policy every member
// but an ingress, under one those it names, and never this device, whose
// own programs a client could make ask; the ingress may open its port by
// TCP alone, for the CA.
func TestANameForMembersGoesToTheTerminatorApart(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Published = []types.PublishedName{{Label: "photos", Port: 443, Members: true}}
		nw.devices[2].record.Roles = []types.Role{types.RoleIngress}
	}, func(o *Options) {
		o.ServePublished, o.ServeTo = true, map[string]string{"photos": ipc.HTTP3To("127.0.0.1:2342")}
	})
	f.learnOthers(t)
	addrs := func(devs ...*device) []netip.Addr {
		var out []netip.Addr
		for _, d := range devs {
			for _, a := range f.auth.State().Addrs(d.record.Identity, time.Now().Unix()) {
				out = append(out, a.Addr())
			}
		}
		slices.SortFunc(out, netip.Addr.Compare)
		return out
	}
	from := func() []netip.Addr {
		t.Helper()
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		got := f.d.Serving(nil)
		if len(got.Names) != 0 || len(got.Members) != 1 || got.Members[0].Name != "photos.pub.example.org" {
			t.Fatalf("the terminator is told %+v", got)
		}
		out := slices.Clone(got.Members[0].From)
		slices.SortFunc(out, netip.Addr.Compare)
		return out
	}
	n1 := f.nw.devices[1]
	if got, want := from(), addrs(n1); !slices.Equal(got, want) {
		t.Errorf("without a policy, from %v, want %v", got, want)
	}
	if a := f.peerOf(t, f.nw.devices[2]).Access; a == nil || !slices.Contains(a.Open, tcp(443)) ||
		slices.Contains(a.Open, conn.Ports{Proto: ipproto.UDP, First: 443, Last: 443}) {
		t.Errorf("the ingress may open %+v", a)
	}
	f.nw.setPolicy(t, f, "pass from n1 to n0 proto tcp port 22\n")
	if got := from(); len(got) != 0 {
		t.Errorf("under a policy naming no name, from %v", got)
	}
	f.nw.setPolicy(t, f, "pass from n1 to name photos\n")
	if got, want := from(), addrs(n1); !slices.Equal(got, want) {
		t.Errorf("under a policy naming it, from %v, want %v", got, want)
	}
	if a := f.peerOf(t, n1).Access; a == nil || !slices.Contains(a.Open, tcp(443)) {
		t.Errorf("n1, which may open photos, may open %+v here", a)
	}
}

// An ingress is told a name for members alone apart, so that one too old to
// know the list passes it to nobody.
func TestAnIngressIsToldANameForMembersApart(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
		nw.devices[1].record.Published = []types.PublishedName{{Label: "photos", Port: 443, Members: true}}
	}, nil)
	e, err := endpointFor(f.nw.devices[1], 7001)
	if err != nil {
		t.Fatal(err)
	}
	e.Published = true
	if err := e.SignPQ(f.nw.devices[1].identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	got := f.d.Published()
	if len(got.Names) != 0 || len(got.Members) != 1 || got.Members[0].Name != "photos.pub.example.org" ||
		len(got.Members[0].Addrs) == 0 || len(got.Members[0].From) != 0 {
		t.Fatalf("the ingress is told %+v", got)
	}
}

// A name for members alone whose service another name's bytes reach as they
// are is not served, which the status says: a client of the other could ask
// the service for it by Host. Where juist proxies the other's HTTP, holding
// it to its own Host, it is.
func TestANameForMembersSharesNoServicePassedOnAsItIs(t *testing.T) {
	serving := func(blog string) (*ipc.Published, *ipc.Publish) {
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Published = []types.PublishedName{{Label: "blog", Port: 443}, {Label: "photos", Port: 443, Members: true}}
		}, func(o *Options) {
			o.ServePublished, o.ServeTo = true, map[string]string{"photos": "127.0.0.1:80", "blog": blog}
		})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		return f.d.Serving(nil), f.d.Status().Publish
	}
	got, st := serving("127.0.0.1:80")
	if len(got.Members) != 0 || st == nil || !slices.Equal(st.Shared, []string{"photos.pub.example.org with blog.pub.example.org"}) {
		t.Errorf("sharing a service passed on as it is: served %+v, status %+v", got.Members, st)
	}
	got, st = serving(ipc.HTTP3To("127.0.0.1:80"))
	if len(got.Members) != 1 || len(st.Shared) != 0 {
		t.Errorf("sharing a service whose HTTP juist proxies: served %+v, status %+v", got.Members, st)
	}
}

// A service is one however its address is spelled, and a share passing
// bytes on as they are shares it too.
func TestAServiceIsOneHoweverSpelledAndAShareSharesIt(t *testing.T) {
	ps := []types.PublishedName{{Label: "blog", Port: 443}, {Label: "photos", Port: 443, Members: true}}
	for _, blog := range []string{"localhost:80", "[::1]:80", "0.0.0.0:80", "LocalHost:80", "127.0.0.1:080",
		"[::ffff:0.0.0.0]:80", "[::ffff:127.0.0.1]:80", "localhost.:80"} {
		if got := sharedService(ps, map[string]string{"photos": "127.0.0.1:80", "blog": blog}, ""); got["photos"] != "blog" {
			t.Errorf("photos at 127.0.0.1:80 and blog at %s: %v", blog, got)
		}
	}
	if got := sharedService(ps, map[string]string{"photos": "127.0.0.1:80"}, "localhost:80"); got["photos"] != "" || len(got) != 1 {
		t.Errorf("a share passing on to the same service: %v", got)
	}
	byTCP := []types.PublishedName{{Label: "blog", Port: 8080, Public: 8080}, {Label: "photos", Port: 443, Members: true}}
	if got := sharedService(byTCP, map[string]string{"photos": "127.0.0.1:80", "blog": ipc.HTTP3To("127.0.0.1:80")}, ""); got["photos"] != "blog" {
		t.Errorf("a name passed by TCP, its target offered HTTP/3, to the same service: %v", got)
	}
	if got := sharedService(ps, map[string]string{"photos": "127.0.0.1:80", "blog": ipc.HTTP3To("127.0.0.1:80")}, ""); len(got) != 0 {
		t.Errorf("a name whose HTTP juist proxies: %v", got)
	}
	if got := sharedService(ps, map[string]string{"photos": "127.0.0.1:80", "blog": "127.0.0.1:81"}, ""); len(got) != 0 {
		t.Errorf("two services: %v", got)
	}
	now := time.Now()
	raw := &share{to: "127.0.0.1:80"}
	if got := rawShare([]*share{raw}, now); got != "127.0.0.1:80" {
		t.Errorf("a share without a path passes on to %q", got)
	}
	if got := rawShare([]*share{raw, {to: "x", prefix: "/abc/"}}, now); got != "" {
		t.Errorf("shares with paths, which juist proxies, pass on to %q", got)
	}
}

// A service meant for members alone is served under its name only while the
// log has the name for members alone, and is said withheld otherwise.
func TestAServiceForMembersIsWithheldFromAPublicName(t *testing.T) {
	serving := func(members bool) (*ipc.Published, *ipc.Publish) {
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Published = []types.PublishedName{{Label: "photos", Port: 443, Members: members}}
		}, func(o *Options) {
			o.ServePublished, o.ServeTo = true, map[string]string{"photos": "127.0.0.1:2342"}
			o.ServeMembers = map[string]bool{"photos": true}
		})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		return f.d.Serving(nil), f.d.Status().Publish
	}
	got, st := serving(false)
	if len(got.Names)+len(got.Members) != 0 || st == nil || !slices.Equal(st.Withheld, []string{"photos.pub.example.org"}) ||
		len(st.Ending) != 0 {
		t.Errorf("public in the log: served %+v, status %+v", got, st)
	}
	got, st = serving(true)
	if len(got.Names) != 0 || len(got.Members) != 1 || len(st.Withheld) != 0 {
		t.Errorf("for members in the log: served %+v, status %+v", got, st)
	}
}

// The mark that a service is for members alone outlives a restart, goes with
// its label, and is a line an older version reads as none.
func TestTheMarkOfAServiceForMembersIsKept(t *testing.T) {
	home := t.TempDir()
	s := &Service{opts: ServiceOptions{Home: home}}
	if err := s.setPublish(&ipc.Request{ServeTo: []ipc.ServeTo{{Label: "photos", To: "127.0.0.1:2342", Members: true},
		{Label: "blog", To: "127.0.0.1:80"}}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, statedir.PublishToFile))
	if string(b) != "blog 127.0.0.1:80\nphotos 127.0.0.1:2342 members\n" {
		t.Errorf("written %q", b)
	}
	if (ipc.ServeTo{Label: "photos", To: "127.0.0.1:2342 members"}).Valid() {
		t.Error("an older version would take the line")
	}
	if _, to, members := loadServeTo(home, t.Logf); to["photos"] != "127.0.0.1:2342" || !members["photos"] || members["blog"] {
		t.Errorf("read back %v %v", to, members)
	}
	if err := s.setPublish(&ipc.Request{ServeTo: []ipc.ServeTo{{Label: "photos", To: "127.0.0.1:2342"}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, members := loadServeTo(home, t.Logf); members["photos"] {
		t.Error("said again without the mark, the service kept it")
	}
	if err := s.setPublish(&ipc.Request{ServeTo: []ipc.ServeTo{{Label: "photos", To: "127.0.0.1:2342", Members: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.setPublish(&ipc.Request{Unserve: []string{"photos"}}); err != nil {
		t.Fatal(err)
	}
	if s.prefs.ServeMembers["photos"] {
		t.Error("the mark outlived its label")
	}
}

// A service member's services are marked as its command line says, not as a
// file left from before says.
func TestAServiceMembersMarkIsItsCommandLines(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, statedir.PublishToFile), []byte("photos 127.0.0.1:1 members\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, marked := range []map[string]bool{nil, {"photos": true}} {
		s, err := NewService(ServiceOptions{Home: home, Socket: filepath.Join(home, "s.sock"),
			ServeTo: map[string]string{"photos": "immich:2283"}, ServeMembers: marked})
		if err != nil {
			t.Fatal(err)
		}
		if s.prefs.ServeMembers["photos"] != marked["photos"] {
			t.Errorf("given %v, marked %v", marked, s.prefs.ServeMembers)
		}
		s.Close()
	}
}
