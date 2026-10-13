package daemon

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

var (
	mcByTCP   = types.PublishedName{Label: "mc", Port: 25565, Public: 25565}
	sshByTCP  = types.PublishedName{Label: "ssh", Port: 22, Public: 2222}
	immichTLS = types.PublishedName{Label: "immich", Port: 443}
)

// An ingress is told the names published by TCP apart from those by TLS,
// each with its public port, so that one too old to know them passes none.
func TestAnIngressIsToldTheNamesPublishedByTCP(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
		nw.devices[1].record.Published = []types.PublishedName{immichTLS, mcByTCP, sshByTCP}
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
	if len(got.Names) != 1 || got.Names[0].Name != "immich.pub.example.org" || got.Names[0].Public != 0 {
		t.Errorf("by TLS: %+v", got.Names)
	}
	if len(got.TCP) != 2 || got.TCP[0].Name != "ssh.pub.example.org" || got.TCP[0].Public != 2222 ||
		got.TCP[0].Port != 22 || got.TCP[1].Public != 25565 || len(got.TCP[1].Addrs) != 2 {
		t.Errorf("by TCP: %+v", got.TCP)
	}

	// Its target no longer serving, a name by TCP keeps its port, with
	// nowhere to go, and one by TLS goes.
	e.Published = false
	e.Seq++
	if err := e.SignPQ(f.nw.devices[1].identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	got = f.d.Published()
	if len(got.Names) != 0 || len(got.TCP) != 2 || len(got.TCP[0].Addrs)+len(got.TCP[1].Addrs) != 0 {
		t.Errorf("not served: %+v", got)
	}
}

// A terminator is told the names published here by TCP apart, with where
// they go; the status says it passes them, and holds no CAA record for them.
func TestATerminatorIsToldWhereTCPGoes(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Published = []types.PublishedName{immichTLS, mcByTCP}
	}, func(o *Options) {
		o.ServePublished = true
		o.ServeTo = map[string]string{"immich": "127.0.0.1:2283", "mc": "127.0.0.1:25565"}
	})
	f.d.Serving(&ipc.TerminatorReport{Account: &ipc.ACMEAccount{URI: "https://ca.example/acct/1",
		Issuers: []string{"ca.example"}}})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	got := f.d.Serving(nil)
	if len(got.Names) != 1 || got.Names[0].Name != "immich.pub.example.org" {
		t.Errorf("by TLS: %+v", got.Names)
	}
	if len(got.TCP) != 1 || got.TCP[0].Name != "mc.pub.example.org" || got.TCP[0].To != "127.0.0.1:25565" ||
		got.TCP[0].Port != 25565 || len(got.TCP[0].Addrs) != 2 {
		t.Errorf("by TCP: %+v", got.TCP)
	}
	st := f.d.Status().Publish
	if st == nil || !slices.Equal(st.Passing, []string{"mc.pub.example.org to 127.0.0.1:25565"}) ||
		!slices.Equal(st.Ending, []string{"immich.pub.example.org to 127.0.0.1:2283"}) {
		t.Fatalf("the status says %+v", st)
	}
	for _, r := range st.CAA {
		if !strings.HasPrefix(r, "immich.pub.example.org. ") {
			t.Errorf("a CAA record for a name whose TLS juist does not end: %q", r)
		}
	}
	if len(st.CAA) == 0 {
		t.Error("no CAA record for the name whose TLS juist ends")
	}
}

// Members reach a name published by TCP at its device where the internet
// reaches it on the device's own port, without --proxy, and through the
// ingress otherwise.
func TestMembersReachANamePublishedByTCPDirectly(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[1].record.Published = []types.PublishedName{
			mcByTCP, {Label: "smtp", Port: 25, Proxy: true, Public: 25}, sshByTCP}
	}, nil)
	target := f.nw.devices[1].record.Identity
	z, _, _ := f.d.namesZone(f.auth.State(), policy.View{}, log.Freshness{}, false, time.Now().Unix(),
		func(id types.Identity) bool { return id == target })
	if o, ok := z.Overrides["mc.pub.example.org"]; !ok || o.Target != target.String() {
		t.Errorf("a name by TCP on its own port resolves to %+v, %v", o, ok)
	}
	for _, name := range []string{"ssh.pub.example.org", "smtp.pub.example.org"} {
		if _, ok := z.Overrides[name]; ok {
			t.Errorf("%s resolves to its device", name)
		}
	}
}

// An ingress's juistd keeps a file of the public ports the log publishes
// names on, for the host's firewall, while it is an ingress whose view is
// fresh, and empties it otherwise.
func TestTheIngressPortsFollowTheLog(t *testing.T) {
	ports := func(roles []types.Role, voucher bool, published ...types.PublishedName) string {
		file := filepath.Join(t.TempDir(), "ingress-ports")
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Roles = roles
			nw.devices[1].record.Published = published
			if voucher {
				nw.devices[2].record.Roles = []types.Role{types.RoleAdmin}
			}
		}, func(o *Options) { o.IngressPorts = file })
		f.d.NoteIngressListening([]uint16{2222, 25565})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	ingress := []types.Role{types.RoleIngress}
	if got := ports(ingress, false, immichTLS, mcByTCP, sshByTCP); got != "2222\n25565\n" {
		t.Errorf("an ingress's file says %q", got)
	}
	if got := ports(ingress, false, immichTLS); got != "" {
		t.Errorf("with no name by TCP, %q", got)
	}
	if got := ports(nil, false, mcByTCP); got != "" {
		t.Errorf("a device that is no ingress says %q", got)
	}
	if got := ports(ingress, true, mcByTCP); got != "" {
		t.Errorf("a stale ingress says %q", got)
	}
}

// The firewall lets in no public port the ingress does not listen on,
// which another program may hold; what juistd said before it restarted
// stands until the ingress says, which it goes on listening on meanwhile.
func TestTheFirewallLetsInWhatTheIngressHolds(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
		nw.devices[1].record.Published = []types.PublishedName{mcByTCP, sshByTCP}
	})
	file := filepath.Join(t.TempDir(), "ingress-ports")
	if err := os.WriteFile(file, []byte("2222\n25565\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := serviceWithChoice(t, nw, nw.devices[0], "", func(o *Options) { o.IngressPorts = file })
	ingress := caller{uid: 4242, known: true}
	if f.s.selfUID == ingress.uid {
		t.Skip("the test user happens to have the ingress's uid")
	}
	f.s.ingressUID = ingress.uid
	read := func() string {
		b, _ := os.ReadFile(file)
		return string(b)
	}
	waitFor(t, 10*time.Second, "the ingress's status", func() bool { return f.s.Status().Ingress != nil })
	if err := f.s.Mesh().Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "2222\n25565\n" {
		t.Errorf("before the ingress said, %q", got)
	}
	f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdPublished, Listening: []string{"25565"},
		Unbound: []string{"2222"}}, ingress, func(*ipc.Event) error { return nil }, nil)
	if got := read(); got != "25565\n" {
		t.Errorf("with 2222 held by another, %q", got)
	}
}

// The status of an ingress says the public ports it listens on, and those
// another program holds, 443/udp among them, as it last said while it runs.
func TestTheStatusSaysTheIngressPorts(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) { nw.devices[0].record.Roles = []types.Role{types.RoleIngress} })
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	ingress := caller{uid: 4242, known: true}
	if f.s.selfUID == ingress.uid {
		t.Skip("the test user happens to have the ingress's uid")
	}
	f.s.ingressUID = ingress.uid
	waitFor(t, 10*time.Second, "the ingress's status", func() bool { return f.s.Status().Ingress != nil })
	f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdPublished, Listening: []string{"25565", "2222", "x"},
		Unbound: []string{"22", "0", "70000", "443/udp"}}, ingress, func(*ipc.Event) error { return nil }, nil)
	in := f.s.Status().Ingress
	if in == nil || !slices.Equal(in.Ports, []uint16{2222, 25565}) || !slices.Equal(in.Unbound, []uint16{22}) || !in.NoQUIC {
		t.Errorf("the status says %+v", in)
	}
	// An operator asking tells nothing of the ingress.
	f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdPublished}, caller{uid: f.s.selfUID, known: true},
		func(*ipc.Event) error { return nil }, nil)
	if in := f.s.Status().Ingress; in == nil || !slices.Equal(in.Ports, []uint16{2222, 25565}) {
		t.Errorf("after an operator asked, the status says %+v", in)
	}
}

// A name published by TCP where the operator said the status page, or a
// service taking HTTP/2, goes to the address alone, or nowhere for the page:
// both are TLS's.
func TestATCPNameGoesToAnAddressAlone(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Published = []types.PublishedName{mcByTCP, sshByTCP}
	}, func(o *Options) {
		o.ServePublished = true
		o.ServeTo = map[string]string{"mc": ipc.HTTP2To("127.0.0.1:25565"), "ssh": ipc.StatusPageTo(ipc.ShowAll)}
	})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	got := f.d.Serving(nil)
	if len(got.TCP) != 1 || got.TCP[0].Name != "mc.pub.example.org" || got.TCP[0].To != "127.0.0.1:25565" {
		t.Errorf("by TCP: %+v", got.TCP)
	}
	if st := f.d.Status().Publish; st == nil || !slices.Equal(st.Passing, []string{"mc.pub.example.org to 127.0.0.1:25565"}) {
		t.Errorf("the status says %+v", st)
	}
}

// The ingress's ports are written where they changed alone, since each
// write has the firewall follow.
func TestTheIngressPortsAreWrittenOnChange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ingress-ports")
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress}
		nw.devices[1].record.Published = []types.PublishedName{mcByTCP}
	}, func(o *Options) { o.IngressPorts = file })
	f.d.NoteIngressListening([]uint16{25565})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("the same ports were written again")
	}
}

// An ingress may send datagrams to the port of a name offered HTTP/3 here,
// for QUIC, and to no port of another name, nor of the share.
func TestAnIngressSendsQUICToNamesOfferedHTTP3Alone(t *testing.T) {
	for _, c := range []struct {
		to   string
		want []uint16
	}{
		{ipc.HTTP3To("127.0.0.1:2283"), []uint16{443}},
		{ipc.StatusPageTo(ipc.ShowAll), []uint16{443}},
		{"127.0.0.1:2283", nil},
	} {
		f := exitFixtureWith(t, func(nw *network) {
			nw.domain = "pub.example.org"
			nw.devices[0].record.Published = []types.PublishedName{immichTLS, mcByTCP}
			nw.devices[1].record.Roles = []types.Role{types.RoleIngress}
		}, func(o *Options) {
			o.ServePublished = true
			o.ServeTo = map[string]string{immichTLS.Label: c.to, mcByTCP.Label: "127.0.0.1:25565"}
		})
		f.learnOthers(t)
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		f.mgr.mu.Lock()
		tcp, udp := slices.Clone(f.mgr.ingressPorts), slices.Clone(f.mgr.ingressUDP)
		f.mgr.mu.Unlock()
		if !slices.Contains(tcp, 443) || !slices.Contains(tcp, 25565) || !slices.Equal(udp, c.want) {
			t.Errorf("to %s, an ingress may open TCP %v, UDP %v", c.to, tcp, udp)
		}
	}
}
