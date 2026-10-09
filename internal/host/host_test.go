package host

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func sealer(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
	_, rec, err := secrets.NewEpoch(epoch, members)
	return rec, err
}

// network is a one-admin network that has admitted the guest.
func network(t *testing.T, admin types.PrivateIdentity, g *keys.Node) []types.AUM {
	t.Helper()
	secret := make([]byte, types.DisablementSecretSize)
	genesis, err := log.Genesis("home", 1, []types.AdminKey{{Public: admin.Public(), Votes: 1, Name: "admin"}},
		[]types.Hash{types.DisablementCommit(secret)}, nil, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := genesis.Sign(admin); err != nil {
		t.Fatal(err)
	}
	auth, err := log.Create(log.NewMemStorage(), genesis)
	if err != nil {
		t.Fatal(err)
	}
	v4 := netip.MustParseAddr("100.64.0.2")
	add, err := auth.Builder().AddNode(types.NodeRecord{Identity: g.Identity.Public(), Name: "phone",
		WireGuard: g.Public.WireGuard, X25519: g.Public.X25519, MLKEM: g.Public.MLKEM, V4: &v4}, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(admin); err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(add); err != nil {
		t.Fatal(err)
	}
	return []types.AUM{genesis, add}
}

// admitting admits with whatever admission it is given.
type admitting struct {
	admission func(req *enroll.JoinRequest) *enroll.Admission
}

func (a admitting) Admit(_ context.Context, req *enroll.JoinRequest, _ func(uint32, uint32) error,
	_ func(enroll.Salt) (enroll.Nonce, error)) (string, *enroll.Admission, error) {
	return "phone", a.admission(req), nil
}

// A link that names the admin binds the guest to that admin's admission: a
// host that sends none, another key's, or one for another log does not get
// the guest to store anything.
func TestTheGuestRequiresTheAdminsAdmission(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	other, _ := types.GenerateIdentity()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	records := network(t, admin, g)
	head := records[len(records)-1].Hash()
	genesis := records[0].Hash()
	sign := func(key types.PrivateIdentity, head types.Hash) func(*enroll.JoinRequest) *enroll.Admission {
		return func(req *enroll.JoinRequest) *enroll.Admission {
			a, err := enroll.SignAdmission(key, genesis, head, req.Identity)
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
	}
	for _, tc := range []struct {
		name      string
		admission func(*enroll.JoinRequest) *enroll.Admission
		want      string // "" joins
	}{
		{"the admin's", sign(admin, head), ""},
		{"none", func(*enroll.JoinRequest) *enroll.Admission { return nil }, "sent no admission"},
		{"another key's", sign(other, head), "not the admin's admission"},
		{"for a head off the chain", sign(admin, types.Hash{9}), "not the one the admin admitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := Listen(Options{Addrs: func(port uint16) []netip.AddrPort {
				return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
			}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			served := make(chan error, 1)
			go func() {
				served <- h.Serve(ctx, admitting{tc.admission},
					func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil }, nil)
			}()
			stored := false
			_, err = guest.Join(ctx, guest.Options{
				Invite: h.Invite().Link().WithAdmin(admin.Public()).String(),
				Name:   "phone",
				Keys:   g,
				Adopt:  func([]types.AUM) error { stored = true; return nil },
			})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("join: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("join = %v, want %q", err, tc.want)
			case tc.want != "" && stored:
				t.Fatal("the guest stored a log without the admin's admission")
			}
			if err := <-served; (err == nil) != (tc.want == "") && !errors.Is(err, context.Canceled) {
				t.Logf("host: %v", err)
			}
		})
	}
}

// Connections that say nothing do not hold the session while the real guest
// waits: hellos are read concurrently, and only a connection that sent one
// is queued.
func TestSilentConnectionsDoNotHoldTheInvite(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	records := network(t, admin, g)
	h, err := Listen(Options{Addrs: func(port uint16) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go h.Serve(ctx, admitting{func(req *enroll.JoinRequest) *enroll.Admission {
		a, _ := enroll.SignAdmission(admin, records[0].Hash(), records[1].Hash(), req.Identity)
		return a
	}}, func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil }, nil)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.Port()).String()
	for range 3 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	start := time.Now()
	if _, err := guest.Join(ctx, guest.Options{Invite: h.Invite().Link().WithAdmin(admin.Public()).String(),
		Name: "phone", Keys: g, Adopt: func([]types.AUM) error { return nil }}); err != nil {
		t.Fatalf("the guest was kept out: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the guest waited %v behind silent connections", d)
	}
}

// A guest that cannot reach the host joins through the member relay the host
// waits at, and only a member may wait there.
func TestAGuestJoinsThroughTheRelay(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	hostID, _ := types.GenerateIdentity()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	records := network(t, admin, g)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := relay.New(relay.Options{
		Admit:       func([32]byte) bool { return false },
		AdmitHost:   func(id [32]byte) bool { return types.Identity(id) == hostID.Public() },
		Listener:    ln,
		DisableSTUN: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	at := forward.Relay{Addrs: []netip.AddrPort{ln.Addr().(*net.TCPAddr).AddrPort()}, CertHash: rs.CertHash(),
		ServerName: rs.HostName()}

	h, err := Listen(Options{
		// Where the guest would reach the host directly, nothing listens.
		Addrs:    func(uint16) []netip.AddrPort { return []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")} },
		Relays:   []forward.Relay{at},
		Identity: hostID,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := h.Invite().Link()
	if len(link.Relays) != 1 {
		t.Fatalf("the link names relays %v", link.Relays)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- h.Serve(ctx, admitting{func(req *enroll.JoinRequest) *enroll.Admission {
			a, _ := enroll.SignAdmission(admin, records[0].Hash(), records[1].Hash(), req.Identity)
			return a
		}}, func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil }, nil)
	}()
	var joinErr error
	relayed := false
	for range 20 { // until the host's wait has registered at the relay
		if _, joinErr = guest.Join(ctx, guest.Options{Invite: link.WithAdmin(admin.Public()).String(),
			Name: "phone", Keys: g, Adopt: func([]types.AUM) error { return nil },
			Progress: func(e guest.Event) { relayed = relayed || e.Kind == guest.Connected && e.Relayed },
		}); joinErr == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if joinErr != nil {
		t.Fatalf("the guest did not join through the relay: %v", joinErr)
	}
	if !relayed {
		t.Error("the guest did not say it came through the relay")
	}
	if err := <-served; err != nil {
		t.Fatalf("host: %v", err)
	}
}

// comparing admits after comparing words the way the CLI does: a salt drawn
// after the request, and the nonce the guest revealed for it.
type comparing struct {
	admission func(req *enroll.JoinRequest) *enroll.Admission
	words     chan string
}

func (c comparing) Admit(_ context.Context, req *enroll.JoinRequest, _ func(uint32, uint32) error,
	compare func(enroll.Salt) (enroll.Nonce, error)) (string, *enroll.Admission, error) {
	salt := enroll.Salt{3}
	nonce, err := compare(salt)
	if err != nil {
		return "", nil, err
	}
	if enroll.CommitNonce(nonce) != req.Commit {
		return "", nil, errors.New("the nonce is not the committed one")
	}
	c.words <- enroll.Fingerprint(salt, nonce, req.Identity, req.Keys)
	return "phone", c.admission(req), nil
}

// Both screens show the same words, made from the admin's salt and the
// nonce the guest committed to before the salt existed.
func TestBothSidesShowTheSameWords(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	records := network(t, admin, g)
	h, err := Listen(Options{Addrs: func(port uint16) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host := comparing{words: make(chan string, 1), admission: func(req *enroll.JoinRequest) *enroll.Admission {
		a, _ := enroll.SignAdmission(admin, records[0].Hash(), records[1].Hash(), req.Identity)
		return a
	}}
	go h.Serve(ctx, host, func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil }, nil)
	var guestWords string
	if _, err := guest.Join(ctx, guest.Options{Invite: h.Invite().Link().WithAdmin(admin.Public()).String(),
		Name: "phone", Keys: g, Adopt: func([]types.AUM) error { return nil },
		Progress: func(e guest.Event) {
			if e.Kind == guest.Compare {
				guestWords = e.Words
			}
		}}); err != nil {
		t.Fatal(err)
	}
	if got := <-host.words; got != guestWords || got == "" {
		t.Fatalf("the admin saw %q and the guest %q", got, guestWords)
	}
}

// Asking for other invite numbers until the code retires is said to the
// admin, as a wrong guess is: the code is gone, and the link is not.
func TestNameplateMissesAreReported(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	records := network(t, admin, g)
	h, err := Listen(Options{LAN: true, Addrs: func(port uint16) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := make(chan Event, 256)
	go h.Serve(ctx, admitting{func(*enroll.JoinRequest) *enroll.Admission { return nil }},
		func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil },
		func(e Event) { events <- e })
	other := h.Invite().Code()
	other.Nameplate = other.Nameplate%999 + 1
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.Port()).String()
	for range enroll.MaxNameplateMisses {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = enroll.Join(c, other)
		c.Close()
	}
	for {
		select {
		case e := <-events:
			if e.Kind == CodeVoided {
				if !strings.Contains(e.Err, "other invite numbers") {
					t.Fatalf("the code was voided for %q", e.Err)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("the code retired without the admin hearing of it")
		}
	}
}

// remoteConn is a connection from addr.
type remoteConn struct {
	net.Conn
	addr net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.addr }

// The typed code is a LAN secret: a hello for it from off the link, through a
// meeting, or while the invite does not answer on the LAN never reaches the
// invite, so it spends nothing of the code; one for the link is taken from
// anywhere.
func TestTheCodeIsTakenFromTheLinkAlone(t *testing.T) {
	inv, err := enroll.NewInvite(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		from             string
		lan, met, queued bool
		link             bool
	}{
		{name: "code on the link", from: "127.0.0.1:4000", lan: true, queued: true},
		{name: "code from off the link", from: "192.0.2.7:4000", lan: true},
		{name: "code through a meeting", from: "127.0.0.1:4000", lan: true, met: true},
		{name: "code without the LAN", from: "127.0.0.1:4000"},
		{name: "link from off the link", from: "192.0.2.7:4000", lan: true, link: true, queued: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := newGreeter(ctx, tc.lan)
			hc, gc := net.Pipe()
			defer gc.Close()
			var secret enroll.Secret = inv.Code()
			if tc.link {
				secret = inv.Link()
			}
			go enroll.Join(gc, secret)
			addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.from))
			src := sourceOf(addr)
			greeting, ok := g.enter(hc, src)
			if !ok {
				t.Fatal("no greeting place")
			}
			if got := g.hello(remoteConn{hc, addr}, src, greeting, tc.met); got != tc.queued {
				t.Fatalf("queued %v, want %v", got, tc.queued)
			}
			g.drain()
		})
	}
}

// The guest hands the host its announcement as the join ends, after it has
// started in the network: a host behind NAT, which a guest can open no
// connection to, learns where the guest is from nothing else.
func TestTheHostIsHandedTheGuestsAnnouncement(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	records := network(t, admin, g)
	h, err := Listen(Options{Addrs: func(port uint16) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	joined := make(chan Event, 1)
	served := make(chan error, 1)
	go func() {
		served <- h.Serve(ctx, admitting{func(req *enroll.JoinRequest) *enroll.Admission {
			a, _ := enroll.SignAdmission(admin, records[0].Hash(), records[len(records)-1].Hash(), req.Identity)
			return a
		}}, func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil }, func(e Event) {
			if e.Kind == Joined {
				joined <- e
			}
		})
	}()
	announcement := []byte("signed endpoint record")
	started := false
	if _, err := guest.Join(ctx, guest.Options{
		Invite: h.Invite().Link().WithAdmin(admin.Public()).String(),
		Name:   "phone",
		Keys:   g,
		Adopt:  func([]types.AUM) error { return nil },
		Announce: func(endpoints, leases [][]byte) []byte {
			started = true
			return announcement
		},
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	if !started {
		t.Fatal("the guest did not start before the join ended")
	}
	select {
	case e := <-joined:
		if !bytes.Equal(e.Announcement, announcement) {
			t.Fatalf("the host was handed %q, want %q", e.Announcement, announcement)
		}
	case <-ctx.Done():
		t.Fatal("the host reported no join")
	}
	<-served
}
