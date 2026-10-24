package daemon

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/netstack"
	"github.com/nning/juist/types"
)

// phone is a daemon whose host asks juistd's resolver alone, through a VPN's
// servers, as the Android app's: host is the host's own stack, joined to the
// resolver's as the data plane joins them, dialed what the resolver dialed,
// and underlay how the network beneath resolves.
type phone struct {
	*reconcileFixture
	host     *netstack.Net
	plumber  *dnsPlumber
	resolver netip.AddrPort

	mu       sync.Mutex
	underlay Underlay
	dialed   []netip.AddrPort
}

// newPhone starts a phone whose resolver asks every resolver upstream of up,
// a loopback resolver answering each query with its question.
func newPhone(t *testing.T, up netip.AddrPort) *phone {
	t.Helper()
	p := &phone{plumber: &dnsPlumber{}, underlay: Underlay{Servers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}}}
	var local tun.Device
	p.reconcileFixture = exitFixture(t, 1, -1, func(o *Options) {
		o.HostDNS = VPNDNS(p.plumber, "juist0", func() Underlay {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.underlay
		})
		o.Resolver = &Resolver{Dial: func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error) {
			p.mu.Lock()
			p.dialed = append(p.dialed, to)
			p.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, up.String())
		}}
		mgr := &fakeManager{}
		o.Connect = func(c conn.Options) (conn.Manager, error) {
			local = c.Local
			if len(c.LocalAddrs) != 1 {
				t.Errorf("the data plane takes %v", c.LocalAddrs)
			}
			return mgr, nil
		}
	})
	p.resolver = netip.AddrPortFrom(types.ResolverAddr(p.auth.State().ULA()), 53)
	dev, host, err := netstack.New([]netip.Addr{p.auth.State().Addr6(p.self.record.Identity)}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close(); local.Close() })
	go joinDevices(dev, local)
	go joinDevices(local, dev)
	p.host = host
	return p
}

// joinDevices writes what from sends to to, until from closes.
func joinDevices(from, to tun.Device) {
	slab := make([]byte, 1<<16)
	packets := make([]tun.ReadPacket, from.BatchSize())
	for {
		n, err := from.Read(slab, packets)
		if err != nil && n == 0 {
			if err == tun.ErrTooManySegments {
				continue
			}
			return
		}
		for _, p := range packets[:n] {
			to.Write([][]byte{slab[p.Offset : p.Offset+p.Size]}, 0)
		}
	}
}

func (p *phone) setUnderlay(u Underlay) {
	p.mu.Lock()
	p.underlay = u
	p.mu.Unlock()
	p.d.NetworkChanged()
}

func (p *phone) dials() []netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.dialed)
}

// askUDP and askTCP put q to the resolver from the host's stack.
func (p *phone) askUDP(t *testing.T, q []byte) ([]byte, error) {
	t.Helper()
	c, err := p.host.DialUDPAddrPort(p.resolver)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	return buf[:n], err
}

func (p *phone) askTCP(t *testing.T, q []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := p.host.DialContextTCPAddrPort(ctx, p.resolver)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(n[:]))
	_, err = io.ReadFull(r, resp)
	return resp, err
}

// echoResolver answers every query on loopback with its question, the
// response bit set, over UDP.
func echoResolver(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			buf[2] |= 0x80
			pc.WriteTo(buf[:n], src)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func rcodeOf(t *testing.T, resp []byte) dnsmessage.RCode {
	t.Helper()
	var h dnsmessage.Header
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("%x: %v", resp, err)
	}
	return h.RCode
}

// A phone's lookups all go to juistd's resolver, at the network's resolver
// address, searching the network's domain alone: it answers
// the network's names itself, over UDP and TCP, and asks the network beneath
// the VPN the rest, by the resolvers it says now.
func TestAPhoneAsksJuistdsResolverAlone(t *testing.T) {
	p := newPhone(t, echoResolver(t))
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	p.plumber.mu.Lock()
	set, search := p.plumber.set[len(p.plumber.set)-1], p.plumber.search[len(p.plumber.search)-1]
	p.plumber.mu.Unlock()
	if !slices.Equal(set, []netip.Addr{p.resolver.Addr()}) || !slices.Equal(search, []string{"m2-testnet.juist"}) {
		t.Errorf("the VPN's servers are %v, searching %v", set, search)
	}
	if n := p.d.Status().Names; n == nil || !n.Resolved || n.Not != "" {
		t.Errorf("the status says %+v", n)
	}
	for over, ask := range map[string]func(*testing.T, []byte) ([]byte, error){"UDP": p.askUDP, "TCP": p.askTCP} {
		resp, err := ask(t, typedQuery(t, "n1.m2-testnet.juist.", dnsmessage.TypeA))
		if err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess || !strings.Contains(string(resp), string(p.nw.devices[1].record.V4.AsSlice())) {
			t.Errorf("over %s, a member's name: %x, %v", over, resp, err)
		}
	}
	for _, a := range []netip.Addr{*p.nw.devices[1].record.V4, p.auth.State().Addr6(p.nw.devices[1].record.Identity)} {
		resp, err := p.askUDP(t, typedQuery(t, reverseName(a)+".", dnsmessage.TypePTR))
		if err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess || !strings.Contains(string(resp), "\x02n1\x0am2-testnet") {
			t.Errorf("%v's reverse name: %x, %v", a, resp, err)
		}
	}
	if d := p.dials(); len(d) != 0 {
		t.Errorf("a member's name was asked of %v", d)
	}
	resp, err := p.askUDP(t, nameQuery(t, "mx.example.net."))
	if err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess {
		t.Errorf("another name: %x, %v", resp, err)
	}
	if d := p.dials(); !slices.Equal(d, []netip.AddrPort{netip.MustParseAddrPort("10.0.2.3:53")}) {
		t.Errorf("another name was asked of %v", d)
	}
	p.setUnderlay(Underlay{Servers: []netip.Addr{netip.MustParseAddr("fe80::1%wlan0")}})
	p.askUDP(t, nameQuery(t, "mx.example.net."))
	if d := p.dials(); len(d) != 2 || d[1] != netip.MustParseAddrPort("[fe80::1%wlan0]:53") {
		t.Errorf("after the network changed, asked %v", d)
	}
}

// A lookup the resolver can ask no one of fails at once, not after the
// phone's own timeout.
func TestAPhoneWithoutResolversFailsAtOnce(t *testing.T) {
	p := newPhone(t, netip.MustParseAddrPort("127.0.0.1:9"))
	p.underlay = Underlay{}
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := p.askUDP(t, nameQuery(t, "mx.example.net."))
	if err != nil || rcodeOf(t, resp) != dnsmessage.RCodeServerFailure || time.Since(start) > time.Second {
		t.Errorf("%x, %v after %v", resp, err, time.Since(start))
	}
}

// Where Private DNS sends every lookup to a host, the VPN takes none, which
// would all fail, and the status says why the network's names are not
// resolved; without it, the VPN takes them again.
func TestPrivateDNSLeavesThePhonesNamesUnresolved(t *testing.T) {
	p := newPhone(t, echoResolver(t))
	p.setUnderlay(Underlay{Servers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}, PrivateDNS: "dns.google"})
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	last := func() []netip.Addr {
		p.plumber.mu.Lock()
		defer p.plumber.mu.Unlock()
		if len(p.plumber.set) == 0 {
			return nil
		}
		return p.plumber.set[len(p.plumber.set)-1]
	}
	if n := p.d.Status().Names; n == nil || n.Resolved || n.Not != PrivateDNSNot("dns.google") || len(last()) != 0 {
		t.Errorf("with Private DNS, the status says %+v, and the VPN takes lookups to %v", n, last())
	}
	exit := p.nw.devices[1]
	p.learnExitDNS(t, exit, 7001, true, 53)
	p.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e := p.d.Status().Exit; e == nil || e.DNS || e.DNSNot != PrivateDNSNot("dns.google") || len(last()) != 0 {
		t.Errorf("with Private DNS and an exit node, the exit says %+v, and the VPN takes lookups to %v", e, last())
	}
	p.setUnderlay(Underlay{Servers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}})
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if n := p.d.Status().Names; n == nil || !n.Resolved || !slices.Equal(last(), []netip.Addr{p.resolver.Addr()}) {
		t.Errorf("without Private DNS, the status says %+v, and the VPN takes lookups to %v", n, last())
	}
}

// With an exit node, the network's names are still the resolver's, and
// every other lookup goes to the exit node, through the tunnel.
func TestAPhonesOtherLookupsGoToTheExitNode(t *testing.T) {
	p := newPhone(t, echoResolver(t))
	exit := p.nw.devices[1]
	p.learnExitDNS(t, exit, 7001, true, 53)
	p.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if resp, err := p.askUDP(t, typedQuery(t, "n1.m2-testnet.juist.", dnsmessage.TypeA)); err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess {
		t.Errorf("a member's name: %x, %v", resp, err)
	}
	if resp, err := p.askUDP(t, nameQuery(t, "mx.example.net.")); err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess {
		t.Errorf("another name: %x, %v", resp, err)
	}
	at := []netip.AddrPort{netip.AddrPortFrom(*exit.record.V4, 53), netip.AddrPortFrom(p.auth.State().Addr6(exit.record.Identity), 53)}
	if d := p.dials(); len(d) != 1 || !slices.Contains(at, d[0]) {
		t.Errorf("another name was asked of %v, not the exit node at %v", d, at)
	}
}

// Where automatic Private DNS found the network's resolvers answering DNS
// over TLS, the phone's resolver asks them so too, in plain text only where
// that fails, as Android would.
func TestAPhoneAsksOverTLSWhereAndroidWould(t *testing.T) {
	p := newPhone(t, echoResolver(t))
	p.setUnderlay(Underlay{Servers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}, OverTLS: true})
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	resp, err := p.askUDP(t, nameQuery(t, "mx.example.net."))
	if err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess {
		t.Errorf("%x, %v", resp, err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("10.0.2.3:853"), netip.MustParseAddrPort("10.0.2.3:53")}
	if d := p.dials(); !slices.Equal(d, want) {
		t.Errorf("asked %v, want %v", d, want)
	}
}

// While the exit node chosen is refused, its internet blocked, a lookup it
// would answer fails at once rather than after the forwarder's timeout; the
// network's names still resolve.
func TestARefusedExitNodesLookupsFailAtOnce(t *testing.T) {
	p := newPhone(t, echoResolver(t))
	exit := p.nw.devices[1]
	p.learnExitDNS(t, exit, 7001, false, 53)
	p.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e := p.d.Status().Exit; e == nil || e.Refused == "" {
		t.Fatalf("the exit node is not refused: %+v", e)
	}
	if resp, err := p.askUDP(t, nameQuery(t, "mx.example.net.")); err != nil || rcodeOf(t, resp) != dnsmessage.RCodeServerFailure {
		t.Errorf("another name: %x, %v", resp, err)
	}
	if d := p.dials(); len(d) != 0 {
		t.Errorf("a refused exit node was asked: %v", d)
	}
	if resp, err := p.askUDP(t, typedQuery(t, "n1.m2-testnet.juist.", dnsmessage.TypeA)); err != nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess {
		t.Errorf("a member's name: %x, %v", resp, err)
	}
}

// ttlResolver answers every query with an address of TTL 3600, over UDP.
func ttlResolver(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 3600}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
			resp, _ := b.Finish()
			pc.WriteTo(resp, src)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// The phone's resolver passes an answer from upstream on with its TTL, which
// a short one would have Android ask again and wake the radio for, but for
// the names the network may yet answer itself: those under its public
// domain, and those it points at members.
func TestAPhoneKeepsUpstreamTTLs(t *testing.T) {
	p := newPhone(t, ttlResolver(t))
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	resp, err := p.askUDP(t, typedQuery(t, "mx.example.net.", dnsmessage.TypeA))
	var m dnsmessage.Message
	if err != nil || m.Unpack(resp) != nil || len(m.Answers) != 1 || m.Answers[0].Header.TTL != 3600 {
		t.Errorf("another name: %+v, %v, want TTL 3600", m.Answers, err)
	}
	p.d.zone.Store(&names.Zone{Domain: "m2-testnet.juist", Public: "pub.example.org",
		Overrides: map[string]names.Override{"mail.example.net": {}}})
	for name, capped := range map[string]bool{"wiki.pub.example.org.": true, "pub.example.org.": true,
		"mail.example.net.": true, "mx.example.net.": false, "example.org.": false} {
		if got := p.d.namesCapped(typedQuery(t, name, dnsmessage.TypeA)); got != capped {
			t.Errorf("%s capped %v, want %v", name, got, capped)
		}
	}
}

// An answer longer than the resolver's stack carries in one datagram, which
// it does not fragment, reaches the phone truncated over UDP, and whole over
// TCP, as the phone then asks.
func TestAPhoneGetsALongAnswerOverTCP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	big := func(q []byte) []byte {
		var p dnsmessage.Parser
		h, _ := p.Start(q)
		qq, _ := p.Question()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
		b.StartQuestions()
		b.Question(qq)
		b.StartAnswers()
		for i := range 150 {
			b.AResource(dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i)}})
		}
		resp, _ := b.Finish()
		return resp
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(big(buf[:n]), src)
		}
	}()
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Skip("no TCP port beside the UDP one")
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var n [2]byte
			if _, err := io.ReadFull(c, n[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(n[:]))
				if _, err := io.ReadFull(c, q); err == nil {
					r := big(q)
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
				}
			}
			c.Close()
		}
	}()
	p := newPhone(t, netip.MustParseAddrPort(pc.LocalAddr().String()))
	if err := p.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	resp, err := p.askUDP(t, typedQuery(t, "big.example.com.", dnsmessage.TypeA))
	if err != nil || m.Unpack(resp) != nil || !m.Truncated {
		t.Errorf("over UDP: %d bytes, %+v, %v", len(resp), m.Header, err)
	}
	resp, err = p.askTCP(t, typedQuery(t, "big.example.com.", dnsmessage.TypeA))
	if err != nil || m.Unpack(resp) != nil || len(m.Answers) != 150 {
		t.Errorf("over TCP: %d answers, %v", len(m.Answers), err)
	}
}
