package dnsfwd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// query is a DNS query for example.com A with id.
func query(id uint16) []byte {
	q := make([]byte, headerLen)
	binary.BigEndian.PutUint16(q, id)
	q[5] = 1 // one question
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return q
}

// upstream is a resolver on loopback, over UDP and TCP, answering every
// query with its question and the response bit set; stray, where set, sends
// an answer to another query first.
type upstream struct {
	addr  netip.AddrPort
	asked atomic.Int32
	stray bool
}

func startUpstream(t *testing.T, stray bool) *upstream {
	t.Helper()
	pc, ln := listenBoth(t)
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	u := &upstream{addr: ap, stray: stray}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	answer := func(q []byte) []byte {
		u.asked.Add(1)
		a := slices.Clone(q)
		a[2] |= 0x80
		return a
	}
	go func() {
		buf := make([]byte, maxMessage)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if u.stray {
				other := answer(buf[:n])
				other[0] ^= 0xff
				pc.WriteTo(other, src)
			}
			pc.WriteTo(answer(buf[:n]), src)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					q, err := readTCPMessage(r)
					if err != nil {
						return
					}
					c.Write(tcpMessage(answer(q)))
				}
			}()
		}
	}()
	return u
}

// listenBoth listens on one loopback port for UDP and TCP both: a port free
// for UDP may be another's for TCP, as under make check.
func listenBoth(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for range 20 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if errors.Is(err, syscall.EADDRINUSE) {
			pc.Close()
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return pc, ln
	}
	t.Fatal("no port free for UDP and TCP both")
	return nil, nil
}

func startForwarder(t *testing.T, up *upstream, allowed func(netip.Addr) bool) netip.AddrPort {
	t.Helper()
	return startForwarderWith(t, up, func(o *Options) { o.Allowed = allowed })
}

// startForwarderWith is [startForwarder] with options set sets.
func startForwarderWith(t *testing.T, up *upstream, set func(*Options)) netip.AddrPort {
	t.Helper()
	// A port free for UDP may be another's for TCP, as under make check.
	for range 20 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := netip.MustParseAddrPort(pc.LocalAddr().String()).Port()
		pc.Close()
		opts := Options{Addrs: []netip.Addr{loopback}, Port: port,
			Upstream: func() []netip.AddrPort { return []netip.AddrPort{up.addr} }}
		set(&opts)
		f, err := Start(opts)
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return netip.AddrPortFrom(loopback, port)
	}
	t.Fatal("no port free for UDP and TCP both")
	return netip.AddrPort{}
}

func askUDP(t *testing.T, at netip.AddrPort, q []byte) ([]byte, error) {
	t.Helper()
	c, err := net.Dial("udp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxMessage)
	n, err := c.Read(buf)
	return buf[:n], err
}

// A member's query is put to the host's resolver and answered, over UDP and
// TCP, and a stray datagram is no answer.
func TestAQueryIsForwarded(t *testing.T) {
	up := startUpstream(t, true)
	at := startForwarder(t, up, func(netip.Addr) bool { return true })
	resp, err := askUDP(t, at, query(0x1234))
	if err != nil || !answers(resp, query(0x1234)) {
		t.Fatalf("over UDP: %x, %v", resp, err)
	}
	c, err := net.Dial("tcp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	r := bufio.NewReader(c)
	for _, id := range []uint16{7, 8} {
		if _, err := c.Write(tcpMessage(query(id))); err != nil {
			t.Fatal(err)
		}
		resp, err := readTCPMessage(r)
		if err != nil || !answers(resp, query(id)) {
			t.Fatalf("over TCP, query %d: %x, %v", id, resp, err)
		}
	}
}

// What is no query, and a query from outside the network, go unanswered and
// reach no resolver.
func TestOnlyMembersQueriesAreForwarded(t *testing.T) {
	up := startUpstream(t, false)
	at := startForwarder(t, up, func(netip.Addr) bool { return true })
	notQuery, update := query(1), query(1)
	notQuery[2] |= 0x80
	update[2] |= 5 << 3
	for _, q := range [][]byte{notQuery, update, {1, 2, 3}, query(1)[:headerLen]} {
		if _, err := askUDP(t, at, q); err == nil {
			t.Errorf("%x was answered", q)
		}
	}
	shut := startForwarder(t, up, func(netip.Addr) bool { return false })
	if _, err := askUDP(t, shut, query(2)); err == nil {
		t.Error("a query from outside the network was answered")
	}
	if n := up.asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times", n)
	}
}

// One member asking too fast is answered at its rate, and the rest dropped.
func TestAMemberIsAnsweredAtItsRate(t *testing.T) {
	up := startUpstream(t, false)
	at := startForwarder(t, up, func(netip.Addr) bool { return true })
	c, err := net.Dial("udp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 3 * perSourceMax {
		c.Write(query(uint16(i)))
	}
	time.Sleep(500 * time.Millisecond)
	// Its rate and its queries in flight both hold it back.
	if n := up.asked.Load(); n > perSourceMax+perSourceQPS || n < perSourceInFlight/2 {
		t.Errorf("%d of %d queries were forwarded", n, 3*perSourceMax)
	}
}

// The host's resolvers are those /etc/resolv.conf names, resolved's stub
// itself where it is that, whose routing then applies.
func TestTheHostsResolvers(t *testing.T) {
	dir := t.TempDir()
	was := ResolvConf
	t.Cleanup(func() { ResolvConf = was })
	ResolvConf = filepath.Join(dir, "resolv.conf")
	write := func(path, s string) {
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(ResolvConf, "nameserver 127.0.0.53\noptions edns0\n")
	if got := HostResolvers(); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}) {
		t.Errorf("behind resolved: %v", got)
	}
	write(ResolvConf, "# comment\nnameserver 192.168.1.1\nsearch lan\n")
	if got := HostResolvers(); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")}) {
		t.Errorf("without resolved: %v", got)
	}
}

// A resolver that fails the query itself is passed over for the next one.
func TestAFailingResolverIsPassedOver(t *testing.T) {
	failing := startUpstream(t, false)
	good := startUpstream(t, false)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, maxMessage)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			buf[2] |= 0x80
			buf[3] = buf[3]&0xf0 | 2 // SERVFAIL
			pc.WriteTo(buf[:n], src)
		}
	}()
	failing.addr = netip.MustParseAddrPort(pc.LocalAddr().String())
	f := &Forwarder{opts: Options{Upstream: func() []netip.AddrPort { return []netip.AddrPort{failing.addr, good.addr} }},
		ctx: context.Background()}
	resp, err := f.ask("udp", query(9))
	if err != nil || resp[3]&0x0f != 0 || good.asked.Load() != 1 {
		t.Errorf("answered %x, %v, the good resolver asked %d times", resp, err, good.asked.Load())
	}
}

// One source holds a few TCP connections at most, so that the rest stay for
// others.
func TestASourceHoldsFewConnections(t *testing.T) {
	up := startUpstream(t, false)
	at := startForwarder(t, up, func(netip.Addr) bool { return true })
	var conns []net.Conn
	for range perSourceConns + 2 {
		c, err := net.Dial("tcp", at.String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		t.Cleanup(func() { c.Close() })
	}
	time.Sleep(200 * time.Millisecond)
	answered := 0
	for _, c := range conns {
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write(tcpMessage(query(3))); err != nil {
			continue
		}
		if resp, err := readTCPMessage(bufio.NewReader(c)); err == nil && answers(resp, query(3)) {
			answered++
		}
	}
	if answered != perSourceConns {
		t.Errorf("%d connections of one source were answered, want %d", answered, perSourceConns)
	}
}

// A query the forwarder answers itself is answered so, over UDP and TCP,
// and reaches no resolver; the rest goes on.
func TestAnAnswerOfItsOwnReachesNoResolver(t *testing.T) {
	up := startUpstream(t, false)
	own := func(q []byte) []byte {
		if q[0] != 0x42 {
			return nil
		}
		a := slices.Clone(q)
		a[2] |= 0x80
		a[3] = 3 // NXDOMAIN, which no upstream here says
		return a
	}
	at := startForwarderWith(t, up, func(o *Options) { o.Answer = own })
	resp, err := askUDP(t, at, query(0x4200))
	if err != nil || resp[3]&0x0f != 3 {
		t.Fatalf("over UDP: %x, %v", resp, err)
	}
	c, err := net.Dial("tcp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write(tcpMessage(query(0x4201)))
	if resp, err := readTCPMessage(bufio.NewReader(c)); err != nil || resp[3]&0x0f != 3 {
		t.Fatalf("over TCP: %x, %v", resp, err)
	}
	if n := up.asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times", n)
	}
	if resp, err := askUDP(t, at, query(0x1000)); err != nil || !answers(resp, query(0x1000)) || up.asked.Load() != 1 {
		t.Errorf("the rest was not forwarded: %x, %v", resp, err)
	}
}

// A query UpstreamFor refuses is answered SERVFAIL, over UDP and TCP, and
// asked of no resolver, not even Upstream's.
func TestARefusedQueryIsAnsweredServerFailure(t *testing.T) {
	up := startUpstream(t, false)
	refuse := func([]byte) ([]netip.AddrPort, error) { return nil, errors.New("no routing") }
	at := startForwarderWith(t, up, func(o *Options) { o.UpstreamFor = refuse })
	q := query(0x5150)
	q[2] = 0x01 // RD
	check := func(over string, resp []byte, err error) {
		t.Helper()
		var p dnsmessage.Parser
		h, perr := p.Start(resp)
		if err != nil || perr != nil {
			t.Fatalf("over %s: %x, %v, %v", over, resp, err, perr)
		}
		qs, _ := p.AllQuestions()
		if h.ID != 0x5150 || !h.Response || h.RCode != dnsmessage.RCodeServerFailure || !h.RecursionDesired ||
			len(qs) != 1 || qs[0].Name.String() != "example.com." {
			t.Errorf("over %s: %+v, %v", over, h, qs)
		}
	}
	resp, err := askUDP(t, at, q)
	check("UDP", resp, err)
	c, err := net.Dial("tcp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write(tcpMessage(q))
	resp, err = readTCPMessage(bufio.NewReader(c))
	check("TCP", resp, err)
	if n := up.asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times", n)
	}
}

// A query UpstreamFor refuses with a Refusal is answered its RCode.
func TestARefusalIsAnsweredItsRCode(t *testing.T) {
	up := startUpstream(t, false)
	refuse := func([]byte) ([]netip.AddrPort, error) {
		return nil, fmt.Errorf("x: %w", &Refusal{RCode: RCodeNXDomain, Err: errors.New("never")})
	}
	at := startForwarderWith(t, up, func(o *Options) { o.UpstreamFor = refuse })
	resp, err := askUDP(t, at, query(0x5151))
	if err != nil || !answers(resp, query(0x5151)) || resp[3]&0x0f != RCodeNXDomain {
		t.Errorf("%x, %v", resp, err)
	}
	if n := up.asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times", n)
	}
}

// The host, asking for all its programs, is held to no one source's rate.
func TestTheHostIsHeldToNoSourcesRate(t *testing.T) {
	up := startUpstream(t, false)
	at := startForwarderWith(t, up, func(o *Options) { o.Local = true })
	c, err := net.Dial("udp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 3 * perSourceMax {
		c.Write(query(uint16(i)))
		if i%50 == 49 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if n := up.asked.Load(); n <= perSourceMax+perSourceQPS {
		t.Errorf("only %d of %d queries were forwarded", n, 3*perSourceMax)
	}
}

// An answer passed on keeps no TTL above the cap, in any section, and an OPT
// record's flags stay as they are.
func TestAnAnswerPassedOnIsCapped(t *testing.T) {
	name := dnsmessage.MustNewName("status.example.org.")
	apex := dnsmessage.MustNewName("example.org.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 38400},
		dnsmessage.CNAMEResource{CNAME: apex})
	b.AResource(dnsmessage.ResourceHeader{Name: apex, Class: dnsmessage.ClassINET, TTL: 5},
		dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
	b.StartAuthorities()
	b.SOAResource(dnsmessage.ResourceHeader{Name: apex, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.SOAResource{NS: apex, MBox: apex, MinTTL: 3600})
	b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, true)
	b.OPTResource(opt, dnsmessage.OPTResource{})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	capTTL(msg, 30)
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	var got []uint32
	for _, r := range slices.Concat(m.Answers, m.Authorities) {
		got = append(got, r.Header.TTL)
	}
	if !slices.Equal(got, []uint32{30, 5, 30}) {
		t.Errorf("TTLs %v, want [30 5 30]", got)
	}
	if len(m.Additionals) != 1 || m.Additionals[0].Header.TTL != opt.TTL {
		t.Errorf("the OPT record: %+v, want TTL %#x", m.Additionals, opt.TTL)
	}
	for n := range len(msg) {
		capTTL(msg[:n], 30) // a cut message is left as it parses
	}
}

// A query no resolver can be asked is answered SERVFAIL at once where
// FailFast says so, and not at all otherwise.
func TestAQueryNoneCanBeAskedFailsAtOnce(t *testing.T) {
	up := startUpstream(t, false)
	none := func() []netip.AddrPort { return nil }
	refused := errors.New("network is unreachable")
	for _, tc := range []struct {
		name string
		set  func(*Options)
	}{
		{"no resolver", func(o *Options) { o.Upstream = none }},
		{"no route", func(o *Options) {
			o.Dial = func(context.Context, string, netip.AddrPort) (net.Conn, error) { return nil, refused }
		}},
	} {
		at := startForwarderWith(t, up, func(o *Options) { tc.set(o); o.FailFast = true })
		start := time.Now()
		resp, err := askUDP(t, at, query(0x5152))
		if err != nil || !answers(resp, query(0x5152)) || resp[3]&0x0f != RCodeServFail || time.Since(start) > 500*time.Millisecond {
			t.Errorf("%s: %x, %v after %v", tc.name, resp, err, time.Since(start))
		}
		at = startForwarderWith(t, up, tc.set)
		if resp, err := askUDP(t, at, query(0x5153)); err == nil {
			t.Errorf("%s, without FailFast: answered %x", tc.name, resp)
		}
	}
	if n := up.asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times", n)
	}
}

// datagrams is a PacketConn that is no *net.UDPConn, as a stack in the
// process gives.
type datagrams struct{ net.PacketConn }

// The forwarder answers on what Listen gives, any PacketConn, and asks
// upstream by Dial.
func TestAForwarderListensAndDialsAsItIsGiven(t *testing.T) {
	up := startUpstream(t, false)
	var dialed atomic.Int32
	at := startForwarderWith(t, up, func(o *Options) {
		o.Listen = func(ap netip.AddrPort) (net.PacketConn, net.Listener, error) {
			pc, err := net.ListenPacket("udp", ap.String())
			if err != nil {
				return nil, nil, err
			}
			ln, err := net.Listen("tcp", ap.String())
			if err != nil {
				pc.Close()
				return nil, nil, err
			}
			return datagrams{pc}, ln, nil
		}
		o.Dial = func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error) {
			dialed.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, to.String())
		}
	})
	resp, err := askUDP(t, at, query(0x5154))
	if err != nil || !answers(resp, query(0x5154)) {
		t.Fatalf("%x, %v", resp, err)
	}
	if dialed.Load() != 1 || up.asked.Load() != 1 {
		t.Errorf("dialed %d times, the resolver asked %d", dialed.Load(), up.asked.Load())
	}
}

// tlsUpstream answers queries by DNS over TLS on loopback with a certificate
// of its own, counting them.
func tlsUpstream(t *testing.T) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var asked atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				q, err := readTCPMessage(bufio.NewReader(c))
				if err != nil {
					return
				}
				asked.Add(1)
				q[2] |= 0x80
				c.Write(tcpMessage(q))
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String()), &asked
}

// A resolver on 853 is asked by DNS over TLS, whatever its certificate, and
// the next one in turn where it cannot be.
func TestAResolverOn853IsAskedOverTLS(t *testing.T) {
	plain := startUpstream(t, false)
	overTLS, asked := tlsUpstream(t)
	dot, dns := netip.MustParseAddrPort("127.0.0.1:853"), netip.MustParseAddrPort("127.0.0.1:53")
	var dotAt atomic.Pointer[netip.AddrPort]
	dotAt.Store(&overTLS)
	at := startForwarderWith(t, plain, func(o *Options) {
		o.Upstream = func() []netip.AddrPort { return []netip.AddrPort{dot, dns} }
		o.Dial = func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error) {
			if to == dot {
				if network != "tcp" {
					t.Errorf("DNS over TLS asked over %s", network)
				}
				to = *dotAt.Load()
			} else {
				to = plain.addr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, to.String())
		}
	})
	if resp, err := askUDP(t, at, query(0x5155)); err != nil || !answers(resp, query(0x5155)) || asked.Load() != 1 || plain.asked.Load() != 0 {
		t.Errorf("over TLS: %x, %v; asked %d over TLS, %d in plain text", resp, err, asked.Load(), plain.asked.Load())
	}
	closed := netip.MustParseAddrPort("127.0.0.1:1")
	dotAt.Store(&closed)
	if resp, err := askUDP(t, at, query(0x5156)); err != nil || !answers(resp, query(0x5156)) || plain.asked.Load() != 1 {
		t.Errorf("TLS refused: %x, %v; asked %d in plain text", resp, err, plain.asked.Load())
	}
	dotAt.Store(&overTLS)
	if resp, err := askUDP(t, at, query(0x5157)); err != nil || !answers(resp, query(0x5157)) || asked.Load() != 1 || plain.asked.Load() != 2 {
		t.Errorf("after TLS failed: %x, %v; asked %d over TLS, %d in plain text, want TLS left alone for a while",
			resp, err, asked.Load(), plain.asked.Load())
	}
}

// failingDatagrams fails every read without being closed, counting them, as
// a stack in the process does once its device is gone.
type failingDatagrams struct {
	net.PacketConn
	reads atomic.Int32
}

func (f *failingDatagrams) ReadFrom([]byte) (int, net.Addr, error) {
	f.reads.Add(1)
	return 0, nil, errors.New("endpoint is in invalid state")
}

// A listener that fails every read or accept is waited on between tries, not
// spun on.
func TestAFailingListenerIsNotSpunOn(t *testing.T) {
	pc, ln := listenBoth(t)
	failing := &failingDatagrams{PacketConn: pc}
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	f, err := Start(Options{Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port(),
		Listen: func(netip.AddrPort) (net.PacketConn, net.Listener, error) { return failing, ln, nil }})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	f.Close()
	if n := failing.reads.Load(); n > 20 {
		t.Errorf("%d reads failed in 300 ms", n)
	}
}

// Where Capped says which, MaxTTL caps the answers to those queries alone,
// and every other passes on as upstream answered it.
func TestCappedSaysWhichAnswersAreCapped(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, maxMessage)
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
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 3600}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
			resp, _ := b.Finish()
			pc.WriteTo(resp, src)
		}
	}()
	up := &upstream{addr: netip.MustParseAddrPort(pc.LocalAddr().String())}
	at := startForwarderWith(t, up, func(o *Options) {
		o.MaxTTL = 30
		o.Capped = func(q []byte) bool { return bytes.Contains(q, []byte("\x07example\x03org")) }
	})
	for name, want := range map[string]uint32{"www.example.org.": 30, "www.example.com.": 3600} {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 9})
		b.StartQuestions()
		b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		resp, err := askUDP(t, at, q)
		var m dnsmessage.Message
		if err != nil || m.Unpack(resp) != nil || len(m.Answers) != 1 || m.Answers[0].Header.TTL != want {
			t.Errorf("%s: %+v, %v, want TTL %d", name, m.Answers, err, want)
		}
	}
}

// bigUpstream answers every query with 150 addresses, about 2.4 KB, over UDP
// and TCP.
func bigUpstream(t *testing.T) *upstream {
	t.Helper()
	pc, ln := listenBoth(t)
	t.Cleanup(func() { pc.Close(); ln.Close() })
	answer := func(q []byte) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if err != nil {
			return nil
		}
		qq, err := p.Question()
		if err != nil {
			return nil
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
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
		buf := make([]byte, maxMessage)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(answer(buf[:n]), src)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				q, err := readTCPMessage(bufio.NewReader(c))
				if err == nil {
					c.Write(tcpMessage(answer(q)))
				}
			}()
		}
	}()
	return &upstream{addr: netip.MustParseAddrPort(pc.LocalAddr().String())}
}

// An answer longer than MaxUDP is sent over UDP truncated, its question
// alone with TC set, for the asker to ask again over TCP, which carries it
// whole.
func TestAnAnswerTooLongForUDPIsTruncated(t *testing.T) {
	up := bigUpstream(t)
	at := startForwarderWith(t, up, func(o *Options) { o.MaxUDP = 1232 })
	resp, err := askUDP(t, at, query(0x5158))
	var m dnsmessage.Message
	if err != nil || len(resp) > 1232 || m.Unpack(resp) != nil || !m.Truncated || m.ID != 0x5158 ||
		len(m.Questions) != 1 || len(m.Answers) != 0 {
		t.Errorf("over UDP: %d bytes, %+v, %v", len(resp), m.Header, err)
	}
	c, err := net.Dial("tcp", at.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write(tcpMessage(query(0x5159)))
	resp, err = readTCPMessage(bufio.NewReader(c))
	if err != nil || m.Unpack(resp) != nil || m.Truncated || len(m.Answers) != 150 {
		t.Errorf("over TCP: %d answers, %v", len(m.Answers), err)
	}
}
