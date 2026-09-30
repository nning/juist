package dnsfwd

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	ln, err := net.Listen("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
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
	f := &Forwarder{opts: Options{Upstream: func() []netip.AddrPort { return []netip.AddrPort{failing.addr, good.addr} }}}
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
