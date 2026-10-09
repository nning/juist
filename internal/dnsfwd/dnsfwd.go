// Package dnsfwd answers DNS queries for a network's members on an exit node:
// on the node's overlay addresses alone, and by asking the host's own
// resolvers, so that a member's lookups leave from the exit node as its
// traffic does.
package dnsfwd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

// Limits on what one forwarder takes on, and each source of it, so that a
// member flooding it slows its own lookups first.
const (
	maxInFlight       = 256
	perSourceInFlight = 32
	perSourceQPS      = 50
	perSourceMax      = 100
	queryTimeout      = 3 * time.Second
	tcpIdle           = 10 * time.Second
	maxTCPConns       = 64
	perSourceConns    = 4
	maxMessage        = 65535
	headerLen         = 12
)

// ResolvConf is where the host's resolvers are read from.
var ResolvConf = "/etc/resolv.conf"

// Options are a forwarder's.
type Options struct {
	// Addrs and Port are where it answers, Device the only device queries
	// may arrive on; "" for any, as in tests.
	Addrs  []netip.Addr
	Port   uint16
	Device string

	// Allowed says whether a source may ask: the network's overlay.
	Allowed func(netip.Addr) bool

	// Upstream is the resolvers asked, read from the host where nil.
	Upstream func() []netip.AddrPort

	// UpstreamFor, where set, is the resolvers asked for query instead, nil
	// for Upstream's; empty, it is asked of none.
	UpstreamFor func(query []byte) []netip.AddrPort

	// Answer, where set, answers a query itself, nil passing it upstream.
	Answer func(query []byte) []byte

	// MaxTTL, where set, caps the TTL of every record an answer from
	// upstream carries, in seconds.
	MaxTTL uint32

	// Local has the host alone ask, its resolver as one source for all its
	// programs: no source is held to the limits on one.
	Local bool

	Logf func(format string, args ...any)
}

// A Forwarder answers until closed.
type Forwarder struct {
	opts     Options
	udp      []*net.UDPConn
	tcp      []net.Listener
	inFlight chan struct{}
	conns    chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	limits  map[netip.Addr]*rate.Limiter
	busy    map[netip.Addr]int // queries in flight per source
	open    map[netip.Addr]int // TCP connections per source
	workers sync.WaitGroup
}

// Start listens on every address, and answers from then on.
func Start(opts Options) (*Forwarder, error) {
	if opts.Upstream == nil {
		opts.Upstream = HostResolvers
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	f := &Forwarder{opts: opts, inFlight: make(chan struct{}, maxInFlight), conns: make(chan struct{}, maxTCPConns),
		limits: map[netip.Addr]*rate.Limiter{}, busy: map[netip.Addr]int{}, open: map[netip.Addr]int{}}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	lc := net.ListenConfig{Control: control(opts.Device)}
	for _, a := range opts.Addrs {
		ap := netip.AddrPortFrom(a, opts.Port)
		pc, err := lc.ListenPacket(context.Background(), "udp", ap.String())
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("dnsfwd: %w", err)
		}
		f.udp = append(f.udp, pc.(*net.UDPConn))
		ln, err := lc.Listen(context.Background(), "tcp", ap.String())
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("dnsfwd: %w", err)
		}
		f.tcp = append(f.tcp, ln)
	}
	for _, c := range f.udp {
		f.workers.Add(1)
		go f.serveUDP(c)
	}
	for _, ln := range f.tcp {
		f.workers.Add(1)
		go f.serveTCP(ln)
	}
	return f, nil
}

// Close stops answering and waits for what was under way.
func (f *Forwarder) Close() error {
	if f.ctx.Err() != nil {
		return nil
	}
	f.cancel()
	for _, c := range f.udp {
		c.Close()
	}
	for _, ln := range f.tcp {
		ln.Close()
	}
	f.workers.Wait()
	return nil
}

// admit reports whether src may ask now.
func (f *Forwarder) admit(src netip.Addr) bool {
	src = src.Unmap()
	if f.opts.Allowed != nil && !f.opts.Allowed(src) {
		return false
	}
	if f.opts.Local {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.limits[src]
	if l == nil {
		if len(f.limits) > 4096 {
			clear(f.limits)
		}
		l = rate.NewLimiter(perSourceQPS, perSourceMax)
		f.limits[src] = l
	}
	return l.Allow()
}

// hold takes one of src's count slots in m, of at most max, reporting
// whether there was one; release gives it back.
func (f *Forwarder) hold(m map[netip.Addr]int, src netip.Addr, max int) bool {
	if f.opts.Local {
		max = maxInFlight
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m[src] >= max {
		return false
	}
	m[src]++
	return true
}

func (f *Forwarder) release(m map[netip.Addr]int, src netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m[src]--; m[src] <= 0 {
		delete(m, src)
	}
}

// isQuery reports whether msg is a DNS query worth asking about: a standard
// query (opcode 0, response bit clear) with a question, at least the root's
// name, type and class. An update or a notify is not passed on.
func isQuery(msg []byte) bool {
	return len(msg) >= headerLen+5 && msg[2]&0xf8 == 0 && binary.BigEndian.Uint16(msg[4:6]) > 0
}

func (f *Forwarder) serveUDP(c *net.UDPConn) {
	defer f.workers.Done()
	buf := make([]byte, maxMessage)
	for {
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		from := src.Addr().Unmap()
		if !isQuery(buf[:n]) || !f.admit(from) {
			continue
		}
		if resp := f.answer(buf[:n]); resp != nil {
			c.WriteToUDPAddrPort(resp, src)
			continue
		}
		if !f.hold(f.busy, from, perSourceInFlight) {
			continue
		}
		select {
		case f.inFlight <- struct{}{}:
		default:
			f.release(f.busy, from)
			continue // too much under way: the member asks again
		}
		q := bytes.Clone(buf[:n])
		f.workers.Add(1)
		go func() {
			defer f.workers.Done()
			defer f.release(f.busy, from)
			defer func() { <-f.inFlight }()
			if resp, err := f.ask("udp", q); err == nil {
				c.WriteToUDPAddrPort(resp, src)
			}
		}()
	}
}

func (f *Forwarder) serveTCP(ln net.Listener) {
	defer f.workers.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		src, _ := netip.ParseAddrPort(c.RemoteAddr().String())
		from := src.Addr().Unmap()
		if (f.opts.Allowed != nil && !f.opts.Allowed(from)) || !f.hold(f.open, from, perSourceConns) {
			c.Close()
			continue
		}
		select {
		case f.conns <- struct{}{}:
		default:
			f.release(f.open, from)
			c.Close()
			continue
		}
		f.workers.Add(1)
		go func() {
			defer f.workers.Done()
			defer f.release(f.open, from)
			defer func() { <-f.conns }()
			defer c.Close()
			f.serveConn(c, src.Addr())
		}()
	}
}

// serveConn answers one TCP connection's queries in turn, until it idles.
func (f *Forwarder) serveConn(c net.Conn, src netip.Addr) {
	stop := context.AfterFunc(f.ctx, func() { c.Close() })
	defer stop()
	r := bufio.NewReader(c)
	for {
		c.SetReadDeadline(time.Now().Add(tcpIdle))
		q, err := readTCPMessage(r)
		if err != nil || !isQuery(q) || !f.admit(src) {
			return
		}
		resp := f.answer(q)
		if resp == nil {
			if resp, err = f.ask("tcp", q); err != nil {
				return
			}
		}
		c.SetWriteDeadline(time.Now().Add(queryTimeout))
		if _, err := c.Write(tcpMessage(resp)); err != nil {
			return
		}
	}
}

// answer is the forwarder's own response to q, nil where it has none.
func (f *Forwarder) answer(q []byte) []byte {
	if f.opts.Answer == nil {
		return nil
	}
	return f.opts.Answer(q)
}

// Port is the port the forwarder answers on, as bound where Options.Port
// was zero.
func (f *Forwarder) Port() uint16 {
	if len(f.udp) == 0 {
		return 0
	}
	return uint16(f.udp[0].LocalAddr().(*net.UDPAddr).Port)
}

// ask puts q to the host's resolvers in turn, over network, and returns the
// first answer that is not a failure of the resolver itself (SERVFAIL or
// REFUSED), else the last answer or error.
func (f *Forwarder) ask(network string, q []byte) ([]byte, error) {
	var last error = errors.New("dnsfwd: no resolver on this host")
	var failed []byte
	var ups []netip.AddrPort
	if f.opts.UpstreamFor != nil {
		ups = f.opts.UpstreamFor(q)
	}
	if ups == nil {
		ups = f.opts.Upstream()
	}
	for _, up := range ups {
		resp, err := exchange(network, up, q)
		switch {
		case err != nil:
			last = err
		case resp[3]&0x0f == 2 || resp[3]&0x0f == 5:
			failed = resp
		default:
			capTTL(resp, f.opts.MaxTTL)
			return resp, nil
		}
	}
	if failed != nil {
		capTTL(failed, f.opts.MaxTTL)
		return failed, nil
	}
	return nil, last
}

// capTTL lowers every TTL in msg above max to max, in place, but an OPT
// record's, whose TTL holds flags; zero caps none. It stops where msg does
// not parse.
func capTTL(msg []byte, max uint32) {
	if max == 0 || len(msg) < headerLen {
		return
	}
	off := headerLen
	for range binary.BigEndian.Uint16(msg[4:]) {
		if off = skipName(msg, off); off < 0 || off+4 > len(msg) {
			return
		}
		off += 4
	}
	records := int(binary.BigEndian.Uint16(msg[6:])) + int(binary.BigEndian.Uint16(msg[8:])) + int(binary.BigEndian.Uint16(msg[10:]))
	for range records {
		if off = skipName(msg, off); off < 0 || off+10 > len(msg) {
			return
		}
		if typ, ttl := binary.BigEndian.Uint16(msg[off:]), binary.BigEndian.Uint32(msg[off+4:]); typ != typeOPT && ttl > max {
			binary.BigEndian.PutUint32(msg[off+4:], max)
		}
		off += 10 + int(binary.BigEndian.Uint16(msg[off+8:]))
	}
}

const typeOPT = 41

// skipName is the offset past the name at off in msg, -1 where there is none.
func skipName(msg []byte, off int) int {
	for off < len(msg) {
		switch l := int(msg[off]); {
		case l == 0:
			return off + 1
		case l&0xc0 == 0xc0:
			return off + 2
		case l&0xc0 != 0:
			return -1
		default:
			off += 1 + l
		}
	}
	return -1
}

func exchange(network string, up netip.AddrPort, q []byte) ([]byte, error) {
	c, err := net.DialTimeout(network, up.String(), queryTimeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(queryTimeout))
	if network == "tcp" {
		if _, err := c.Write(tcpMessage(q)); err != nil {
			return nil, err
		}
		resp, err := readTCPMessage(bufio.NewReader(c))
		if err != nil || !answers(resp, q) {
			return nil, cmpErr(err, "dnsfwd: an answer to another question")
		}
		return resp, nil
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, maxMessage)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// A stray datagram for another query is no answer to this one.
		if answers(buf[:n], q) {
			return bytes.Clone(buf[:n]), nil
		}
	}
}

func cmpErr(err error, s string) error {
	if err != nil {
		return err
	}
	return errors.New(s)
}

// answers reports whether resp is a response to q: its ID, with the
// response bit set.
func answers(resp, q []byte) bool {
	return len(resp) >= headerLen && resp[0] == q[0] && resp[1] == q[1] && resp[2]&0x80 != 0
}

func readTCPMessage(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func tcpMessage(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// HostResolvers is the resolvers the host asks, as /etc/resolv.conf names
// them, resolved's stub among them, which then applies the host's own DNS
// routing, DNS-over-TLS and DNSSEC. Port 53 throughout.
func HostResolvers() []netip.AddrPort { return ResolversIn(ResolvConf) }

// ResolversIn is the resolvers the resolv.conf at path names, port 53.
func ResolversIn(path string) []netip.AddrPort {
	servers := nameservers(path)
	out := make([]netip.AddrPort, len(servers))
	for i, s := range servers {
		out[i] = netip.AddrPortFrom(s, 53)
	}
	return out
}

func nameservers(path string) []netip.Addr {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

// control binds a listener to device, where one is named, and lets it bind
// an overlay address the device does not hold yet, as IPv6 before its
// duplicate address detection ends.
func control(device string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return bindTo(c, device)
	}
}
