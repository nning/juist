// Package dnsfwd answers DNS queries for a network's members on an exit node:
// on the node's overlay addresses alone, and by asking the host's own
// resolvers, so that a member's lookups leave from the exit node as its
// traffic does.
package dnsfwd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	"github.com/nning/juist/internal/admit"
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
	maxSources        = 4096
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

	// Listen, where set, binds each address in its place, as a helper
	// binds a port the forwarder may not, or a stack in this process holds
	// it; Device does not apply to it. Its datagrams' addresses are
	// [net.UDPAddr]s.
	Listen func(netip.AddrPort) (net.PacketConn, net.Listener, error)

	// Dial, where set, opens a connection to a resolver upstream in place of
	// [net.Dialer], over network, udp or tcp.
	Dial func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error)

	// MaxUDP, where set, is the longest answer sent over UDP, as a stack that
	// fragments nothing carries; a longer one is sent truncated, for the
	// asker to ask again over TCP.
	MaxUDP int

	// FailFast answers SERVFAIL a query no resolver upstream answered, at
	// once where none could be asked, rather than leaving the asker to time
	// out.
	FailFast bool

	// Allowed says whether a source may ask: the network's overlay.
	Allowed func(netip.Addr) bool

	// Upstream is the resolvers asked, read from the host where nil. One on
	// [TLSPort] is asked by DNS over TLS.
	Upstream func() []netip.AddrPort

	// UpstreamFor, where set, is the resolvers asked for query instead, nil
	// for Upstream's; empty, it is asked of none. An error answers SERVFAIL,
	// a [Refusal] its RCode.
	UpstreamFor func(query []byte) ([]netip.AddrPort, error)

	// Answer, where set, answers a query itself, nil passing it upstream.
	Answer func(query []byte) []byte

	// MaxTTL, where set, caps the TTL of every record an answer from
	// upstream carries, in seconds; Capped, where set, the answers to the
	// queries it reports alone.
	MaxTTL uint32
	Capped func(query []byte) bool

	// Local has the host alone ask, its resolver as one source for all its
	// programs: no source is held to the limits on one.
	Local bool

	Logf func(format string, args ...any)
}

// A Forwarder answers until closed.
type Forwarder struct {
	opts     Options
	udp      []net.PacketConn
	tcp      []net.Listener
	inFlight chan struct{}
	conns    chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	// tlsConf resumes sessions with resolvers over TLS, and tlsFailed is
	// when each last failed, which is then asked in plain text alone until
	// tlsBackoff passed.
	tlsConf   *tls.Config
	tlsFailed sync.Map // netip.AddrPort → time.Time

	limits  *admit.Rates[netip.Addr]
	busy    *admit.Set[netip.Addr] // queries in flight per source
	open    *admit.Set[netip.Addr] // TCP connections per source
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
		limits: admit.NewRates[netip.Addr](perSourceQPS, perSourceMax, maxSources)}
	perQueries, perConns := perSourceInFlight, perSourceConns
	if opts.Local {
		perQueries, perConns = maxInFlight, maxInFlight
	}
	f.busy, f.open = admit.New[netip.Addr](admit.Limits{PerSource: perQueries}), admit.New[netip.Addr](admit.Limits{PerSource: perConns})
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.tlsConf = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(maxTLSSessions)}
	lc := net.ListenConfig{Control: control(opts.Device)}
	for _, a := range opts.Addrs {
		ap := netip.AddrPortFrom(a, opts.Port)
		if opts.Listen != nil {
			pc, ln, err := opts.Listen(ap)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("dnsfwd: %w", err)
			}
			f.udp, f.tcp = append(f.udp, pc), append(f.tcp, ln)
			continue
		}
		pc, err := lc.ListenPacket(context.Background(), "udp", ap.String())
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("dnsfwd: %w", err)
		}
		f.udp = append(f.udp, pc)
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

// failedRetry is how long a listener that failed waits before it reads
// again: one failing for good, as a stack's whose device is gone, would
// otherwise spin.
const failedRetry = 50 * time.Millisecond

// pause waits failedRetry, and reports whether the forwarder still runs.
func (f *Forwarder) pause() bool {
	select {
	case <-f.ctx.Done():
		return false
	case <-time.After(failedRetry):
		return true
	}
}

// admit reports whether src may ask now.
func (f *Forwarder) admit(src netip.Addr) bool {
	src = src.Unmap()
	if f.opts.Allowed != nil && !f.opts.Allowed(src) {
		return false
	}
	return f.opts.Local || f.limits.Allow(src)
}

// isQuery reports whether msg is a DNS query worth asking about: a standard
// query (opcode 0, response bit clear) with a question, at least the root's
// name, type and class. An update or a notify is not passed on.
func isQuery(msg []byte) bool {
	return len(msg) >= headerLen+5 && msg[2]&0xf8 == 0 && binary.BigEndian.Uint16(msg[4:6]) > 0
}

func (f *Forwarder) serveUDP(c net.PacketConn) {
	defer f.workers.Done()
	buf := make([]byte, maxMessage)
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || !f.pause() {
				return
			}
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		src := ua.AddrPort()
		from := src.Addr().Unmap()
		if !isQuery(buf[:n]) || !f.admit(from) {
			continue
		}
		if resp := f.answer(buf[:n]); resp != nil {
			c.WriteTo(f.fitUDP(resp), ua)
			continue
		}
		slot, ok := f.busy.Admit(from, nil)
		if !ok {
			continue
		}
		select {
		case f.inFlight <- struct{}{}:
		default:
			slot.Release()
			continue // too much under way: the member asks again
		}
		q := bytes.Clone(buf[:n])
		f.workers.Add(1)
		go func() {
			defer f.workers.Done()
			defer slot.Release()
			defer func() { <-f.inFlight }()
			if resp, err := f.ask("udp", q); err == nil {
				c.WriteTo(f.fitUDP(resp), ua)
			}
		}()
	}
}

func (f *Forwarder) serveTCP(ln net.Listener) {
	defer f.workers.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || !f.pause() {
				return
			}
			continue
		}
		src, _ := netip.ParseAddrPort(c.RemoteAddr().String())
		from := src.Addr().Unmap()
		if f.opts.Allowed != nil && !f.opts.Allowed(from) {
			c.Close()
			continue
		}
		slot, ok := f.open.Admit(from, nil)
		if !ok {
			c.Close()
			continue
		}
		select {
		case f.conns <- struct{}{}:
		default:
			slot.Release()
			c.Close()
			continue
		}
		f.workers.Add(1)
		go func() {
			defer f.workers.Done()
			defer slot.Release()
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
	ua, _ := f.udp[0].LocalAddr().(*net.UDPAddr)
	if ua == nil {
		return 0
	}
	return uint16(ua.Port)
}

// ask puts q to the host's resolvers in turn, over network, and returns the
// first answer that is not a failure of the resolver itself (SERVFAIL or
// REFUSED), else the last answer, or the last error, which FailFast answers
// SERVFAIL.
func (f *Forwarder) ask(network string, q []byte) ([]byte, error) {
	resp, err := f.askUpstream(network, q)
	if err != nil && f.opts.FailFast {
		return failure(q, RCodeServFail), nil
	}
	return resp, err
}

func (f *Forwarder) askUpstream(network string, q []byte) ([]byte, error) {
	var last error = errors.New("dnsfwd: no resolver on this host")
	var failed []byte
	var ups []netip.AddrPort
	if f.opts.UpstreamFor != nil {
		var err error
		if ups, err = f.opts.UpstreamFor(q); err != nil {
			rcode := uint8(RCodeServFail)
			if r := (*Refusal)(nil); errors.As(err, &r) {
				rcode = r.RCode
			}
			return failure(q, rcode), nil
		}
	}
	if ups == nil {
		ups = f.opts.Upstream()
	}
	for _, up := range ups {
		if up.Port() == TLSPort && f.tlsFailedLately(up) {
			continue
		}
		resp, err := f.exchange(network, up, q)
		if err != nil && up.Port() == TLSPort {
			f.tlsFailed.Store(up, time.Now())
		}
		switch {
		case err != nil:
			last = err
		case resp[3]&0x0f == 2 || resp[3]&0x0f == 5:
			failed = resp
		default:
			capTTL(resp, f.maxTTL(q))
			return resp, nil
		}
	}
	if failed != nil {
		capTTL(failed, f.maxTTL(q))
		return failed, nil
	}
	return nil, last
}

// maxTTL is the cap on the TTLs of an answer to q, zero for none.
func (f *Forwarder) maxTTL(q []byte) uint32 {
	if f.opts.Capped != nil && !f.opts.Capped(q) {
		return 0
	}
	return f.opts.MaxTTL
}

// RCodes a refused query is answered; a [Refusal] names one.
const (
	RCodeFormErr  = 1
	RCodeServFail = 2
	RCodeNXDomain = 3
	RCodeRefused  = 5
)

// A Refusal answers a query RCode, asking no one.
type Refusal struct {
	RCode uint8
	Err   error
}

func (r *Refusal) Error() string { return r.Err.Error() }
func (r *Refusal) Unwrap() error { return r.Err }

// fitUDP is resp, truncated to its question with TC set where it is longer
// than MaxUDP.
func (f *Forwarder) fitUDP(resp []byte) []byte {
	if f.opts.MaxUDP == 0 || len(resp) <= f.opts.MaxUDP || len(resp) < headerLen {
		return resp
	}
	end := headerLen
	if binary.BigEndian.Uint16(resp[4:]) == 1 {
		if off := skipName(resp, headerLen); off >= 0 && off+4 <= len(resp) {
			end = off + 4
		}
	}
	out := bytes.Clone(resp[:end])
	out[2] |= 0x02 // TC
	clear(out[4:headerLen])
	if end > headerLen {
		out[5] = 1
	}
	return out
}

// failure is a response to q with rcode, and q's question.
func failure(q []byte, rcode uint8) []byte {
	end := headerLen
	if binary.BigEndian.Uint16(q[4:]) == 1 {
		if off := skipName(q, headerLen); off >= 0 && off+4 <= len(q) {
			end = off + 4
		}
	}
	resp := make([]byte, end)
	copy(resp, q[:4])
	resp[2] = 0x80 | q[2]&0x79  // QR; opcode and RD as asked
	resp[3] = 0x80 | rcode&0x0f // RA
	if end > headerLen {
		resp[5] = 1
		copy(resp[headerLen:], q[headerLen:end])
	}
	return resp
}

// capTTL lowers every TTL in msg above max to max, in place, but an
// additional OPT record's, whose TTL holds flags; zero caps none. It stops
// where msg does not parse.
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
	answers := int(binary.BigEndian.Uint16(msg[6:])) + int(binary.BigEndian.Uint16(msg[8:]))
	records := answers + int(binary.BigEndian.Uint16(msg[10:]))
	for i := range records {
		if off = skipName(msg, off); off < 0 || off+10 > len(msg) {
			return
		}
		opt := i >= answers && binary.BigEndian.Uint16(msg[off:]) == typeOPT
		if ttl := binary.BigEndian.Uint32(msg[off+4:]); !opt && ttl > max {
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

// TLSPort is where a resolver upstream answers DNS over TLS. It is asked
// opportunistically, its certificate unchecked, as Android's automatic
// Private DNS asks a network's resolver: encrypted against those who only
// listen.
const TLSPort = 853

// tlsBackoff is how long a resolver whose TLS failed is asked in plain text
// alone, and maxTLSSessions how many resolvers' sessions are kept to resume.
const (
	tlsBackoff     = 10 * time.Minute
	maxTLSSessions = 8
)

// tlsFailedLately reports whether up's TLS failed within tlsBackoff.
func (f *Forwarder) tlsFailedLately(up netip.AddrPort) bool {
	at, ok := f.tlsFailed.Load(up)
	return ok && time.Since(at.(time.Time)) < tlsBackoff
}

func (f *Forwarder) exchange(network string, up netip.AddrPort, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(f.ctx, queryTimeout)
	defer cancel()
	overTLS := up.Port() == TLSPort
	if overTLS {
		network = "tcp"
	}
	var c net.Conn
	var err error
	if f.opts.Dial != nil {
		c, err = f.opts.Dial(ctx, network, up)
	} else {
		var d net.Dialer
		c, err = d.DialContext(ctx, network, up.String())
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(queryTimeout))
	if overTLS {
		tc := tls.Client(c, f.tlsConf)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		c = tc
	}
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
