// Package mdns is blinded LAN discovery: it lets members of one juist network
// find each other on a local network with no internet and no rendezvous
// service. Nothing here is trust-critical — a beacon carries a signed
// [gossip.Endpoint] saying where a node is, and membership is decided by the
// log — so a hostile responder can at worst waste a dial.
//
// The name a member queries for is a keyed derivation of the epoch group
// secret ([secrets.Secret.MDNSName]) and the payload is sealed under the same
// secret, so an observer learns that juist is in use and nothing more, and a
// revoked device cannot compute the name at the next epoch.
//
// The exchange is ordinary multicast DNS: a TXT query at the blinded name,
// answered by every member that recognizes it, plus announcements on a timer.
// There is no PTR browsing and no SRV or A record — only a holder of the
// secret can construct a name that means anything, and the payload carries the
// port.
package mdns

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/trust/secrets"
)

// The multicast endpoint. IPv4 only: the IPv6 group (ff02::fb) needs
// per-interface join handling that is not written yet.
var (
	// Group is the mDNS multicast endpoint beacons are sent to.
	Group = netip.AddrPortFrom(netip.MustParseAddr("224.0.0.251"), 5353)
)

// Service is the DNS-SD service the blinded label sits under, and the one part
// of the exchange that is not blinded: a label with no service suffix would be
// a malformed name.
const Service = "_juist._udp.local."

// TTL on an announcement, in seconds. Short, because what it advertises — a
// node's current underlay address — is exactly the thing that changes when a
// laptop moves between networks.
const ttl = 120

// DefaultInterval is how often a node announces itself unsolicited. Aggressive
// for mDNS, because a node that has just joined must be found inside the
// five-second convergence budget; the cost is a few hundred bytes per node.
const DefaultInterval = 2 * time.Second

// maxMessageSize bounds a received datagram. 1232 is the conventional mDNS
// payload ceiling (1280-byte IPv6 MTU less headers); anything larger is either
// not for us or not worth reassembling.
const maxMessageSize = 1232

// minAnswerInterval is the least time between two multicast transmissions of
// this node's record under one name, as RFC 6762 §6 requires. It also stops an
// amplifier: the name is public on the wire, so anyone can replay a question
// at it, and name compression fits hundreds of copies in one datagram.
const minAnswerInterval = time.Second

// A PacketConn is the datagram socket beacons travel over. It exists so that
// tests can substitute a plain loopback fan-out for a multicast group, which
// CI machines do not reliably provide.
type PacketConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
	Close() error
}

// Options configures a [Beacon].
type Options struct {
	// Keyring holds the epoch secrets. Every epoch in it yields a name this
	// node answers to, which is what keeps discovery working across the
	// window where members are one epoch apart.
	Keyring *keyring.Keyring

	// Announce returns this node's current announcement, or false if it has
	// none yet.
	Announce func() (gossip.Endpoint, bool)

	// OnPeer receives each verified announcement learned from the LAN. It
	// runs on the beacon's read goroutine, so it must not block for long.
	OnPeer func(gossip.Endpoint)

	// NeedsPeers reports whether this node is still looking for members it has
	// not heard from. Nil means "always", which is correct and noisy: every
	// query is answered by every member, so asking unconditionally makes LAN
	// traffic quadratic in the member count.
	NeedsPeers func() bool

	// Interval is the unsolicited announcement period. Zero uses
	// [DefaultInterval].
	Interval time.Duration

	// Conn is the datagram socket. Nil opens the real multicast socket.
	Conn PacketConn

	// Dst is where announcements are sent. Zero uses [Group].
	Dst netip.AddrPort

	// SkipInterface is an interface discovery must never join or send on, in
	// practice the overlay's TUN device: discovery is an underlay function,
	// and a Linux TUN carries IFF_MULTICAST so it joins otherwise. The
	// devices of the host's juist instances (juist0 to juist9) are skipped
	// whatever it says.
	SkipInterface string

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// A Beacon announces this node on the LAN and reports the members it hears.
type Beacon struct {
	opts     Options
	conn     PacketConn
	dst      *net.UDPAddr
	interval time.Duration
	logf     func(string, ...any)

	// closing guards the wait set: a sync.WaitGroup forbids an Add that
	// takes the counter off zero from racing a Wait, which is what starting
	// the read loop while Close drains would be.
	closeOnce sync.Once
	closed    chan struct{}
	trackMu   sync.Mutex
	closing   bool
	wg        sync.WaitGroup

	// mu guards the two maps below, both keyed by epoch. nameCache holds
	// derived rendezvous names, so the keyed HKDF does not run per datagram —
	// the group carries every other service on the LAN. lastSent enforces
	// [minAnswerInterval].
	mu        sync.Mutex
	nameCache map[uint64]cachedName
	lastSent  map[uint64]time.Time
}

// A cachedName is one epoch's derived rendezvous name, remembered together
// with the secret it came from so that a replaced secret invalidates it.
type cachedName struct {
	secret secrets.Secret
	name   blindedName
}

// New opens a beacon. The caller runs [Beacon.Run].
func New(opts Options) (*Beacon, error) {
	if opts.Keyring == nil {
		return nil, errors.New("mdns: Keyring is required")
	}
	dst := opts.Dst
	if !dst.IsValid() {
		dst = Group
	}
	b := &Beacon{
		opts:      opts,
		conn:      opts.Conn,
		dst:       net.UDPAddrFromAddrPort(dst),
		interval:  opts.Interval,
		logf:      opts.Logf,
		closed:    make(chan struct{}),
		nameCache: map[uint64]cachedName{},
		lastSent:  map[uint64]time.Time{},
	}
	if b.interval == 0 {
		b.interval = DefaultInterval
	}
	if b.logf == nil {
		b.logf = func(string, ...any) {}
	}
	if b.conn == nil {
		c, err := listenMulticast(dst, opts.SkipInterface)
		if err != nil {
			return nil, err
		}
		b.conn = c
	}
	return b, nil
}

// listenMulticast opens the mDNS socket and joins the group on every interface
// that can carry it.
//
// Not net.ListenMulticastUDP: that binds the socket to the group address, so
// datagrams leave with a multicast source and the kernel drops them silently.
// Joining nowhere is an error — losing discovery looks like every peer being
// offline.
func listenMulticast(group netip.AddrPort, skipIface string) (PacketConn, error) {
	lc := net.ListenConfig{Control: reuseAddr}
	pc, err := lc.ListenPacket(context.Background(), "udp4",
		net.JoinHostPort("", strconv.Itoa(int(group.Port()))))
	if err != nil {
		return nil, fmt.Errorf("mdns: listening on port %d: %w", group.Port(), err)
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("mdns: expected a UDP socket, got %T", pc)
	}
	p := ipv4.NewPacketConn(uc)
	// Loopback on, so two members on one host can see each other. TTL 255 is
	// what RFC 6762 requires of link-local mDNS.
	_ = p.SetMulticastLoopback(true)
	_ = p.SetMulticastTTL(255)

	c := &groupConn{
		UDPConn:   uc,
		p:         p,
		group:     &net.UDPAddr{IP: group.Addr().AsSlice()},
		skipIface: skipIface,
	}
	if c.rejoin() == 0 {
		uc.Close()
		return nil, fmt.Errorf(
			"mdns: no interface can carry multicast, so members cannot be found on the LAN; " +
				"run with LAN discovery off if that is intended")
	}
	return c, nil
}

// groupConn writes each datagram out of every interface it joined on. A
// wildcard-bound socket would send out only one, chosen by the route table,
// which on a multi-homed host is not necessarily where the members are.
type groupConn struct {
	*net.UDPConn
	p     *ipv4.PacketConn
	group *net.UDPAddr

	// skipIface is [Options.SkipInterface]: never joined, never sent on.
	skipIface string

	// mu guards ifaces and serializes writers with each other and with rejoin:
	// the multicast egress interface is per-socket state, so two goroutines
	// doing set-interface-then-send would race.
	mu     sync.Mutex
	ifaces []net.Interface
}

// rejoin joins the group on every usable interface and refreshes the send
// list, reporting how many qualified. It runs periodically because an
// interface appearing later would otherwise never carry discovery; re-joining
// returns EADDRINUSE, which is what makes it idempotent.
func (c *groupConn) rejoin() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	var joined []net.Interface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		// Nor the host's other juist instances' devices: each leads into
		// another network's tunnel, which drops multicast anyway.
		if c.skipIface != "" && ifi.Name == c.skipIface || instance.IsDevice(ifi.Name) {
			continue
		}
		if err := c.p.JoinGroup(&ifi, c.group); err != nil && !errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		joined = append(joined, ifi)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ifaces = joined
	return len(joined)
}

func (c *groupConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var firstErr error
	sent := 0
	for i := range c.ifaces {
		if err := c.p.SetMulticastInterface(&c.ifaces[i]); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n, err := c.UDPConn.WriteTo(b, addr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sent = n
	}
	if sent == 0 && firstErr != nil {
		return 0, firstErr
	}
	return sent, nil
}

// Run serves the beacon until [Beacon.Close]: it reads the group, answers
// queries for a name it recognizes, and announces itself on a timer.
func (b *Beacon) Run(ctx context.Context) {
	b.trackMu.Lock()
	if b.closing {
		b.trackMu.Unlock()
		return
	}
	b.wg.Add(1)
	b.trackMu.Unlock()
	go func() {
		defer b.wg.Done()
		b.readLoop()
	}()

	// One query straight away, so that a node joining an established LAN is
	// answered rather than waiting a full interval for others to announce.
	b.Query()
	t := time.NewTicker(b.interval)
	defer t.Stop()
	lastRejoin := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.closed:
			return
		case <-t.C:
			// So an interface that appeared since startup starts carrying
			// discovery. Tests substitute a conn with none to rejoin.
			if gc, ok := b.conn.(*groupConn); ok && time.Since(lastRejoin) >= rejoinInterval {
				lastRejoin = time.Now()
				gc.rejoin()
			}
			// Both, every interval. A node announces under its newest name
			// only, so a member an epoch behind never hears it, while a
			// query names every epoch the asker holds; and a node that just
			// arrived should not wait for someone else's question.
			b.Announce()
			if b.opts.NeedsPeers == nil || b.opts.NeedsPeers() {
				b.Query()
			}
		}
	}
}

// Close stops the beacon.
func (b *Beacon) Close() error {
	b.closeOnce.Do(func() {
		b.trackMu.Lock()
		b.closing = true
		b.trackMu.Unlock()
		close(b.closed)
		b.conn.Close()
	})
	b.wg.Wait()
	return nil
}

// Query multicasts a question for every name this node currently recognizes.
func (b *Beacon) Query() {
	names := b.names()
	if len(names) == 0 {
		return
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: false},
	}
	for _, n := range names {
		msg.Questions = append(msg.Questions, dnsmessage.Question{
			Name:  n.dns,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		})
	}
	raw, err := msg.Pack()
	if err != nil {
		b.logf("mdns: packing a query: %v", err)
		return
	}
	b.send(raw)
}

// rejoinInterval is how often [Beacon.Run] refreshes the multicast group
// membership. Slow, since each refresh is an interface walk plus a join.
const rejoinInterval = 10 * time.Second

// Announce multicasts this node's own record, unsolicited, under its newest
// name.
func (b *Beacon) Announce() {
	names := b.names()
	if len(names) == 0 {
		return
	}
	newest := names[0]
	if !b.allowSend(newest.epoch) {
		return
	}
	raw, err := b.answerFor(newest)
	if err != nil {
		b.logf("mdns: building an announcement: %v", err)
		return
	}
	if raw != nil {
		b.send(raw)
	}
}

// allowSend reports whether this node may multicast its record under an
// epoch's name now, and reserves the slot if so. One gate for answers and
// announcements: [minAnswerInterval] is a property of the name.
func (b *Beacon) allowSend(epoch uint64) bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if last, ok := b.lastSent[epoch]; ok && now.Sub(last) < minAnswerInterval {
		return false
	}
	b.lastSent[epoch] = now
	return true
}

func (b *Beacon) send(raw []byte) {
	if _, err := b.conn.WriteTo(raw, b.dst); err != nil {
		select {
		case <-b.closed:
		default:
			b.logf("mdns: sending to %v: %v", b.dst, err)
		}
	}
}

func (b *Beacon) readLoop() {
	buf := make([]byte, maxMessageSize)
	for {
		n, _, err := b.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-b.closed:
				return
			default:
			}
			b.logf("mdns: read: %v", err)
			// Almost always fatal for this socket; back off rather than
			// spin, so a broken socket does not burn a core.
			select {
			case <-b.closed:
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		b.handle(buf[:n])
	}
}

// handle processes one datagram: answers what it can, and takes what it is
// told. Every parse failure is a silent drop, since most of what the group
// carries is other services' traffic.
func (b *Beacon) handle(raw []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		return
	}
	names := b.names()

	for {
		q, err := p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return
		}
		if q.Type != dnsmessage.TypeTXT {
			continue
		}
		for _, n := range names {
			if !strings.EqualFold(q.Name.String(), n.dns.String()) {
				continue
			}
			// The rate gate comes before the answer is built, not after:
			// sealing costs real work, and a flood of questions must be
			// cheap to ignore, not merely unanswered.
			if !b.allowSend(n.epoch) {
				break
			}
			// Answer under the epoch that was asked for, not under ours, so
			// that a member one epoch behind can read the reply.
			reply, err := b.answerFor(n)
			if err != nil {
				b.logf("mdns: answering: %v", err)
			} else if reply != nil {
				b.send(reply)
			}
			break
		}
	}

	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return
		}
		if err != nil {
			return
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return
		}
		var epoch uint64
		matched := false
		for _, n := range names {
			if strings.EqualFold(h.Name.String(), n.dns.String()) {
				epoch, matched = n.epoch, true
				break
			}
		}
		if !matched {
			continue
		}
		ep, err := b.openAnnouncement(epoch, txt.TXT)
		if err != nil {
			// Silent: the name is public on the wire, so a log line per
			// datagram is a flood any bystander could trigger. Nothing
			// legitimate produces this — a member that can construct the
			// name holds the key that opens the payload.
			continue
		}
		if b.opts.OnPeer != nil {
			b.opts.OnPeer(ep)
		}
	}
}

// answerFor builds a TXT answer carrying this node's announcement, sealed
// under the epoch the given name belongs to. It returns nil when this node has
// nothing to announce yet.
func (b *Beacon) answerFor(n blindedName) ([]byte, error) {
	if b.opts.Announce == nil {
		return nil, nil
	}
	ep, ok := b.opts.Announce()
	if !ok {
		return nil, nil
	}
	body, err := ep.Encode()
	if err != nil {
		return nil, err
	}
	s, ok := b.opts.Keyring.Secret(n.epoch)
	if !ok {
		return nil, nil
	}
	sealed, err := sealPayload(s, n.epoch, body)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  n.dns,
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   ttl,
			},
			Body: &dnsmessage.TXTResource{TXT: chunk(base64.RawStdEncoding.EncodeToString(sealed))},
		}},
	}
	return msg.Pack()
}

// openAnnouncement reverses answerFor: it reassembles the TXT strings, opens
// the seal, and verifies the announcement's own signature.
func (b *Beacon) openAnnouncement(epoch uint64, txt []string) (gossip.Endpoint, error) {
	s, ok := b.opts.Keyring.Secret(epoch)
	if !ok {
		return gossip.Endpoint{}, fmt.Errorf("mdns: no secret for epoch %d", epoch)
	}
	sealed, err := base64.RawStdEncoding.DecodeString(strings.Join(txt, ""))
	if err != nil {
		return gossip.Endpoint{}, fmt.Errorf("mdns: decoding an announcement: %w", err)
	}
	body, err := openPayload(s, epoch, sealed)
	if err != nil {
		return gossip.Endpoint{}, err
	}
	// DecodeEndpoint verifies the signature, so what comes back is a
	// statement by the node it names and by nobody else.
	return gossip.DecodeEndpoint(body)
}

// sealPayload and openPayload wrap an announcement in the shared sealed-blob
// format under [secrets.Secret.DiscoveryKey] — a different key from the one
// gossip frames use, so an announcement cannot be replayed as a frame.
func sealPayload(s secrets.Secret, epoch uint64, body []byte) ([]byte, error) {
	key := s.DiscoveryKey(epoch)
	return aead.Seal(key, epoch, body)
}

func openPayload(s secrets.Secret, epoch uint64, sealed []byte) ([]byte, error) {
	// The epoch is chosen by the name the announcement arrived under, and it
	// is also the blob's additional data, so a blob relabelled to a different
	// epoch fails to authenticate rather than being opened with the wrong key.
	got, err := aead.Epoch(sealed)
	if err != nil {
		return nil, fmt.Errorf("mdns: %w", err)
	}
	if got != epoch {
		return nil, fmt.Errorf("mdns: announcement at the epoch-%d name is sealed under epoch %d",
			epoch, got)
	}
	key := s.DiscoveryKey(epoch)
	pt, err := aead.Open(key, sealed)
	if err != nil {
		return nil, fmt.Errorf("mdns: %w", err)
	}
	return pt, nil
}

// txtStringMax is the largest a single DNS TXT string may be.
const txtStringMax = 255

func chunk(s string) []string {
	var out []string
	for len(s) > txtStringMax {
		out = append(out, s[:txtStringMax])
		s = s[txtStringMax:]
	}
	return append(out, s)
}

// A blindedName is one epoch's rendezvous name.
type blindedName struct {
	epoch uint64
	dns   dnsmessage.Name
}

// nameEncoding is lowercase base32 without padding: DNS labels are
// case-insensitive and limited to 63 bytes, and 20 blinded bytes come to 32
// characters.
var nameEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func name(s secrets.Secret, epoch uint64) blindedName {
	label := nameEncoding.EncodeToString(s.MDNSName(epoch))
	// MustNewName is safe here: the label is fixed-length base32 and the
	// suffix is a constant, so the result is always a legal name.
	return blindedName{epoch: epoch, dns: dnsmessage.MustNewName(label + "." + Service)}
}

// names returns the rendezvous name for every epoch this node holds a secret
// for, newest first. Answering to more than the current epoch keeps discovery
// alive across a bump, when members are an epoch apart. Names are cached per
// epoch, since this runs on every datagram the group delivers, and state for
// dropped epochs is pruned here.
func (b *Beacon) names() []blindedName {
	epochs := b.opts.Keyring.Epochs()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]blindedName, 0, len(epochs))
	current := make(map[uint64]bool, len(epochs))
	for i := len(epochs) - 1; i >= 0; i-- {
		epoch := epochs[i]
		s, ok := b.opts.Keyring.Secret(epoch)
		if !ok {
			continue
		}
		// The secret is part of the cache key, not just the epoch: resolving
		// onto a different chain replaces a secret at the same epoch.
		c, held := b.nameCache[epoch]
		if !held || !c.secret.Equal(s) {
			c = cachedName{secret: s, name: name(s, epoch)}
			b.nameCache[epoch] = c
		}
		current[epoch] = true
		out = append(out, c.name)
	}
	for epoch := range b.nameCache {
		if !current[epoch] {
			delete(b.nameCache, epoch)
			delete(b.lastSent, epoch)
		}
	}
	return out
}
