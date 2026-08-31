// Package mdns is blinded LAN discovery: it lets members of one juist
// network find each other on a local network with no internet, no coordination
// server, and no rendezvous service of any kind.
//
// Nothing here is trust-critical. What a beacon carries is a
// [gossip.Endpoint], which is signed by the node it describes and says only
// where that node is; membership is decided by the log, several layers up.
// A hostile responder on the LAN can at worst waste a dial.
//
// # What "blinded" means
//
// The service name a member queries for is a keyed derivation of the epoch
// group secret ([secrets.Secret.MDNSName]), not a name. A LAN observer sees
// that *some* host is asking about *some* opaque 32-character label under
// `_juist._udp.local`, and can conclude that juist is in use — which
// docs/02-threat-model.md accepts as residual weakness 5 — but cannot tell
// which network, who is on it, or how many. The payload is sealed under the
// same secret, so even the announcement's contents are opaque.
//
// Two consequences follow from deriving the name from the group secret, and
// both are wanted. A revoked device stops being able to compute the name at
// the next epoch, so it cannot even ask the LAN where the network is — the
// discovery half of revocation (docs/research/building-blocks.md §5). And two
// juist networks sharing a coffee-shop LAN are mutually invisible rather than
// merely mutually incompatible.
//
// # Shape of the exchange
//
// Ordinary multicast DNS: a TXT query at the blinded name, answered with TXT
// records by every member that recognizes it, plus unsolicited announcements
// on a timer so that a node arriving on the LAN is found without anyone having
// to ask. There is no PTR browsing and no SRV or A record, because there is
// nothing to browse: only a holder of the group secret can construct the one
// name that means anything, and the sealed payload already carries the port.
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
	"github.com/nning/juist/trust/secrets"
)

// The multicast endpoint. IPv4 only at this milestone: a LAN that carries
// IPv4 multicast is the M2 target (docs/05-roadmap.md), and the IPv6 group
// (ff02::fb) needs per-interface join handling that lands with the netns
// harness in M3.
var (
	// Group is the mDNS multicast endpoint beacons are sent to.
	Group = netip.AddrPortFrom(netip.MustParseAddr("224.0.0.251"), 5353)
)

// Service is the DNS-SD service the blinded label sits under. It is the one
// part of the exchange that is not blinded, and it is deliberate: a label with
// no service suffix would be a malformed name, and hiding the fact that
// *something* is running buys nothing when the packets are on the wire either
// way.
const Service = "_juist._udp.local."

// TTL on an announcement, in seconds. Short, because what it advertises — a
// node's current underlay address — is exactly the thing that changes when a
// laptop moves between networks.
const ttl = 120

// DefaultInterval is how often a node announces itself unsolicited.
//
// Two seconds is aggressive for mDNS and right for this: docs/05-roadmap.md
// gives revocation five seconds to converge across a five-node mesh, and a
// node that has just joined the LAN has to be found inside that budget. The
// traffic is a few hundred bytes per node per interval.
const DefaultInterval = 2 * time.Second

// maxMessageSize bounds a received datagram. 1232 is the conventional mDNS
// payload ceiling (1280-byte IPv6 MTU less headers); anything larger is either
// not for us or not worth reassembling.
const maxMessageSize = 1232

// minAnswerInterval is the least time between two multicast transmissions of
// this node's record under one name, whether as an answer or as an unsolicited
// announcement. RFC 6762 §6 sets this floor for multicast responders, and here
// it carries security weight as well as etiquette: the blinded name is public
// on the wire — every answer and announcement carries it — so anyone on the
// LAN can replay a question at it without holding any secret, and DNS name
// compression fits a couple of hundred copies of one question into a single
// datagram. Without the floor, each copy would cost every member a multicast
// answer: a ~100x bandwidth amplifier aimed at the whole segment for the price
// of one small packet. With it, a member transmits under a name at most once a
// second no matter what arrives.
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
	Keyring *secrets.Keyring

	// Announce returns this node's current announcement, or false if it has
	// none yet.
	Announce func() (gossip.Endpoint, bool)

	// OnPeer receives each verified announcement learned from the LAN. It
	// runs on the beacon's read goroutine, so it must not block for long.
	OnPeer func(gossip.Endpoint)

	// NeedsPeers reports whether this node is still looking for members it
	// has not heard from. Nil means "always", which is correct and noisy.
	//
	// Every query is answered by every member that recognizes the name, so
	// querying unconditionally makes LAN traffic quadratic in the member
	// count — fine at the two-to-five nodes M2 targets, and not fine at the
	// twenty-five to a hundred the design does. Announcements alone are
	// linear and are what keeps a settled network in step; the question is
	// only needed by a node that is missing someone.
	NeedsPeers func() bool

	// Interval is the unsolicited announcement period. Zero uses
	// [DefaultInterval].
	Interval time.Duration

	// Conn is the datagram socket. Nil opens the real multicast socket.
	Conn PacketConn

	// Dst is where announcements are sent. Zero uses [Group].
	Dst netip.AddrPort

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

	// mu guards the two maps below, both keyed by epoch. nameCache holds the
	// derived rendezvous names: the derivation is keyed HKDF, and running it
	// per received datagram — the mDNS group carries every other service on
	// the LAN — would be a CPU tax anyone can levy by flooding the group.
	// lastSent enforces [minAnswerInterval].
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
		c, err := listenMulticast(dst)
		if err != nil {
			return nil, err
		}
		b.conn = c
	}
	return b, nil
}

// listenMulticast opens the mDNS socket and joins the group on every
// interface that can carry it.
//
// Not net.ListenMulticastUDP, which is the obvious call and the wrong one:
// it binds the socket to the *group* address, so a datagram sent from it
// carries a multicast source address and the kernel drops it. That failure is
// silent in both directions — the join succeeds, the reads work, and nothing
// ever arrives — which is exactly the shape of "my mesh does not form" with no
// error to point at. So the socket is bound to the wildcard address with
// SO_REUSEADDR (mDNS is a shared port; other responders on the host must keep
// working), and the group is joined explicitly per interface.
//
// Failure to join anywhere is reported rather than tolerated: a daemon that
// silently loses LAN discovery looks exactly like a daemon whose peers are all
// offline.
func listenMulticast(group netip.AddrPort) (PacketConn, error) {
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
	// Loopback on, so that two members on one host — which is what a test
	// bed and a first demo look like — can see each other. TTL 255 is what
	// RFC 6762 requires, so that a beacon is recognizably link-local mDNS
	// rather than something an intermediate device should forward.
	_ = p.SetMulticastLoopback(true)
	_ = p.SetMulticastTTL(255)

	c := &groupConn{UDPConn: uc, p: p, group: &net.UDPAddr{IP: group.Addr().AsSlice()}}
	if c.rejoin() == 0 {
		uc.Close()
		return nil, fmt.Errorf(
			"mdns: no interface can carry multicast, so members cannot be found on the LAN; " +
				"run with LAN discovery off if that is intended")
	}
	return c, nil
}

// groupConn writes each datagram out of every interface it joined on.
//
// A wildcard-bound socket sends multicast out one interface, chosen by the
// route table, which on a multi-homed host is not necessarily the one the
// other members are on. Looping is what makes "the members on my LAN" mean
// every LAN this host is attached to.
type groupConn struct {
	*net.UDPConn
	p     *ipv4.PacketConn
	group *net.UDPAddr

	// mu guards ifaces, and serializes writers with each other and with
	// rejoin. The serialization is not optional: the multicast egress
	// interface is per-socket state, so set-interface-then-send from two
	// goroutines at once — the ticker's announce and the read loop's answer —
	// would race, and datagrams would leave on whichever interface the other
	// goroutine chose last.
	mu     sync.Mutex
	ifaces []net.Interface
}

// rejoin joins the group on every interface that can carry it and refreshes
// the send list, reporting how many interfaces qualified.
//
// It runs at startup and then periodically from [Beacon.Run], because the
// interface set is not fixed: multicast membership is per interface, and one
// that appears after the daemon starts — Wi-Fi associating, a cable plugged
// in, a laptop arriving on a new network — would otherwise never carry
// discovery until a restart, even while the daemon's own announcements
// advertise the new interface's address. Joining a group the socket is
// already in fails with EADDRINUSE, which is what makes the call idempotent.
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
			// Refresh the group membership on a slow cadence, so an
			// interface that appeared since startup starts carrying
			// discovery; see [groupConn.rejoin]. Tests substitute a
			// fan-out conn, which has no interfaces to rejoin.
			if gc, ok := b.conn.(*groupConn); ok && time.Since(lastRejoin) >= rejoinInterval {
				lastRejoin = time.Now()
				gc.rejoin()
			}
			// Announce and ask, every interval. Announcing alone is not
			// enough: a node announces under its newest name only, so a
			// member that is an epoch behind would never hear it — while a
			// query names every epoch the asker holds, and is answered
			// under the one it asked about. Asking alone is not enough
			// either, since a node that has just arrived on the LAN should
			// not have to wait for someone else's question.
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
// membership. Slow next to the announce interval: interface changes are
// human-scale events, and each refresh is an interface walk plus a join
// syscall per interface.
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
// announcements both, because both transmit the same record under the same
// name and [minAnswerInterval] is a property of the name, not of why it was
// sent.
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
			// A read error that is not shutdown is almost always fatal for
			// this socket (it was closed underneath us, or the interface
			// went away). Backing off rather than spinning keeps a broken
			// socket from burning a core.
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
// told.
//
// Every parse failure is a silent drop. The mDNS group carries every other
// service on the LAN, so most of what arrives is not addressed to this code at
// all, and logging it would be noise rather than diagnostics.
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
			// Silent, like every other parse failure here. The name is
			// public on the wire, so anyone on the LAN can send rubbish at
			// it as fast as they like, and a log line per datagram would be
			// a log flood any bystander could trigger. Nothing legitimate
			// produces this either: the name is derived from the same secret
			// as the key, so a member that can construct the name can always
			// be opened.
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
// format, keyed by the epoch's discovery key.
//
// [secrets.Secret.DiscoveryKey] is the derivation whose documented purpose is
// exactly this — "the AEAD key protecting announcement payloads, so that a DHT
// storage node sees opaque bytes at an opaque key" — and a LAN beacon is the
// same statement to a different audience. It is a different key from the one
// gossip frames use, so a captured announcement can never be replayed as a
// frame or the reverse.
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
// for, newest first.
//
// Answering to more than the current epoch is what keeps discovery alive
// across a bump: for the length of a convergence round, members are one epoch
// apart and would otherwise be asking about names none of the others
// recognize.
//
// Names are derived once per epoch and cached, not once per call: this runs on
// every datagram the mDNS group delivers, most of which are other services'
// traffic, and the derivation is keyed HKDF. State for epochs the keyring has
// dropped is pruned here, which keeps both maps bounded by [secrets.KeyringDepth].
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
		// The secret is part of the cache check, not just the epoch: the
		// keyring replaces an epoch's secret when the node resolves onto a
		// different chain at the same epoch number, and the name has to
		// follow it.
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
