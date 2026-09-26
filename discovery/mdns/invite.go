package mdns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Invites are found on the LAN by their nameplate, the number a typed code
// starts with. Nothing here is secret or trusted: the nameplate is not the
// password, and a host found this way still has to prove it knows the code.
// A bystander learns that someone on the LAN is joining a juist network.

// InviteService is the DNS-SD service invite names sit under.
const InviteService = "_juist-invite._tcp.local."

// inviteQueryInterval is how often a guest repeats its question.
const inviteQueryInterval = 500 * time.Millisecond

func inviteName(nameplate uint16) (dnsmessage.Name, error) {
	return dnsmessage.NewName("n" + strconv.Itoa(int(nameplate)) + "." + InviteService)
}

// InviteOptions configures the invite exchange. The zero value uses the real
// multicast group.
type InviteOptions struct {
	// Conn replaces the multicast socket, for tests.
	Conn PacketConn

	// Dst is where queries and answers are sent. Zero uses [Group].
	Dst netip.AddrPort

	// SkipInterface is an interface never to send on; see
	// [Options.SkipInterface].
	SkipInterface string
}

func (o InviteOptions) open() (PacketConn, *net.UDPAddr, error) {
	dst := o.Dst
	if !dst.IsValid() {
		dst = Group
	}
	if o.Conn != nil {
		return o.Conn, net.UDPAddrFromAddrPort(dst), nil
	}
	c, err := listenMulticast(dst, o.SkipInterface)
	return c, net.UDPAddrFromAddrPort(dst), err
}

// An InviteResponder answers questions for one invite's nameplate with the
// TCP port its host listens on.
type InviteResponder struct {
	conn PacketConn
	dst  *net.UDPAddr
	name dnsmessage.Name
	txt  []string

	closeOnce sync.Once
	done      chan struct{}

	mu       sync.Mutex
	lastSent time.Time
}

// AnswerInvite starts answering for nameplate until Close.
func AnswerInvite(nameplate, port uint16, opts InviteOptions) (*InviteResponder, error) {
	name, err := inviteName(nameplate)
	if err != nil {
		return nil, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	conn, dst, err := opts.open()
	if err != nil {
		return nil, err
	}
	r := &InviteResponder{
		conn: conn,
		dst:  dst,
		name: name,
		// The id tells one host answering from two interfaces apart from two
		// hosts answering for one nameplate, which the guest must refuse.
		txt:  []string{"port=" + strconv.Itoa(int(port)), "id=" + hex.EncodeToString(id[:])},
		done: make(chan struct{}),
	}
	go r.serve()
	return r, nil
}

// Close stops answering.
func (r *InviteResponder) Close() error {
	r.closeOnce.Do(func() { r.conn.Close() })
	<-r.done
	return nil
}

func (r *InviteResponder) serve() {
	defer close(r.done)
	buf := make([]byte, maxMessageSize)
	for {
		n, _, err := r.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if asksFor(buf[:n], r.name) && r.allow() {
			if raw, err := txtAnswer(r.name, r.txt); err == nil {
				_, _ = r.conn.WriteTo(raw, r.dst)
			}
		}
	}
}

// allow applies RFC 6762's one-answer-per-second rule, which is also what
// keeps a replayed question from turning this host into an amplifier.
func (r *InviteResponder) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastSent) < minAnswerInterval {
		return false
	}
	r.lastSent = time.Now()
	return true
}

func asksFor(raw []byte, name dnsmessage.Name) bool {
	var p dnsmessage.Parser
	if h, err := p.Start(raw); err != nil || h.Response {
		return false
	}
	for {
		q, err := p.Question()
		if err != nil {
			return false
		}
		if q.Type == dnsmessage.TypeTXT && strings.EqualFold(q.Name.String(), name.String()) {
			return true
		}
	}
}

func txtAnswer(name dnsmessage.Name, txt []string) ([]byte, error) {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET, TTL: 10},
			Body: &dnsmessage.TXTResource{TXT: txt},
		}},
	}
	return msg.Pack()
}

// An InviteHost is one device answering for a nameplate, at every address it
// was heard from.
type InviteHost struct {
	ID    string
	Addrs []netip.AddrPort
}

// FindInvite asks the LAN who holds an invite with nameplate. It returns once
// a host has answered and a short grace period has passed for a second one to
// show itself, or when wait runs out with none.
func FindInvite(ctx context.Context, nameplate uint16, wait time.Duration, opts InviteOptions) ([]InviteHost, error) {
	name, err := inviteName(nameplate)
	if err != nil {
		return nil, err
	}
	conn, dst, err := opts.open()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	query, err := (&dnsmessage.Message{Questions: []dnsmessage.Question{{
		Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET,
	}}}).Pack()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	type heard struct {
		id   string
		addr netip.AddrPort
	}
	answers := make(chan heard, 16)
	go func() {
		buf := make([]byte, maxMessageSize)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			src, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			id, port, ok := parseInviteAnswer(buf[:n], name)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(src.IP)
			if !ok || !OnLink(ip.Unmap()) {
				continue
			}
			select {
			case answers <- heard{id, netip.AddrPortFrom(ip.Unmap(), port)}:
			default:
			}
		}
	}()

	hosts := map[string][]netip.AddrPort{}
	var grace <-chan time.Time
	tick := time.NewTicker(inviteQueryInterval)
	defer tick.Stop()
	_, _ = conn.WriteTo(query, dst)
	for {
		select {
		case <-ctx.Done():
			return collectHosts(hosts), nil
		case <-grace:
			return collectHosts(hosts), nil
		case <-tick.C:
			_, _ = conn.WriteTo(query, dst)
		case h := <-answers:
			if !slices.Contains(hosts[h.id], h.addr) {
				hosts[h.id] = append(hosts[h.id], h.addr)
			}
			if grace == nil {
				grace = time.After(2 * inviteQueryInterval)
			}
		}
	}
}

// OnLink reports whether addr is this host or on one of its own subnets. An
// mDNS answer comes from the link by definition; one from further away is
// someone steering a guest, and its one guess at the code, to a host of
// theirs.
func OnLink(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(n.String()); err == nil && p.Masked().Contains(addr) {
				return true
			}
		}
	}
	return false
}

func collectHosts(m map[string][]netip.AddrPort) []InviteHost {
	out := make([]InviteHost, 0, len(m))
	for id, addrs := range m {
		out = append(out, InviteHost{ID: id, Addrs: addrs})
	}
	slices.SortFunc(out, func(a, b InviteHost) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func parseInviteAnswer(raw []byte, name dnsmessage.Name) (id string, port uint16, ok bool) {
	var p dnsmessage.Parser
	if h, err := p.Start(raw); err != nil || !h.Response {
		return "", 0, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", 0, false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return "", 0, false
		}
		if h.Type != dnsmessage.TypeTXT || !strings.EqualFold(h.Name.String(), name.String()) {
			if err := p.SkipAnswer(); err != nil {
				return "", 0, false
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return "", 0, false
		}
		for _, kv := range txt.TXT {
			switch k, v, _ := strings.Cut(kv, "="); k {
			case "port":
				n, err := strconv.ParseUint(v, 10, 16)
				if err == nil && n != 0 {
					port = uint16(n)
				}
			case "id":
				if len(v) == 16 {
					id = v
				}
			}
		}
		return id, port, id != "" && port != 0
	}
}
