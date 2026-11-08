package conn

import (
	"io"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
)

// A VPNHub is one VPN device that several networks share, each by a plumber
// of its own; docs/13-multi-network-notes.md says how it routes between them.
type VPNHub struct {
	v    VPN
	logf logger.Logf

	mu              sync.Mutex
	members         map[int]*hubMember
	host            []netip.Prefix
	f               *os.File
	swapped         chan struct{} // closed and replaced whenever f changes
	closed          bool
	reading         bool
	established     VPNConfig
	everEstablished bool
	count           int
	last            time.Time

	fd    atomic.Pointer[os.File]
	table atomic.Pointer[hubTable]
	nat   hubNAT
}

// A hubMember is one network on a hub: its device and router, as its mesh
// last made them, and what it routes.
type hubMember struct {
	dev         *vpnTUN // nil while its mesh restarts
	rtr         *vpnRouter
	part        *vpnPart // nil before its router first set addresses
	stale       *time.Timer
	hostChanged func()
}

// A vpnPart is what one network routes into the hub's device.
type vpnPart struct {
	addrs    []netip.Prefix // sorted
	own      []netip.Addr   // the same, in the engine's order
	routes   []netip.Prefix // into the tunnel, for this network
	overlay  []netip.Prefix // what the internet's routes leave out
	internet bool
	dns      []netip.Addr
	search   []string
	mtu      int
}

// vpnStaleAfter is how long a network whose mesh stopped keeps its routes,
// so that a mesh restarting establishes the device no more than once.
const vpnStaleAfter = 10 * time.Second

// NewVPNHub is a hub establishing its device by v.
func NewVPNHub(v VPN, logf logger.Logf) *VPNHub {
	return &VPNHub{v: v, logf: logf, members: map[int]*hubMember{}, swapped: make(chan struct{})}
}

// Plumber is the plumber of the network in slot, whose prefixes cover names,
// routed whole. A lower slot's routes win where two networks' overlap.
func (h *VPNHub) Plumber(slot int, cover func() []netip.Prefix) Plumber {
	return &vpnPlumber{hub: h, slot: slot, cover: cover}
}

// Remove drops the network in slot, whose mesh has stopped for good, and
// establishes the device without it, or takes it down where none is left.
func (h *VPNHub) Remove(slot int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.members[slot]
	if m == nil {
		return
	}
	if m.stale != nil {
		m.stale.Stop()
	}
	delete(h.members, slot)
	h.rebuildLocked()
	h.reestablishLocked()
}

// Close takes the device down for good.
func (h *VPNHub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	for _, m := range h.members {
		if m.stale != nil {
			m.stale.Stop()
		}
	}
	f := h.f
	h.f = nil
	h.fd.Store(nil)
	close(h.swapped)
	h.table.Store(nil)
	h.mu.Unlock()
	if f != nil {
		f.Close()
	}
}

// SetHostRoutes takes routes as what the network beneath the VPN reaches but
// by its default routes, telling every network of a change.
func (h *VPNHub) SetHostRoutes(routes []netip.Prefix) {
	routes = sortedPrefixes(routes)
	h.mu.Lock()
	same := slices.Equal(h.host, routes)
	h.host = routes
	var heard []func()
	for _, slot := range h.slotsLocked() {
		if c := h.members[slot].hostChanged; c != nil {
			heard = append(heard, c)
		}
	}
	h.mu.Unlock()
	if !same {
		for _, c := range heard {
			c()
		}
	}
}

// Established is how often the hub established a device, and when last.
func (h *VPNHub) Established() (int, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count, h.last
}

func (h *VPNHub) hostRoutes() []netip.Prefix {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.host)
}

func (h *VPNHub) watchHostRoutes(slot int, changed func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.memberLocked(slot).hostChanged = changed
}

func (h *VPNHub) router(slot int) *vpnRouter {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.members[slot]; m != nil {
		return m.rtr
	}
	return nil
}

func (h *VPNHub) file() *os.File { return h.fd.Load() }

// source is the address of slot's network of the family asked for, where
// the device last established carries it.
func (h *VPNHub) source(slot int, v4 bool) (netip.Addr, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.members[slot]
	if m == nil || m.part == nil || h.f == nil {
		return netip.Addr{}, false
	}
	for _, a := range m.part.own {
		if a.Is4() == v4 && slices.ContainsFunc(h.established.Addrs, func(p netip.Prefix) bool { return p.Addr() == a }) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func (h *VPNHub) memberLocked(slot int) *hubMember {
	m := h.members[slot]
	if m == nil {
		m = &hubMember{}
		h.members[slot] = m
	}
	return m
}

func (h *VPNHub) slotsLocked() []int {
	slots := make([]int, 0, len(h.members))
	for s := range h.members {
		slots = append(slots, s)
	}
	slices.Sort(slots)
	return slots
}

// attach makes d and r slot's device and router, those of its mesh's start;
// what the mesh before routed stays until r sets its own.
func (h *VPNHub) attach(slot int, d *vpnTUN, r *vpnRouter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.memberLocked(slot)
	m.dev, m.rtr = d, r
	h.rebuildLocked()
}

// detach takes d off the hub, its network's routes kept a while for its
// mesh's next start.
func (h *VPNHub) detach(d *vpnTUN) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.members[d.slot]
	if m == nil || m.dev != d {
		return
	}
	m.dev = nil
	if m.part == nil {
		delete(h.members, d.slot) // gone before it routed anything
	}
	h.rebuildLocked()
	if m.part != nil && !h.closed {
		if m.stale != nil {
			m.stale.Stop()
		}
		part := m.part
		m.stale = time.AfterFunc(vpnStaleAfter, func() { h.dropStale(d.slot, part) })
	}
}

// dropStale drops what slot's network routes where its mesh has set nothing
// new since part.
func (h *VPNHub) dropStale(slot int, part *vpnPart) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.members[slot]
	if h.closed || m == nil || m.part != part {
		return
	}
	m.part = nil
	if m.dev == nil {
		delete(h.members, slot)
	}
	h.rebuildLocked()
	h.reestablishLocked()
}

// set takes part as what r's network routes, and establishes the device
// again where that changed it, returning what it established then.
func (h *VPNHub) set(slot int, r *vpnRouter, part *vpnPart) (*VPNConfig, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, os.ErrClosed
	}
	m := h.members[slot]
	if m == nil || m.rtr != r {
		return nil, nil // a mesh's that has stopped
	}
	m.part = part
	if m.stale != nil {
		m.stale.Stop()
		m.stale = nil
	}
	h.rebuildLocked()
	return h.establishLocked()
}

// reestablishLocked establishes the device for what is left, and takes it
// down where nothing is.
func (h *VPNHub) reestablishLocked() {
	if h.closed {
		return
	}
	if _, ok := h.configLocked(); !ok {
		if h.f != nil {
			h.f.Close()
		}
		h.f = nil
		h.fd.Store(nil)
		h.everEstablished, h.established = false, VPNConfig{}
		return
	}
	if _, err := h.establishLocked(); err != nil {
		h.logf("conn: establishing the VPN device: %v", err)
	}
}

func (h *VPNHub) establishLocked() (*VPNConfig, error) {
	c, ok := h.configLocked()
	if !ok || h.everEstablished && h.f != nil && c.equal(h.established) {
		return nil, nil
	}
	f, err := h.v.Establish(c)
	if err != nil {
		return nil, err
	}
	old := h.f
	h.f = f
	h.fd.Store(f)
	close(h.swapped)
	h.swapped = make(chan struct{})
	if old != nil {
		old.Close()
	}
	h.established, h.everEstablished = c, true
	h.count++
	h.last = time.Now()
	if !h.reading {
		h.reading = true
		go h.readLoop()
	}
	return &c, nil
}

// configLocked is the device every network's part makes together, false
// where none has addresses.
func (h *VPNHub) configLocked() (VPNConfig, bool) {
	var c VPNConfig
	var routes, avoid []netip.Prefix
	var parts []*vpnPart
	var exit, named *vpnPart
	for _, slot := range h.slotsLocked() {
		p := h.members[slot].part
		if p == nil {
			continue
		}
		parts = append(parts, p)
		c.Addrs = append(c.Addrs, p.addrs...)
		routes = append(routes, p.routes...)
		avoid = append(avoid, p.overlay...)
		c.MTU = p.mtu
		if p.internet && exit == nil {
			exit = p
		}
		if len(p.dns) > 0 && named == nil {
			named = p
		}
	}
	if len(parts) == 0 {
		return c, false
	}
	if exit != nil {
		routes = append(routes, Internet(true, true, avoid)...)
		// Lookups leave by the exit node as the rest does.
		if len(exit.dns) > 0 {
			named = exit
		}
	}
	if named != nil {
		c.DNS = named.dns
		c.Search = slices.Clone(named.search)
		for _, p := range parts {
			if p != named && len(p.dns) > 0 {
				for _, s := range p.search {
					if !slices.Contains(c.Search, s) {
						c.Search = append(c.Search, s)
					}
				}
			}
		}
		// The servers taking the host's lookups are in the tunnel, juistd's
		// own resolver among them, which no member's route covers.
		for _, a := range c.DNS {
			if !slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Contains(a) }) {
				routes = append(routes, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	c.Addrs, c.Routes = sortedPrefixes(c.Addrs), sortedPrefixes(routes)
	return c, true
}

// A hubTable is how the hub hands out packets, rebuilt on every change and
// read without a lock.
type hubTable struct {
	// only is set where the hub holds a single network, which takes every
	// packet: single, nil while its mesh restarts.
	only    bool
	single  *vpnTUN
	members []hubEntry // by slot
	exit    int        // the member the internet goes to, -1 for none
	owners  map[netip.Addr]int
	slotOf  map[netip.Addr]int // each owned address's network, by slot
}

type hubEntry struct {
	dev    *vpnTUN
	routes *netipx.IPSet // nil before its router set any
	own    []netip.Addr
}

func (e *hubEntry) ownOf(v4 bool) (netip.Addr, bool) {
	for _, a := range e.own {
		if a.Is4() == v4 {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func (t *hubTable) index(d *vpnTUN) int {
	for i := range t.members {
		if t.members[i].dev == d {
			return i
		}
	}
	return -1
}

// route is the member a packet to dst goes to, -1 for none.
func (t *hubTable) route(dst netip.Addr) int {
	for i, e := range t.members {
		if e.routes != nil && e.routes.Contains(dst) {
			return i
		}
	}
	return t.exit
}

func (h *VPNHub) rebuildLocked() {
	if h.closed {
		return
	}
	slots := h.slotsLocked()
	if len(slots) == 0 {
		h.purgeMovedLocked(&hubTable{})
		h.table.Store(nil)
		return
	}
	t := &hubTable{exit: -1, owners: map[netip.Addr]int{}, slotOf: map[netip.Addr]int{}}
	if len(slots) == 1 {
		t.only, t.single = true, h.members[slots[0]].dev
	}
	for i, slot := range slots {
		m := h.members[slot]
		e := hubEntry{dev: m.dev}
		if p := m.part; p != nil {
			var b netipx.IPSetBuilder
			for _, r := range p.routes {
				b.AddPrefix(r)
			}
			for _, a := range p.dns {
				b.Add(a)
			}
			e.routes, _ = b.IPSet()
			e.own = p.own
			for _, a := range p.own {
				if _, taken := t.owners[a]; !taken {
					t.owners[a], t.slotOf[a] = i, slot
				}
			}
			if p.internet && t.exit < 0 {
				t.exit = i
			}
		}
		t.members = append(t.members, e)
	}
	h.purgeMovedLocked(t)
	h.table.Store(t)
}

// purgeMovedLocked drops the translations of every address t no longer
// gives the network the last table gave it, so that none outlives its
// network into another's.
func (h *VPNHub) purgeMovedLocked(t *hubTable) {
	old := h.table.Load()
	if old == nil {
		return
	}
	var moved []netip.Addr
	for a, slot := range old.slotOf {
		if now, ok := t.slotOf[a]; !ok || now != slot {
			moved = append(moved, a)
		}
	}
	h.nat.purge(moved)
}

// current is the device's descriptor, waiting for the first.
func (h *VPNHub) current() (*os.File, error) {
	for {
		h.mu.Lock()
		f, closed, swapped := h.f, h.closed, h.swapped
		h.mu.Unlock()
		if closed {
			return nil, os.ErrClosed
		}
		if f != nil {
			return f, nil
		}
		<-swapped
	}
}

// vpnReadMax is the longest packet the hub reads off its device.
const vpnReadMax = 1 << 16

// readLoop hands what the host sends into the device to the networks, on
// whichever descriptor was established last.
func (h *VPNHub) readLoop() {
	buf := make([]byte, vpnReadMax)
	var wait time.Duration
	for {
		f, err := h.current()
		if err != nil {
			return
		}
		n, err := f.Read(buf)
		if err != nil {
			if h.fd.Load() != f {
				continue // established again, or taken down
			}
			h.mu.Lock()
			closed := h.closed
			h.mu.Unlock()
			if closed {
				return
			}
			wait = min(max(2*wait, 10*time.Millisecond), time.Second)
			if wait == time.Second {
				h.logf("conn: reading the VPN device: %v", err)
			}
			time.Sleep(wait)
			continue
		}
		wait = 0
		if n > 0 {
			h.dispatch(getPacket(buf[:n]))
		}
	}
}

// dispatch hands b, a packet from the host, to its network.
func (h *VPNHub) dispatch(b *[]byte) {
	t := h.table.Load()
	switch {
	case t == nil:
		putPacket(b)
		return
	case t.only:
		if t.single == nil {
			putPacket(b)
			return
		}
		t.single.deliver(b)
		return
	}
	var q packet.Parsed
	q.Decode(*b)
	if q.IPVersion != 4 && q.IPVersion != 6 {
		putPacket(b)
		return
	}
	dst := q.Dst.Addr()
	if dst.IsMulticast() {
		for i, e := range t.members {
			if e.dev == nil || e.routes == nil || !e.routes.Contains(dst) {
				continue
			}
			c := getPacket(*b)
			var cq packet.Parsed
			cq.Decode(*c)
			if h.outbound(t, i, &cq) {
				e.dev.deliver(c)
			} else {
				putPacket(c)
			}
		}
		putPacket(b)
		return
	}
	i := t.route(dst)
	if i < 0 || t.members[i].dev == nil || !h.outbound(t, i, &q) {
		putPacket(b)
		return
	}
	t.members[i].dev.deliver(b)
}

// outbound has q, going to member i, leave from i's address where the host
// sent it from another network's, and reports whether it may go.
func (h *VPNHub) outbound(t *hubTable, i int, q *packet.Parsed) bool {
	src := q.Src.Addr()
	o, ok := t.owners[src]
	if !ok || o == i {
		// A flow the host sends from this network's address itself owns its
		// tuple, whatever a translation once did with it.
		// TCP's says so by its SYN alone.
		if ok && (q.IPProto != ipproto.TCP || q.IsTCPSyn()) {
			if k, ok := natKeyOut(q); ok {
				h.nat.forget(k)
			}
		}
		return true
	}
	if !translatable(q.IPProto) {
		return false
	}
	to, ok := t.members[i].ownOf(src.Is4())
	if !ok {
		return false // the network runs without this family
	}
	checksum.UpdateSrcAddr(q, to)
	if k, ok := natKeyOut(q); ok {
		h.nat.put(k, src, time.Now())
	}
	return true
}

// A fragKey names the fragments of one datagram, by its addresses and ID.
type fragKey struct {
	src, dst netip.Addr
	id       uint32
}

// fragmentOf is the datagram b, of IP version version, is a fragment of,
// and whether it is its first; false where b is whole. IPv6's fragment
// header is taken where it follows the fixed header.
func fragmentOf(b []byte, version uint8) (k fragKey, first, ok bool) {
	switch {
	case version == 4 && len(b) >= 20:
		flags := uint16(b[6])<<8 | uint16(b[7])
		if flags&0x3fff == 0 {
			return fragKey{}, false, false
		}
		return fragKey{netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), uint32(b[4])<<8 | uint32(b[5])},
			flags&0x1fff == 0, true
	case version == 6 && len(b) >= 48 && b[6] == 44:
		off := (uint16(b[42])<<8 | uint16(b[43])) >> 3
		return fragKey{netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])),
			uint32(b[44])<<24 | uint32(b[45])<<16 | uint32(b[46])<<8 | uint32(b[47])}, off == 0, true
	}
	return fragKey{}, false, false
}

// inbound reports whether pkt, from member i's engine, may reach the host:
// to an address of i's own alone, or a multicast group. An answer to what
// left translated goes back to the address it was sent from.
func (h *VPNHub) inbound(t *hubTable, i int, pkt []byte) bool {
	var q packet.Parsed
	q.Decode(pkt)
	if q.IPVersion != 4 && q.IPVersion != 6 {
		return false
	}
	dst := q.Dst.Addr()
	if dst.IsMulticast() {
		return true
	}
	if o, ok := t.owners[dst]; !ok || o != i {
		return false
	}
	// From where another network's routes lead, as an exit node or a
	// subnet router of i's could claim, it would have the host answer there.
	if r := t.route(q.Src.Addr()); r >= 0 && r != i {
		return false
	}
	now := time.Now()
	switch k, keyed := natKeyIn(&q); {
	case keyed:
		orig, hit := h.nat.get(k, now)
		// A first fragment says where the datagram's later ones go, or that
		// they stay, whatever an earlier datagram of its ID did; read before
		// its destination changes.
		if hit || h.nat.fragN.Load() > 0 {
			if frag, first, ok := fragmentOf(pkt, q.IPVersion); ok && first {
				if hit {
					h.nat.putFragment(frag, orig, now)
				} else {
					h.nat.forgetFragment(frag)
				}
			}
		}
		if hit {
			checksum.UpdateDstAddr(&q, orig)
		}
	case q.IPProto == ipproto.Fragment:
		// A later fragment carries no ports: it goes where its first went,
		// which has to come before it.
		if h.nat.fragN.Load() > 0 {
			if frag, _, ok := fragmentOf(pkt, q.IPVersion); ok {
				if orig, ok := h.nat.fragment(frag, now); ok {
					checksum.UpdateDstAddr(&q, orig)
				}
			}
		}
	case q.IsError():
		h.translateError(&q)
	}
	return true
}

// translateError has an ICMP error about a translated flow, such as a packet
// too big, reach the address the flow left the host from: the error's
// destination and the packet it quotes both name it.
func (h *VPNHub) translateError(q *packet.Parsed) {
	b := q.Buffer()
	icmp := q.Transport()
	if len(icmp) < 8 {
		return
	}
	inner := icmp[8:]
	k, ok := quotedKey(inner, q.IPVersion)
	if !ok || k.local.Addr() != q.Dst.Addr() {
		return
	}
	orig, ok := h.nat.get(k, time.Now())
	if !ok {
		return
	}
	checksum.UpdateDstAddr(q, orig)
	if q.IPVersion == 4 {
		copy(inner[12:16], orig.AsSlice())
		if ihl := int(inner[0]&0x0f) * 4; ihl >= 20 && ihl <= len(inner) {
			inner[10], inner[11] = 0, 0
			sum := ^uint16(onesSum(0, inner[:ihl]))
			inner[10], inner[11] = byte(sum>>8), byte(sum)
		}
		icmp[2], icmp[3] = 0, 0
		sum := ^uint16(onesSum(0, icmp))
		icmp[2], icmp[3] = byte(sum>>8), byte(sum)
		return
	}
	copy(inner[8:24], orig.AsSlice())
	icmp[2], icmp[3] = 0, 0
	var pseudo [40]byte
	copy(pseudo[0:32], b[8:40])
	n := len(icmp)
	pseudo[32], pseudo[33], pseudo[34], pseudo[35] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	pseudo[39] = byte(ipproto.ICMPv6)
	sum := ^uint16(onesSum(onesSum(0, pseudo[:]), icmp))
	icmp[2], icmp[3] = byte(sum>>8), byte(sum)
}

// quotedKey is the flow of the packet an ICMP error quotes, its header and
// the first eight bytes after it, as [natKeyOut] keys it.
func quotedKey(b []byte, version uint8) (natKey, bool) {
	var proto ipproto.Proto
	var src, dst netip.Addr
	var rest []byte
	switch {
	case version == 4 && len(b) >= 20 && b[0]>>4 == 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 {
			return natKey{}, false
		}
		proto, src, dst, rest = ipproto.Proto(b[9]), netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[ihl:]
	case version == 6 && len(b) >= 48 && b[0]>>4 == 6:
		proto, src, dst, rest = ipproto.Proto(b[6]), netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), b[40:]
	default:
		return natKey{}, false
	}
	port := func(i int) uint16 { return uint16(rest[i])<<8 | uint16(rest[i+1]) }
	switch proto {
	case ipproto.TCP, ipproto.UDP:
		return natKey{proto, netip.AddrPortFrom(src, port(0)), netip.AddrPortFrom(dst, port(2))}, true
	case ipproto.ICMPv4, ipproto.ICMPv6:
		if echo := rest[0] == 8 && proto == ipproto.ICMPv4 || rest[0] == 128 && proto == ipproto.ICMPv6; echo {
			return natKey{proto, netip.AddrPortFrom(src, port(4)), netip.AddrPortFrom(dst, 0)}, true
		}
	}
	return natKey{}, false
}

// onesSum adds b to sum as the Internet checksum does, folded.
func onesSum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return sum
}

func (h *VPNHub) write(d *vpnTUN, bufs [][]byte, offset int) (int, error) {
	f := h.fd.Load()
	if f == nil {
		return len(bufs), nil
	}
	t := h.table.Load()
	i := -1
	if t != nil && !t.only {
		i = t.index(d)
	}
	for n, buf := range bufs {
		if len(buf) <= offset {
			return n, io.ErrShortBuffer
		}
		pkt := buf[offset:]
		switch {
		case t == nil:
			continue
		case t.only:
			if t.single != d {
				continue
			}
		case i < 0 || !h.inbound(t, i, pkt):
			continue
		}
		if _, err := f.Write(pkt); err != nil {
			if h.fd.Load() != f {
				return len(bufs), nil // established again; these are lost as on any change
			}
			return n, err
		}
	}
	return len(bufs), nil
}

// translatable reports whether a packet of p can leave from another
// address: one whose checksums the translation keeps right, or a fragment
// after the first, which has none.
func translatable(p ipproto.Proto) bool {
	return p == ipproto.TCP || p == ipproto.UDP || p == ipproto.ICMPv4 || p == ipproto.ICMPv6 || p == ipproto.Fragment
}

// How long a translation is kept without a packet: a TCP connection's as
// long as Android keeps one idle, the rest's a few minutes; and how many
// are kept at most.
const (
	natIdleTCP = 2 * time.Hour
	natIdle    = 5 * time.Minute
	natMax     = 16384
	natSweep   = time.Minute
)

// A natKey is a flow as it runs through the tunnel, from local, an address
// of the network's own, to remote; an echo's identifier is its port.
type natKey struct {
	proto         ipproto.Proto
	local, remote netip.AddrPort
}

type natEntry struct {
	orig netip.Addr
	used atomic.Int64 // Unix nanoseconds
}

// natFragment is how long a datagram's later fragments follow its first.
const natFragment = 30 * time.Second

type fragEntry struct {
	orig netip.Addr
	at   time.Time
}

// A hubNAT holds the address each translated flow left the host from, and
// where the fragments of a datagram translated back go.
type hubNAT struct {
	n     atomic.Int32
	fragN atomic.Int32
	mu    sync.RWMutex
	m     map[natKey]*natEntry
	frags map[fragKey]fragEntry
	swept time.Time
}

func natKeyOut(q *packet.Parsed) (natKey, bool) {
	switch q.IPProto {
	case ipproto.TCP, ipproto.UDP:
		return natKey{q.IPProto, q.Src, q.Dst}, true
	case ipproto.ICMPv4, ipproto.ICMPv6:
		if q.IsEchoRequest() {
			id := uint16(q.EchoIDSeq() >> 16)
			return natKey{q.IPProto, netip.AddrPortFrom(q.Src.Addr(), id), netip.AddrPortFrom(q.Dst.Addr(), 0)}, true
		}
	}
	return natKey{}, false
}

func natKeyIn(q *packet.Parsed) (natKey, bool) {
	switch q.IPProto {
	case ipproto.TCP, ipproto.UDP:
		return natKey{q.IPProto, q.Dst, q.Src}, true
	case ipproto.ICMPv4, ipproto.ICMPv6:
		if q.IsEchoResponse() {
			id := uint16(q.EchoIDSeq() >> 16)
			return natKey{q.IPProto, netip.AddrPortFrom(q.Dst.Addr(), id), netip.AddrPortFrom(q.Src.Addr(), 0)}, true
		}
	}
	return natKey{}, false
}

func (e *natEntry) expired(k natKey, now time.Time) bool {
	idle := natIdle
	if k.proto == ipproto.TCP {
		idle = natIdleTCP
	}
	return now.Sub(time.Unix(0, e.used.Load())) > idle
}

func (t *hubNAT) put(k natKey, orig netip.Addr, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[natKey]*natEntry{}
	}
	if _, ok := t.m[k]; !ok {
		if now.Sub(t.swept) > natSweep {
			t.sweepLocked(now)
		}
		// Still full within a sweep's time: any one goes, at no scan's cost.
		for victim := range t.m {
			if len(t.m) < natMax {
				break
			}
			delete(t.m, victim)
		}
	}
	e := &natEntry{orig: orig}
	e.used.Store(now.UnixNano())
	t.m[k] = e
	t.n.Store(int32(len(t.m)))
}

// forget drops k's translation, if any.
func (t *hubNAT) forget(k natKey) {
	if t.n.Load() == 0 {
		return
	}
	t.mu.RLock()
	_, ok := t.m[k]
	t.mu.RUnlock()
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, k)
	t.n.Store(int32(len(t.m)))
}

func (t *hubNAT) get(k natKey, now time.Time) (netip.Addr, bool) {
	if t.n.Load() == 0 {
		return netip.Addr{}, false
	}
	t.mu.RLock()
	e, ok := t.m[k]
	t.mu.RUnlock()
	if !ok || e.expired(k, now) {
		return netip.Addr{}, false
	}
	e.used.Store(now.UnixNano())
	return e.orig, true
}

func (t *hubNAT) putFragment(k fragKey, orig netip.Addr, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frags == nil {
		t.frags = map[fragKey]fragEntry{}
	}
	if len(t.frags) >= natMax {
		for k, e := range t.frags {
			if now.Sub(e.at) > natFragment {
				delete(t.frags, k)
			}
		}
		for victim := range t.frags {
			if len(t.frags) < natMax {
				break
			}
			delete(t.frags, victim)
		}
	}
	t.frags[k] = fragEntry{orig: orig, at: now}
	t.fragN.Store(int32(len(t.frags)))
}

func (t *hubNAT) forgetFragment(k fragKey) {
	t.mu.RLock()
	_, ok := t.frags[k]
	t.mu.RUnlock()
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.frags, k)
	t.fragN.Store(int32(len(t.frags)))
}

// purge drops every translation from or to one of addrs, the host's.
func (t *hubNAT) purge(addrs []netip.Addr) {
	if len(addrs) == 0 || t.n.Load() == 0 && t.fragN.Load() == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.m {
		if slices.Contains(addrs, k.local.Addr()) {
			delete(t.m, k)
		}
	}
	for k := range t.frags {
		if slices.Contains(addrs, k.dst) {
			delete(t.frags, k)
		}
	}
	t.n.Store(int32(len(t.m)))
	t.fragN.Store(int32(len(t.frags)))
}

func (t *hubNAT) fragment(k fragKey, now time.Time) (netip.Addr, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.frags[k]
	if !ok || now.Sub(e.at) > natFragment {
		return netip.Addr{}, false
	}
	return e.orig, true
}

// sweepLocked drops what has expired.
func (t *hubNAT) sweepLocked(now time.Time) {
	t.swept = now
	for k, e := range t.m {
		if e.expired(k, now) {
			delete(t.m, k)
		}
	}
	for k, e := range t.frags {
		if now.Sub(e.at) > natFragment {
			delete(t.frags, k)
		}
	}
	t.fragN.Store(int32(len(t.frags)))
}

// packetPool holds buffers for packets the hub queues, of the size a VPN's
// MTU allows; a longer one gets one of its own.
var packetPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// getPacket is a pooled copy of b.
func getPacket(b []byte) *[]byte {
	if len(b) > 2048 {
		c := slices.Clone(b)
		return &c
	}
	p := packetPool.Get().(*[]byte)
	*p = append((*p)[:0], b...)
	return p
}

func putPacket(p *[]byte) {
	if cap(*p) == 2048 {
		packetPool.Put(p)
	}
}
