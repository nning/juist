package relay

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nning/juist/internal/admit"
	"github.com/nning/juist/relay/forward"
)

// Invite forwarding: a member that invites from behind a NAT waits at a relay
// for its guest, who cannot reach it directly. The inviting device holds a
// connection open to the relay, registered under the invite's forward id, and
// the guest asks the relay for that id; the relay joins the two and copies
// bytes. The enrollment handshake runs end to end over them, keyed by the
// invite's secret, which the relay never sees: the forward id is derived from
// it one way. So a relay can refuse to forward, and see who talks to whom,
// and nothing more.
//
// Registering takes a member's identity key, checked against the log and
// bound to this relay's certificate and a nonce of its own, so a registration
// can be neither replayed nor carried to another relay. Asking takes only the
// id, which is 128 bits nobody but the link's holders can know.
//
// Both halves are HTTP upgrades on the DERP port, the one hole a relay's
// firewall already has.
const (
	// Bounds on what forwarding may cost the relay's owner.
	maxForwardIDs      = 64 // invites waiting here at once
	maxIDsPerHost      = 4  // of them, per member
	maxWaitingPerID    = 2  // connections a host keeps waiting per invite
	maxGuestsWaiting   = 64 // guests waiting for a host's connection
	maxGuestsPerSource = 4
	maxSessionsPerHost = maxIDsPerHost * maxWaitingPerID // forwarded at once, per member
	guestWait          = 10 * time.Second                // for a host's next waiting connection
	registerTimeout    = 10 * time.Second
	spliceIdle         = 2 * time.Minute
	maxSpliceBytes     = 64 << 20 // each way; a log is far smaller
)

// forwarder holds the invites waiting at this relay.
type forwarder struct {
	admit    func(identity [32]byte) bool
	certHash [32]byte
	logf     func(string, ...any)

	mu      sync.Mutex
	cond    *sync.Cond
	ids     map[[16]byte]*waitingInvite
	waiting *admit.Set[netip.Prefix] // guests, by group

	// active are the connections of invites being forwarded, by the member
	// that waited for them: a relay shutting down ends them all, and a
	// member removed from the log its own.
	active map[net.Conn][32]byte

	// starting counts the sessions admitted for a member and not yet in
	// active, so the bound holds while a guest waits for its host.
	starting map[[32]byte]int
	closed   bool
}

// waitingInvite is one invite's registration: who owns it, and the host
// connections waiting for a guest.
type waitingInvite struct {
	owner [32]byte
	conns []*hostConn

	// idle is when the last waiting connection was taken by a guest. The
	// registration is kept for guestWait after, for the host to put its next
	// connection up, and swept after that.
	idle time.Time
}

type hostConn struct {
	conn   net.Conn
	owner  [32]byte
	paired atomic.Bool   // set before the watcher is stopped for a guest
	watch  chan struct{} // closed once the watcher has stopped reading
}

func newForwarder(isMember func([32]byte) bool, certHash [32]byte, logf func(string, ...any)) *forwarder {
	f := &forwarder{admit: isMember, certHash: certHash, logf: logf,
		ids: map[[16]byte]*waitingInvite{}, active: map[net.Conn][32]byte{}, starting: map[[32]byte]int{},
		waiting: admit.New[netip.Prefix](admit.Limits{PerSource: maxGuestsPerSource, Total: maxGuestsWaiting})}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func parseForwardID(r *http.Request, prefix string) ([16]byte, bool) {
	var id [16]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Path, prefix))
	if err != nil || len(raw) != len(id) {
		return id, false
	}
	return [16]byte(raw), true
}

// upgrade answers an upgrade request and takes the connection over.
func upgrade(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, bool) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), forward.Upgrade) {
		http.Error(w, "an invite forward is an upgrade", http.StatusBadRequest)
		return nil, nil, false
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot take the connection over", http.StatusInternalServerError)
		return nil, nil, false
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, false
	}
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + forward.Upgrade +
		"\r\nConnection: Upgrade\r\n\r\n")
	if rw.Flush() != nil {
		c.Close()
		return nil, nil, false
	}
	return c, rw, true
}

// serveHost registers a member's waiting connection.
func (f *forwarder) serveHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseForwardID(r, forward.HostPath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, rw, ok := upgrade(w, r)
	if !ok {
		return
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Now().Add(registerTimeout))
	if _, err := c.Write(nonce[:]); err != nil {
		c.Close()
		return
	}
	var proof [32 + ed25519.SignatureSize]byte
	if _, err := io.ReadFull(rw, proof[:]); err != nil {
		c.Close()
		return
	}
	owner := [32]byte(proof[:32])
	if !ed25519.Verify(owner[:], forward.Message(f.certHash, id, nonce), proof[32:]) || !f.admit(owner) {
		c.Close()
		return
	}
	if rw.Reader.Buffered() > 0 {
		c.Close() // a host says nothing more until a guest is on the line
		return
	}
	// Told it waits, and its deadline cleared, before anyone can take it:
	// a guest that took it earlier would find its own deadline undone, or a
	// watcher never started.
	if _, err := c.Write([]byte{forward.Waiting}); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	h := &hostConn{conn: c, owner: owner, watch: make(chan struct{})}
	if err := f.register(id, h); err != nil {
		c.Close()
		return
	}
	admittedOn(c)
	// A waiting connection says nothing; one that ends, or speaks out of
	// turn, is no longer waiting.
	go func() {
		defer close(h.watch)
		var b [1]byte
		_, _ = c.Read(b[:])
		if !h.paired.Load() {
			f.drop(id, h)
		}
	}()
}

func (f *forwarder) register(id [16]byte, h *hostConn) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	inv := f.ids[id]
	switch {
	case f.closed:
		return errors.New("the relay is closing")
	case inv != nil && inv.owner != h.owner:
		return errors.New("another member holds this id")
	case inv != nil && len(inv.conns) >= maxWaitingPerID:
		return errors.New("enough connections wait for this invite")
	case inv == nil && len(f.ids) >= maxForwardIDs:
		return errors.New("too many invites wait here")
	case inv == nil && f.idsOf(h.owner) >= maxIDsPerHost:
		return errors.New("this member has enough invites waiting here")
	}
	if inv == nil {
		inv = &waitingInvite{owner: h.owner}
		f.ids[id] = inv
	}
	inv.conns = append(inv.conns, h)
	f.cond.Broadcast()
	return nil
}

// sweep forgets registrations whose host has not put up another connection
// within guestWait of the last one being taken, with f.mu held.
func (f *forwarder) sweep() {
	for id, inv := range f.ids {
		if len(inv.conns) == 0 && time.Since(inv.idle) > guestWait {
			delete(f.ids, id)
		}
	}
}

// sessionsOf counts the forwarded sessions a member waited for, with f.mu
// held; each has two connections in active.
func (f *forwarder) sessionsOf(owner [32]byte) int {
	n := 0
	for _, o := range f.active {
		if o == owner {
			n++
		}
	}
	return n/2 + f.starting[owner]
}

func (f *forwarder) idsOf(owner [32]byte) int {
	n := 0
	for _, inv := range f.ids {
		if inv.owner == owner {
			n++
		}
	}
	return n
}

// drop forgets a waiting connection, and closes it.
func (f *forwarder) drop(id [16]byte, h *hostConn) {
	f.mu.Lock()
	if inv := f.ids[id]; inv != nil {
		for i, c := range inv.conns {
			if c == h {
				inv.conns = append(inv.conns[:i], inv.conns[i+1:]...)
				break
			}
		}
		if len(inv.conns) == 0 {
			delete(f.ids, id)
		}
	}
	f.mu.Unlock()
	h.conn.Close()
}

// take hands a guest the next connection waiting for id, waiting a little
// for one where the host is between connections. It fails at once for an id
// nobody registered.
func (f *forwarder) take(id [16]byte) *hostConn {
	deadline := time.Now().Add(guestWait)
	timer := time.AfterFunc(guestWait, func() {
		f.mu.Lock()
		f.cond.Broadcast()
		f.mu.Unlock()
	})
	defer timer.Stop()
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		inv := f.ids[id]
		if inv == nil {
			return nil
		}
		if len(inv.conns) > 0 {
			h := inv.conns[0]
			inv.conns = inv.conns[1:]
			if len(inv.conns) == 0 {
				inv.idle = time.Now()
			}
			h.paired.Store(true)
			return h
		}
		if time.Now().After(deadline) {
			return nil
		}
		f.cond.Wait()
	}
}

// guestAdmitted runs once a guest is admitted; a variable so a test can hold
// one there.
var guestAdmitted = func() {}

// serveGuest joins a guest to the host waiting for its id.
func (f *forwarder) serveGuest(w http.ResponseWriter, r *http.Request) {
	id, ok := parseForwardID(r, forward.GuestPath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		// Read to its end after the answer, with no deadline: it stays in
		// the relay's bounds, where a guest admitted to wait does not.
		w.Header().Set("Connection", "close")
		http.Error(w, "an invite forward carries no body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.sweep()
	inv, known := f.ids[id]
	var waiting *admit.Ticket[netip.Prefix]
	admitted := false
	var owner [32]byte
	if known && f.sessionsOf(inv.owner) < maxSessionsPerHost {
		waiting, admitted = f.waiting.Admit(admit.Group(admit.ParseSource(r.RemoteAddr)), nil)
	}
	if admitted {
		owner = inv.owner
		f.starting[owner]++
	}
	f.mu.Unlock()
	switch {
	case !known:
		http.Error(w, "no invite waits here under this id", http.StatusNotFound)
		return
	case !admitted:
		http.Error(w, "too many guests wait here", http.StatusServiceUnavailable)
		return
	}
	// Bounded by waiting from here, and so out of the relay's own bounds,
	// which a flood would otherwise close it by; any answer but the
	// upgrade ends the connection, or it would be held unbounded.
	if c, ok := r.Context().Value(connContextKey{}).(net.Conn); ok {
		admittedOn(c)
	}
	w.Header().Set("Connection", "close")
	defer waiting.Release()
	started := false
	defer func() {
		if !started {
			f.mu.Lock()
			f.unstartLocked(owner)
			f.mu.Unlock()
		}
	}()
	guestAdmitted()

	h := f.take(id)
	if h == nil {
		http.Error(w, "the inviting device is not waiting here now", http.StatusServiceUnavailable)
		return
	}
	// Stop the watcher reading the host's connection before the guest's
	// bytes are copied onto it.
	_ = h.conn.SetReadDeadline(time.Unix(1, 0))
	<-h.watch
	_ = h.conn.SetReadDeadline(time.Time{})

	g, rw, ok := upgrade(w, r)
	if !ok {
		h.conn.Close()
		return
	}
	defer g.Close()
	defer h.conn.Close()
	// In active before either side hears it joined, so a member removed
	// meanwhile is refused here or ended by reauthorize, and never both told
	// and cut off.
	f.mu.Lock()
	if f.closed || !f.admit(owner) {
		f.mu.Unlock()
		return
	}
	f.unstartLocked(owner)
	started = true
	f.active[g], f.active[h.conn] = owner, owner
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.active, g)
		delete(f.active, h.conn)
		f.mu.Unlock()
	}()
	// The host hears who the guest is, for its own bounds per source; the
	// guest hears only that the host is there.
	who := r.RemoteAddr[:min(len(r.RemoteAddr), 255)]
	msg := append([]byte{forward.Joined, byte(len(who))}, who...)
	if _, err := h.conn.Write(msg); err != nil {
		return
	}
	if _, err := g.Write([]byte{forward.Joined}); err != nil {
		return
	}
	splice(g, rw.Reader, h.conn)
}

// unstartLocked takes back a session admitted for owner, with f.mu held.
func (f *forwarder) unstartLocked(owner [32]byte) {
	if f.starting[owner]--; f.starting[owner] <= 0 {
		delete(f.starting, owner)
	}
}

// splice copies both ways until either side ends, goes quiet for spliceIdle,
// or sends more than maxSpliceBytes.
func splice(guest net.Conn, guestBuffered io.Reader, host net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn, from io.Reader) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32<<10)
		var total int64
		for total < maxSpliceBytes {
			_ = src.SetReadDeadline(time.Now().Add(spliceIdle))
			n, err := from.Read(buf)
			if n > 0 {
				total += int64(n)
				_ = dst.SetWriteDeadline(time.Now().Add(spliceIdle))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(host, guest, guestBuffered)
	go pipe(guest, host, host)
	<-done
	guest.Close()
	host.Close()
	<-done
}

// reauthorize drops the waiting connections of hosts that are no longer
// members.
func (f *forwarder) reauthorize() {
	f.mu.Lock()
	var gone []*hostConn
	for id, inv := range f.ids {
		if f.admit(inv.owner) {
			continue
		}
		gone = append(gone, inv.conns...)
		delete(f.ids, id)
	}
	var ended []net.Conn
	for c, owner := range f.active {
		if !f.admit(owner) {
			ended = append(ended, c)
		}
	}
	f.mu.Unlock()
	for _, h := range gone {
		h.conn.Close()
	}
	for _, c := range ended {
		c.Close()
	}
}

func (f *forwarder) close() {
	f.mu.Lock()
	f.closed = true
	var all []*hostConn
	for id, inv := range f.ids {
		all = append(all, inv.conns...)
		delete(f.ids, id)
	}
	active := make([]net.Conn, 0, len(f.active))
	for c := range f.active {
		active = append(active, c)
	}
	f.cond.Broadcast()
	f.mu.Unlock()
	for _, h := range all {
		h.conn.Close()
	}
	for _, c := range active {
		c.Close()
	}
}

// String names the forwarder's state, for diagnostics.
func (f *forwarder) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("%d invites waiting, %d guests", len(f.ids), f.waiting.Len())
}
