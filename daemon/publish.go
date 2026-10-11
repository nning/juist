package daemon

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/ipproto"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// publishing is the operator's word on serving the names the log publishes
// on this device, and what the last reconcile made of it. A lock of its own,
// apart from the daemon's.
type publishing struct {
	mu      sync.Mutex
	consent bool
	to      map[string]string // by label, where names whose TLS juist ends go
	members map[string]bool   // by label, where to's service is for members alone
	account *ipc.ACMEAccount  // the terminator's, as it last said
	asked   time.Time         // when the terminator last asked

	// listening and unbound are where the terminator last said it listens,
	// and where another program holds the port, as ADDR:PORT; noCert, the
	// names it said it has no certificate for.
	listening, unbound []string
	noCert             []ipc.NoCert
	status             *ipc.Publish
	shares             []*share // what this device publishes under its own name, in the order they started

	// flagged is whether the terminator's file was last left to exist,
	// once flagSet.
	flagged, flagSet bool

	// publicPorts is what the ingress's file last said, once publicSet;
	// publicWant the public ports the log publishes names on, and
	// ingressListening those the ingress last said it listens on.
	publicPorts, publicWant, ingressListening []uint16
	publicSet, listeningSet                   bool
}

// nothingPublished is why a device the log publishes nothing on serves none.
const nothingPublished = "the network publishes nothing on this device"

// SetPublishConsent records whether this device's operator agrees to serve
// the names the log publishes on it, and where those go whose TLS juist ends,
// by label.
func (d *Daemon) SetPublishConsent(on bool, to map[string]string, members map[string]bool) {
	d.pub.mu.Lock()
	d.pub.consent, d.pub.to, d.pub.members = on, maps.Clone(to), maps.Clone(members)
	d.flagTerminatorLocked()
	d.pub.mu.Unlock()
	d.MarkDirty()
}

// wantsTerminatorLocked reports whether this device needs its terminator: a
// name whose TLS juist ends, or a share. d.pub.mu is held.
func (d *Daemon) wantsTerminatorLocked() bool {
	return d.pub.consent && len(d.pub.to) > 0 || len(d.pub.shares) > 0
}

// flagTerminatorLocked has [Options.TerminatorWanted] exist while this
// device needs its terminator, and not otherwise. d.pub.mu is held.
func (d *Daemon) flagTerminatorLocked() {
	want := d.wantsTerminatorLocked()
	if d.terminatorWanted == "" || d.pub.flagSet && d.pub.flagged == want {
		return
	}
	var err error
	if want {
		err = os.WriteFile(d.terminatorWanted, nil, 0o644)
	} else if err = os.Remove(d.terminatorWanted); errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err != nil {
		d.logOnce("daemon: telling systemd about the terminator: " + err.Error())
		return
	}
	d.pub.flagged, d.pub.flagSet = want, true
}

// publicPorts is the ports every ingress takes for the names s publishes by
// TCP, where this device is an ingress whose view is fresh; none otherwise.
func (d *Daemon) publicPorts(s snapshot, fresh bool) []uint16 {
	if self, ok := s.state.Node(d.self); !ok || !fresh || !self.HasRole(types.RoleIngress) {
		return nil
	}
	var ports []uint16
	for _, n := range s.members {
		if !s.live[n.Identity] {
			continue
		}
		for _, p := range n.Published {
			if p.Public != 0 {
				ports = append(ports, p.Public)
			}
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// noteIngressPorts has [Options.IngressPorts] list, of ports, those the
// ingress listens on, one a line, for the host's firewall to let in: a port
// another program holds is no ingress's to open. It is written where they
// changed alone, since each write has the firewall follow.
func (d *Daemon) noteIngressPorts(ports []uint16) {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	d.pub.publicWant = slices.Clone(ports)
	d.writeIngressPortsLocked()
}

// NoteIngressListening is what the ingress said it listens on.
func (d *Daemon) NoteIngressListening(ports []uint16) {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	d.pub.ingressListening, d.pub.listeningSet = slices.Clone(ports), true
	d.writeIngressPortsLocked()
}

func (d *Daemon) writeIngressPortsLocked() {
	ports := slices.DeleteFunc(slices.Clone(d.pub.publicWant), func(p uint16) bool {
		return !slices.Contains(d.pub.ingressListening, p)
	})
	switch {
	case d.ingressPorts == "" || d.pub.publicSet && slices.Equal(d.pub.publicPorts, ports):
		return
	case !d.pub.listeningSet && len(ports) == 0 && len(d.pub.publicWant) > 0:
		return // until the ingress says, as after juistd restarted beside it
	}
	var b strings.Builder
	for _, p := range ports {
		fmt.Fprintf(&b, "%d\n", p)
	}
	// Renamed into place: the firewall reads it as it changes, and would
	// read a file half written as ports withdrawn.
	tmp := d.ingressPorts + ".new"
	err := os.WriteFile(tmp, []byte(b.String()), 0o644)
	if err == nil {
		err = os.Rename(tmp, d.ingressPorts)
	}
	if err != nil {
		d.logOnce("daemon: telling the firewall the ingress's ports: " + err.Error())
		return
	}
	d.pub.publicPorts, d.pub.publicSet = slices.Clone(ports), true
}

// ingressPorts are the ports of this device's own addresses an ingress may
// open by TCP, and send UDP to.
type ingressPorts struct{ TCP, UDP []uint16 }

// access is the ports as the data plane passes them.
func (p ingressPorts) access() []conn.Ports {
	var out []conn.Ports
	for _, l := range []struct {
		proto ipproto.Proto
		ports []uint16
	}{{ipproto.TCP, p.TCP}, {ipproto.UDP, p.UDP}} {
		for _, port := range slices.Sorted(slices.Values(l.ports)) {
			if n := len(out); n == 0 || out[n-1] != (conn.Ports{Proto: l.proto, First: port, Last: port}) {
				out = append(out, conn.Ports{Proto: l.proto, First: port, Last: port})
			}
		}
	}
	return out
}

// planPublish is the ports an ingress may open on this device: log sync's,
// and those of the names the log publishes on it, once its operator agreed,
// and its shares', while its view is fresh, so that a withdrawn name ends at
// the freshness TTL; by UDP too, those of names offered HTTP/3, for QUIC.
func (d *Daemon) planPublish(s snapshot, fresh bool) ingressPorts {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	self, _ := s.state.Node(d.self)
	ports := ingressPorts{TCP: []uint16{d.gossipPort}}
	if fresh && slices.ContainsFunc(d.pub.shares, func(sh *share) bool { return sh.live(time.Unix(s.now, 0)) }) {
		if _, err := shareName(s.state, d.self); err == nil {
			ports.TCP = append(ports.TCP, sharePort)
		}
	}
	d.pub.status = nil
	if !d.pub.consent && len(self.Published) == 0 {
		return ports
	}
	st := &ipc.Publish{Consent: d.pub.consent, Ends: d.pub.consent && len(d.pub.to) > 0}
	switch {
	case !d.pub.consent:
	case len(self.Published) == 0:
		st.NotServing = nothingPublished
	case !fresh:
		st.NotServing = "this device's view of the network is stale"
	default:
		for _, p := range self.Published {
			ports.TCP = append(ports.TCP, p.Port)
			to, ok := passedTo(p, d.pub.to, d.pub.members)
			if ok && p.Public == 0 && ipc.OffersHTTP3(to) && !p.Members {
				ports.UDP = append(ports.UDP, p.Port)
			}
			name := p.Under(s.state.Domain())
			st.Serving = append(st.Serving, name)
			other, shared := sharedService(self.Published, d.pub.to, rawShare(d.pub.shares, time.Unix(s.now, 0)))[p.Label]
			switch {
			case !ok && d.pub.members[p.Label] && d.pub.to[p.Label] != "":
				st.Withheld = append(st.Withheld, name)
			case !ok:
			case shared && other == "":
				st.Shared = append(st.Shared, name+" with this device's share")
			case shared:
				st.Shared = append(st.Shared, name+" with "+(types.PublishedName{Label: other}).Under(s.state.Domain()))
			case p.Public != 0:
				st.Passing = append(st.Passing, name+" to "+to)
			default:
				st.Ending = append(st.Ending, name+" to "+to)
				st.CAA = append(st.CAA, d.pub.account.CAA(name)...)
			}
		}
	}
	d.pub.status = st
	return ports
}

// publishing reports whether this device serves something published on it.
func (d *Daemon) publishing() bool {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	return d.pub.status != nil && len(d.pub.status.Serving) > 0
}

// notePublishing has the announcement say whether this device serves what is
// published on it, members resolving its names to it only where it does.
func (d *Daemon) notePublishing() {
	on := d.publishing()
	d.mu.Lock()
	changed := d.servingPublished != on
	d.servingPublished = on
	d.mu.Unlock()
	if changed {
		d.MarkDirty()
	}
}

// publishNow is a copy of what the last reconcile made of published names.
func (d *Daemon) publishNow() *ipc.Publish {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	if d.pub.status == nil {
		return nil
	}
	st := *d.pub.status
	st.Serving, st.Ending, st.CAA = slices.Clone(st.Serving), slices.Clone(st.Ending), slices.Clone(st.CAA)
	st.Passing = slices.Clone(st.Passing)
	return &st
}

// Serving is what a terminator on this device ends TLS for: each name the
// log publishes here that the operator said where to send, on this
// device's own addresses; nothing without the operator's word or while the
// view is stale. It is the terminator asking, with its report, if any.
func (d *Daemon) Serving(r *ipc.TerminatorReport) *ipc.Published {
	return d.serving(r, true)
}

// terminatorSilence is how long the terminator, which asks every 5 s, may
// go without asking before the status says it does not run.
const terminatorSilence = 15 * time.Second

// terminatorStatus is what the status says of the terminator, nil where it
// never asked.
func (d *Daemon) terminatorStatus() *ipc.Terminator {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	if d.pub.asked.IsZero() {
		return nil
	}
	return &ipc.Terminator{Running: d.now().Sub(d.pub.asked) <= terminatorSilence,
		Listening: slices.Clone(d.pub.listening), Unbound: slices.Clone(d.pub.unbound),
		NoCert: slices.Clone(d.pub.noCert)}
}

// terminatorSilent reports whether the terminator has not asked lately.
func (d *Daemon) terminatorSilent() bool {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	return d.now().Sub(d.pub.asked) > terminatorSilence
}

// serving is [Daemon.Serving], asked by the terminator or, where not, by
// someone looking.
func (d *Daemon) serving(r *ipc.TerminatorReport, byTerminator bool) *ipc.Published {
	var account *ipc.ACMEAccount
	if r != nil {
		account = r.Account
	}
	if byTerminator {
		d.pub.mu.Lock()
		d.pub.asked = d.now()
		if r != nil {
			d.pub.listening, d.pub.unbound = slices.Clone(r.Listening), slices.Clone(r.Unbound)
			d.pub.noCert = slices.Clone(r.NoCert)
		}
		stopping := r != nil && r.Stopping
		if stopping {
			d.pub.asked = time.Time{}
		}
		d.pub.mu.Unlock()
		if stopping {
			return &ipc.Published{}
		}
	}
	if account != nil {
		d.pub.mu.Lock()
		changed := d.pub.account == nil || d.pub.account.URI != account.URI ||
			!slices.Equal(d.pub.account.Issuers, account.Issuers)
		d.pub.account = account
		d.pub.mu.Unlock()
		if changed {
			d.MarkDirty()
		}
	}
	out := &ipc.Published{}
	d.pub.mu.Lock()
	out.Idle = d.terminatorWanted != "" && !d.wantsTerminatorLocked()
	d.pub.mu.Unlock()
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return out
	}
	now := d.now()
	self, ok := state.Node(d.self)
	if !ok || self.Expired(now.Unix()) || !d.freshness(now).Fresh(now.Unix()) {
		return out
	}
	var addrs []netip.Addr
	for _, a := range d.overlayAddrs(state, d.self, now.Unix()) {
		addrs = append(addrs, a.Addr())
	}
	for _, n := range state.NodesWithRole(types.RoleIngress) {
		for _, a := range d.overlayAddrs(state, n.Identity, now.Unix()) {
			out.Ingresses = append(out.Ingresses, a.Addr())
		}
	}
	// A share is its operator's word: it needs no other.
	// One look at the shares, so that what is served and what a name for
	// members is checked against agree.
	shares := d.sharesNow(now)
	if t, ok := d.shareServed(state, addrs, shares); ok {
		out.Names = append(out.Names, t)
	}
	d.pub.mu.Lock()
	consent, to, members := d.pub.consent, d.pub.to, d.pub.members
	d.pub.mu.Unlock()
	if !consent {
		return out
	}
	var s *snapshot
	var shs []*share
	for _, sh := range shares {
		shs = append(shs, &sh)
	}
	shared := sharedService(self.Published, to, rawShare(shs, now))
	for _, p := range self.Published {
		dst, ok := passedTo(p, to, members)
		if _, sh := shared[p.Label]; !ok || sh {
			continue
		}
		t := ipc.PublishedTarget{Name: p.Under(state.Domain()), Addrs: addrs, Port: p.Port, Proxy: p.Proxy,
			To: dst, Public: p.Public}
		if !p.Members {
			addPublished(out, t)
			continue
		}
		if s == nil {
			m := d.membersOf(state)
			s = &m
		}
		t.From = d.membersFor(*s, p.Label)
		out.Members = append(out.Members, t)
	}
	return out
}

// sharedService is, by label, each name for members alone of ps whose
// service another name's bytes reach as they are, or a share's, at raw, and
// that name, "" for the share: a service picking its site by the Host a
// client sends would answer a client of the other for it. A name whose HTTP
// juist proxies is held to its own Host.
func sharedService(ps []types.PublishedName, to map[string]string, raw string) map[string]string {
	addr := func(t string) string {
		if _, page := ipc.StatusPageOf(t); page {
			return ""
		}
		a, _ := ipc.HTTP2Of(t)
		return sameService(a)
	}
	out := map[string]string{}
	for _, p := range ps {
		mine := addr(to[p.Label])
		if !p.Members || mine == "" {
			continue
		}
		if raw != "" && addr(raw) == mine {
			out[p.Label] = ""
			continue
		}
		for _, q := range ps {
			t, ok := to[q.Label]
			// HTTP/3 is proxied where juist ends TLS; by TCP, bytes pass as they are.
			if _, h3 := ipc.HTTP3Of(t); ok && q.Label != p.Label && !(h3 && q.Public == 0) && addr(t) == mine {
				out[p.Label] = q.Label
				break
			}
		}
	}
	return out
}

// sameService is addr as one service is named however it is spelled: a
// loopback or unspecified address as 127.0.0.1, localhost too, the port as
// a number.
func sameService(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(n, 10)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		if a = a.Unmap(); a.IsLoopback() || a.IsUnspecified() {
			host = "127.0.0.1"
		} else {
			host = a.String()
		}
	} else if host == "localhost" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// rawShare is where the shares live at now go as they are: the one without
// a path where it is the only one, whose bytes the terminator passes on;
// with paths it proxies their HTTP, held to the share's own Host.
func rawShare(shs []*share, now time.Time) string {
	var to string
	for _, sh := range shs {
		switch {
		case !sh.live(now):
		case sh.prefix != "":
			return ""
		default:
			to = sh.to
		}
	}
	return to
}

// membersFor are the overlay addresses of the members s lets open this
// device's name for members alone label: every live one but an ingress and a
// service member where the network has no policy, those it names under one,
// and this device itself.
func (d *Daemon) membersFor(s snapshot, label string) []netip.Addr {
	var out []netip.Addr
	for _, n := range s.members {
		// Not this device itself: its own programs, one a client can make
		// ask, would come from its overlay address.
		switch {
		case n.Identity == d.self, !s.live[n.Identity], n.HasRole(types.RoleIngress), n.HasRole(types.RoleService):
			continue
		case s.view.Restricted && !slices.Contains(s.view.In[n.Identity].Names, label):
			continue
		}
		for _, a := range s.state.Addrs(n.Identity, s.now) {
			out = append(out, a.Addr())
		}
	}
	return out
}

// servesPublished reports whether id serves what is published on it: this
// device as its last reconcile found, another as its announcement says.
func (d *Daemon) servesPublished(id types.Identity) bool {
	if id == d.self {
		return d.publishing()
	}
	ep, ok := d.endpoints.Get(id)
	return ok && ep.Published
}

// Published is what an ingress on this device serves: every name published
// in the network whose target serves it, and every member's share, under its
// own name while its announcement holds, and where they go; a name published
// by TCP whose target does not serve it, with no address; nothing while this
// device is no ingress or its view is stale.
func (d *Daemon) Published() *ipc.Published {
	out := &ipc.Published{}
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return out
	}
	now := d.now()
	self, ok := state.Node(d.self)
	if !ok || self.Expired(now.Unix()) || !self.HasRole(types.RoleIngress) {
		return out
	}
	// Whatever the freshness: the relay is how members bring it back.
	if t, ok := d.relayHandedOn(); ok {
		out.Relays = append(out.Relays, t)
	}
	if !d.freshness(now).Fresh(now.Unix()) {
		return out
	}
	s := d.membersOf(state)
	for _, n := range s.members {
		if !s.live[n.Identity] {
			continue
		}
		if name, err := shareName(state, n.Identity); err == nil && n.Identity != d.self && d.sharing(n.Identity, now) {
			t := ipc.PublishedTarget{Name: name, Port: sharePort}
			for _, a := range d.overlayAddrs(state, n.Identity, now.Unix()) {
				t.Addrs = append(t.Addrs, a.Addr())
			}
			out.Names = append(out.Names, t)
		}
		serves := d.servesPublished(n.Identity)
		for _, p := range n.Published {
			// A public port is held while its target does not serve it,
			// with nowhere to go, as the host's firewall lets it in.
			if !serves && p.Public == 0 {
				continue
			}
			t := ipc.PublishedTarget{Name: p.Under(state.Domain()), Port: p.Port, Proxy: p.Proxy, Public: p.Public}
			for _, a := range d.overlayAddrs(state, n.Identity, now.Unix()) {
				if serves {
					t.Addrs = append(t.Addrs, a.Addr())
				}
			}
			if p.Members {
				out.Members = append(out.Members, t)
				continue
			}
			addPublished(out, t)
		}
	}
	// The relay keeps its name: a member's name the same would be handed
	// the relay's clients, and its certificate's challenges.
	relayed := func(t ipc.PublishedTarget) bool {
		return slices.ContainsFunc(out.Relays, func(r ipc.PublishedTarget) bool { return r.Name == t.Name })
	}
	out.Names, out.Members = slices.DeleteFunc(out.Names, relayed), slices.DeleteFunc(out.Members, relayed)
	slices.SortFunc(out.Names, func(x, y ipc.PublishedTarget) int { return strings.Compare(x.Name, y.Name) })
	slices.SortFunc(out.Members, func(x, y ipc.PublishedTarget) int { return strings.Compare(x.Name, y.Name) })
	slices.SortFunc(out.TCP, func(x, y ipc.PublishedTarget) int { return cmp.Compare(x.Public, y.Public) })
	return out
}

// relayHandedOn is where the ingress here hands the relay's public name on:
// the relay's own port, on loopback, the client named in a PROXY header.
func (d *Daemon) relayHandedOn() (ipc.PublishedTarget, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Only once the relay takes them at the hand-off socket.
	if d.relay == nil || d.relayCerts == nil || !d.httpsHanded {
		return ipc.PublishedTarget{}, false
	}
	return ipc.PublishedTarget{Name: d.relayName, Socket: d.handOffPath, Proxy: true}, true
}

// addPublished puts t in p's list of the names published as t is: by TCP
// or by TLS.
func addPublished(p *ipc.Published, t ipc.PublishedTarget) {
	if t.Public != 0 {
		p.TCP = append(p.TCP, t)
	} else {
		p.Names = append(p.Names, t)
	}
}

// passedTo is where p goes on this device, as to has it by label: for a name
// published by TCP, an address alone, which HTTP/2 and the status page are
// not, being TLS's; nowhere where members says the service is for members
// alone and the log has p public.
func passedTo(p types.PublishedName, to map[string]string, members map[string]bool) (string, bool) {
	dst, ok := to[p.Label]
	if members[p.Label] && !p.Members {
		return "", false
	}
	if !ok || p.Public == 0 {
		return dst, ok
	}
	if _, page := ipc.StatusPageOf(dst); page {
		return "", false
	}
	addr, _ := ipc.HTTP2Of(dst)
	return addr, true
}
