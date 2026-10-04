package daemon

import (
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

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
	account *ipc.ACMEAccount  // the terminator's, as it last said
	asked   time.Time         // when the terminator last asked

	// listening and unbound are where the terminator last said it listens,
	// and where another program holds the port, as ADDR:PORT; noCert, the
	// names it said it has no certificate for.
	listening, unbound []string
	noCert             []ipc.NoCert
	status             *ipc.Publish
	share              *share // what this device publishes under its own name

	// flagged is whether the terminator's file was last left to exist,
	// once flagSet.
	flagged, flagSet bool
}

// nothingPublished is why a device the log publishes nothing on serves none.
const nothingPublished = "the network publishes nothing on this device"

// SetPublishConsent records whether this device's operator agrees to serve
// the names the log publishes on it, and where those go whose TLS juist ends,
// by label.
func (d *Daemon) SetPublishConsent(on bool, to map[string]string) {
	d.pub.mu.Lock()
	d.pub.consent, d.pub.to = on, maps.Clone(to)
	d.flagTerminatorLocked()
	d.pub.mu.Unlock()
	d.MarkDirty()
}

// wantsTerminatorLocked reports whether this device needs its terminator: a
// name whose TLS juist ends, or a share. d.pub.mu is held.
func (d *Daemon) wantsTerminatorLocked() bool {
	return d.pub.consent && len(d.pub.to) > 0 || d.pub.share != nil
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

// planPublish is the TCP ports an ingress may open on this device: log
// sync's, and those of the names the log publishes on it, once its operator
// agreed, and its share's, while its view is fresh, so that a withdrawn name
// ends at the freshness TTL.
func (d *Daemon) planPublish(s snapshot, fresh bool) []uint16 {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	self, _ := s.state.Node(d.self)
	ports := []uint16{d.gossipPort}
	if sh := d.pub.share; sh != nil && fresh && (sh.end.IsZero() || s.now < sh.end.Unix()) {
		if _, err := shareName(s.state, d.self); err == nil {
			ports = append(ports, sharePort)
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
			if !slices.Contains(ports, p.Port) {
				ports = append(ports, p.Port)
			}
			st.Serving = append(st.Serving, p.Under(s.state.Domain()))
			if to, ok := d.pub.to[p.Label]; ok {
				st.Ending = append(st.Ending, p.Under(s.state.Domain())+" to "+to)
				st.CAA = append(st.CAA, d.pub.account.CAA(p.Under(s.state.Domain()))...)
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
	if t, ok := d.shareServed(state, addrs, now); ok {
		out.Names = append(out.Names, t)
	}
	d.pub.mu.Lock()
	consent, to := d.pub.consent, d.pub.to
	d.pub.mu.Unlock()
	if !consent {
		return out
	}
	for _, p := range self.Published {
		if dst, ok := to[p.Label]; ok {
			out.Names = append(out.Names, ipc.PublishedTarget{Name: p.Under(state.Domain()), Addrs: addrs,
				Port: p.Port, Proxy: p.Proxy, To: dst})
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
// own name while its announcement holds, and where they go; nothing while
// this device is no ingress or its view is stale.
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
	if !ok || self.Expired(now.Unix()) || !self.HasRole(types.RoleIngress) || !d.freshness(now).Fresh(now.Unix()) {
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
		if !d.servesPublished(n.Identity) {
			continue
		}
		for _, p := range n.Published {
			t := ipc.PublishedTarget{Name: p.Under(state.Domain()), Port: p.Port, Proxy: p.Proxy}
			for _, a := range d.overlayAddrs(state, n.Identity, now.Unix()) {
				t.Addrs = append(t.Addrs, a.Addr())
			}
			out.Names = append(out.Names, t)
		}
	}
	slices.SortFunc(out.Names, func(x, y ipc.PublishedTarget) int { return strings.Compare(x.Name, y.Name) })
	return out
}
