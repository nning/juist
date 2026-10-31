package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
)

// filter builds the packet policy: any member may send anything to any other
// member. It is installed explicitly, because a nil filter drops every inbound
// packet, and built from Match values directly rather than through
// tailcfg.FilterRule's parser, which only adds failure modes.
func (m *tsManager) filter() (*filter.Filter, error) {
	st := m.state.Load()
	srcs := make([]netip.Prefix, 0, len(st.peers))
	for _, p := range st.peers {
		srcs = append(srcs, p.Addrs...)
	}

	serves := m.serve.Routes
	if len(serves) > 0 {
		var nets []netip.Prefix
		var hosts []netip.Addr
		if m.exits != nil {
			nets, hosts = m.exits.lans()
		} else {
			nets, hosts = attached(m.tunName)
		}
		serves = served(serves, nets, hosts)
	}
	// A subnet router's networks are the very ones it serves.
	serves = append(serves, m.serve.Subnets...)
	var localNets netipx.IPSetBuilder
	dsts := make([]filtertype.NetPortRange, 0, len(m.self.Addrs)+len(serves))
	// What this node serves its peers is theirs to send to, as its own
	// addresses are; nothing else outside them is.
	for _, pfx := range slices.Concat(m.self.Addrs, serves) {
		localNets.AddPrefix(pfx)
		dsts = append(dsts, filtertype.NetPortRange{Net: pfx, Ports: filtertype.AllPorts})
	}
	ls, err := localNets.IPSet()
	if err != nil {
		return nil, fmt.Errorf("building local net set: %w", err)
	}
	if len(srcs) == 0 {
		return filter.NewAllowNone(m.logf, ls), nil
	}
	matches := []filter.Match{{
		IPProto: allIPProtos,
		Srcs:    srcs,
		Dsts:    dsts,
	}}
	// Sharing state with the previous filter carries the flow-tracking cache
	// across rebuilds, so a membership change does not send every established
	// UDP flow back through the slow path. Nil on the first build.
	return filter.New(matches, nil, ls, ls, m.eng.GetFilter(), m.logf), nil
}

// refilter builds the packet filter again, where this node serves as an exit
// node.
func (m *tsManager) refilter() {
	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed || !m.serve.serving() {
		return
	}
	filt, err := m.filter()
	if err != nil {
		m.logf("conn: building filter: %v", err)
		return
	}
	m.eng.SetFilter(filt)
}

// allIPProtos enumerates every IP protocol number, the only way to say "any
// protocol": Match.IPProto is a membership test with no wildcard.
var allIPProtos = func() views.Slice[ipproto.Proto] {
	p := make([]ipproto.Proto, 256)
	for i := range p {
		p[i] = ipproto.Proto(i)
	}
	return views.SliceOf(p)
}()

func (m *tsManager) Unguarded() string {
	if g, ok := m.inGuard.(unguardedRouter); ok {
		return g.unguardedBy()
	}
	return ""
}

// AnswersThrough is why answers to what comes in by another device would go
// through the exit node though not isolated, "" where they leave the way
// they came, or where there is no device.
func (m *tsManager) AnswersThrough() string {
	if m.exits == nil {
		return ""
	}
	return m.exits.answersThrough()
}

// tunnelledBy is what peers carry, answers as asked.
func (m *tsManager) tunnelledBy(peers map[key.NodePublic]Peer) tunnelled {
	t := tunnelledBy(peers)
	t.answers = m.isolate
	return t
}

// errNoExits is egress or serving asked of a node that routes nothing itself.
var errNoExits = errors.New("conn: exit nodes need a device of this node's own")

func (m *tsManager) SetEgress(e Egress, isolate bool) error {
	m.apply.Lock()
	defer m.apply.Unlock()
	m.isolate = isolate
	switch {
	case m.closed:
		return errors.New("conn: manager is closed")
	case e == EgressDirect && m.egress == EgressDirect:
		return nil
	case m.exits == nil && e != EgressDirect:
		return errNoExits
	}
	// Given again, the router installs it again: a route someone flushed is
	// not announced, and every reconcile gives the egress.
	if m.exits != nil {
		t := m.tunnelledBy(m.state.Load().peers)
		if err := m.exits.setEgress(e, t); err != nil {
			return err
		}
		m.tunnelled = t
	}
	m.egress = e
	return nil
}

func (m *tsManager) SetServe(s Serve) error {
	s = Serve{Routes: slices.Clone(s.Routes), Subnets: slices.Clone(s.Subnets), Sources: slices.Clone(s.Sources), DNS: s.DNS}
	m.apply.Lock()
	defer m.apply.Unlock()
	switch {
	case m.closed:
		return errors.New("conn: manager is closed")
	case slices.Equal(s.Routes, m.serve.Routes) && slices.Equal(s.Subnets, m.serve.Subnets) &&
		slices.Equal(s.Sources, m.serve.Sources) && s.DNS == m.serve.DNS:
		// Given again, the router installs it again, as it does egress; where
		// it no longer may, nothing is served.
		if s.serving() && m.exits != nil {
			if err := m.exits.setServe(s); err != nil {
				m.serve = Serve{}
				return errors.Join(err, m.reconfig())
			}
		}
		return nil
	case m.exits == nil && s.serving():
		return errNoExits
	}
	for _, r := range slices.Concat(s.Routes, s.Subnets) {
		if tsaddr.PrefixesContainsIP(m.self.Addrs, r.Addr()) || !r.IsValid() || r.Masked() != r {
			return fmt.Errorf("conn: route %v to serve is not a prefix outside this node", r)
		}
	}
	// Masquerading before the filter lets anything through, and taking it
	// away after, so that nothing leaves with an overlay source.
	if s.serving() && m.exits != nil {
		if err := m.exits.setServe(s); err != nil {
			return err
		}
	}
	m.serve = s
	err := m.reconfig()
	if !s.serving() && m.exits != nil {
		err = errors.Join(err, m.exits.setServe(s))
	}
	return err
}
