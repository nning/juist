package daemon

import (
	"errors"
	"maps"
	"net/netip"
	"slices"

	"github.com/nning/juist/internal/changelog"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// errNoStatusPage refuses the status page where the operator serves none.
var errNoStatusPage = errors.New("this device serves no status page")

// servesStatusPage reports whether the operator agreed to serve a status
// page here.
func (s *Service) servesStatusPage() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prefs.ServePublished && slices.ContainsFunc(slices.Collect(maps.Values(s.prefs.ServeTo)), func(to string) bool {
		_, ok := ipc.StatusPageOf(to)
		return ok
	})
}

// StatusPage is what a status page served here shows.
func (s *Service) StatusPage() (*ipc.StatusPage, error) {
	if !s.servesStatusPage() {
		return nil, errNoStatusPage
	}
	p := &ipc.StatusPage{Status: s.Status()}
	m := s.Mesh()
	if m == nil {
		return p, nil
	}
	var err error
	p.Members, p.Shares, _ = m.pageMembers()
	if p.Changes, p.Total, err = s.Changes(ipc.MaxPageChanges); err != nil {
		return nil, err
	}
	return p, nil
}

// Changes are the log's newest changes, at most max, newest first, as juist
// log lists them, and how many it holds; none while no mesh runs.
func (s *Service) Changes(max int) ([]ipc.Change, int, error) {
	m := s.Mesh()
	if m == nil {
		return nil, 0, nil
	}
	chain, err := m.Chain()
	if err != nil {
		return nil, 0, err
	}
	_, _, admins := m.pageMembers()
	entries := changelog.Of(chain, admins)
	var out []ipc.Change
	for i := len(entries) - 1; i >= 0 && len(out) < max; i-- {
		e := entries[i]
		out = append(out, ipc.Change{Index: i, What: e.What, Signers: e.Signers, Hash: e.Hash})
	}
	return out, len(entries), nil
}

// pageMembers is, for a status page, the overlay addresses of every member
// but an ingress, the names members share under now, and the admin keys.
func (d *Daemon) pageMembers() ([]netip.Addr, []string, []types.AdminKey) {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil, nil, nil
	}
	now := d.now()
	var members []netip.Addr
	var shares []string
	for _, n := range state.Nodes() {
		if n.Expired(now.Unix()) {
			continue
		}
		if !n.HasRole(types.RoleIngress) {
			for _, a := range state.Addrs(n.Identity, now.Unix()) {
				members = append(members, a.Addr())
			}
		}
		if name, err := shareName(state, n.Identity); err == nil && d.sharing(n.Identity, now) {
			shares = append(shares, name)
		}
	}
	slices.Sort(shares)
	return members, shares, state.Admins()
}
