package govern

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"go4.org/netipx"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Sealer draws each epoch's group secret, sealed to the members.
func Sealer() log.Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
}

// DrawBreakGlass draws a network's one break-glass secret, which its founder
// is shown once and nothing keeps, and the genesis's commitment to it.
func DrawBreakGlass() (types.DisablementSecret, types.Hash, error) {
	var s types.DisablementSecret
	if _, err := rand.Read(s[:]); err != nil {
		return s, types.Hash{}, fmt.Errorf("drawing the break-glass secret: %w", err)
	}
	return s, types.DisablementCommit(s[:]), nil
}

// V4DrawBits is the length of the prefix a network founded without a range
// numbers from: 1022 addresses, one of 128 in [types.OverlayV4]. That is
// about twice [types.MaxNodes] at once, and 1022 admissions over the network's
// life, since no address is handed out twice; renumbering into a larger
// range makes room. A network holding all of 198.18/15 would overlap every
// other on a host that is in two.
const V4DrawBits = 22

// DrawV4 picks a random /22 in [types.OverlayV4] that taken leaves. The
// first is never drawn: a network founded before prefixes were drawn numbers
// from the start of the range, so a host in one of those and a new one would
// otherwise hold the same addresses.
func DrawV4(taken func(netip.Prefix) bool) (netip.Prefix, error) {
	candidates := V4DrawCandidates()
	for _, i := range mathrand.Perm(len(candidates)) {
		if !taken(candidates[i]) {
			return candidates[i], nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("every /%d in %v overlaps a network on this host\n"+
		"hint: choose the range with --ipv4", V4DrawBits, types.OverlayV4)
}

// V4DrawCandidates lists the prefixes [DrawV4] draws from, in order: every
// /22 in [types.OverlayV4] but the first.
func V4DrawCandidates() []netip.Prefix {
	var out []netip.Prefix
	p := netip.PrefixFrom(types.OverlayV4.Addr(), V4DrawBits)
	for types.OverlayV4.Contains(p.Addr()) {
		out = append(out, p)
		p = netip.PrefixFrom(netipx.PrefixLastIP(p).Next(), V4DrawBits)
	}
	return out[1:]
}

// A Grant is who a record gave an IPv4 address to.
type Grant struct {
	ID   types.Identity
	Name string
}

// GivenOut maps every IPv4 address a member holds, or any record in history
// gave out, to whom it went last. A device removed a moment ago still
// believes it holds its address, and so do members that have not heard of
// the removal yet; the same goes for an address a renumbering retired.
func GivenOut(state *log.State, history []types.AUM) map[netip.Addr]Grant {
	out := map[netip.Addr]Grant{}
	mark := func(nodes []types.NodeRecord) {
		for _, n := range nodes {
			for _, v4 := range n.V4Addrs() {
				out[v4] = Grant{n.Identity, n.Name}
			}
		}
	}
	for i := range history {
		switch h := &history[i]; {
		case h.Node != nil:
			mark([]types.NodeRecord{*h.Node})
		case h.State != nil:
			mark(h.State.Nodes)
		case h.Renumber != nil && h.Subject != nil && h.Renumber.V4 != nil:
			out[*h.Renumber.V4] = Grant{ID: *h.Subject}
		case h.Renumber != nil:
			for _, e := range h.Renumber.Addrs {
				out[e.V4] = Grant{ID: e.Identity}
			}
		}
	}
	mark(state.Nodes())
	return out
}

// NextV4 returns the lowest overlay IPv4 address in the network's range that
// is not [GivenOut]: handing on one a removed device still believes it holds
// would have members route one device's traffic to another. history includes
// the records off the chain, whose admissions may yet be reissued.
func NextV4(state *log.State, history []types.AUM) (netip.Addr, error) {
	taken := map[netip.Addr]bool{}
	for v4 := range GivenOut(state, history) {
		taken[v4] = true
	}
	v4, err := FirstFreeV4(state.V4Range(), taken)
	if err != nil && len(state.Nodes()) < types.MaxNodes {
		// Full by history rather than by members: every address has been
		// given out once. A range of its own is 1022 addresses for good.
		return netip.Addr{}, fmt.Errorf("%w: every address in it went to a device once, and none is "+
			"handed out twice\nhint: juist network renumber PREFIX, into a larger range", err)
	}
	return v4, err
}

// FirstFreeV4 skips r's first and last address, which some systems treat as
// the network and broadcast address.
func FirstFreeV4(r netip.Prefix, taken map[netip.Addr]bool) (netip.Addr, error) {
	last := netipx.PrefixLastIP(r)
	for a := r.Addr().Next(); a.Less(last); a = a.Next() {
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IPv4 range %v full", r)
}

// UniqueName returns name, or name with a number appended if a member already
// uses it: devices are removed and addressed by name, so two alike are a trap.
// Names are compared folded, so that no two members are told apart only by
// what "juist remove" ignores.
func UniqueName(state *log.State, name string) string {
	used := map[string]bool{}
	for _, n := range state.Nodes() {
		used[types.FoldName(n.Name)] = true
	}
	if !used[types.FoldName(name)] {
		return name
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf("-%d", i)
		base := name
		for len(base)+len(suffix) > types.MaxNameLen {
			_, size := utf8.DecodeLastRuneInString(base)
			base = base[:len(base)-size]
		}
		candidate := strings.TrimRight(base, " \t") + suffix
		if types.ValidateName(candidate) == nil && !used[types.FoldName(candidate)] {
			return candidate
		}
	}
}

// CheckName holds a name a person gives — a device's, an admin key's, the
// network's — to one spelling: ASCII letters and digits, and ".", "_" and "-"
// after the first. The log accepts more, but names are what "juist remove"
// takes and what reaches everyone's terminal and command line, so a name
// that looks like another, or that a shell would read as code, is refused
// where it is first given.
func CheckName(what, name string) error {
	if err := types.ValidateName(name); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	for i, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			i > 0 && strings.ContainsRune("._-", r)) {
			return fmt.Errorf("%s %q: letters, digits, then also . _ -", what, name)
		}
	}
	return nil
}

// MemberName makes a name a joining device proposed into one CheckName
// accepts: the device chose it, and the admin's log is where it ends up.
func MemberName(proposed string) string {
	var b strings.Builder
	dash := false
	for _, r := range proposed {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_'
		switch {
		case ok:
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	name := strings.TrimLeft(strings.TrimRight(b.String(), "-"), "._-")
	if len(name) > types.MaxNameLen {
		name = strings.TrimRight(name[:types.MaxNameLen], "._-")
	}
	if name == "" || CheckName("name", name) != nil {
		return "device"
	}
	return name
}

// ErrLastVoucher says a change takes the network's last voucher, after which
// freshness goes unchecked: allowed, but worth saying.
var ErrLastVoucher = errors.New("the last voucher; without one, freshness goes unchecked")

// VoucherLoss is asked before target stops being a voucher: an error where
// the network would keep fewer vouchers than its threshold, after which every
// device goes stale, and [ErrLastVoucher] where none would be left.
func VoucherLoss(state *log.State, target types.NodeRecord) error {
	if !slices.Contains(target.Roles, types.RoleAdmin) {
		return nil
	}
	switch left := len(state.NodesWithRole(types.RoleAdmin)) - 1; {
	case left == 0:
		return ErrLastVoucher
	case uint32(left) < state.Vouchers():
		return fmt.Errorf("%s is one of the %d vouchers needed; without it every device goes stale\n"+
			"hint: juist admins vouchers %d", cmp.Or(target.Name, target.Identity.ShortString()), state.Vouchers(), left)
	}
	return nil
}
