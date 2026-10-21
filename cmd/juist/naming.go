package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// resolveDevice finds a member by name, identity key, the start of one, or
// an overlay address.
func resolveDevice(state *log.State, arg string) (types.NodeRecord, error) {
	nodes := state.Nodes()
	var matches []types.NodeRecord
	addr, addrErr := netip.ParseAddr(arg)
	for _, n := range nodes {
		switch {
		case strings.EqualFold(n.Name, arg),
			n.Identity.String() == arg,
			len(arg) >= 8 && strings.HasPrefix(n.Identity.String(), arg),
			len(arg) >= 8 && strings.HasPrefix(n.Identity.String(), "nid:"+arg),
			addrErr == nil && (state.Addr6(n.Identity) == addr || slices.Contains(n.V4Addrs(), addr)):
			matches = append(matches, n)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return types.NodeRecord{}, fmt.Errorf("no device %q in %q\nhint: juist devices", arg, state.Network())
	default:
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = displayMember(m) + " " + m.Identity.ShortString()
		}
		return types.NodeRecord{}, fmt.Errorf("%q matches %d devices (%s); use a key",
			arg, len(matches), strings.Join(names, ", "))
	}
}

func displayMember(n types.NodeRecord) string {
	if n.Name != "" {
		return n.Name
	}
	return n.Identity.ShortString()
}

// uniqueName returns name, or name with a number appended if a member already
// uses it: devices are removed and addressed by name, so two alike are a trap.
//
// Names are compared as resolveDevice compares them, folded, so that no two
// members are told apart only by what "juist remove" ignores.
func uniqueName(state *log.State, name string) string {
	used := map[string]bool{}
	for _, n := range state.Nodes() {
		used[foldName(n.Name)] = true
	}
	if !used[foldName(name)] {
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
		if types.ValidateName(candidate) == nil && !used[foldName(candidate)] {
			return candidate
		}
	}
}

// fileSafe turns a member name into something usable in a file name.
func fileSafe(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "device"
	}
	return b.String()
}

// foldName is how names are compared: the log's rule for holders, and the
// CLI's for every other name.
func foldName(s string) string { return types.FoldName(s) }

// checkName holds a name a person gives — a device's, an admin key's, the
// network's — to one spelling: ASCII letters and digits, and ".", "_" and "-"
// after the first. The log accepts more, but names are what "juist remove"
// takes and what reaches everyone's terminal and command line, so a name
// that looks like another, or that a shell would read as code, is refused
// where it is first given.
func checkName(what, name string) error {
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

// memberName makes a name a joining device proposed into one checkName
// accepts: the device chose it, and the admin's log is where it ends up.
func memberName(proposed string) string {
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
	if name == "" || checkName("name", name) != nil {
		return "device"
	}
	return name
}
