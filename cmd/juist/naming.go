package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nning/juist/internal/govern"
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
		return types.NodeRecord{}, fmt.Errorf("%q matches %d devices: %s\nhint: give a key",
			arg, len(matches), strings.Join(names, ", "))
	}
}

func displayMember(n types.NodeRecord) string {
	if n.Name != "" {
		return n.Name
	}
	return n.Identity.ShortString()
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

func uniqueName(state *log.State, name string) string { return govern.UniqueName(state, name) }

func checkName(what, name string) error { return govern.CheckName(what, name) }

func memberName(proposed string) string { return govern.MemberName(proposed) }
