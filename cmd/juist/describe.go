package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// effect says what a record would do, one line per change, from the record
// itself and, where a log is held, the state it applies to. It is what an
// admin reads before signing, so it names everything the record changes and
// takes nothing from the file's name or its comments, which whoever handed
// the file over chose.
func effect(aum *types.AUM, state *log.State, now int64) []string {
	member := func(id types.Identity) string {
		if state != nil {
			if n, ok := state.Node(id); ok {
				return fmt.Sprintf("%s (%v)", displayMember(n), id.ShortString())
			}
		}
		return id.ShortString()
	}
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	switch aum.Kind {
	case types.KindGenesis, types.KindCheckpoint:
		st := aum.State
		if aum.Kind == types.KindGenesis {
			add("creates the network %q", st.Network)
		} else {
			add("checkpoints %q", st.Network)
		}
		add("a change needs %s", count(st.Quorum, "vote"))
		if st.Vouchers > 1 {
			add("%d vouchers must confirm a device's view", st.Vouchers)
		}
		for _, p := range adminPeople(st.Admins) {
			ids := make([]string, len(p.keys))
			for i, k := range p.keys {
				ids[i] = k.Public.ShortString()
				if on := keyMachine(k); on != "" {
					ids[i] += " on " + on
				}
			}
			signs := "its key"
			if len(p.keys) > 1 {
				signs = fmt.Sprintf("%d of its %d keys (%s)", p.keys[0].NeededKeys(), len(p.keys), strings.Join(ids, ", "))
			} else {
				signs += " " + ids[0]
			}
			add("admin %s: %s, cast with %s", p.name, count(p.keys[0].Votes, "vote"), signs)
		}
		for _, n := range st.Nodes {
			add("device %s (%v)%s", displayMember(n), n.Identity.ShortString(), rolesSuffix(n.Roles))
		}
	case types.KindAddNode:
		n := aum.Node
		add("admits the device %q (%v)", n.Name, n.Identity.ShortString())
		add("with the keys %s", keysDigest(types.NodeKeys{WireGuard: n.WireGuard, X25519: n.X25519, MLKEM: n.MLKEM}))
		if n.V4 != nil {
			add("at %v", *n.V4)
		}
		add("with %s", rolesPhrase(n.Roles))
		if len(n.Routes) > 0 {
			add("routing %v", n.Routes)
		}
		for _, name := range n.Names {
			add("pointing %s at it", name)
		}
		domain := "DOMAIN"
		if state != nil {
			domain = cmp.Or(state.Domain(), domain)
		}
		for _, p := range n.Published {
			line := fmt.Sprintf("publishing %s on port %d of it", publishedPhrase(p, domain), p.Port)
			if p.Proxy {
				line += ", with PROXY protocol"
			}
			add("%s", line)
		}
	case types.KindRemoveNode:
		roles := ""
		if state != nil {
			if n, ok := state.Node(*aum.Subject); ok {
				roles = rolesSuffix(n.Roles)
			}
		}
		add("removes the device %s%s", member(*aum.Subject), roles)
	case types.KindSetNodeRoutes:
		var now *types.NodeRecord
		if state != nil {
			if n, ok := state.Node(*aum.Subject); ok {
				now = &n
			}
		}
		// Said as what changes, where the log says what it has now.
		if now == nil {
			add("gives %s %s", member(*aum.Subject), rolesPhrase(aum.Grant.Roles))
		} else {
			var added, taken []types.Role
			for _, r := range aum.Grant.Roles {
				if !slices.Contains(now.Roles, r) {
					added = append(added, r)
				}
			}
			for _, r := range now.Roles {
				if !slices.Contains(aum.Grant.Roles, r) {
					taken = append(taken, r)
				}
			}
			if len(added) > 0 {
				add("gives %s the %s %s", member(*aum.Subject), plural(len(added), "role"), describeRoles(added))
			}
			if len(taken) > 0 {
				add("takes the %s %s from %s", plural(len(taken), "role"), describeRoles(taken), member(*aum.Subject))
			}
			if len(added)+len(taken) == 0 && slices.Equal(now.Routes, aum.Grant.Routes) {
				add("leaves %s as it is, with %s", member(*aum.Subject), rolesPhrase(now.Roles))
			}
		}
		// Routes are shown whenever they change, taking them away too.
		switch {
		case now != nil && !slices.Equal(now.Routes, aum.Grant.Routes):
			add("changes the routes it carries from %s to %s", describeRoutes(now.Routes),
				describeRoutes(aum.Grant.Routes))
		case now == nil && len(aum.Grant.Routes) > 0:
			add("routing %v", aum.Grant.Routes)
		}
	case types.KindRotateNodeKey:
		add("replaces the keys of %s with %s", member(*aum.Subject), keysDigest(*aum.Keys))
	case types.KindRotateIdentity:
		add("replaces the identity key of %s with %v", member(*aum.Subject), aum.NewIdentity.ShortString())
		if state != nil {
			if n, ok := state.Node(*aum.Subject); ok {
				add("which takes over %s", rolesPhrase(n.Roles))
			}
		}
	case types.KindAddAdminKey:
		k := aum.Admin
		if k.Holder == "" {
			add("gives the admin key %s (%v) %s", orDash(k.Name), k.Public.ShortString(), count(k.Votes, "vote"))
		} else {
			key := k.Public.ShortString()
			if on := keyMachine(*k); on != "" {
				key += " on " + on
			}
			add("gives %s the admin key %s, casting %s", k.Holder, key, count(k.Votes, "vote"))
			if state != nil {
				if n := len(holderKeys(state, k.Holder)); n > 0 {
					add("besides %s's %s; one vote between them", k.Holder, count(n, "key"))
				}
			}
		}
		if state != nil {
			after := append(state.Admins(), *k)
			add("(quorum %d of %d; %d after)", state.Quorum(), state.TotalVotes(), types.AchievableVotes(after))
		}
	case types.KindSetHolder:
		h := aum.Holder
		add("counts %s's %s only when %d of their keys sign", h.Name, count(h.Votes, "vote"), h.Needed)
		if state != nil {
			if keys := holderKeys(state, h.Name); len(keys) > 0 {
				add("(holds %s, needs %d now)", count(len(keys), "key"), keys[0].NeededKeys())
			}
		}
	case types.KindRemoveAdminKey:
		name := aum.Subject.ShortString()
		if state != nil {
			if k, ok := state.Admin(*aum.Subject); ok {
				on := ""
				if m := keyMachine(k); m != "" {
					on = " on " + m
				}
				name = fmt.Sprintf("%s (%s's, %s)", k.Public.ShortString()+on, orDash(keyPerson(k)), count(k.Votes, "vote"))
			}
		}
		add("takes the vote away from the admin key %s", name)
	case types.KindSetAdminRecipient:
		name := "the admin key " + aum.Subject.ShortString()
		if state != nil {
			if k, ok := state.Admin(*aum.Subject); ok {
				name = orDash(keyPerson(k)) + "'s admin key " + aum.Subject.ShortString()
				if m := keyMachine(k); m != "" {
					name += " on " + m
				}
			}
		}
		add("gives %s the encryption key %s", name, recipientDigest(*aum.Recipient))
	case types.KindSetQuorum:
		if state != nil {
			add("changes the quorum from %d to %d, of %d", state.Quorum(), *aum.Quorum, state.TotalVotes())
		} else {
			add("sets the quorum to %d", *aum.Quorum)
		}
	case types.KindEpochBump:
		add("rotates the network's group secret")
	case types.KindSchemaUpgrade:
		add("moves the network to record schema %d; devices on older builds stop there", *aum.Schema)
	case types.KindSetVouchers:
		if state != nil {
			add("requires %d vouchers, not %d", *aum.Vouchers, max(state.Vouchers(), 1))
		} else {
			add("requires %d vouchers", *aum.Vouchers)
		}
	case types.KindRenumberNetwork:
		r := aum.Renumber
		if state != nil {
			add("moves every device from %v to %v", state.V4Range(), *r.Prefix)
		} else {
			add("moves every device to %v", *r.Prefix)
		}
		for _, e := range r.Addrs {
			add("%s to %v", member(e.Identity), e.V4)
		}
		add("old addresses until %s", deadline(r.Until))
		if past := deadlineNote(r.Until, now); past != "" {
			add("%s", past)
		}
	case types.KindRenumberNode:
		r := aum.Renumber
		var old *netip.Addr
		known := false
		if state != nil {
			if n, ok := state.Node(*aum.Subject); ok {
				old, known = n.V4, true
			}
		}
		atOnce := r.Until == types.RetireAtOnce && (old != nil || !known)
		if atOnce {
			add("moves %s to %v at once", member(*aum.Subject), *r.V4)
		} else {
			add("moves %s to %v", member(*aum.Subject), *r.V4)
		}
		switch {
		case atOnce && old != nil:
			add("retires %v now: devices not told yet reach the device over IPv6 only", *old)
		case atOnce:
			add("retires its old address now")
		case r.Until == types.RetireAtOnce:
		case old != nil:
			add("%v until %s", *old, deadline(r.Until))
			if past := deadlineNote(r.Until, now); past != "" {
				add("%s", past)
			}
		}
	case types.KindRetireAddresses:
		add("retires old addresses before their deadlines")
	case types.KindSetNodeNames:
		var had []string
		if state != nil {
			if n, ok := state.Node(*aum.Subject); ok {
				had = n.Names
			}
		}
		// What each member that accepts names then resolves, which is what
		// an approver has to weigh: a public name sent into the network.
		for _, n := range aum.Names.Names {
			if !slices.Contains(had, n) {
				add("points %s at %s", n, member(*aum.Subject))
			}
		}
		for _, n := range had {
			if !slices.Contains(aum.Names.Names, n) {
				add("no longer points %s at %s", n, member(*aum.Subject))
			}
		}
		if len(out) == 0 {
			add("leaves %s's names as they are", member(*aum.Subject))
		}
	case types.KindSetDomain:
		was := ""
		if state != nil {
			was = state.Domain()
		}
		switch d := *aum.Domain; {
		case d == "" && was != "":
			add("withdraws the public domain %s", was)
		case d == "":
			add("withdraws the public domain")
		case was != "":
			add("moves the public domain from %s to %s, and every published name with it", was, d)
			add(domainResolution, d, d)
			for _, n := range state.Nodes() {
				if slices.ContainsFunc(n.Published, func(p types.PublishedName) bool { return p.Label == "" }) {
					add("publishes the domain %s itself on %s", d, displayMember(n))
				}
			}
		default:
			add("sets the public domain to %s", d)
			add(domainResolution, d, d)
		}
	case types.KindSetPublished:
		var had []types.PublishedName
		domain := "DOMAIN"
		if state != nil {
			if n, ok := state.Node(*aum.Subject); ok {
				had = n.Published
			}
			domain = cmp.Or(state.Domain(), domain)
		}
		// What the internet then reaches, which is what an approver weighs.
		for _, p := range aum.Publish.Names {
			if !slices.Contains(had, p) {
				line := fmt.Sprintf("publishes %s on port %d of %s", publishedPhrase(p, domain), p.Port, member(*aum.Subject))
				if p.Proxy {
					line += ", with PROXY protocol"
				}
				add("%s", line)
			}
		}
		for _, p := range had {
			if !slices.ContainsFunc(aum.Publish.Names, func(q types.PublishedName) bool { return q.Label == p.Label }) {
				add("no longer publishes %s", publishedPhrase(p, domain))
			}
		}
		if len(out) == 0 {
			add("leaves what %s publishes as it is", member(*aum.Subject))
		}
	case types.KindRenameNetwork:
		if state != nil {
			add("renames the network %q to %q", state.Network(), *aum.Network)
		} else {
			add("renames the network to %q", *aum.Network)
		}
	case types.KindRenameNode:
		add("renames %s to %q", member(*aum.Subject), *aum.NodeName)
		if state == nil {
			break
		}
		n, ok := state.Node(*aum.Subject)
		if !ok {
			break
		}
		// What others then reach it by, which is what an approver weighs.
		if network := names.Label(state.Network()); network != "" {
			zone := network + "." + types.NamesTLD
			was, is := names.Label(n.Name), names.Label(*aum.NodeName)
			// A label two members held, which resolved to neither, goes to the other.
			var other string
			for _, o := range state.Nodes() {
				if o.Identity != n.Identity && was != "" && names.Label(o.Name) == was {
					other = member(o.Identity)
				}
			}
			switch {
			case was == is:
			case other != "" && is != "":
				add("%s.%s resolves to it, and %s.%s to %s", is, zone, was, zone, other)
			case other != "":
				add("%s.%s resolves to %s", was, zone, other)
			case was != "" && is != "":
				add("%s.%s resolves to it, and %s.%s no longer does", is, zone, was, zone)
			case was != "":
				add("%s.%s no longer resolves, and no name under %s does", was, zone, zone)
			case is != "":
				add("%s.%s resolves to it", is, zone)
			}
		}
		renamed := n.Clone()
		renamed.Name = *aum.NodeName
		was, _ := n.ShareLabel()
		is, _ := renamed.ShareLabel()
		if n.HasRole(types.RolePublish) && state.Domain() != "" && was != is {
			add("shares under %s, not %s", nameUnder(is, state.Domain()), nameUnder(was, state.Domain()))
		}
	default:
		add("a %s record", aum.Kind)
	}
	return out
}

// deadlineNote warns of a renumbering whose deadline has passed, or is near.
// Its deadline was fixed when it was proposed, so every approval after that
// leaves less of the transition: applied past it, it moves every address at
// once, with nothing to fall back on; applied close to it, a device offline
// for longer than is left loses its old address before it hears of the new.
func deadlineNote(until uint64, now int64) string {
	left := time.Duration(int64(min(until, 1<<32))-now) * time.Second
	switch {
	case left <= 0:
		return "BUT that deadline has passed: old addresses stop on applying; redo it with a longer --for"
	case left < shortTransition:
		return fmt.Sprintf("BUT only %s of that is left: a device offline longer loses its old address "+
			"before it hears of the move; redo it with a longer --for if that is too short", roughly(left))
	}
	return ""
}

// shortTransition is how little of a renumbering's transition is worth an
// approver's attention: less than the freshness TTL a device may be offline
// for and still count as current.
const shortTransition = 48 * time.Hour

// changesAuthority reports whether a record changes who may approve changes
// or vouch for the network's state. Such a record is approved only where the
// log it applies to is held: without one, juist cannot show what it changes,
// only what it claims. An identity rotation moves a member's roles — an admin
// device's too — to the new key, which only the log can say.
func changesAuthority(aum *types.AUM) bool {
	if aum.Kind == types.KindAddNode {
		return slices.Contains(aum.Node.Roles, types.RoleAdmin)
	}
	changes, known := kindChangesAuthority[aum.Kind]
	return changes || !known
}

// kindChangesAuthority is, for every kind but an admission, whether its record
// can; a kind missing from it is taken to.
var kindChangesAuthority = map[types.Kind]bool{
	types.KindGenesis:           true,
	types.KindRemoveNode:        true, // the device may be a voucher, which only the log says
	types.KindSetNodeRoutes:     true, // it can grant the admin role, or take the last one away
	types.KindRotateNodeKey:     false,
	types.KindRotateIdentity:    true,
	types.KindAddAdminKey:       true,
	types.KindRemoveAdminKey:    true,
	types.KindSetQuorum:         true,
	types.KindCheckpoint:        true,
	types.KindEpochBump:         false,
	types.KindSchemaUpgrade:     true,
	types.KindSetVouchers:       true,
	types.KindSetHolder:         true,
	types.KindRenumberNetwork:   false,
	types.KindRenumberNode:      false,
	types.KindRetireAddresses:   false,
	types.KindRenameNetwork:     false,
	types.KindSetAdminRecipient: true,
	types.KindSetNodeNames:      false,
	types.KindSetDomain:         false,
	types.KindSetPublished:      false,
	types.KindRenameNode:        false,
}

// voucherLost returns the device aum takes the admin role from, by removing
// it or by a grant without the role.
func voucherLost(state *log.State, aum *types.AUM) (types.NodeRecord, bool) {
	switch {
	case aum.Kind == types.KindRemoveNode:
	case aum.Kind == types.KindSetNodeRoutes && !slices.Contains(aum.Grant.Roles, types.RoleAdmin):
	default:
		return types.NodeRecord{}, false
	}
	n, ok := state.Node(*aum.Subject)
	return n, ok && slices.Contains(n.Roles, types.RoleAdmin)
}

// plural is word, or its plural where n is not one.
func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// rolesPhrase is "no role", or "the roles: relay, admin".
func rolesPhrase(roles []types.Role) string {
	if len(roles) == 0 {
		return "no role"
	}
	return "the roles: " + describeRoles(roles)
}

func rolesSuffix(roles []types.Role) string {
	if len(roles) == 0 {
		return ""
	}
	return ", " + describeRoles(roles)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func describeRoutes(r []netip.Prefix) string {
	if len(r) == 0 {
		return "none"
	}
	return fmt.Sprint(r)
}

// keysDigest names a device's data-plane and sealing keys in a short, stable
// form, which "juist rotate" prints on the device for an approver to
// compare.
func keysDigest(k types.NodeKeys) string {
	sum := sha256.Sum256(slices.Concat(k.WireGuard[:], k.X25519[:], k.MLKEM[:]))
	return hex.EncodeToString(sum[:6])
}

// recipientDigest names an encryption key in the same form.
func recipientDigest(r types.RecipientKey) string {
	sum := sha256.Sum256(slices.Concat(r.X25519[:], r.MLKEM[:]))
	return hex.EncodeToString(sum[:6])
}

// publishedPhrase is p's name under domain as an approval says it, the
// domain itself said so.
func publishedPhrase(p types.PublishedName, domain string) string {
	if p.Label == "" {
		return "the domain " + domain + " itself"
	}
	return p.Under(domain)
}

// domainResolution is what a public domain makes of members' resolution,
// which an approver weighs: every name of it goes to juistd, without each
// device's consent, and DNSSEC with it.
const domainResolution = "has every member resolve %s through juistd, which answers the names published " +
	"there with their devices, and turns DNSSEC off for %s on members"
