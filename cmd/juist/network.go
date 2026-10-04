package main

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"go4.org/netipx"

	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func networkFamily() family {
	return family{name: "juist network", intro: "Show, rename and renumber the network, and set its domain.", subs: []subcommand{
		{name: "show", run: networkShow, forms: [][2]string{{"[NETWORK]", "name and address ranges; every\nnetwork's, without NETWORK"}}},
		{name: "rename", run: networkRename, forms: [][2]string{{"rename [NETWORK] NAME", "rename the network"}}},
		{name: "domain", run: networkDomain, forms: [][2]string{
			{"domain [NETWORK] DOMAIN", "the public domain names are\npublished under (juist publish)"},
			{"domain [NETWORK] off", "withdraw it"},
		}},
		{name: "renumber", run: networkRenumber, forms: [][2]string{
			{"renumber [NETWORK] PREFIX", "move every device into PREFIX,\nsuch as 10.7.0.0/22"},
			{"renumber [NETWORK] DEVICE ADDR", "move one device to ADDR; with\n--finish, retiring its old one now"},
			{"renumber [NETWORK] --finish", "retire the old addresses now"},
		}},
	}, footer: `NETWORK names one of this device's networks, or its juistd (juist1); it may
be left out where the device is in one. Old IPv4 addresses keep working
until the deadline. IPv6 addresses never move.`}
}

func cmdNetwork(a *app, args []string) error { return networkFamily().run(a, args) }

func networkShow(a *app, args []string) error {
	s := spec{name: "juist network", args: "[SUBCOMMAND]", about: networkFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	a.listingHeads = true
	if listed, err := a.forEachNetwork(a.showNetwork); listed {
		return err
	}
	return a.showNetwork()
}

// showNetwork is "juist network" for one network.
func (a *app) showNetwork() error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	now := a.now().Unix()
	if a.listing != "" {
		a.printf("%s · %s\n", a.bold(state.Network()), a.dim(a.listing))
	} else {
		a.printf("%s\n", a.bold(state.Network()))
	}
	line := state.V4Range().String()
	for _, r := range types.V4Ranges(state.Schema(), nil) {
		if r != state.V4Range() && !state.V4Range().Overlaps(r) && holdsIn(state, r) {
			line += a.dim(fmt.Sprintf(", %v (before schema %d)", r, types.SchemaOverlayV4))
		}
	}
	if r, ok := state.V4Retiring(); ok && r.Live(now) {
		line += a.dim(fmt.Sprintf(", %s until %s", joinPrefixes(r.Prefixes), deadline(r.Until)))
	}
	a.field("IPv4", "%s", line)
	a.field("IPv6", "%v", state.ULA())
	if d := state.Domain(); d != "" {
		a.field("Domain", "%s", d)
	}
	var moving, heldNodes []types.NodeRecord
	for _, n := range state.Nodes() {
		switch {
		case n.Retiring.Live(now):
			moving = append(moving, n)
		case n.Retiring != nil:
			heldNodes = append(heldNodes, n)
		}
	}
	slices.SortFunc(heldNodes, func(x, y types.NodeRecord) int { return x.Retiring.Addr.Compare(y.Retiring.Addr) })
	var held []string
	r, retiring := state.V4Retiring()
	if retiring && !r.Live(now) {
		held = append(held, joinPrefixes(r.Prefixes)+" (the old range)")
	}
	for _, n := range heldNodes {
		// What the old range holds needs no line of its own.
		if !retiring || r.Live(now) || !slices.ContainsFunc(r.Prefixes, func(p netip.Prefix) bool { return p.Contains(n.Retiring.Addr) }) {
			held = append(held, fmt.Sprintf("%v (%s's old address)", n.Retiring.Addr, displayMember(n)))
		}
	}
	if len(held) > 0 {
		a.field("Held", "%s", strings.Join(held, ", "))
		if len(moving) > 0 {
			a.hint("juist network renumber --finish frees them, and ends the moves below")
		} else {
			a.hint("juist network renumber --finish frees them")
		}
	}
	if len(moving) == 0 {
		return nil
	}
	slices.SortFunc(moving, func(x, y types.NodeRecord) int { return x.Retiring.Addr.Compare(y.Retiring.Addr) })
	a.printf("\n")
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MOVING\tFROM\tTO\tOLD UNTIL")
	for _, n := range moving {
		fmt.Fprintf(tw, "%s\t%v\t%v\t%s\n", displayMember(n), n.Retiring.Addr, *n.V4, deadline(n.Retiring.Until))
	}
	return tw.Flush()
}

func networkRename(a *app, args []string) error {
	s := spec{name: "juist network rename", args: "NAME", min: 1, max: 1, about: `
Rename the network on every device. Nothing else changes.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	name := pos[0]
	if err := checkName("network name", name); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	if state.Network() == name {
		a.ok("unchanged: named %q", name)
		return nil
	}
	if state.Schema() < types.SchemaRename {
		return needsUpgrade("renaming")
	}
	aum, err := auth.Builder().RenameNetwork(name)
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "rename.rec",
		done: fmt.Sprintf("renamed %q to %q", state.Network(), name)})
	return err
}

func networkDomain(a *app, args []string) error {
	s := spec{name: "juist network domain", args: "DOMAIN|off", min: 1, max: 1, about: `
Set the public domain devices publish names under, such as pub.example.org,
whose DNS points *.DOMAIN at the ingresses; off withdraws it. Every member
then resolves DOMAIN through juistd, with DNSSEC off for it.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	domain := ""
	if pos[0] != "off" {
		if domain, err = parseHostName(pos[0]); err != nil {
			return err
		}
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	if state.Domain() == domain {
		a.ok("unchanged: %s", cmp.Or(domain, "no domain"))
		return nil
	}
	if state.Schema() < types.SchemaPublish {
		return needsUpgrade("a public domain")
	}
	if domain == "" {
		for _, n := range state.Nodes() {
			if len(n.Published) > 0 {
				return fmt.Errorf("%s publishes names under %s\nhint: juist publish remove %s %s", displayMember(n),
					state.Domain(), displayMember(n), n.Published[0].Under(state.Domain()))
			}
		}
	}
	aum, err := auth.Builder().SetDomain(domain)
	if err != nil {
		return err
	}
	if domain != "" {
		a.warn("every member then resolves %s through juistd, names on or not, with DNSSEC off for it", domain)
	}
	done := "domain " + domain
	if domain == "" {
		done = "no domain"
	}
	_, err = a.submit(auth, &change{aum: aum, file: "domain.rec", done: done})
	return err
}

// A longDuration is a duration flag that takes days too, as "7d".
type longDuration time.Duration

func (d *longDuration) String() string {
	if t := time.Duration(*d); t > 0 && t%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", t/(24*time.Hour))
	}
	return shortDuration(time.Duration(*d))
}
func (d *longDuration) Set(v string) error {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.ParseUint(days, 10, 16)
		if err != nil {
			return fmt.Errorf("%q is not a number of days", v)
		}
		*d = longDuration(time.Duration(n) * 24 * time.Hour)
		return nil
	}
	p, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("%q is not a duration such as 12h or 7d", v)
	}
	*d = longDuration(p)
	return nil
}

func networkRenumber(a *app, args []string) error {
	s := spec{name: "juist network renumber", args: "PREFIX | DEVICE ADDR | --finish", max: 2, about: `
Move IPv4 addresses.

  juist network renumber [NETWORK] PREFIX        every device into PREFIX,
                                                 at its offset where free
  juist network renumber [NETWORK] DEVICE ADDR   one device to ADDR; with
                                                 --finish, retiring its old
                                                 one now
  juist network renumber [NETWORK] --finish      retire the old addresses now

Old addresses keep working until --for from now; make it long enough for
every device to come online once. Retired ones are held, for no other
device to take, until a plain --finish. Configuration outside juist that
names old addresses is not moved.`}
	fs := newFlags(s.name)
	keep := longDuration(7 * 24 * time.Hour)
	fs.Var(&keep, "for", "keep old addresses for `DURATION`, like 12h or 7d")
	finish := fs.Bool("finish", false, "retire old addresses now; with DEVICE ADDR, only that device's")
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	switch {
	case *finish && cliflag.IsSet(fs, "for"):
		return fmt.Errorf("--finish takes no --for: it retires the old address now\n%s", s.usage(fs))
	case *finish && len(pos) == 1:
		return fmt.Errorf("--finish takes DEVICE ADDR, or nothing\n%s", s.usage(fs))
	case !*finish && len(pos) == 0:
		return fmt.Errorf("missing PREFIX, or DEVICE ADDR\n%s", s.usage(fs))
	}
	if keep <= 0 {
		return errors.New("--for must be positive")
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	if auth.State().Schema() < types.SchemaRenumber {
		return needsUpgrade("renumbering")
	}
	until := uint64(a.now().Add(time.Duration(keep)).Unix())
	switch len(pos) {
	case 0:
		return a.retireAddresses(auth, *yes)
	case 1:
		return a.renumberNetwork(auth, pos[0], until, *yes)
	default:
		if *finish {
			until = types.RetireAtOnce
		}
		return a.renumberDevice(auth, pos[0], pos[1], until, *yes)
	}
}

func (a *app) renumberNetwork(auth *log.Authority, arg string, until uint64, yes bool) error {
	state := auth.State()
	prefix, err := netip.ParsePrefix(arg)
	if err != nil {
		return fmt.Errorf("bad prefix %q (want e.g. 10.7.0.0/22; one device: renumber DEVICE ADDR)", arg)
	}
	if err := types.ValidateV4Prefix(prefix); err != nil {
		return err
	}
	if numberedFrom(state, prefix) {
		a.ok("unchanged: numbered from %v", prefix)
		return nil
	}
	if room := usableHosts(prefix); room < uint64(len(state.Nodes())) {
		return fmt.Errorf("%v fits %s, the network has %d", prefix, count(room, "device"), len(state.Nodes()))
	}
	history, err := a.addressHistory()
	if err != nil {
		return err
	}
	addrs, err := renumbered(state, prefix, history)
	if err != nil {
		return err
	}
	var own []netip.Addr
	if self, _, err := a.selfID(); err == nil {
		if n, ok := state.Node(self); ok {
			own = n.V4Addrs()
		}
	}
	// Each risk is said here, and the one question below covers them all.
	if used := hostNetsOverlapping(prefix, own...); len(used) > 0 {
		a.warn("%v overlaps %s here; traffic to both goes into the network", prefix, strings.Join(used, ", "))
	}
	if other := a.networkClaiming(prefix); other != "" {
		a.warn("%v overlaps %s, which this device is in; one of the two would run here without IPv4",
			prefix, other)
	}
	to := make(map[types.Identity]netip.Addr, len(addrs))
	for _, m := range addrs {
		to[m.Identity] = m.V4
	}
	a.warnTransitionEnds(state.Nodes(), to)
	if err := a.proceed(yes, fmt.Sprintf("move %q from %v to %v, old addresses until %s?", state.Network(),
		state.V4Range(), prefix, deadline(until))); err != nil {
		return err
	}
	aum, err := auth.Builder().RenumberNetwork(prefix, addrs, until)
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{
		aum:  aum,
		file: "renumber.rec",
		done: fmt.Sprintf("moving to %v; old addresses until %s", prefix, deadline(until)),
	})
	return err
}

func (a *app) renumberDevice(auth *log.Authority, dev, arg string, until uint64, yes bool) error {
	state := auth.State()
	target, err := resolveDevice(state, dev)
	if err != nil {
		return err
	}
	name := displayMember(target)
	addr, err := netip.ParseAddr(arg)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("bad IPv4 address %q", arg)
	}
	r := state.V4Range()
	if !r.Contains(addr) {
		return fmt.Errorf("%v is outside the network's range %v", addr, r)
	}
	if addr == r.Addr() || addr == netipx.PrefixLastIP(r) {
		return fmt.Errorf("%v is the first or last address of %v", addr, r)
	}
	if target.V4 != nil && *target.V4 == addr {
		now := a.now().Unix()
		if r := target.Retiring; r.Live(now) {
			a.ok("unchanged: %s at %v; its old %v works until %s", name, addr, r.Addr, deadline(r.Until))
			if until == types.RetireAtOnce {
				a.hint("juist network renumber --finish retires every old address now")
			}
			return nil
		}
		a.ok("unchanged: %s at %v", name, addr)
		return nil
	}
	for _, n := range state.Nodes() {
		switch {
		case n.Identity == target.Identity || !slices.Contains(n.V4Addrs(), addr):
		case n.Retiring != nil && n.Retiring.Addr == addr && !n.Retiring.Live(a.now().Unix()):
			return fmt.Errorf("%v is held as %s's old address\nhint: juist network renumber --finish frees it",
				addr, displayMember(n))
		default:
			return fmt.Errorf("%v is taken by %s", addr, displayMember(n))
		}
	}
	history, err := a.addressHistory()
	if err != nil {
		return err
	}
	if g, held := givenOut(state, history)[addr]; held && g.id != target.Identity {
		a.warn("%v was %s's; devices not yet told still send its traffic there", addr,
			cmp.Or(g.name, g.id.ShortString()))
	}
	a.warnTransitionEnds([]types.NodeRecord{target}, map[types.Identity]netip.Addr{target.Identity: addr})
	atOnce := until == types.RetireAtOnce && target.V4 != nil
	if atOnce {
		a.warn("connections to %s's %v end; devices not told yet reach %s over IPv6 only until they are", name,
			*target.V4, name)
	}
	question := fmt.Sprintf("give %s %v?", name, addr)
	switch {
	case atOnce:
		question = fmt.Sprintf("move %s from %v to %v, retiring %v now?", name, *target.V4, addr, *target.V4)
	case target.V4 != nil:
		question = fmt.Sprintf("move %s from %v to %v, old address until %s?", name, *target.V4, addr,
			deadline(until))
	}
	if err := a.proceed(yes, question); err != nil {
		return err
	}
	aum, err := auth.Builder().RenumberNode(target.Identity, addr, until)
	if err != nil {
		return err
	}
	done := fmt.Sprintf("%s moving to %v", name, addr)
	switch {
	case atOnce:
		done = fmt.Sprintf("%s moved to %v; %v retired", name, addr, *target.V4)
	case target.V4 != nil:
		done = fmt.Sprintf("%s moving to %v; %v until %s", name, addr, *target.V4, deadline(until))
	}
	_, err = a.submit(auth, &change{aum: aum, file: "renumber-" + fileSafe(name) + ".rec", done: done})
	return err
}

func (a *app) retireAddresses(auth *log.Authority, yes bool) error {
	state := auth.State()
	now := a.now().Unix()
	nodes := slices.DeleteFunc(state.Nodes(), func(n types.NodeRecord) bool { return n.Retiring == nil })
	slices.SortFunc(nodes, func(x, y types.NodeRecord) int { return x.Retiring.Addr.Compare(y.Retiring.Addr) })
	// What still works is retired; what works no more, but is held, is freed.
	var live, held []string
	if r, ok := state.V4Retiring(); ok {
		item := "the old range " + joinPrefixes(r.Prefixes)
		if r.Live(now) {
			live = append(live, item)
		} else {
			held = append(held, item)
		}
	}
	for _, n := range nodes {
		item := fmt.Sprintf("%s's %v", displayMember(n), n.Retiring.Addr)
		if n.Retiring.Live(now) {
			live = append(live, item)
		} else {
			held = append(held, item)
		}
	}
	if len(live)+len(held) == 0 {
		a.ok("no old addresses to retire")
		return nil
	}
	if len(live) > 0 {
		a.warn("devices not told yet lose %s", strings.Join(live, ", "))
	}
	list := func(items []string, what string) string {
		if len(items) > 3 {
			return count(len(items), what)
		}
		return strings.Join(items, ", ")
	}
	var question, done string
	switch {
	case len(held) == 0:
		question, done = "retire "+list(live, "old address"), "old addresses retired"
	case len(live) == 0:
		question, done = "free "+list(held, "held address"), "held addresses freed"
	default:
		question = "retire " + list(live, "old address") + " and free " + list(held, "held address")
		done = "old addresses retired; held ones freed"
	}
	if err := a.proceed(yes, question+" now?"); err != nil {
		return err
	}
	aum, err := auth.Builder().RetireAddresses()
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "retire.rec", done: done})
	return err
}

// warnTransitionEnds warns of moving members that still answer at an address
// an earlier renumbering left them: a member keeps one old address, so moving
// it again drops that one now instead of at its deadline. One moving back to
// that address loses nothing.
func (a *app) warnTransitionEnds(moving []types.NodeRecord, to map[types.Identity]netip.Addr) {
	now := a.now().Unix()
	var cut []string
	for _, n := range moving {
		if n.Retiring.Live(now) && to[n.Identity] != n.Retiring.Addr {
			cut = append(cut, fmt.Sprintf("%s's %v", displayMember(n), n.Retiring.Addr))
		}
	}
	if len(cut) > 0 {
		a.warn("old addresses retire now, not at their deadline: %s", strings.Join(cut, ", "))
	}
}

// holdsIn reports whether a member's IPv4 address lies in r.
func holdsIn(state *log.State, r netip.Prefix) bool {
	return slices.ContainsFunc(state.Nodes(), func(n types.NodeRecord) bool { return n.V4 != nil && r.Contains(*n.V4) })
}

// numberedFrom reports whether the network is numbered from p already: new
// devices are, and every device's address lies in it.
func numberedFrom(state *log.State, p netip.Prefix) bool {
	return p == state.V4Range() &&
		!slices.ContainsFunc(state.Nodes(), func(n types.NodeRecord) bool { return n.V4 != nil && !p.Contains(*n.V4) })
}

// A grant is who a record gave an IPv4 address to.
type grant struct {
	id   types.Identity
	name string
}

// givenOut maps every IPv4 address a member holds, or any record in history
// gave out, to whom it went last. A device removed a moment ago still
// believes it holds its address, and so do members that have not heard of
// the removal yet; the same goes for an address a renumbering retired.
func givenOut(state *log.State, history []types.AUM) map[netip.Addr]grant {
	out := map[netip.Addr]grant{}
	mark := func(nodes []types.NodeRecord) {
		for _, n := range nodes {
			for _, v4 := range n.V4Addrs() {
				out[v4] = grant{n.Identity, n.Name}
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
			out[*h.Renumber.V4] = grant{id: *h.Subject}
		case h.Renumber != nil:
			for _, e := range h.Renumber.Addrs {
				out[e.V4] = grant{id: e.Identity}
			}
		}
	}
	mark(state.Nodes())
	return out
}

// renumbered gives every member an address in prefix: the one it holds,
// where that is in prefix already; else the one at its place in the range it
// is numbered from, where that is free; else the lowest free one. None is one
// held back for someone else.
func renumbered(state *log.State, prefix netip.Prefix, history []types.AUM) ([]types.MemberV4, error) {
	held := givenOut(state, history)
	nodes := state.Nodes()
	slices.SortStableFunc(nodes, func(x, y types.NodeRecord) int {
		switch {
		case x.V4 == nil || y.V4 == nil:
			return cmp.Compare(boolInt(x.V4 == nil), boolInt(y.V4 == nil))
		}
		return x.V4.Compare(*y.V4)
	})
	last := netipx.PrefixLastIP(prefix)
	given := make(map[types.Identity]netip.Addr, len(nodes))
	take := func(n types.NodeRecord, v4 netip.Addr, ok bool) {
		if _, done := given[n.Identity]; done || !ok || !prefix.Contains(v4) || v4 == prefix.Addr() || v4 == last {
			return
		}
		if g, taken := held[v4]; taken && g.id != n.Identity {
			return
		}
		given[n.Identity] = v4
		held[v4] = grant{id: n.Identity}
	}
	for _, n := range nodes {
		if n.V4 != nil {
			take(n, *n.V4, true)
		}
	}
	for _, n := range nodes {
		if n.V4 == nil {
			continue
		}
		for _, r := range state.V4Ranges() {
			if r.Contains(*n.V4) {
				v4, ok := offsetInto(prefix, ipv4Uint(*n.V4)-ipv4Uint(r.Addr()))
				take(n, v4, ok)
				break
			}
		}
	}
	next := prefix.Addr().Next()
	for _, n := range nodes {
		for ; next.Less(last); next = next.Next() {
			if _, done := given[n.Identity]; done {
				break
			}
			take(n, next, true)
		}
		if _, done := given[n.Identity]; !done {
			return nil, fmt.Errorf("%v: no room for %s", prefix, displayMember(n))
		}
	}
	out := make([]types.MemberV4, 0, len(given))
	for id, v4 := range given {
		out = append(out, types.MemberV4{Identity: id, V4: v4})
	}
	slices.SortFunc(out, func(x, y types.MemberV4) int { return x.Identity.Compare(y.Identity) })
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func offsetInto(r netip.Prefix, off uint32) (netip.Addr, bool) {
	if uint64(off) >= uint64(1)<<(32-r.Bits()) {
		return netip.Addr{}, false
	}
	return uintIPv4(ipv4Uint(r.Addr()) + off), true
}

func ipv4Uint(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uintIPv4(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

// usableHosts is how many addresses of p a device may be given: all but the
// first and the last.
func usableHosts(p netip.Prefix) uint64 {
	return max(uint64(1)<<(32-p.Bits()), 2) - 2
}

func joinPrefixes(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, " and ")
}

// addressHistory is every record that gave out an IPv4 address: the chain,
// and the branches that lost fork choice, whose records may yet be reissued.
func (a *app) addressHistory() ([]types.AUM, error) {
	n, err := a.openNode()
	if err != nil {
		return nil, err
	}
	history, err := n.chain()
	if err != nil {
		return nil, err
	}
	orphans, err := n.orphans()
	if err != nil {
		return nil, err
	}
	return append(slices.Clone(history), orphans...), nil
}
