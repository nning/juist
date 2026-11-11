package main

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"go4.org/netipx"

	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/internal/govern"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func networkFamily() family {
	return family{name: "juist network", intro: "Show, rename and renumber the network, set its domain and public DERP servers, or end it.", subs: []subcommand{
		{name: "show", run: networkShow, forms: [][2]string{{"[NETWORK]", "show name and address ranges,\nfor every network without NETWORK"}}},
		{name: "rename", run: networkRename, forms: [][2]string{{"rename [NETWORK] NAME", "rename the network"}}},
		{name: "domain", run: networkDomain, forms: [][2]string{
			{"domain [NETWORK] DOMAIN", "set the public domain for juist publish"},
			{"domain [NETWORK] off", "remove it"},
		}},
		{name: "derp", run: networkDERP, forms: [][2]string{
			{"derp [NETWORK] on", "use Tailscale's public DERP servers\nwhere no member relays"},
			{"derp [NETWORK] off", "use none"},
		}},
		{name: "renumber", run: networkRenumber, forms: [][2]string{
			{"renumber [NETWORK] PREFIX", "move every device into PREFIX,\nsuch as 10.7.0.0/22"},
			{"renumber [NETWORK] DEVICE ADDR", "move one device to ADDR"},
			{"renumber [NETWORK] --finish", "retire the old addresses now"},
		}},
		{name: "disable", run: networkDisable, forms: [][2]string{
			{"disable [NETWORK]", "end the network for good with the\nbreak-glass secret; every device stops"},
		}},
	}, footer: `NETWORK is a network of this device, or its juistd (juist1); it can be left
out if there is only one. Old IPv4 addresses work until the deadline; IPv6
addresses never move.`}
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
	if r, ok := state.V4Retiring(); ok && r.Live(now) {
		line += a.dim(fmt.Sprintf(", %s until %s", joinPrefixes(r.Prefixes), deadline(r.Until)))
	}
	a.field("IPv4", "%s", line)
	a.field("IPv6", "%v", state.ULA())
	if d := state.Domain(); d != "" {
		a.field("Domain", "%s", d)
	}
	if state.PublicDERP().Tailscale {
		a.field("Public DERP", "Tailscale")
	}
	// From schema 25 what is retired is free; before, it is held.
	free := state.Schema() >= types.SchemaTakeRetired
	var moving, heldNodes []types.NodeRecord
	for _, n := range state.Nodes() {
		switch {
		case n.Retiring.Live(now):
			moving = append(moving, n)
		case n.Retiring != nil && !free:
			heldNodes = append(heldNodes, n)
		}
	}
	slices.SortFunc(heldNodes, func(x, y types.NodeRecord) int { return x.Retiring.Addr.Compare(y.Retiring.Addr) })
	var held []string
	r, retiring := state.V4Retiring()
	if retiring && !r.Live(now) && !free {
		held = append(held, joinPrefixes(r.Prefixes)+" (the old range)")
	}
	for _, n := range heldNodes {
		// What the old range holds needs no line of its own.
		if !retiring || r.Live(now) || !slices.ContainsFunc(r.Prefixes, func(p netip.Prefix) bool { return p.Contains(n.Retiring.Addr) }) {
			held = append(held, fmt.Sprintf("%v (old address of %s)", n.Retiring.Addr, displayMember(n)))
		}
	}
	if len(held) > 0 {
		a.field("Held", "%s", strings.Join(held, ", "))
		if len(moving) > 0 {
			a.hint("to free them and end the moves below: juist network renumber --finish")
		} else {
			a.hint("to free them: juist network renumber --finish")
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
		return a.usageErr("%v", err)
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
Set the public domain for published names, such as pub.example.org. Its
DNS points *.DOMAIN at the ingresses. off removes it. Members resolve DOMAIN
through juistd, without DNSSEC.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	domain := ""
	if pos[0] != "off" {
		if domain, err = parseHostName(pos[0]); err != nil {
			return a.usageErr("%v", err)
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
	if domain == "" {
		for _, n := range state.Nodes() {
			if len(n.Published) > 0 {
				return fmt.Errorf("%s still publishes names under %s\nhint: juist publish --stop %s --on %s", displayMember(n),
					state.Domain(), n.Published[0].Under(state.Domain()), displayMember(n))
			}
		}
	}
	aum, err := auth.Builder().SetDomain(domain)
	if err != nil {
		return err
	}
	if domain != "" {
		a.warn("every member resolves %s through juistd without DNSSEC, even with names off", domain)
	}
	done := "domain " + domain
	if domain == "" {
		done = "no domain"
	}
	_, err = a.submit(auth, &change{aum: aum, file: "domain.rec", done: done})
	return err
}

func networkDERP(a *app, args []string) error {
	s := spec{name: "juist network derp", args: "on|off", min: 1, max: 1, about: `
Use Tailscale's public DERP servers where no member relays, or none. They
see only encrypted traffic, but also the public address of every device and
who talks to whom, when and how much. Member relays come first.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	var want types.PublicDERP
	switch pos[0] {
	case "on":
		want.Tailscale = true
	case "off":
	default:
		return a.usageErr("%q is not on or off", pos[0])
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	if state.PublicDERP() == want {
		a.ok("unchanged: public DERP %s", pos[0])
		return nil
	}
	if state.Schema() < types.SchemaPublicDERP {
		return needsUpgrade("public DERP servers")
	}
	aum, err := auth.Builder().SetPublicDERP(want)
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "public-derp.rec", done: "public DERP " + pos[0]})
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
Move every device into PREFIX, at the same offset where free, or one device
to ADDR. Old addresses keep working for the time --for gives; make that long enough for
every device to come online once. --finish alone retires them now.
Configuration outside juist is not changed.`}
	fs := newFlags(s.name)
	keep := longDuration(7 * 24 * time.Hour)
	fs.Var(&keep, "for", "keep old addresses for `DURATION`, like 12h or 7d")
	finish := fs.Bool("finish", false, "retire old addresses now; with DEVICE ADDR, only its old one")
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	switch {
	case *finish && cliflag.IsSet(fs, "for"):
		return a.usageErr("--finish cannot be used with --for")
	case *finish && len(pos) == 1:
		return a.usageErr("--finish takes DEVICE ADDR or no argument")
	case !*finish && len(pos) == 0:
		return a.usageErr("missing PREFIX or DEVICE ADDR")
	case keep <= 0:
		return a.usageErr("--for must be positive")
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
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
		return a.usageErr("%q is not a prefix such as 10.7.0.0/22", arg)
	}
	if err := types.ValidateV4Prefix(prefix); err != nil {
		return a.usageErr("%v", err)
	}
	if numberedFrom(state, prefix) {
		a.ok("unchanged: numbered from %v", prefix)
		return nil
	}
	if room := usableHosts(prefix); room < uint64(len(state.Nodes())) {
		return fmt.Errorf("%v has room for %s, but the network has %d", prefix, count(room, "device"), len(state.Nodes()))
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
		a.warn("%v overlaps %s, also on this device; one of them would run here without IPv4", prefix, other)
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
		return a.usageErr("%q is not an IPv4 address", arg)
	}
	r := state.V4Range()
	if !r.Contains(addr) {
		return fmt.Errorf("%v is outside the network (%v)", addr, r)
	}
	if addr == r.Addr() || addr == netipx.PrefixLastIP(r) {
		return fmt.Errorf("%v cannot be the first or last address of %v", addr, r)
	}
	if target.V4 != nil && *target.V4 == addr {
		now := a.now().Unix()
		if r := target.Retiring; r.Live(now) {
			a.ok("unchanged: %s at %v; its old %v works until %s", name, addr, r.Addr, deadline(r.Until))
			if until == types.RetireAtOnce {
				a.hint("to retire every old address now: juist network renumber --finish")
			}
			return nil
		}
		a.ok("unchanged: %s at %v", name, addr)
		return nil
	}
	for _, n := range state.Nodes() {
		switch {
		case n.Identity == target.Identity || !slices.Contains(n.V4Addrs(), addr):
		case n.Retiring != nil && n.Retiring.Addr == addr && n.Retiring.Live(a.now().Unix()):
			return fmt.Errorf("%v is the old address of %s until %s\nhint: to free it now: juist network renumber --finish",
				addr, displayMember(n), deadline(n.Retiring.Until))
		case n.Retiring != nil && n.Retiring.Addr == addr && state.Schema() >= types.SchemaTakeRetired:
		case n.Retiring != nil && n.Retiring.Addr == addr:
			return fmt.Errorf("%v is held as the old address of %s\nhint: to free it: juist network renumber --finish",
				addr, displayMember(n))
		default:
			return fmt.Errorf("%v is taken by %s", addr, displayMember(n))
		}
	}
	history, err := a.addressHistory()
	if err != nil {
		return err
	}
	if g, held := givenOut(state, history)[addr]; held && g.ID != target.Identity {
		a.warn("%v was used by %s; devices not told yet still send its traffic there", addr,
			cmp.Or(g.Name, g.ID.ShortString()))
	}
	a.warnTransitionEnds([]types.NodeRecord{target}, map[types.Identity]netip.Addr{target.Identity: addr})
	atOnce := until == types.RetireAtOnce && target.V4 != nil
	if atOnce {
		a.warn("connections to %v (%s) end; devices not told yet reach %s over IPv6 only until they are",
			*target.V4, name, name)
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
	free := state.Schema() >= types.SchemaTakeRetired
	nodes := slices.DeleteFunc(state.Nodes(), func(n types.NodeRecord) bool { return n.Retiring == nil })
	slices.SortFunc(nodes, func(x, y types.NodeRecord) int { return x.Retiring.Addr.Compare(y.Retiring.Addr) })
	// What still works is retired; what works no more, but is held, is freed.
	var live, held []string
	if r, ok := state.V4Retiring(); ok {
		item := "the old range " + joinPrefixes(r.Prefixes)
		if r.Live(now) {
			live = append(live, item)
		} else if !free {
			held = append(held, item)
		}
	}
	for _, n := range nodes {
		item := fmt.Sprintf("%v (%s)", n.Retiring.Addr, displayMember(n))
		if n.Retiring.Live(now) {
			live = append(live, item)
		} else if !free {
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
			cut = append(cut, fmt.Sprintf("%v (%s)", n.Retiring.Addr, displayMember(n)))
		}
	}
	if len(cut) > 0 {
		a.warn("old addresses retire now, not at their deadline: %s", strings.Join(cut, ", "))
	}
}

// numberedFrom reports whether the network is numbered from p already: new
// devices are, and every device's address lies in it.
func numberedFrom(state *log.State, p netip.Prefix) bool {
	return p == state.V4Range() &&
		!slices.ContainsFunc(state.Nodes(), func(n types.NodeRecord) bool { return n.V4 != nil && !p.Contains(*n.V4) })
}

type grant = govern.Grant

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
		if g, taken := held[v4]; taken && g.ID != n.Identity {
			return
		}
		given[n.Identity] = v4
		held[v4] = grant{ID: n.Identity}
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

func givenOut(state *log.State, history []types.AUM) map[netip.Addr]grant {
	return govern.GivenOut(state, history)
}
