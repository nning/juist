package mobile

import (
	"cmp"
	"slices"
	"time"

	"github.com/nning/juist/daemon"
	juistnames "github.com/nning/juist/internal/names"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A view is an [ipc.Status] as the app shows it, judged as `juist status`
// judges it, and with nothing the status does not carry.
type view struct {
	// State is none, joining, disabled, unstarted, removed, disconnected,
	// refused, limited, waiting, notunnel or connected, in the order they win.
	State   string `json:"state"`
	Network string `json:"network,omitempty"`
	// Detail is why the mesh did not start, for unstarted.
	Detail string `json:"detail,omitempty"`

	Self    member   `json:"self"`
	Members []member `json:"members,omitempty"`

	Fresh   freshness `json:"fresh"`
	Tunnels tunnels   `json:"tunnels"`
	Exit    *exit     `json:"exit,omitempty"`
	Names   *names    `json:"names,omitempty"`
	Alarms  []alarm   `json:"alarms,omitempty"`

	// Updated is when the peer set was last derived, Unix seconds.
	Updated int64 `json:"updated,omitempty"`

	Settings settings `json:"settings"`
	Details  details  `json:"details"`

	// Admins are the network's admin keys, as [AdminKeyOf] names them, by
	// which the app tells the networks it holds a key of; Waiting is how many
	// changes wait for votes on this phone.
	Admins  []string `json:"admins,omitempty"`
	Waiting int      `json:"waiting,omitempty"`
}

// settings are the phone's own: Names whether its lookups go to juist's
// resolver, PublicNames whether it resolves the public names the network
// points at members to them, HTTPSOnly whether it reaches relays by TLS on
// 443 alone, PortMapping whether it has the router open a port for it.
type settings struct {
	Names       bool `json:"names"`
	PublicNames bool `json:"publicNames,omitempty"`
	HTTPSOnly   bool `json:"httpsOnly,omitempty"`
	PortMapping bool `json:"portMapping"`
}

// details are what `juist status` says beyond the state: the network's
// schema and this build's, the log's head, the relays, the subnets.
type details struct {
	Schema    int    `json:"schema,omitempty"`
	AppSchema int    `json:"appSchema"`
	Epoch     uint64 `json:"epoch,omitempty"`
	Head      string `json:"head,omitempty"`
	// Relays is how many members may relay, Installed how many this phone
	// holds, Home the one it is homed at; HTTPSRelays those on 443 it
	// reaches while on HTTPS alone.
	Relays      int      `json:"relays,omitempty"`
	Installed   int      `json:"installed,omitempty"`
	Home        string   `json:"home,omitempty"`
	HTTPSRelays []string `json:"httpsRelays,omitempty"`
	// PublicDERP says members meet through Tailscale's public DERP servers
	// where no member relays.
	PublicDERP bool `json:"publicDerp,omitempty"`
	// Underlay is what the data plane measured of the network beneath.
	Underlay *measured     `json:"underlay,omitempty"`
	Subnets  []subnetRoute `json:"subnets,omitempty"`
}

// A subnetRoute is a subnet the network routes through Router, in use or
// not and why.
type subnetRoute struct {
	Prefix string `json:"prefix"`
	Router string `json:"router,omitempty"`
	InUse  bool   `json:"inUse,omitempty"`
	Why    string `json:"why,omitempty"`
}

// A member is a device of the network.
type member struct {
	Identity string `json:"identity"`
	Name     string `json:"name"`
	// DNS is its name under the network's domain, where it has one.
	DNS   string   `json:"dns,omitempty"`
	V4    string   `json:"v4,omitempty"`
	V6    string   `json:"v6,omitempty"`
	Roles []string `json:"roles,omitempty"`
	// Retiring is the IPv4 address a renumbering moved it from, until
	// RetiringUntil.
	Retiring      string `json:"retiring,omitempty"`
	RetiringUntil int64  `json:"retiringUntil,omitempty"`

	// Reach is self, direct, relay, outdated, down, sought, absent,
	// silent, unchecked or unconnected; see [reachOf].
	Reach string `json:"reach"`
	// Relay names the member whose relay carries the traffic to it, where
	// Reach is relay.
	Relay string `json:"relay,omitempty"`
	// RelayPublic says Relay is one of Tailscale's public DERP servers.
	RelayPublic bool `json:"relayPublic,omitempty"`
	// Heard is when it last signed its announcement, and Since when its
	// tunnel was first found down, Unix seconds.
	Heard int64 `json:"heard,omitempty"`
	Since int64 `json:"since,omitempty"`

	// Published are the names published on it, NAME:PORT for one passed by
	// TCP, MembersOnly those of them for members alone, Names the public
	// names pointed at it, Subnets the prefixes it routes, and Build the
	// newest schema its juist implements.
	Published   []string `json:"published,omitempty"`
	MembersOnly []string `json:"membersOnly,omitempty"`
	Names       []string `json:"names,omitempty"`
	Subnets     []string `json:"subnets,omitempty"`
	Build       int      `json:"build,omitempty"`
	// Phone says it is a phone, which can only vouch.
	Phone bool `json:"phone,omitempty"`
}

// freshness is whether admin devices vouch for this device's view: State is
// unenforced where no device may vouch, fresh, or stale, when only tunnels to
// admin devices are kept.
type freshness struct {
	State    string `json:"state"`
	Since    int64  `json:"since,omitempty"`
	Until    int64  `json:"until,omitempty"`
	Vouching int    `json:"vouching,omitempty"`
	Vouchers int    `json:"vouchers,omitempty"`
}

// exit is this device's use of exit nodes: Node, by its identity and name,
// the one chosen, or none; Refused why the internet it would carry is
// refused instead, Failed why it is not even refused; DNS whether the
// phone's lookups go to it, DNSNot why not, Partly which family it carries
// not. Offering are the exit nodes to choose from.
type exit struct {
	Node     string   `json:"node,omitempty"`
	Name     string   `json:"name,omitempty"`
	Refused  string   `json:"refused,omitempty"`
	Failed   string   `json:"failed,omitempty"`
	DNS      bool     `json:"dns,omitempty"`
	DNSNot   string   `json:"dnsNot,omitempty"`
	Partly   string   `json:"partly,omitempty"`
	Offering []member `json:"offering,omitempty"`
}

// names is what the phone resolves of the network's names: Domain the
// network's, Own the phone's own names, Resolved whether its lookups
// reach juist's resolver, which the alarms say why not, and Public the
// public names the network points at other members.
type names struct {
	Domain   string       `json:"domain,omitempty"`
	Own      []string     `json:"own,omitempty"`
	Resolved bool         `json:"resolved,omitempty"`
	Public   []publicName `json:"public,omitempty"`
}

// A publicName is a public name pointed at Member, and Not why the phone
// resolves it publicly now, where it agreed to resolve it to Member.
type publicName struct {
	Name   string `json:"name"`
	Member string `json:"member,omitempty"`
	Not    string `json:"not,omitempty"`
}

// tunnels is the last check of the installed peers' tunnels, at Checked.
type tunnels struct {
	Live    int   `json:"live"`
	Total   int   `json:"total"`
	Checked int64 `json:"checked,omitempty"`
}

// An alarm is a note `juist status` would make that applies on a phone. Kind
// names it for the app to word; Names, Count and Text fill it in, Text being
// the daemon's own words, in English.
type alarm struct {
	Kind     string   `json:"kind"`
	Severity string   `json:"severity"` // alarm, warn or info
	Names    []string `json:"names,omitempty"`
	Count    int      `json:"count,omitempty"`
	Text     string   `json:"text,omitempty"`
}

// viewOf is s as the app shows it, Private DNS sending every lookup to
// privateDNS where set.
func viewOf(s *ipc.Status, privateDNS string) view {
	v := view{Network: s.NetworkName, Updated: s.LastReconcile,
		Self: member{Identity: s.Self.String(), Name: cmp.Or(s.SelfName, s.Self.ShortString()), Reach: "self", Phone: true},
		Settings: settings{Names: s.Names == nil || !s.Names.Off, PublicNames: s.Names != nil && s.Names.Accepted,
			HTTPSOnly: s.HTTPS != nil && s.HTTPS.Only, PortMapping: !s.PortMapOff},
		Details: details{AppSchema: int(types.CurrentSchema)}, Waiting: s.Waiting}
	for _, p := range s.Addrs {
		if p.Addr().Is4() {
			v.Self.V4 = cmp.Or(v.Self.V4, p.Addr().String())
		} else {
			v.Self.V6 = cmp.Or(v.Self.V6, p.Addr().String())
		}
	}
	switch {
	case !s.InNetwork && s.Joining:
		v.State = "joining"
		return v
	case !s.InNetwork:
		v.State = "none"
		return v
	case s.Disabled != "":
		v.State = "disabled"
		return v
	case s.StartError != "":
		v.State, v.Detail = "unstarted", s.StartError
		return v
	case s.NotMember:
		v.State = "removed"
		return v
	case s.Alarm != "":
		v.State = "disconnected"
	case s.Refused:
		v.State = "refused"
	case s.Stale:
		v.State = "limited"
	case s.Members > 1 && s.Peers == 0:
		v.State = "waiting"
	case s.TunnelsChecked && s.Peers > 0 && s.TunnelsLive == 0:
		v.State = "notunnel"
	default:
		v.State = "connected"
	}

	reach := make(map[types.Identity]ipc.PeerReach, len(s.Reach))
	for _, r := range s.Reach {
		reach[r.Identity] = r
	}
	builds := make(map[types.Identity]types.SchemaVersion, len(s.Builds))
	for _, b := range s.Builds {
		builds[b.Identity] = b.Schema
	}
	for _, d := range s.Devices {
		m := member{Identity: d.Identity.String(), Name: d.Name, V4: d.V4, V6: d.V6,
			Retiring: d.Retiring, RetiringUntil: d.RetiringUntil, Published: d.Published, MembersOnly: d.Members,
			Names: d.Names, Build: int(cmp.Or(d.Build, builds[d.Identity])), Phone: d.Phone}
		for _, p := range d.Subnets {
			m.Subnets = append(m.Subnets, p.String())
		}
		for _, r := range d.Roles {
			m.Roles = append(m.Roles, string(r))
		}
		if d.Identity == s.Self {
			// The addresses the device holds, which during a renumbering
			// are not yet the log's.
			m.Reach, m.Name = "self", cmp.Or(m.Name, v.Self.Name)
			m.V4, m.V6 = cmp.Or(v.Self.V4, m.V4), cmp.Or(v.Self.V6, m.V6)
			v.Self = m
			continue
		}
		r, installed := reach[d.Identity]
		m.Reach, m.Heard, m.Since = reachOf(r, installed, slices.Contains(s.Silent, d.Name), s.ReachChecked != 0), r.Heard, r.Since
		if m.Reach == "relay" {
			m.Relay, m.RelayPublic = r.Relay, r.PublicRelay
		}
		v.Members = append(v.Members, m)
	}
	slices.SortStableFunc(v.Members, func(a, b member) int { return cmp.Compare(a.Name, b.Name) })
	if s.HostConflict != nil {
		// Running without IPv4, the phone reaches no member's.
		v.Self.V4, v.Self.Retiring = "", ""
		for i := range v.Members {
			v.Members[i].V4, v.Members[i].Retiring = "", ""
		}
	}
	if s.Names != nil && s.Names.Domain != "" {
		dnsNames(&v, s.Names.Domain)
	}

	switch {
	case s.LeaseSigners == 0:
		v.Fresh.State = "unenforced"
	case s.Stale:
		v.Fresh.State = "stale"
	default:
		v.Fresh.State = "fresh"
	}
	v.Fresh.Since, v.Fresh.Until, v.Fresh.Vouching, v.Fresh.Vouchers = s.FreshSince, s.FreshUntil, s.Vouching, s.Vouchers
	if s.TunnelsChecked {
		v.Tunnels = tunnels{Live: s.TunnelsLive, Total: s.TunnelsLive + len(s.TunnelsDown), Checked: s.ReachChecked}
	}
	v.Exit = exitOf(s.Exit, v.Members)
	v.Names = namesOf(s.Names, v.Self)
	v.Alarms = alarmsOf(s, privateDNS)
	v.Details = detailsOf(s)
	return v
}

// detailsOf is what s says beyond the state.
func detailsOf(s *ipc.Status) details {
	d := details{Schema: int(s.Schema), AppSchema: int(types.CurrentSchema), Epoch: s.Epoch,
		Relays: s.RelayCapable, Installed: s.Relays, Home: s.HomeRelay, Underlay: underlayOf(s.Underlay),
		PublicDERP: s.PublicDERP}
	if s.Head != (types.Hash{}) {
		d.Head = s.Head.String()[:12]
	}
	if s.HTTPS != nil && s.HTTPS.Only {
		d.HTTPSRelays = s.HTTPS.Relays
	}
	if s.Subnets != nil {
		for _, r := range s.Subnets.Routes {
			d.Subnets = append(d.Subnets, subnetRoute{Prefix: r.Prefix.String(), Router: r.Name, InUse: r.InUse, Why: r.Why})
		}
	}
	return d
}

// dnsNames gives each device its name under domain, as the zone does: none
// to a label two devices' names share.
func dnsNames(v *view, domain string) {
	labels := map[string]int{}
	all := []*member{&v.Self}
	for i := range v.Members {
		all = append(all, &v.Members[i])
	}
	for _, m := range all {
		labels[juistnames.Label(m.Name)]++
	}
	for _, m := range all {
		if l := juistnames.Label(m.Name); l != "" && labels[l] == 1 {
			m.DNS = l + "." + domain
		}
	}
}

// namesOf is n as the app shows it, nil where there are none.
func namesOf(n *ipc.Names, self member) *names {
	if n == nil || n.Domain == "" && n.Public == "" && len(n.Overrides) == 0 {
		return nil
	}
	out := &names{Domain: n.Domain, Resolved: n.Resolved}
	if self.DNS != "" {
		out.Own = append(out.Own, self.DNS)
	}
	for _, o := range n.Overrides {
		if o.Device == self.Name && self.Name != "" {
			out.Own = append(out.Own, o.Name)
			continue
		}
		out.Public = append(out.Public, publicName{Name: o.Name, Member: o.Device, Not: o.Not})
	}
	return out
}

// exitOf is e as the app shows it, the exit nodes on offer by their members;
// nil where there is none to use and none chosen.
func exitOf(e *ipc.Exit, members []member) *exit {
	if e == nil || len(e.Offering) == 0 && e.Node.IsZero() {
		return nil
	}
	x := &exit{Refused: e.Refused, Failed: e.Failed, DNS: e.DNS, DNSNot: e.DNSNot, Partly: e.Partly}
	if !e.Node.IsZero() {
		x.Node, x.Name = e.Node.String(), e.Name
	}
	for _, id := range e.Offering {
		for _, m := range members {
			if m.Identity == id.String() {
				x.Offering = append(x.Offering, member{Identity: m.Identity, Name: m.Name, Reach: m.Reach})
			}
		}
	}
	return x
}

// reachOf is how the last check reached a peer, as `juist status` lists it:
// silent where it has announced nothing yet, unchecked before the first
// check, unconnected where it is heard from yet has no tunnel installed.
func reachOf(r ipc.PeerReach, installed, silent, checked bool) string {
	switch {
	case !installed && silent:
		return "silent"
	case !installed && !checked:
		return "unchecked"
	case !installed:
		return "unconnected"
	case r.Live && r.Outdated:
		return "outdated"
	case r.Live && r.Direct:
		return "direct"
	case r.Live:
		return "relay"
	case r.Absent:
		return "absent"
	case r.Seeking:
		return "sought"
	}
	return "down"
}

// alarmsOf are the notes of `juist status` that a phone can have, most
// severe first; those about a host's firewall, ports, relay or terminator
// cannot apply.
func alarmsOf(s *ipc.Status, privateDNS string) []alarm {
	var out []alarm
	add := func(a alarm) { out = append(out, a) }
	if s.Alarm != "" {
		add(alarm{Kind: "fork", Severity: "alarm", Text: s.Alarm})
	}
	if s.SchemaAlarm != "" {
		add(alarm{Kind: "schema", Severity: "alarm", Text: s.SchemaAlarm})
	}
	if s.StaleKeys {
		add(alarm{Kind: "staleKeys", Severity: "warn"})
	}
	if s.Refused {
		add(alarm{Kind: "refused", Severity: "warn"})
	}
	if s.EpochError != "" {
		add(alarm{Kind: "epoch", Severity: "warn", Text: s.EpochError})
	}
	if s.DataPlaneError != "" {
		add(alarm{Kind: "dataPlane", Severity: "warn", Text: s.DataPlaneError})
	}
	if down := s.Blocked(); len(down) > 0 {
		// As juist health: with a relay to meet at, NAT is not to blame.
		kind := "noTraffic"
		if s.Relays > 0 || s.PublicDERP {
			kind = "noTrafficRelayed"
		}
		add(alarm{Kind: kind, Severity: "warn", Names: down})
	}
	if len(s.SyncNewer) > 0 {
		add(alarm{Kind: "newer", Severity: "warn", Names: s.SyncNewer})
	}
	if len(s.Outdated) > 0 {
		add(alarm{Kind: "outdated", Severity: "warn", Names: s.Outdated})
	}
	if len(s.OlderBuild) > 0 {
		add(alarm{Kind: "older", Severity: "warn", Names: s.OlderBuild})
	}
	if s.Conflicted > 0 {
		add(alarm{Kind: "conflicted", Severity: "warn", Count: s.Conflicted})
	}
	if left, ending := s.FreshnessEnding(time.Now().Unix()); ending {
		add(alarm{Kind: "freshnessEnding", Severity: "warn", Count: int((left + time.Hour - 1) / time.Hour)})
	}
	if s.RelayCapable == 0 && !s.PublicDERP && s.Members > 2 && s.Alarm == "" {
		add(alarm{Kind: "noRelay", Severity: "warn"})
	}
	for _, l := range s.Lost {
		add(alarm{Kind: "lost", Severity: "warn", Text: l})
	}
	for _, u := range s.Unrevoked {
		add(alarm{Kind: "unrevoked", Severity: "warn", Text: u})
	}
	out = append(out, namesAlarms(s.Names, privateDNS)...)
	if s.Unreachable > 0 && s.Peers > 0 {
		add(alarm{Kind: "silent", Severity: "info", Names: s.Silent, Count: s.Unreachable})
	}
	return out
}

// namesAlarms are what `juist health` says of the network's names that a
// phone can have: why they are not resolved, Private DNS by the host it
// sends every lookup to, and each name for members alone then out of reach.
func namesAlarms(n *ipc.Names, privateDNS string) []alarm {
	if n == nil || n.Resolved || n.Off {
		return nil
	}
	var out []alarm
	switch {
	case privateDNS != "" && n.Not == daemon.PrivateDNSNot(privateDNS):
		out = append(out, alarm{Kind: "privateDns", Severity: "warn", Names: []string{privateDNS}})
	case n.Cannot:
		out = append(out, alarm{Kind: "names", Severity: "info", Text: n.Not})
	default:
		out = append(out, alarm{Kind: "names", Severity: "warn", Text: n.Not})
	}
	if len(n.ForMembers) > 0 {
		out = append(out, alarm{Kind: "forMembers", Severity: "warn", Names: slices.Clone(n.ForMembers)})
	}
	return out
}

// measured is what the data plane measured of the network beneath, as
// [ipc.Underlay] says it.
type measured struct {
	UDP         bool     `json:"udp,omitempty"`
	IPv4        bool     `json:"ipv4,omitempty"`
	IPv6        bool     `json:"ipv6,omitempty"`
	Mapping     bool     `json:"mapping,omitempty"`
	PortPerPeer bool     `json:"portPerPeer,omitempty"`
	Offered     []string `json:"offered,omitempty"`
	Mapped      string   `json:"mapped,omitempty"`
}

func underlayOf(u *ipc.Underlay) *measured {
	if u == nil {
		return nil
	}
	return &measured{UDP: u.UDP, IPv4: u.IPv4, IPv6: u.IPv6, Mapping: u.Mapping, PortPerPeer: u.PortPerPeer,
		Offered: u.Offered, Mapped: u.Mapped}
}

// adminsOf are state's admin keys, as [AdminKeyOf] names them.
func adminsOf(state *log.State) []string {
	var out []string
	for _, a := range state.Admins() {
		out = append(out, a.Public.String())
	}
	return out
}
