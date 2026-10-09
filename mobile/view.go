package mobile

import (
	"cmp"
	"slices"
	"time"

	"github.com/nning/juist/ipc"
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
	Alarms  []alarm   `json:"alarms,omitempty"`

	// Updated is when the peer set was last derived, Unix seconds.
	Updated int64 `json:"updated,omitempty"`
}

// A member is a device of the network.
type member struct {
	Identity string   `json:"identity"`
	Name     string   `json:"name"`
	V4       string   `json:"v4,omitempty"`
	V6       string   `json:"v6,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	// Retiring is the IPv4 address a renumbering moved it from, until
	// RetiringUntil.
	Retiring      string `json:"retiring,omitempty"`
	RetiringUntil int64  `json:"retiringUntil,omitempty"`

	// Reach is self, direct, relay, down, sought, absent, silent,
	// unchecked or unconnected; see [reachOf].
	Reach string `json:"reach"`
	// Heard is when it last signed its announcement, and Since when its
	// tunnel was first found down, Unix seconds.
	Heard int64 `json:"heard,omitempty"`
	Since int64 `json:"since,omitempty"`
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

// viewOf is s as the app shows it.
func viewOf(s *ipc.Status) view {
	v := view{Network: s.NetworkName, Updated: s.LastReconcile,
		Self: member{Identity: s.Self.String(), Name: cmp.Or(s.SelfName, s.Self.ShortString()), Reach: "self"}}
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
	for _, d := range s.Devices {
		m := member{Identity: d.Identity.String(), Name: d.Name, V4: d.V4, V6: d.V6,
			Retiring: d.Retiring, RetiringUntil: d.RetiringUntil}
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
		v.Members = append(v.Members, m)
	}
	slices.SortStableFunc(v.Members, func(a, b member) int { return cmp.Compare(a.Name, b.Name) })

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
	v.Alarms = alarmsOf(s)
	return v
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
func alarmsOf(s *ipc.Status) []alarm {
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
	if down := slices.DeleteFunc(slices.Clone(s.TunnelsDown), func(n string) bool {
		return slices.Contains(s.Seeking, n) || slices.Contains(s.Absent, n)
	}); len(down) > 0 {
		add(alarm{Kind: "noTraffic", Severity: "warn", Names: down})
	}
	if s.Conflicted > 0 {
		add(alarm{Kind: "conflicted", Severity: "warn", Count: s.Conflicted})
	}
	if left, ending := s.FreshnessEnding(time.Now().Unix()); ending {
		add(alarm{Kind: "freshnessEnding", Severity: "warn", Count: int((left + time.Hour - 1) / time.Hour)})
	}
	if s.RelayCapable == 0 && s.Members > 2 && s.Alarm == "" {
		add(alarm{Kind: "noRelay", Severity: "warn"})
	}
	for _, l := range s.Lost {
		add(alarm{Kind: "lost", Severity: "warn", Text: l})
	}
	for _, u := range s.Unrevoked {
		add(alarm{Kind: "unrevoked", Severity: "warn", Text: u})
	}
	if s.Unreachable > 0 && s.Peers > 0 {
		add(alarm{Kind: "silent", Severity: "info", Names: s.Silent, Count: s.Unreachable})
	}
	if len(s.Seeking) > 0 {
		add(alarm{Kind: "seeking", Severity: "info", Names: s.Seeking})
	}
	return out
}
