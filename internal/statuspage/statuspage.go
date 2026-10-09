// Package statuspage serves a network's status page, as the device serving
// it sees the network, to members whole and to the public as far as its
// operator lets it.
package statuspage

import (
	"cmp"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nning/juist/internal/webstyle"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

//go:embed page.html
var pageHTML string

//go:embed refresh.js
var refreshJS []byte

var pageTmpl = webstyle.Page("status", pageHTML, template.FuncMap{
	"join":  func(s []string) string { return strings.Join(s, ", ") },
	"short": func(h types.Hash) string { return h.String()[:12] },
})

// assets is where the page's fonts, icon and script are: a dot-entry, which no
// page of its own is.
const assets = "/.juist/"

// csp lets the page style itself, load its fonts, icon and script, and fetch
// itself again, and nothing else.
const csp = "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// cacheFor is how long one answer of juistd's serves every client, and
// keepFor how long while juistd does not answer.
const (
	cacheFor = 2 * time.Second
	keepFor  = 15 * time.Second
)

// A Server serves status pages from what Fetch says, asking it at most once
// every [cacheFor].
type Server struct {
	fetch func(context.Context) (*ipc.StatusPage, error)
	now   func() time.Time

	mu   sync.Mutex
	at   time.Time
	page *ipc.StatusPage
}

// New is a Server asking fetch; now is the clock, nil for time.Now.
func New(fetch func(context.Context) (*ipc.StatusPage, error), now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{fetch: fetch, now: now}
}

// get is the page, juistd's last answer while it is younger than
// [cacheFor], and while it is younger than [keepFor] where juistd does not
// answer: the terminator's one slot on the socket is shared with its polls.
func (s *Server) get(ctx context.Context) (*ipc.StatusPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.at.IsZero() && now.Sub(s.at) < cacheFor && !now.Before(s.at) {
		return s.page, nil
	}
	p, err := s.fetch(ctx)
	switch {
	case err == nil:
		s.page, s.at = p, now
	case s.page != nil && now.Sub(s.at) < keepFor && !now.Before(s.at):
		return s.page, nil
	default:
		s.page = nil
	}
	return p, err
}

// Handler serves the status page under name, showing a client who is no
// member, by its connection's address, what public lets it.
func (s *Server) Handler(name string, public ipc.Visibility) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex")
		// http:// to the name reaches whatever holds port 80 on this device.
		h.Set("Strict-Transport-Security", "max-age=31536000")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p, err := s.get(r.Context())
		member := false
		if ap, perr := netip.ParseAddrPort(r.RemoteAddr); perr == nil && p != nil {
			member = p.Member(ap.Addr())
		}
		if !member && public == ipc.ShowNone {
			http.NotFound(w, r)
			return
		}
		switch {
		case r.URL.Path == assets+"refresh.js":
			h.Set("Content-Type", "text/javascript; charset=utf-8")
			h.Set("Cache-Control", "max-age=3600")
			_, _ = w.Write(refreshJS)
			return
		case strings.HasPrefix(r.URL.Path, assets):
			webstyle.ServeAsset(w, r, strings.TrimPrefix(r.URL.Path, assets))
			return
		case r.URL.Path != "/":
			http.NotFound(w, r)
			return
		}
		h.Set("Content-Security-Policy", csp)
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		v := build(p, err, name, public, member, s.now())
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if r.Method == http.MethodHead {
			return
		}
		_ = pageTmpl.Execute(w, v)
	})
}

// A view is the page as rendered.
type view struct {
	Assets, Name, Title, From, Updated string
	State, StateClass, Summary         string
	Unavailable                        string
	Member                             bool
	Public                             string

	Services []service
	Devices  []device
	Alarms   []string
	Facts    []fact
	Changes  []ipc.Change
	Total    int

	ShowNetwork, ShowChanges bool
}

type service struct {
	Name, Href, Device, State, Class string
}

type device struct {
	Name, Addrs, Roles, Reach, Class, Heard string
	Self                                    bool
}

type fact struct{ Label, Text string }

// publicWords say what the public sees, for members.
var publicWords = map[ipc.Visibility]string{
	ipc.ShowNone:     "nothing of this page",
	ipc.ShowServices: "the services alone",
	ipc.ShowNetwork:  "all of this page but the changes",
	ipc.ShowAll:      "all of this page",
}

// build is the view of p a member sees whole, and the public as public
// says; err is why there is no p.
func build(p *ipc.StatusPage, err error, name string, public ipc.Visibility, member bool, now time.Time) view {
	shown := public
	if member {
		shown = ipc.ShowAll
	}
	v := view{Assets: assets, Name: name, Title: name, Member: member, Updated: now.UTC().Format("15:04:05 UTC"),
		ShowNetwork: shown >= ipc.ShowNetwork, ShowChanges: shown >= ipc.ShowAll}
	if err != nil || p == nil {
		v.Unavailable = "juistd does not answer on this device"
		v.State, v.StateClass = "unknown", "absent"
		return v
	}
	st := &p.Status
	v.Title = cmp.Or(st.NetworkName, name)
	v.From = cmp.Or(st.SelfName, st.Self.ShortString())
	v.State, v.StateClass = state(st)
	v.Services = services(p)
	if member {
		v.Public = publicWords[public]
	}
	if !v.ShowNetwork {
		// Which devices there are is the network's to show.
		v.From = ""
		up := 0
		for i, s := range v.Services {
			v.Services[i].Device = ""
			if s.Class == "direct" {
				up++
			}
		}
		v.Summary = fmt.Sprintf("%d of %s up", up, plural(len(v.Services), "service"))
		return v
	}
	v.Devices = devices(st, now)
	live := 0
	for _, d := range v.Devices {
		if d.Self || d.Class == "direct" || d.Class == "relay" {
			live++
		}
	}
	v.Summary = fmt.Sprintf("%s, %d reached", plural(len(v.Devices), "device"), live)
	v.Alarms = alarms(st)
	v.Facts = facts(st, p, now)
	if v.ShowChanges {
		v.Changes, v.Total = p.Changes, p.Total
	}
	return v
}

// state is the network's state as juist status heads it, and its class.
func state(st *ipc.Status) (string, string) {
	switch {
	case !st.InNetwork:
		return "no network", "alarm"
	case st.Disabled != "":
		return "disabled", "alarm"
	case st.NotMember:
		return "removed", "alarm"
	case st.StartError != "":
		return "not connected", "alarm"
	case st.Alarm != "":
		return "disconnected", "alarm"
	case st.Refused:
		return "refused", "alarm"
	case st.Stale:
		return "limited", "relay"
	case st.Members > 1 && st.Peers == 0:
		return "waiting for peers", "relay"
	case st.TunnelsChecked && st.Peers > 0 && st.TunnelsLive == 0:
		return "no tunnel up", "relay"
	}
	return "connected", "direct"
}

// reachOf is how this device last found it reaches id, if it installed id.
func reachOf(st *ipc.Status, id types.Identity) (ipc.PeerReach, bool) {
	i := slices.IndexFunc(st.Reach, func(r ipc.PeerReach) bool { return r.Identity == id })
	if i < 0 {
		return ipc.PeerReach{}, false
	}
	return st.Reach[i], true
}

func devices(st *ipc.Status, now time.Time) []device {
	var out []device
	for _, d := range st.Devices {
		dev := device{Name: cmp.Or(d.Name, d.Identity.ShortString()), Addrs: strings.Join(nonEmpty(d.V4, d.V6), "  ")}
		var roles []string
		for _, r := range d.Roles {
			roles = append(roles, string(r))
		}
		dev.Roles = strings.Join(roles, ", ")
		r, installed := reachOf(st, d.Identity)
		switch {
		case d.Identity == st.Self:
			dev.Self, dev.Reach, dev.Class = true, "this device", "self"
		case !installed && slices.Contains(st.Silent, dev.Name):
			dev.Reach, dev.Class = "not heard from", "absent"
		case !installed:
			dev.Reach, dev.Class = "no tunnel", "absent"
		case !st.TunnelsChecked:
			dev.Reach, dev.Class = "not checked yet", "absent"
		case r.Live && r.Direct:
			dev.Reach, dev.Class = "direct", "direct"
		case r.Live:
			dev.Reach, dev.Class = "relay", "relay"
		case r.Absent:
			dev.Reach, dev.Class = "absent", "absent"
		case r.Seeking:
			dev.Reach, dev.Class = "sought", "sought"
		default:
			dev.Reach, dev.Class = "down", "alarm"
		}
		if r.Heard > 0 {
			dev.Heard = "heard " + ago(now.Sub(time.Unix(r.Heard, 0)))
		}
		out = append(out, dev)
	}
	slices.SortStableFunc(out, func(a, b device) int {
		if a.Self != b.Self {
			if a.Self {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out
}

// services are the names published in the network and shared now, and
// whether each is up as this device sees it: served, and its device
// reached.
func services(p *ipc.StatusPage) []service {
	st := &p.Status
	var out []service
	for _, d := range st.Devices {
		self := d.Identity == st.Self
		served := d.Serving
		if self {
			served = st.Publish != nil && len(st.Publish.Serving) > 0
		}
		r, _ := reachOf(st, d.Identity)
		for _, name := range d.Published {
			s := service{Name: name, Device: cmp.Or(d.Name, d.Identity.ShortString())}
			if !strings.Contains(name, ":") {
				s.Href = "https://" + name + "/" // one published by TCP, NAME:PORT, is no web page
			}
			switch {
			case !served:
				s.State, s.Class = "not served", "absent"
			case self || r.Live:
				s.State, s.Class = "up", "direct"
			default:
				s.State, s.Class = "unreached", "alarm"
			}
			out = append(out, s)
		}
	}
	for _, name := range p.Shares {
		label, _, _ := strings.Cut(name, ".")
		out = append(out, service{Name: name, Device: label, State: "shared", Class: "direct"})
	}
	slices.SortFunc(out, func(a, b service) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// alarms are what needs attention, as this device finds it.
func alarms(st *ipc.Status) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	if st.Disabled != "" {
		add("the network was ended with a break-glass secret")
	}
	if st.Alarm != "" {
		add("%s; tunnels down until resolved", st.Alarm)
	}
	if st.SchemaAlarm != "" {
		add("%s; no changes apply until juist is updated", st.SchemaAlarm)
	}
	if st.StartError != "" {
		add("tunnels not up, retrying: %s", st.StartError)
	}
	if st.Stale {
		add("this device's view of the network is stale: tunnels to admin devices alone")
	}
	if st.Refused {
		add("the network's devices refuse this one: most likely it was removed")
	}
	if st.StaleKeys {
		add("juistd runs on replaced keys")
	}
	if st.EpochError != "" {
		add("cannot open the group secret: %s", st.EpochError)
	}
	if st.DataPlaneError != "" {
		add("data plane refused the device set: %s", st.DataPlaneError)
	}
	if t := st.Terminator; t != nil && t.Running {
		for _, n := range t.NoCert {
			add("no certificate for %s: %s", n.Name, n.Why)
		}
		if on := t.HTTPHeldOn(); len(on) > 0 {
			add("another program holds port 80 on %s, which http:// to a name served there reaches instead of "+
				"a redirect to https", strings.Join(on, ", "))
		}
	}
	if len(st.SyncFailing) > 0 {
		add("log sync to %s fails in the tunnel", strings.Join(st.SyncFailing, ", "))
	}
	if down := slices.DeleteFunc(slices.Clone(st.TunnelsDown), func(n string) bool {
		return slices.Contains(st.Seeking, n) || slices.Contains(st.Absent, n)
	}); len(down) > 0 {
		add("no tunnel traffic from %s", strings.Join(down, ", "))
	}
	if st.Conflicted > 0 {
		add("%s announce a key another device uses", plural(st.Conflicted, "device"))
	}
	if left, ending := st.FreshnessEnding(time.Now().Unix()); ending {
		add("freshness ends in %s unless %s", roughly(left), st.VouchAgain())
	}
	if st.RelayUnreached {
		add("no device reaches this device's relay")
	}
	if h := st.HTTPS; h != nil && h.Only && len(h.Relays) == 0 {
		add("no relay on 443/tcp, the one way this device reaches the others")
	}
	if h := st.HTTPS; h != nil && h.Name != "" && st.Relaying {
		switch {
		case h.NotAnnounced != "":
			add("members are not told of %s: %s", h.Name, h.NotAnnounced)
		case h.ListenError != "":
			add("the relay cannot take 443: %s", h.ListenError)
		case h.NoCert != "":
			add("no certificate for %s yet: %s", h.Name, h.NoCert)
		}
	}
	for _, l := range st.Lost {
		add("%s lost to a concurrent change", l)
	}
	for _, u := range st.Unrevoked {
		add("%s lost to a concurrent change and is not in effect", u)
	}
	return out
}

func facts(st *ipc.Status, p *ipc.StatusPage, now time.Time) []fact {
	var out []fact
	add := func(label, format string, args ...any) {
		out = append(out, fact{Label: label, Text: fmt.Sprintf(format, args...)})
	}
	var addrs []string
	for _, a := range st.Addrs {
		addrs = append(addrs, a.Addr().String())
	}
	add("Seen from", "%s  %s", cmp.Or(st.SelfName, st.Self.ShortString()), strings.Join(addrs, "  "))
	if st.TunnelsChecked && st.Peers > 0 {
		text := fmt.Sprintf("%d of %d live", st.TunnelsLive, st.TunnelsLive+len(st.TunnelsDown))
		if st.ReachChecked > 0 {
			text += ", checked " + ago(now.Sub(time.Unix(st.ReachChecked, 0)))
		}
		add("Tunnels", "%s", text)
	}
	if st.RelayCapable > 0 || st.Relaying {
		text := fmt.Sprintf("%d available", st.RelayCapable)
		if st.HomeRelay != "" && !st.Relaying {
			text += ", via " + st.HomeRelay
		}
		if st.Relaying {
			text += "; this device relays for " + plural(st.RelayedFor, "device")
		}
		add("Relays", "%s", text)
	}
	if h := st.HTTPS; h != nil && h.Only {
		add("HTTPS", "only, by %s", cmp.Or(strings.Join(h.Relays, ", "), "no relay"))
	}
	if h := st.HTTPS; h != nil && h.Name != "" && st.Relaying {
		add("Relay name", "%s, on 443", h.Name)
	}
	var exits, subnets []string
	for _, d := range st.Devices {
		if slices.Contains(d.Roles, types.RoleExit) {
			exits = append(exits, cmp.Or(d.Name, d.Identity.ShortString()))
		}
		for _, s := range d.Subnets {
			subnets = append(subnets, s.String()+" via "+cmp.Or(d.Name, d.Identity.ShortString()))
		}
	}
	if len(exits) > 0 {
		add("Exit nodes", "%s", strings.Join(exits, ", "))
	}
	if len(subnets) > 0 {
		add("Subnets", "%s", strings.Join(subnets, ", "))
	}
	if n := st.Names; n != nil && n.Public != "" {
		add("Domain", "%s", n.Public)
	}
	switch {
	case st.LeaseSigners == 0:
		add("Freshness", "unchecked: no voucher")
	case st.Stale:
		add("Freshness", "expired")
	case st.FreshUntil > 0:
		add("Freshness", "vouched %s, valid %s more", ago(now.Sub(time.Unix(st.FreshSince, 0))),
			roughly(time.Unix(st.FreshUntil, 0).Sub(now)))
	}
	head := st.Head.String()
	if len(head) > 12 {
		head = head[:12]
	}
	add("Log", "%s, schema %d, head %s", plural(p.Total, "change"), st.Schema, head)
	return out
}

func nonEmpty(s ...string) []string {
	return slices.DeleteFunc(s, func(x string) bool { return x == "" })
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// ago says how long d ago was, roughly.
func ago(d time.Duration) string {
	if d < 5*time.Second {
		return "just now"
	}
	return roughly(d) + " ago"
}

// roughly is d in its largest unit.
func roughly(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
