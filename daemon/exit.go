package daemon

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// An ExitChoice is which exit node this device's owner chose: none yet, none
// ("off"), or one, by identity, which follows the node's renames, renumbering
// and identity rotations. Unreadable is a choice kept that cannot be read,
// refused as a node that cannot be used is. A default an admin sets comes
// below the first two. Isolate sends answers to connections that came in by
// another device through the node too.
type ExitChoice struct {
	Chosen     bool
	Node       types.Identity
	Unreadable bool
	Isolate    bool
}

// Off reports a choice to go direct.
func (c ExitChoice) Off() bool { return c.Chosen && c.Node.IsZero() && !c.Unreadable }

// Refuses reports a choice whose traffic, where it cannot be carried, is
// refused rather than sent directly.
func (c ExitChoice) Refuses() bool { return c.Chosen && !c.Off() }

// LoadExitChoice reads the choice kept at path; a missing file is no choice.
func LoadExitChoice(path string) (ExitChoice, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ExitChoice{}, nil
	}
	if err != nil {
		return ExitChoice{}, err
	}
	f := strings.Fields(string(b))
	if len(f) == 1 && f[0] == "off" {
		return ExitChoice{Chosen: true}, nil
	}
	if len(f) == 0 || len(f) > 2 || len(f) == 2 && f[1] != "isolate" {
		return ExitChoice{}, fmt.Errorf("%s: %q is no exit node", path, strings.TrimSpace(string(b)))
	}
	id, err := types.ParseIdentity(f[0])
	if err != nil {
		return ExitChoice{}, fmt.Errorf("%s: %w", path, err)
	}
	return ExitChoice{Chosen: true, Node: id, Isolate: len(f) == 2}, nil
}

// SaveExitChoice keeps c at path, or removes the file for no choice.
func SaveExitChoice(path string, c ExitChoice) error {
	switch {
	case !c.Chosen:
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	case c.Off():
		return statedir.WriteFilePrivate(path, []byte("off\n"))
	case c.Isolate:
		return statedir.WriteFilePrivate(path, []byte(c.Node.String()+" isolate\n"))
	}
	return statedir.WriteFilePrivate(path, []byte(c.Node.String()+"\n"))
}

// SetExitChoice makes c the exit node this device uses, from the next
// reconcile on.
func (d *Daemon) SetExitChoice(c ExitChoice) {
	d.mu.Lock()
	d.exitChoice = c
	d.mu.Unlock()
	d.MarkDirty()
}

// SetServeConsent records whether this device's operator agrees to serve as
// an exit node where the log grants it the role.
func (d *Daemon) SetServeConsent(on bool) {
	d.mu.Lock()
	d.serveConsent = on
	d.mu.Unlock()
	d.MarkDirty()
}

// An exitPlan is what one reconcile decides about exit nodes.
type exitPlan struct {
	egress  conn.Egress
	isolate bool
	serve   conn.Serve
	status  ipc.Exit
	subnets ipc.Subnets

	// dns is where the host's DNS goes, none for its own; keepDNS leaves it
	// as it is. dnsServe are the addresses this device answers members' DNS
	// on as an exit node, from the network's overlay.
	dns        []netip.AddrPort
	keepDNS    bool
	dnsServe   []netip.Addr
	dnsOverlay []netip.Prefix

	// routed is whether the log routes anything through this device, whose
	// clients then need to know it has no IPv4.
	routed bool

	// zone is what the host resolves of the network's names, nil to keep
	// what it resolves; overrides are the public names the log holds, and
	// namesUntil until when they may be answered.
	zone       *names.Zone
	overrides  []heldOverride
	namesUntil int64
	accepted   bool
}

// withSubnets adds sub's serving and status to p.
func (p exitPlan) withSubnets(sub subnetPlan, sources []netip.Prefix) exitPlan {
	p.serve.Subnets, p.subnets = sub.serve, sub.status
	if len(sub.serve) > 0 {
		p.serve.Sources = sources
	}
	return p
}

// exitRoutesOf is what member n's grant lets it carry as an exit node: the
// internet, in the families its default routes name, without overlay.
func exitRoutesOf(state *log.State, n types.NodeRecord, noV4 bool) []netip.Prefix {
	if !n.HasRole(types.RoleExit) {
		return nil
	}
	v4 := !noV4 && slices.Contains(n.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	v6 := slices.Contains(n.Routes, netip.MustParsePrefix("::/0"))
	if !v4 && !v6 {
		return nil
	}
	return conn.Internet(v4, v6, overlaySpace(state))
}

// overlaySpace is every overlay prefix of the network: its IPv4 ranges, the
// retiring and legacy ones included, and its IPv6 prefix.
func overlaySpace(state *log.State) []netip.Prefix {
	return append(slices.Clone(state.V4Ranges()), state.ULA())
}

// planExit decides egress and serving from the snapshot, and gives the chosen
// exit node's peer entry its routes. It fails closed: where the chosen node
// cannot carry this device's traffic, the traffic is refused, not let out
// directly.
func (d *Daemon) planExit(s snapshot, fresh bool, held map[types.Identity]gossip.Endpoint, peers []conn.Peer,
	named []namedPeer, taken []netip.Prefix) exitPlan {
	d.mu.Lock()
	choice, consent := d.exitChoice, d.serveConsent
	d.mu.Unlock()
	var p exitPlan
	p.status.Consent = consent
	for id, e := range held {
		if n, ok := s.state.Node(id); ok && e.Exit && id != d.self && s.live[id] && exitRoutesOf(s.state, n, false) != nil {
			p.status.Offering = append(p.status.Offering, id)
		}
	}
	slices.SortFunc(p.status.Offering, func(x, y types.Identity) int { return strings.Compare(x.String(), y.String()) })
	self, _ := s.state.Node(d.self)
	p.routed = len(self.Routes) > 0
	if serves := exitRoutesOf(s.state, self, d.noV4); consent {
		switch {
		case serves == nil:
			p.status.NotServing = "the network has not made this device an exit node"
		case !fresh:
			p.status.NotServing = "this device's view of the network is stale"
		case choice.Unreadable:
			p.status.NotServing = errUnreadableChoice
		case choice.Refuses():
			p.status.NotServing = "this device uses an exit node itself"
		default:
			p.serve = conn.Serve{Routes: serves, Sources: overlaySpace(s.state), DNS: DefaultDNSPort}
			for _, a := range d.overlayAddrs(s.state, d.self, s.now) {
				p.dnsServe = append(p.dnsServe, a.Addr())
			}
			p.dnsOverlay = overlaySpace(s.state)
		}
	}
	if !choice.Refuses() {
		p.status.Off = choice.Off()
		return p
	}
	p.egress, p.isolate, p.status.Isolated = conn.EgressRefused, choice.Isolate, choice.Isolate
	// Where no exit node is known to point DNS at, it stays where it is:
	// lookups go nowhere rather than to the LAN, as the traffic does.
	p.keepDNS = true
	if choice.Unreadable {
		p.status.Refused = errUnreadableChoice
		return p
	}
	if _, member := s.state.Node(choice.Node); !member {
		if next, ok := d.successor(choice.Node, s.state.Head()); ok {
			d.followExit(choice.Node, next)
			choice.Node = next
		}
	}
	p.status.Node = choice.Node
	n, member := s.state.Node(choice.Node)
	if member {
		p.status.Name = n.Name
		p.status.StrictRP6 = d.strictRP6 != nil && d.strictRP6()
		// Refused too: lookups then go nowhere, rather than to the LAN.
		p.dns = exitDNS(d.overlayAddrs(s.state, n.Identity, s.now), held[n.Identity])
		p.keepDNS = false
	}
	routes := exitRoutesOf(s.state, n, d.noV4 || held[choice.Node].NoV4)
	i := slices.IndexFunc(named, func(np namedPeer) bool { return np.id == choice.Node })
	switch {
	case !member || !s.live[choice.Node]:
		p.status.Refused = "it is no member of the network"
	case routes == nil && exitRoutesOf(s.state, n, false) != nil && d.noV4:
		p.status.Refused = "it carries IPv4 alone, and this device has no IPv4 in the network"
	case routes == nil && exitRoutesOf(s.state, n, false) != nil:
		p.status.Refused = "it carries IPv4 alone, and has no IPv4 in the network"
	case routes == nil:
		p.status.Refused = "the network has not made it an exit node"
	case !fresh:
		p.status.Refused = "this device's view of the network is stale"
	case i < 0:
		p.status.Refused = "it cannot be reached"
	case !held[choice.Node].Exit:
		p.status.Refused = "its operator has not agreed to serve"
	case d.userEgress != "":
		p.status.Refused = d.userEgress
	default:
		// What a subnet router takes is routed through it instead.
		for j := range peers {
			if peers[j].NodeKey == named[i].peer.NodeKey {
				peers[j].Routes = lessTaken(routes, taken)
			}
		}
		p.egress = conn.EgressTunnel
		name := cmp.Or(n.Name, "it")
		switch {
		case !slices.Contains(n.Routes, netip.MustParsePrefix("::/0")):
			p.status.Partly = "IPv6 refused: " + name + " carries IPv4 alone"
		case !slices.Contains(n.Routes, netip.MustParsePrefix("0.0.0.0/0")):
			p.status.Partly = "IPv4 refused: " + name + " carries IPv6 alone"
		case d.noV4:
			p.status.Partly = "IPv4 refused: this device has no IPv4 in the network"
		case held[choice.Node].NoV4:
			p.status.Partly = "IPv4 refused: " + name + " has no IPv4 in the network"
		}
		if held[choice.Node].DNS == 0 {
			// An exit node of a build that answers none.
			p.dns, p.status.DNSNot = nil, cmp.Or(n.Name, "it")+" answers no DNS"
		}
	}
	return p
}

// applyExit hands the plan to the data plane, egress before serving, and
// records what it did. The peer set carrying the routes is installed first.
func (d *Daemon) applyExit(p exitPlan) {
	if err := d.manager.SetEgress(p.egress, p.isolate); err != nil {
		// Refused is only what is refused: where even that fails, the
		// traffic may leave directly, and the status says so apart.
		switch {
		case p.egress == conn.EgressDirect:
			// Going direct is neither refusing nor failing to: the log says it.
		case errors.Is(err, conn.ErrEgressTaken):
			// The other network's table takes this one's traffic: not direct.
			p.status.Refused = err.Error()
		case p.egress == conn.EgressTunnel && d.manager.SetEgress(conn.EgressRefused, p.isolate) == nil:
			p.status.Refused = err.Error()
		default:
			p.status.Refused, p.status.Failed = "", err.Error()
		}
		d.logOnce("daemon: routing through the exit node: " + err.Error())
	}
	if err := d.manager.SetServe(p.serve); err != nil {
		if len(p.serve.Routes) > 0 {
			p.status.NotServing = err.Error()
		}
		if len(p.serve.Subnets) > 0 {
			p.subnets.NotServing = err.Error()
		}
		p.serve = conn.Serve{}
		d.logOnce("daemon: serving: " + err.Error())
	}
	p.status.Serving = len(p.serve.Routes) > 0
	p.subnets.Serving = p.serve.Subnets
	if !p.isolate {
		p.status.AnswersThrough = d.manager.AnswersThrough()
	}
	port := d.serveDNS(p.status.Serving, p.dnsServe, p.dnsOverlay)
	if port != 0 && p.serve.DNS != 0 {
		// Asked on 53, which the data plane sends to the forwarder.
		port = dnsAskedPort
	}
	d.setZone(p)
	through, why := d.routeDNS(p.dns, p.keepDNS)
	p.status.DNS = through
	if !through && !p.status.Node.IsZero() && p.status.DNSNot == "" {
		p.status.DNSNot = why
	}
	noV4 := d.noV4 && p.routed
	d.mu.Lock()
	changed := d.servingExit != p.status.Serving || d.servingSubnets != (len(p.serve.Subnets) > 0) ||
		d.dnsPort != port || d.announcedNoV4 != noV4
	d.dnsPort, d.announcedNoV4 = port, noV4
	d.servingExit = p.status.Serving
	d.servingSubnets = len(p.serve.Subnets) > 0
	d.exitStatus = p.status
	d.subnetStatus = p.subnets
	d.mu.Unlock()
	if changed {
		// Peers learn it from the announcement, which says so.
		d.MarkDirty()
	}
}

// egressUserOf is what f says, or the host of juistd's own user: an exit node
// is refused to a juistd of root or of a person's user, since its own
// traffic goes outside the tunnel, and so would all of that user's.
func egressUserOf(f func() string) string {
	if f != nil {
		return f()
	}
	return egressUser(os.Getuid(), os.ReadFile)
}

func egressUser(uid int, read func(string) ([]byte, error)) string {
	switch {
	case uid == 0:
		return "juistd runs as root, whose traffic is the host's"
	case !systemUser(uid, read):
		return "juistd runs as a login user, whose traffic would go around the exit node"
	}
	return ""
}

// systemUser reports whether uid is a system user's, below login.defs' UID_MIN
// as read, and not root.
func systemUser(uid int, read func(string) ([]byte, error)) bool {
	min := 1000
	if b, err := read("/etc/login.defs"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "UID_MIN" {
				if n, err := strconv.Atoi(f[1]); err == nil {
					min = n
				}
			}
		}
	}
	return uid > 0 && uid < min
}

// errUnreadableChoice is why a choice kept that cannot be read is refused.
const errUnreadableChoice = "the exit node chosen cannot be read"

// successor is the identity id's member rotated to, on the active chain up to
// head, if any. A miss is remembered for that head: the chain is walked
// under authMu, which gossip waits on.
func (d *Daemon) successor(id types.Identity, head types.Hash) (types.Identity, bool) {
	d.mu.Lock()
	missed := d.successorMiss.id == id && d.successorMiss.head == head
	d.mu.Unlock()
	if missed {
		return types.Identity{}, false
	}
	next, ok := d.walkSuccessor(id)
	if !ok {
		d.mu.Lock()
		d.successorMiss.id, d.successorMiss.head = id, head
		d.mu.Unlock()
	}
	return next, ok
}

func (d *Daemon) walkSuccessor(id types.Identity) (types.Identity, bool) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	chain, err := d.authority.Chain()
	if err != nil {
		return types.Identity{}, false
	}
	moved := false
	for _, h := range chain {
		aum, err := d.storage.AUM(h)
		if err != nil {
			return types.Identity{}, false
		}
		if aum.Kind == types.KindRotateIdentity && aum.Subject != nil && *aum.Subject == id && aum.NewIdentity != nil {
			id, moved = *aum.NewIdentity, true
		}
	}
	return id, moved
}

// followExit makes the node from's identity rotated to the choice, where from
// is still chosen, and has it kept.
func (d *Daemon) followExit(from, to types.Identity) {
	d.mu.Lock()
	still := d.exitChoice.Node == from
	if still {
		d.exitChoice.Node = to
	}
	d.mu.Unlock()
	if still && d.onExitMoved != nil {
		go d.onExitMoved(from, to)
	}
}

func (d *Daemon) exitChoiceNow() ExitChoice {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.exitChoice
}

// exitDown is the plan while this device cannot say who is a member: nothing
// served, and a chosen exit node's traffic refused.
func (d *Daemon) exitDown(why string) exitPlan {
	d.mu.Lock()
	choice, consent := d.exitChoice, d.serveConsent
	subnetConsent, subnetsOff := d.subnetConsent, d.subnetsOff
	d.mu.Unlock()
	p := exitPlan{status: ipc.Exit{Consent: consent, Off: choice.Off(), Node: choice.Node},
		subnets: ipc.Subnets{Consent: subnetConsent, Off: subnetsOff}, keepDNS: choice.Refuses()}
	if consent {
		p.status.NotServing = why
	}
	if subnetConsent {
		p.subnets.NotServing = why
	}
	if choice.Refuses() {
		p.egress, p.status.Refused = conn.EgressRefused, why
		p.isolate, p.status.Isolated = choice.Isolate, choice.Isolate
		if choice.Unreadable {
			p.status.Refused = errUnreadableChoice
		}
	}
	return p
}

// exitNow is a copy of what the last reconcile made of exit nodes, nil where
// nothing is chosen, agreed or offered.
func (d *Daemon) exitNow() *ipc.Exit {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.exitChoice.Chosen && !d.serveConsent && len(d.exitStatus.Offering) == 0 {
		return nil
	}
	e := d.exitStatus
	e.Offering = slices.Clone(e.Offering)
	return &e
}

// loggedStrictRP6 is read, whose failure is logged: silent, it would read as
// a loose filter.
func (d *Daemon) loggedStrictRP6(read func() (bool, error)) func() bool {
	return func() bool {
		s, err := read()
		if err != nil {
			d.logOnce("daemon: reading the host's reverse-path filter: " + err.Error())
		}
		return s
	}
}
