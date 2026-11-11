// Package mobile is juistd for the Android app, bound with gomobile: the
// daemon's service in the app's process, its control protocol over a pipe,
// and its device a VpnService's. Values cross to Kotlin as JSON.
package mobile

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/net/netmon"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// Platform is what the app does for the core.
type Platform interface {
	// Protect keeps fd's traffic out of the tunnel, as VpnService.protect.
	Protect(fd int32) bool
	// Establish brings the VPN interface up as config, a JSON [establish],
	// says and returns its descriptor, which the core then owns.
	Establish(config string) (int32, error)
	// Interfaces lists the network interfaces as JSON [iface]s, which
	// Android does not let an app's own code read from the kernel.
	Interfaces() (string, error)
	// Seal and Open encrypt the device's keys under a Keystore key.
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
	// Log receives the core's diagnostics.
	Log(line string)
}

// JoinListener hears how a join goes: kind is a guest.EventKind, text the
// words to compare or how the host was reached, votes and quorum the
// admission's so far.
type JoinListener interface {
	Progress(kind int32, text string, votes, quorum int32)
}

// tunName is cosmetic: Android names the device itself.
const tunName = "juist0"

// MaxNetworks is how many networks a phone is a member of at most: each
// keeps tunnels, relays and announcements of its own, which a phone pays
// for in battery.
const MaxNetworks = 4

// A Core is the running daemon: a service per network, in a slot of its
// own, all behind one VPN. Its methods are safe from any thread, and block;
// call them off the main thread.
type Core struct {
	home string // slot 0's state directory; slot n's is beside it
	hub  *conn.VPNHub
	pace *daemon.Pace
	logf func(format string, args ...any)
	// underlay is how the network beneath the VPN resolves, as the app last
	// said.
	underlay atomic.Pointer[daemon.Underlay]
	// cancelInvite ends the invite open, whose admission inviteAnswer
	// answers.
	cancelInvite context.CancelFunc
	inviteAnswer chan []byte
	// routes are the network beneath's own, as it last named them.
	routes atomic.Pointer[[]netip.Prefix]
	dns    *dnsStats

	// exitMu has one exit node chosen at a time.
	exitMu sync.Mutex

	mu         sync.Mutex
	nets       map[int]*network
	failed     map[int]string // slots whose service did not start, and why
	cancelJoin context.CancelFunc
	joinSlot   int
}

// A network is one slot's service.
type network struct {
	c       *Core
	slot    int
	s       *daemon.Service
	cancel  context.CancelFunc
	plumber conn.Plumber
	// cover is the network's prefixes, as the status last named them, which
	// the VPN routes whole.
	cover atomic.Pointer[[]netip.Prefix]
	// coverChanged has the VPN route a changed cover.
	coverChanged func() error
}

// platformMu guards running, the one core whose platform the process-wide
// hooks call: a second would take them over from the first.
var (
	platformMu sync.Mutex
	running    *Core
)

// errNoNetwork answers for a slot no network is in.
var errNoNetwork = errors.New("mobile: no network in that slot")

// Start opens the state directory home, creating this device's keys sealed
// by p where it has none, and runs the mesh of each network the phone is in:
// slot 0's in home, the others' beside it.
func Start(home string, p Platform) (*Core, error) {
	if p == nil {
		return nil, errors.New("mobile: no platform")
	}
	platformMu.Lock()
	defer platformMu.Unlock()
	if running != nil {
		return nil, errors.New("mobile: a core runs already; close it first")
	}
	hookTo(p)
	ok := false
	defer func() {
		if !ok {
			hookTo(nil)
		}
	}()
	logf := func(format string, args ...any) { p.Log(fmt.Sprintf(format, args...)) }
	c := &Core{home: filepath.Clean(home), pace: daemon.NewPace(), logf: logf, dns: newDNSStats(logf),
		nets: map[int]*network{}, failed: map[int]string{}, joinSlot: -1}
	c.hub = conn.NewVPNHub(vpn{p}, logf)
	if _, err := c.startNetwork(0); err != nil {
		c.hub.Close()
		return nil, err
	}
	for slot := 1; slot < MaxNetworks; slot++ {
		home := c.homeOf(slot)
		switch {
		case holdsNetwork(home):
			if _, err := c.startNetwork(slot); err != nil {
				c.logf("mobile: network %d: %v", slot, err)
				c.mu.Lock()
				c.failed[slot] = err.Error()
				c.mu.Unlock()
			}
		case fileExists(home):
			// What a join the app did not live to finish left.
			removeHome(home)
		}
	}
	running, ok = c, true
	return c, nil
}

// homeOf is slot's state directory: home for 0, juistn beside it for n, as
// instances' are on Linux.
func (c *Core) homeOf(slot int) string {
	if slot == 0 {
		return c.home
	}
	return filepath.Join(filepath.Dir(c.home), instance.Name(slot))
}

// holdsNetwork reports whether home holds a network's log.
func holdsNetwork(home string) bool { return fileExists(filepath.Join(home, keys.LogDir, "anchor")) }

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// removeHome deletes a slot's state directory, keys and all, where it is
// one: a juist home always holds its node keys.
func removeHome(home string) error {
	if !fileExists(filepath.Join(home, keys.NodeKeysFile)) {
		if entries, err := os.ReadDir(home); err != nil || len(entries) > 0 {
			return fmt.Errorf("mobile: %s is no juist home, so it is kept", home)
		}
	}
	return os.RemoveAll(home)
}

// startNetwork runs slot's service, in a network or not yet.
func (c *Core) startNetwork(slot int) (*network, error) {
	n := &network{c: c, slot: slot}
	n.plumber = c.hub.Plumber(slot, n.networkPrefixes)
	n.coverChanged = func() error { return conn.VPNCoverChanged(n.plumber) }
	logf := c.logf
	if slot > 0 {
		prefix := instance.Name(slot) + ": "
		logf = func(format string, args ...any) { c.logf(prefix+format, args...) }
	}
	opts := daemon.ServiceOptions{
		Home:      c.homeOf(slot),
		InProcess: true,
		Logf:      logf,
		Mesh: daemon.Options{
			TunName:      tunName,
			Plumber:      n.plumber,
			HostDNS:      daemon.VPNDNS(n.plumber, tunName, c.underlayNow),
			ListenPort:   instance.Port(daemon.DefaultListenPort, slot),
			GossipPort:   instance.Port(daemon.DefaultGossipPort, slot),
			PortFallback: true,
			DisableRelay: true,
			STUN:         rendezvous.DefaultSTUN,
			ServeDNS:     func([]netip.Addr, func(netip.Addr) bool) (io.Closer, error) { return nil, errNoMembersDNS },
			Resolver: &daemon.Resolver{Dial: resolverDial(conn.VPNDialer(n.plumber), n.networkPrefixes),
				Observe: c.dns.observe, Others: n.otherNames},
			// The core's own sockets leave past the tunnel, protected, as
			// juistd's user's do on Linux, and the app opens none of its own.
			EgressUser: func() string { return "" },
			// Before the VPN routes the overlay, a dial would leave by the LAN.
			GossipDial: conn.VPNDial(n.plumber),
			Pace:       c.pace,
			Rests:      true,
			Logf:       logf,
			// A higher slot yields IPv4 to a lower one, as a higher instance
			// does on Linux; the kernel shows a VPN app nothing of either.
			Instance:     slot,
			HostHoldings: func(int, string) ([]conn.Holding, error) { return nil, nil },
			LowerStatus:  c.lowerStatus,
			LowerHome:    c.homeOf,
		},
	}
	if meshForTests != nil {
		meshForTests(slot, &opts.Mesh)
	}
	opts.InviteAddrs = inviteAddrsForTests
	s, err := daemon.NewService(opts)
	if err != nil {
		return nil, err
	}
	n.s = s
	// Earlier apps turned subnets off for good; the LAN the phone is on is
	// kept out of them by the network beneath's routes instead.
	accept := true
	if _, err := ipc.CallVia(s.Pipe, ipc.Request{Command: ipc.CmdSubnet, AcceptSubnets: &accept}); err != nil {
		s.Close()
		return nil, err
	}
	st := s.Status()
	n.follow(&st)
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	if err := s.Start(ctx); err != nil {
		cancel()
		s.Close()
		return nil, err
	}
	c.mu.Lock()
	c.nets[slot] = n
	delete(c.failed, slot)
	c.mu.Unlock()
	return n, nil
}

// meshForTests, where set, changes what a slot's mesh runs with: a test's
// host has no device carrying the overlay's addresses.
var meshForTests func(slot int, o *daemon.Options)

// inviteAddrsForTests, where set, is where an invite is reached, as a phone
// with no interface of a test's reaches none.
var inviteAddrsForTests func(port uint16) []netip.AddrPort

// lowerStatus is slot's status, for a higher slot's check of what it holds.
func (c *Core) lowerStatus(_ context.Context, slot int) (*ipc.Status, error) {
	n := c.network(slot)
	if n == nil {
		return nil, errNoNetwork
	}
	st := n.s.Status()
	return &st, nil
}

func (c *Core) network(slot int) *network {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nets[slot]
}

// networks are the running networks, by slot.
func (c *Core) networks() []*network {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*network, 0, len(c.nets))
	for _, n := range c.nets {
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b *network) int { return a.slot - b.slot })
	return out
}

// errNoCore is what the process-wide hooks answer while no core runs.
var errNoCore = errors.New("mobile: no core runs")

// hookTo has the process-wide hooks call p, or fail where p is nil, so that
// none calls a closed platform and no key is written unsealed. Under
// platformMu.
func hookTo(p Platform) {
	if p == nil {
		p = noPlatform{}
	}
	keys.SealWith(sealer{p})
	protectBy(p)
	hooked.Store(&p)
	registerGetter()
}

// hooked is the platform the interface getter asks. netmon keeps its getter
// in a plain variable that magicsock reads from goroutines a closed core may
// leave behind, so it is set once, and the platform changes beneath it.
var (
	hooked         atomic.Pointer[Platform]
	registerGetter = sync.OnceFunc(func() {
		netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) { return interfaces(*hooked.Load()) })
	})
)

// follow keeps the network's prefixes st names, for the VPN's routes, and
// has a device established before they changed route them. A network that
// yields IPv4 to a lower slot routes its IPv6 alone.
func (n *network) follow(st *ipc.Status) {
	var ps []netip.Prefix
	if st.InNetwork && !st.NotMember {
		if st.HostConflict == nil {
			ps = slices.Clone(st.V4Claims)
		}
		ps = append(ps, types.ULA(st.Network))
	}
	old := n.cover.Swap(&ps)
	if old != nil && !slices.Equal(*old, ps) && n.coverChanged != nil {
		if err := n.coverChanged(); err != nil {
			n.c.logf("mobile: routing the network's prefixes: %v", err)
		}
	}
}

func (n *network) networkPrefixes() []netip.Prefix {
	if ps := n.cover.Load(); ps != nil {
		return *ps
	}
	return nil
}

// otherNames answers q from the other networks' names, so that the one
// resolver the phone asks answers every network's.
func (n *network) otherNames(q []byte) []byte {
	for _, o := range n.c.networks() {
		if o == n {
			continue
		}
		if a := o.s.AnswerNames(q); a != nil {
			return a
		}
	}
	return nil
}

// errNoMembersDNS: a phone is no exit node.
var errNoMembersDNS = errors.New("an Android device answers no member's DNS")

func (c *Core) underlayNow() daemon.Underlay {
	if u := c.underlay.Load(); u != nil {
		return *u
	}
	return daemon.Underlay{}
}

// resolverDial reaches a resolver in the network's prefixes, an exit node's,
// through the tunnel by overlay, and any other on the network beneath the
// VPN, protected from the tunnel.
func resolverDial(overlay func(context.Context, string, netip.AddrPort) (net.Conn, error),
	cover func() []netip.Prefix) func(context.Context, string, netip.AddrPort) (net.Conn, error) {
	return func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error) {
		if slices.ContainsFunc(cover(), func(p netip.Prefix) bool { return p.Contains(to.Addr()) }) {
			return overlay(ctx, network, to)
		}
		return underlay.Dialer(0).DialContext(ctx, network, to.String())
	}
}

// Close stops every network's mesh and daemon, and takes the VPN down.
func (c *Core) Close() {
	c.CancelJoin()
	nets := c.networks()
	for i := len(nets) - 1; i >= 0; i-- {
		nets[i].close()
	}
	c.hub.Close()
	platformMu.Lock()
	if running == c {
		running = nil
		hookTo(nil)
	}
	platformMu.Unlock()
}

func (n *network) close() {
	n.cancel()
	n.s.Close()
}

// on is slot's network, or errNoNetwork.
func (c *Core) on(slot int32) (*network, error) {
	if n := c.network(int(slot)); n != nil {
		return n, nil
	}
	return nil, errNoNetwork
}

func (n *network) call(req ipc.Request) (ipc.Response, error) { return ipc.CallVia(n.s.Pipe, req) }

// A slotView is one network's view, by its slot.
type slotView struct {
	Slot int `json:"slot"`
	view
}

// Status is every network's status as the app shows it, by slot, a JSON
// list of [view]s each with its slot: slot 0's always, in a network or not.
func (c *Core) Status() (string, error) {
	nets := c.networks()
	sts := make(map[int]*ipc.Status, len(nets))
	out := []slotView{}
	for _, n := range nets {
		resp, err := n.call(ipc.Request{Command: ipc.CmdStatus})
		if err != nil {
			if n.slot == 0 {
				return "", err
			}
			out = append(out, slotView{Slot: n.slot, view: view{State: "unstarted", Detail: err.Error()}})
			continue
		}
		n.follow(resp.Status)
		sts[n.slot] = resp.Status
		v := viewOf(resp.Status, c.underlayNow().PrivateDNS)
		if m := n.s.Mesh(); m != nil {
			if state, err := m.TrustedState(); err == nil {
				v.Admins = adminsOf(state)
			}
		}
		out = append(out, slotView{Slot: n.slot, view: v})
	}
	for i := range out {
		if st := sts[out[i].Slot]; st != nil && st.HostConflict != nil && !st.HostConflict.SameNetwork {
			var names []string
			if o := sts[st.HostConflict.Instance]; o != nil && o.NetworkName != "" {
				names = []string{o.NetworkName}
			}
			out[i].Alarms = append(out[i].Alarms, alarm{Kind: "noV4", Severity: "warn", Names: names})
		}
	}
	c.mu.Lock()
	for slot, why := range c.failed {
		out = append(out, slotView{Slot: slot, view: view{State: "unstarted", Detail: why}})
	}
	c.mu.Unlock()
	slices.SortFunc(out, func(a, b slotView) int { return a.Slot - b.Slot })
	b, err := json.Marshal(out)
	return string(b), err
}

// Join redeems invite, a code or a link, asking for the member name name, in
// the lowest slot no network is in, and returns that slot once this device
// is a member there or the join failed. CancelJoin ends it.
func (c *Core) Join(invite, name string, l JoinListener) (int32, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.mu.Lock()
	if c.cancelJoin != nil {
		c.mu.Unlock()
		return -1, errors.New("a join is under way")
	}
	c.cancelJoin = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancelJoin, c.joinSlot = nil, -1
		c.mu.Unlock()
	}()
	n, made, err := c.freeSlot()
	if err != nil {
		return -1, err
	}
	c.mu.Lock()
	c.joinSlot = n.slot
	c.mu.Unlock()
	_, err = ipc.StreamVia(ctx, n.s.Pipe, ipc.Request{Command: ipc.CmdJoin, Invite: invite, Name: name},
		func(e *ipc.Event) {
			if l != nil {
				l.Progress(int32(e.Kind), e.Text, int32(e.Votes), int32(e.Quorum))
			}
		})
	if ctx.Err() != nil {
		err = context.Canceled
	}
	if err == nil {
		err = c.joinedTwice(n)
	}
	if err != nil && made {
		c.drop(n)
	}
	if err != nil {
		return -1, err
	}
	return int32(n.slot), nil
}

// joinedTwice undoes a join into a network another slot is in already,
// which would have the lower of the two stop the other, and says which
// admission an admin should remove.
func (c *Core) joinedTwice(n *network) error {
	st := n.s.Status()
	for _, o := range c.networks() {
		if o == n {
			continue
		}
		if ost := o.s.Status(); ost.InNetwork && ost.Network == st.Network {
			if _, err := n.call(ipc.Request{Command: ipc.CmdReset, Force: true}); err != nil {
				return err
			}
			if n.slot == 0 {
				c.hub.Remove(0)
			}
			return fmt.Errorf("this phone is in %s already; an admin should remove its second admission, %s",
				cmp.Or(ost.NetworkName, "that network"), cmp.Or(st.SelfName, st.Self.ShortString()))
		}
	}
	return nil
}

// freeSlot is the slot a join takes, made where it runs no service yet, and
// whether it was: the lowest above every slot in a network, so that a new
// network takes IPv4 from none the phone is in, else the lowest free one.
func (c *Core) freeSlot() (*network, bool, error) {
	running := map[int]*network{}
	top := -1
	for _, n := range c.networks() {
		running[n.slot] = n
		if n.s.Status().InNetwork {
			top = n.slot
		}
	}
	c.mu.Lock()
	failed := maps.Clone(c.failed)
	c.mu.Unlock()
	for _, slot := range joinOrder(top) {
		if failed[slot] != "" {
			continue
		}
		if n := running[slot]; n != nil {
			if !n.s.Status().InNetwork {
				return n, false, nil
			}
			continue
		}
		if fileExists(c.homeOf(slot)) {
			if err := removeHome(c.homeOf(slot)); err != nil {
				return nil, false, err
			}
		}
		n, err := c.startNetwork(slot)
		return n, err == nil, err
	}
	return nil, false, fmt.Errorf("this phone is in %d networks, the most it joins", MaxNetworks)
}

// joinOrder is the order a join tries the slots in: those above top, then
// those below it.
func joinOrder(top int) []int {
	var out []int
	for slot := top + 1; slot < MaxNetworks; slot++ {
		out = append(out, slot)
	}
	for slot := 0; slot < top; slot++ {
		out = append(out, slot)
	}
	return out
}

// drop stops a slot's service but slot 0's, deletes its state and takes its
// routes off the VPN.
func (c *Core) drop(n *network) error {
	if n.slot == 0 {
		return nil
	}
	c.mu.Lock()
	delete(c.nets, n.slot)
	c.mu.Unlock()
	n.close()
	c.hub.Remove(n.slot)
	return removeHome(c.homeOf(n.slot))
}

// CancelJoin ends a join under way, if any.
func (c *Core) CancelJoin() {
	c.mu.Lock()
	cancel := c.cancelJoin
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Ping sends one TSMP ping through slot's tunnel to the member whose
// identity is given as in a [view], and returns the round trip in
// microseconds.
func (c *Core) Ping(slot int32, identity string) (int64, error) {
	n, err := c.on(slot)
	if err != nil {
		return 0, err
	}
	id, err := types.ParseIdentity(identity)
	if err != nil {
		return 0, err
	}
	resp, err := n.call(ipc.Request{Command: ipc.CmdPing, Ping: id})
	if err != nil {
		return 0, err
	}
	if resp.Ping.Err != "" {
		return 0, errors.New(resp.Ping.Err)
	}
	return resp.Ping.Micros, nil
}

// UseExit sends the phone's internet through the exit node of slot's
// network whose identity is given as in a [view], kept across restarts as
// `juist exit use` keeps it; another network's exit node is let go then,
// since the internet goes to one at a time.
func (c *Core) UseExit(slot int32, identity string) error {
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	id, err := types.ParseIdentity(identity)
	if err != nil {
		return err
	}
	var others []exitChooser
	for _, o := range c.networks() {
		if o != n {
			others = append(others, o)
		}
	}
	return c.chooseExit(n, id, others)
}

// ExitOff sends the phone's internet directly again.
func (c *Core) ExitOff(slot int32) error {
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	c.exitMu.Lock()
	defer c.exitMu.Unlock()
	return n.exitOff()
}

// An exitChooser is a network as the phone chooses its exit node.
type exitChooser interface {
	exitNode() (types.Identity, bool)
	useExit(types.Identity) error
	exitOff() error
}

// chooseExit has target's exit node id carry the internet, chosen before
// the others' are let go, so that it never leaves beside the tunnel
// meanwhile; where one of theirs cannot be, target's choice goes back to
// what it was, since the lower of two would keep carrying it.
func (c *Core) chooseExit(target exitChooser, id types.Identity, others []exitChooser) error {
	c.exitMu.Lock()
	defer c.exitMu.Unlock()
	was, had := target.exitNode()
	if err := target.useExit(id); err != nil {
		return err
	}
	for _, o := range others {
		if _, ok := o.exitNode(); !ok {
			continue
		}
		if err := o.exitOff(); err != nil {
			undo := target.exitOff
			if had {
				undo = func() error { return target.useExit(was) }
			}
			return errors.Join(err, undo())
		}
	}
	return nil
}

func (n *network) exitNode() (types.Identity, bool) {
	st := n.s.Status()
	if st.Exit == nil || st.Exit.Node.IsZero() {
		return types.Identity{}, false
	}
	return st.Exit.Node, true
}

func (n *network) useExit(id types.Identity) error {
	_, err := n.call(ipc.Request{Command: ipc.CmdExit, ExitNode: id})
	return err
}

func (n *network) exitOff() error {
	_, err := n.call(ipc.Request{Command: ipc.CmdExit, ExitOff: true})
	return err
}

// Forget returns slot's device, one the network removed or one in a
// disabled network, to a fresh install, with new keys, so it can join
// again; a slot but the first is let go with it.
func (c *Core) Forget(slot int32) error { return c.leave(slot, false) }

// Leave is Forget for a device the network still lists, which it goes on
// listing until an admin removes it.
func (c *Core) Leave(slot int32) error { return c.leave(slot, true) }

func (c *Core) leave(slot int32, force bool) error {
	if slot > 0 {
		c.mu.Lock()
		failed := c.failed[int(slot)] != ""
		delete(c.failed, int(slot))
		c.mu.Unlock()
		if failed {
			return removeHome(c.homeOf(int(slot)))
		}
	}
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	c.mu.Lock()
	joining := c.joinSlot == n.slot
	c.mu.Unlock()
	if joining {
		return errors.New("this network is being joined; cancel the join")
	}
	if _, err := n.call(ipc.Request{Command: ipc.CmdReset, Force: force}); err != nil {
		return err
	}
	if n.slot == 0 {
		c.hub.Remove(0)
		return nil
	}
	return c.drop(n)
}

// NetworkChanged tells the core that Android's default network changed, to
// iface, its interface's name, or to none where it is empty, which resolves
// as resolvers, a JSON [underlayDNS]; the core's monitor only polls every few
// minutes there.
func (c *Core) NetworkChanged(iface, resolvers string) {
	defaultRouteVia(iface, underlayGateway(resolvers))
	u, err := parseUnderlay(resolvers)
	if err != nil {
		c.logf("mobile: %v", err)
	}
	c.underlay.Store(&u)
	routes := underlayRoutes(resolvers)
	c.routes.Store(&routes)
	c.hub.SetHostRoutes(routes)
	for _, n := range c.networks() {
		if m := n.s.Mesh(); m != nil {
			m.NetworkChanged()
		}
	}
}

// SetNames has the phone's lookups go to juist's resolver, which answers
// slot's network's names, or leaves them out, as `juist set --dns`.
func (c *Core) SetNames(slot int32, on bool) error {
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	_, err = n.call(ipc.Request{Command: ipc.CmdSettings, DNS: &on})
	return err
}

// SetPublicNames has the phone resolve the public names slot's network
// points at members to them, through the tunnel, or publicly, as `juist
// names on` and `off`.
func (c *Core) SetPublicNames(slot int32, on bool) error {
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	_, err = n.call(ipc.Request{Command: ipc.CmdNames, AcceptNames: &on})
	return err
}

// SetPortMapping has slot's network ask the router to open a port for the
// phone by UPnP, NAT-PMP or PCP, or not, as `juist set --port-mapping`.
func (c *Core) SetPortMapping(slot int32, on bool) error {
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	_, err = n.call(ipc.Request{Command: ipc.CmdSettings, PortMapping: &on})
	return err
}

// SetHTTPSOnly has slot's network reach its relays by TLS on 443 alone, as
// `juist set --https-only`, which restarts its mesh.
func (c *Core) SetHTTPSOnly(slot int32, on bool) error {
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	_, err = n.call(ipc.Request{Command: ipc.CmdSettings, HTTPSOnly: &on})
	return err
}

// maxChanges is how many of the log's changes Changes lists.
const maxChanges = 20

// A change is one of the log's, as `juist log` lists it.
type change struct {
	Index   int      `json:"index"`
	What    string   `json:"what"`
	Signers []string `json:"signers,omitempty"`
}

// Changes lists the newest changes of slot's log, newest first, as JSON
// changes.
func (c *Core) Changes(slot int32) (string, error) {
	n, err := c.on(slot)
	if err != nil {
		return "", err
	}
	changes, _, err := n.s.Changes(maxChanges)
	if err != nil {
		return "", err
	}
	out := []change{}
	for _, ch := range changes {
		out = append(out, change{Index: ch.Index, What: ch.What, Signers: ch.Signers})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// SetSaving slows the mesh down to save battery, as while the screen is off,
// or brings it back to its pace.
func (c *Core) SetSaving(saving bool) { c.pace.SetSaving(saving) }

// CheckInvite says what is wrong with s as an invite, "" where nothing is.
func CheckInvite(s string) string {
	if _, err := guest.ParseInvite(s); err != nil {
		return err.Error()
	}
	return ""
}

// maxCompletions bounds what CompleteWord offers.
const maxCompletions = 6

// CompleteWord lists, one per line, the words an invite code may hold at
// position, from 0 after the number, that start with prefix: prefix itself
// first where it is one.
func CompleteWord(prefix string, position int) string {
	if position < 0 || position >= enroll.CodeWords || prefix == "" {
		return ""
	}
	prefix = strings.ToLower(prefix)
	words := enroll.WordsAt(position)
	var out []string
	if slices.Contains(words, prefix) {
		out = append(out, prefix)
	}
	for _, w := range words {
		if len(out) == maxCompletions {
			break
		}
		if strings.HasPrefix(w, prefix) && w != prefix {
			out = append(out, w)
		}
	}
	return strings.Join(out, "\n")
}
