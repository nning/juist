// Package mobile is juistd for the Android app, bound with gomobile: the
// daemon's service in the app's process, its control protocol over a pipe,
// and its device a VpnService's. Values cross to Kotlin as JSON.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/net/netmon"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/rendezvous"
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

// A Core is the running daemon. Its methods are safe from any thread, and
// block; call them off the main thread.
type Core struct {
	s      *daemon.Service
	cancel context.CancelFunc
	pace   *daemon.Pace
	// cover is the network's prefixes, as the status last named them, which
	// the VPN routes whole.
	cover atomic.Pointer[[]netip.Prefix]

	mu         sync.Mutex
	cancelJoin context.CancelFunc
}

// platformMu guards running, the one core whose platform the process-wide
// hooks call: a second would take them over from the first.
var (
	platformMu sync.Mutex
	running    *Core
)

// Start opens the state directory home, creating this device's keys sealed
// by p where it has none, and runs the mesh where it is in a network.
func Start(home string, p Platform) (*Core, error) {
	if p == nil {
		return nil, errors.New("mobile: no platform")
	}
	platformMu.Lock()
	defer platformMu.Unlock()
	if running != nil {
		return nil, errors.New("mobile: a core runs already; close it first")
	}
	keys.SealWith(sealer{p})
	protectBy(p)
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) { return interfaces(p) })
	logf := func(format string, args ...any) { p.Log(fmt.Sprintf(format, args...)) }
	c := &Core{pace: daemon.NewPace()}
	plumber := conn.NewVPNPlumber(vpn{p}, c.networkPrefixes)
	s, err := daemon.NewService(daemon.ServiceOptions{
		Home:      home,
		InProcess: true,
		Logf:      logf,
		Mesh: daemon.Options{
			TunName:      tunName,
			Plumber:      plumber,
			HostDNS:      daemon.VPNDNS(plumber, tunName),
			ListenPort:   daemon.DefaultListenPort,
			GossipPort:   daemon.DefaultGossipPort,
			PortFallback: true,
			DisableRelay: true,
			STUN:         rendezvous.DefaultSTUN,
			ServeDNS:     func([]netip.Addr, func(netip.Addr) bool) (io.Closer, error) { return nil, errNoNames },
			ServeNames: func(netip.AddrPort, func([]byte) []byte, func([]byte) []netip.AddrPort) (io.Closer, error) {
				return nil, errNoNames
			},
			// The core's own sockets leave past the tunnel, protected, as
			// juistd's user's do on Linux, and the app opens none of its own.
			EgressUser: func() string { return "" },
			// Before the VPN routes the overlay, a dial would leave by the LAN.
			GossipDial: conn.VPNDial(plumber),
			Pace:       c.pace,
			Logf:       logf,
		},
	})
	if err != nil {
		return nil, err
	}
	c.s = s
	// A phone routes no member's subnets, which could cover the LAN it is on.
	accept := false
	if _, err := ipc.CallVia(s.Pipe, ipc.Request{Command: ipc.CmdSubnet, AcceptSubnets: &accept}); err != nil {
		s.Close()
		return nil, err
	}
	st := s.Status()
	c.follow(&st)
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	if err := s.Start(ctx); err != nil {
		cancel()
		s.Close()
		return nil, err
	}
	running = c
	return c, nil
}

// follow keeps the network's prefixes st names, for the VPN's routes.
func (c *Core) follow(st *ipc.Status) {
	var ps []netip.Prefix
	if st.InNetwork && !st.NotMember {
		ps = append(slices.Clone(st.V4Claims), types.ULA(st.Network))
	}
	c.cover.Store(&ps)
}

func (c *Core) networkPrefixes() []netip.Prefix {
	if ps := c.cover.Load(); ps != nil {
		return *ps
	}
	return nil
}

// errNoNames: with a DNS server set, VpnService sends all of the phone's DNS
// to it, so the network's names are not resolved here.
var errNoNames = errors.New("an Android device resolves no names of the network")

// Close stops the mesh and the daemon.
func (c *Core) Close() {
	c.CancelJoin()
	c.cancel()
	c.s.Close()
	platformMu.Lock()
	if running == c {
		running = nil
	}
	platformMu.Unlock()
}

func (c *Core) call(req ipc.Request) (ipc.Response, error) { return ipc.CallVia(c.s.Pipe, req) }

// Status is the daemon's status as the app shows it, a JSON [view].
func (c *Core) Status() (string, error) {
	resp, err := c.call(ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		return "", err
	}
	c.follow(resp.Status)
	b, err := json.Marshal(viewOf(resp.Status))
	return string(b), err
}

// Join redeems invite, a code or a link, asking for the member name name,
// and returns once this device is a member or the join failed. CancelJoin
// ends it.
func (c *Core) Join(invite, name string, l JoinListener) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.mu.Lock()
	if c.cancelJoin != nil {
		c.mu.Unlock()
		return errors.New("a join is under way")
	}
	c.cancelJoin = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancelJoin = nil
		c.mu.Unlock()
	}()
	_, err := ipc.StreamVia(ctx, c.s.Pipe, ipc.Request{Command: ipc.CmdJoin, Invite: invite, Name: name},
		func(e *ipc.Event) {
			if l != nil {
				l.Progress(int32(e.Kind), e.Text, int32(e.Votes), int32(e.Quorum))
			}
		})
	if ctx.Err() != nil {
		return context.Canceled
	}
	return err
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

// Ping sends one TSMP ping through the tunnel to the member whose identity is
// given as in a [view], and returns the round trip in microseconds.
func (c *Core) Ping(identity string) (int64, error) {
	id, err := types.ParseIdentity(identity)
	if err != nil {
		return 0, err
	}
	resp, err := c.call(ipc.Request{Command: ipc.CmdPing, Ping: id})
	if err != nil {
		return 0, err
	}
	if resp.Ping.Err != "" {
		return 0, errors.New(resp.Ping.Err)
	}
	return resp.Ping.Micros, nil
}

// UseExit sends the phone's internet through the exit node whose identity is
// given as in a [view], kept across restarts as `juist exit use` keeps it.
func (c *Core) UseExit(identity string) error {
	id, err := types.ParseIdentity(identity)
	if err != nil {
		return err
	}
	_, err = c.call(ipc.Request{Command: ipc.CmdExit, ExitNode: id})
	return err
}

// ExitOff sends the phone's internet directly again.
func (c *Core) ExitOff() error {
	_, err := c.call(ipc.Request{Command: ipc.CmdExit, ExitOff: true})
	return err
}

// Forget returns a device the network removed, or one in a disabled network,
// to a fresh install, with new keys, so it can join again.
func (c *Core) Forget() error {
	_, err := c.call(ipc.Request{Command: ipc.CmdReset})
	return err
}

// NetworkChanged tells the core that Android's default network changed, to
// iface, its interface's name, or to none where it is empty; the core's
// monitor only polls every few minutes there.
func (c *Core) NetworkChanged(iface string) {
	defaultRouteVia(iface)
	if m := c.s.Mesh(); m != nil {
		m.NetworkChanged()
	}
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
