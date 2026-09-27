package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// hostClaims is what a network claims of a host's address space at unix time
// now: its ULA, and in IPv4 its prefix and the ranges it is moving away from,
// or — for a network founded before prefixes were drawn, which numbers from
// all of 198.18/15 — its members' addresses alone. Claiming that whole range
// would keep such a network off every host that is in a newer one.
func hostClaims(state *log.State, now int64) (v4 []netip.Prefix, ula netip.Prefix) {
	if _, ok := state.V4Prefix(); ok {
		return state.V4RangesAt(now), state.ULA()
	}
	for _, n := range state.Nodes() {
		for _, a := range state.Addrs(n.Identity, now) {
			if a.Addr().Is4() {
				v4 = append(v4, a)
			}
		}
	}
	return v4, state.ULA()
}

// A lowerInstance is what the service learned of an instance below it on the
// host: its status, where it answered on its socket, or else what the kernel
// shows it holds.
type lowerInstance struct {
	n  int
	st *ipc.Status
	// held is the kernel's view, for an instance that did not answer.
	held *conn.Holding
}

// findHostConflict returns what a lower instance holds of what state's
// network claims, the same network before any IPv4. Only lower instances are
// asked: this one's table is consulted first, so higher ones are the ones
// to yield. An instance that answered is compared by its claims, which move
// only with its log; one that did not, by the kernel, which moves with its
// peers' comings and goings too.
func findHostConflict(state *log.State, now int64, lower []lowerInstance) *ipc.HostConflict {
	v4, ula := hostClaims(state, now)
	genesis := state.GenesisHash()
	for _, l := range lower {
		switch {
		case l.st != nil:
			if member(l.st) && l.st.Network == genesis {
				return &ipc.HostConflict{Instance: l.n, Device: l.st.Device, SameNetwork: true,
					Held: types.ULA(l.st.Network), Claim: ula}
			}
		case l.held != nil:
			for _, p := range l.held.Prefixes {
				// A held address inside the ULA, not a route that covers
				// it: a default route covers every ULA there is.
				if p.Bits() >= ula.Bits() && ula.Contains(p.Addr()) {
					return &ipc.HostConflict{Instance: l.n, Device: l.held.Device, SameNetwork: true,
						Held: p, Claim: ula}
				}
			}
		}
	}
	for _, l := range lower {
		var theirs []netip.Prefix
		dev := ""
		switch {
		case l.st != nil:
			if !routes(l.st) {
				continue
			}
			theirs, dev = l.st.V4Claims, l.st.Device
		case l.held != nil:
			theirs, dev = l.held.Prefixes, l.held.Device
		}
		for _, p := range theirs {
			if !p.Addr().Is4() {
				continue
			}
			for _, c := range v4 {
				if c.Overlaps(p) {
					return &ipc.HostConflict{Instance: l.n, Device: dev, Held: p, Claim: c}
				}
			}
		}
	}
	return nil
}

// member reports whether an instance's status says the device is a member of
// its network through it.
func member(st *ipc.Status) bool { return st.InNetwork && !st.NotMember }

// routes reports whether an instance's status says it routes its network's
// IPv4: a member, on a device, whose mesh runs, and with IPv4 of its own.
func routes(st *ipc.Status) bool {
	return member(st) && st.Device != "" && st.StartError == "" && st.HostConflict == nil
}

// A hostConflictError is what another instance on the host holds of this
// network's claims: the reason the mesh runs without IPv4, or, for the same
// network, does not start.
type hostConflictError struct {
	ipc.HostConflict
	network string
}

func (e *hostConflictError) Error() string {
	other := instance.Name(e.Instance)
	if e.Device != "" && e.Device != other {
		other += " (" + e.Device + ")"
	}
	if e.SameNetwork {
		return fmt.Sprintf("network %q runs on this host already, as instance %s", e.network, other)
	}
	if e.Unanswered {
		return fmt.Sprintf("instance %s on this host holds a network and has not answered yet", other)
	}
	held := e.Held.String()
	if e.Held.IsSingleIP() {
		held = e.Held.Addr().String()
	}
	return fmt.Sprintf("instance %s on this host holds %s, which network %q claims (%v)",
		other, held, e.network, e.Claim)
}

// conflictClearChecks is how many checks in a row must find a conflict gone
// before IPv4 comes back: a lower instance restarting — an upgrade, a
// rotation, a renumbering's deadline — has no device and no socket for a
// moment, and that is no verdict.
const conflictClearChecks = 3

// lowerAsk bounds how long another instance may take to answer.
const lowerAsk = 2 * time.Second

// hostConflictLocked checks state's network against the host's instances
// below this one. An error says the host could not be read, which is no
// verdict either way.
//
// It runs under the service's lock, asking the instances below. That cannot
// deadlock: an instance only ever asks those below it, and the default asks
// none.
func (s *Service) hostConflictLocked(state *log.State) (*hostConflictError, error) {
	self := s.opts.Mesh.Instance
	if self == 0 || s.opts.Mesh.HostHoldings == nil {
		return nil, nil
	}
	// Asked all at once, so the lock waits one timeout at most.
	answers := make([]*ipc.Status, self)
	if ask := s.opts.Mesh.LowerStatus; ask != nil {
		ctx, cancel := context.WithTimeout(context.Background(), lowerAsk)
		var wg sync.WaitGroup
		for n := range self {
			wg.Go(func() {
				if st, err := ask(ctx, n); err == nil {
					answers[n] = st
				}
			})
		}
		wg.Wait()
		cancel()
	}
	lower := make([]lowerInstance, 0, self)
	var held []conn.Holding
	kernelRead := false
	silent := -1 // the lowest that holds a network and did not answer
	for n := range self {
		if answers[n] == nil && silent < 0 && s.opts.Mesh.LowerHome != nil &&
			fileExists(filepath.Join(s.opts.Mesh.LowerHome(n), keys.LogDir, "anchor")) {
			silent = n
		}
		if answers[n] != nil {
			lower = append(lower, lowerInstance{n: n, st: answers[n]})
			continue
		}
		if !kernelRead {
			var err error
			if held, err = s.opts.Mesh.HostHoldings(self, s.opts.Mesh.TunName); err != nil {
				return nil, fmt.Errorf("reading what the host's other instances hold: %w", err)
			}
			kernelRead = true
		}
		for i := range held {
			if held[i].Instance == n {
				lower = append(lower, lowerInstance{n: n, held: &held[i]})
			}
		}
	}
	c := findHostConflict(state, s.now().Unix(), lower)
	// Starting beside one that holds a network and is not up yet, as when
	// the host boots or an upgrade restarts both, the kernel shows nothing
	// of it: IPv4 waits until it has answered, and the conflict is known.
	if c == nil && silent >= 0 && !s.meshStarted {
		c = &ipc.HostConflict{Instance: silent, Unanswered: true}
	}
	if c == nil {
		return nil, nil
	}
	return &hostConflictError{HostConflict: *c, network: state.Network()}, nil
}

// lowerHomesBeside is where the instances below one whose home is home keep
// theirs, in the packaged layout: the default's is the parent, holding the
// others' as juistn. It is nil where home is not laid out so.
func lowerHomesBeside(home string, self int) func(n int) string {
	if self == 0 || filepath.Base(filepath.Clean(home)) != instance.Name(self) {
		return nil
	}
	parent := filepath.Dir(filepath.Clean(home))
	return func(n int) string {
		if n == 0 {
			return parent
		}
		return filepath.Join(parent, instance.Name(n))
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// lowerStatusBeside asks the instances beside a socket in the packaged
// layout, where instance n's is juistn.sock and the default's juistd.sock.
func lowerStatusBeside(sock string) func(ctx context.Context, n int) (*ipc.Status, error) {
	dir := filepath.Dir(sock)
	return func(ctx context.Context, n int) (*ipc.Status, error) {
		name := instance.Name(n) + ".sock"
		if n == 0 {
			name = filepath.Base(ipc.SystemSocket)
		}
		resp, err := ipc.Stream(ctx, filepath.Join(dir, name), ipc.Request{Command: ipc.CmdStatus}, nil)
		if err != nil {
			return nil, err
		}
		return resp.Status, nil
	}
}

// now is the mesh's clock.
func (s *Service) now() time.Time {
	if clock := s.opts.Mesh.Clock; clock != nil {
		return clock()
	}
	return time.Now()
}

// logHostOnce logs a failure to read the host, once until it changes.
func (s *Service) logHostOnce(err error) {
	if err.Error() != s.hostErr {
		s.hostErr = err.Error()
		s.logf("daemon: %v", err)
	}
}
