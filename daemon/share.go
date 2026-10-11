package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A share is what this device publishes under its own name while a call
// holds it open: where its connections go, under prefix, the first segment
// of its path, or the whole name where that is empty; and its end, zero for
// none but the call's.
type share struct {
	to, what, path, prefix string
	end                    time.Time
	// stopped is closed once [Daemon.StopShare] ends the share.
	stopped chan struct{}
}

// live reports whether sh has not ended at now.
func (sh *share) live(now time.Time) bool { return sh.end.IsZero() || now.Before(sh.end) }

// sharePort is the port of this device's overlay addresses its own name is
// reached on.
const sharePort = 443

// shareLease is how far ahead an announced share ends at most; it is
// renewed while the share lasts, so one whose device is gone ends with it.
const shareLease = 10 * time.Minute

// maxShares bounds the shares a device holds at once.
const maxShares = 16

// TerminatorNotRunning is why a share reaches nobody where no terminator
// asks what to serve.
const TerminatorNotRunning = "the terminator does not run"

// Why a share does not start, or stop.
var (
	ErrNoPublishRole = errors.New("this device holds no publish role")
	ErrNoDomain      = errors.New("the network has no domain to publish under")
	ErrPortShared    = errors.New("this device publishes a port already")
	ErrPathShared    = errors.New("this device shares under this path already")
	ErrTooManyShares = fmt.Errorf("this device holds %d shares already", maxShares)
	ErrNotSharing    = errors.New("this device shares nothing")
)

// StartShare publishes this device under its own name, its connections
// going where req says, until end where not zero, and returns the name and
// the share, which [Daemon.EndShare] ends. A share without a path is the
// one that takes what no other's path does.
func (d *Daemon) StartShare(req *ipc.ShareRequest, end time.Time) (string, *share, error) {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return "", nil, err
	}
	name, err := shareName(state, d.self)
	if err != nil {
		return "", nil, err
	}
	prefix := ipc.SharePrefix(req.Path)
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	switch {
	case slices.ContainsFunc(d.pub.shares, func(o *share) bool { return o.prefix == prefix }) && prefix == "":
		return "", nil, ErrPortShared
	case slices.ContainsFunc(d.pub.shares, func(o *share) bool { return o.prefix == prefix }):
		return "", nil, ErrPathShared
	case len(d.pub.shares) >= maxShares:
		return "", nil, ErrTooManyShares
	}
	sh := &share{to: req.To, what: req.What, path: req.Path, prefix: prefix, end: end, stopped: make(chan struct{})}
	d.pub.shares = append(d.pub.shares, sh)
	d.flagTerminatorLocked()
	d.MarkDirty()
	return name, sh, nil
}

// EndShare ends sh, where it is still one of this device's shares.
func (d *Daemon) EndShare(sh *share) {
	d.pub.mu.Lock()
	n := len(d.pub.shares)
	d.pub.shares = slices.DeleteFunc(d.pub.shares, func(o *share) bool { return o == sh })
	ended := len(d.pub.shares) < n
	if ended {
		d.flagTerminatorLocked()
	}
	d.pub.mu.Unlock()
	if ended {
		d.MarkDirty()
	}
}

// StopShare ends the share under path, the one without a path where path
// is empty, or every share where all, and the calls that hold them.
func (d *Daemon) StopShare(path string, all bool) error {
	d.pub.mu.Lock()
	var stopped []*share
	d.pub.shares = slices.DeleteFunc(d.pub.shares, func(sh *share) bool {
		if all || sh.path == path {
			stopped = append(stopped, sh)
			return true
		}
		return false
	})
	d.flagTerminatorLocked()
	d.pub.mu.Unlock()
	if len(stopped) == 0 {
		return ErrNotSharing
	}
	for _, sh := range stopped {
		close(sh.stopped)
	}
	d.MarkDirty()
	return nil
}

// ShareName is the name this device shares under now.
func (d *Daemon) ShareName() (string, error) {
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return "", err
	}
	return shareName(state, d.self)
}

// shareName is the name id publishes under, as the publish role lets it.
func shareName(state *log.State, id types.Identity) (string, error) {
	n, ok := state.Node(id)
	if !ok || !n.HasRole(types.RolePublish) {
		return "", ErrNoPublishRole
	}
	l, ok := n.ShareLabel()
	if !ok {
		return "", ErrNoPublishRole
	}
	if state.Domain() == "" {
		return "", ErrNoDomain
	}
	return l + "." + state.Domain(), nil
}

// sharesNow is this device's shares not past their end, in the order they
// started.
func (d *Daemon) sharesNow(now time.Time) []share {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	var out []share
	for _, sh := range d.pub.shares {
		if sh.live(now) {
			out = append(out, *sh)
		}
	}
	return out
}

// shareAnnounced is the share this device announces at now, while it can
// serve one: an end half a lease to a lease ahead, so that it changes once
// each half lease, or the last share's own where sooner.
func (d *Daemon) shareAnnounced(now time.Time) *gossip.Share {
	shs := d.sharesNow(now)
	if len(shs) == 0 || !d.freshness(now).Fresh(now.Unix()) {
		return nil
	}
	d.authMu.Lock()
	state, err := d.authority.TrustedState()
	d.authMu.Unlock()
	if err != nil {
		return nil
	}
	if _, err := shareName(state, d.self); err != nil {
		return nil
	}
	half := int64(shareLease / 2 / time.Second)
	until := (now.Unix()/half + 2) * half
	var last time.Time
	for _, sh := range shs {
		if sh.end.IsZero() {
			last = time.Time{}
			break
		}
		if sh.end.After(last) {
			last = sh.end
		}
	}
	if !last.IsZero() && last.Unix() < until {
		until = last.Unix()
	}
	return &gossip.Share{Port: sharePort, Until: until}
}

// sharing reports whether id shares at now: this device as it holds one,
// another as its announcement says, which ends no further ahead than a
// lease, so that a share whose device is gone ends with it.
func (d *Daemon) sharing(id types.Identity, now time.Time) bool {
	if id == d.self {
		return len(d.sharesNow(now)) > 0
	}
	ep, ok := d.endpoints.Get(id)
	return ok && ep.Share.Live(now) && ep.Share.Port == sharePort &&
		ep.Share.Until <= now.Add(shareLease+clockSkew).Unix()
}

// renewShare has this device's announcement go out where its shares' end
// moved since last, which it updates.
func (d *Daemon) renewShare(last *int64) bool {
	var until int64
	if sh := d.shareAnnounced(d.now()); sh != nil {
		until = sh.Until
	}
	if until == *last {
		return false
	}
	*last = until
	d.MarkDirty()
	return true
}

// shareServed is shs, this device's shares, as its terminator ends TLS for
// them, on addrs, while state grants the role: the one without a path as the
// name's To, the others by their paths.
func (d *Daemon) shareServed(state *log.State, addrs []netip.Addr, shs []share) (ipc.PublishedTarget, bool) {
	if len(shs) == 0 {
		return ipc.PublishedTarget{}, false
	}
	name, err := shareName(state, d.self)
	if err != nil {
		return ipc.PublishedTarget{}, false
	}
	t := ipc.PublishedTarget{Name: name, Addrs: addrs, Port: sharePort}
	for _, sh := range shs {
		if sh.prefix == "" {
			t.To = sh.to
		} else {
			t.Paths = append(t.Paths, ipc.PathTarget{Prefix: sh.prefix, To: sh.to})
		}
	}
	// Outside its path a file's share answers 404; a terminator that knows
	// no paths sends everything there.
	if t.To == "" {
		t.To = t.Paths[0].To
	}
	return t, true
}

// sharesStatus is what the status says of this device's shares.
func (d *Daemon) sharesStatus(state *log.State, fresh bool, now time.Time) []ipc.Share {
	shs := d.sharesNow(now)
	if len(shs) == 0 {
		return nil
	}
	name, err := shareName(state, d.self)
	var why string
	switch {
	case err != nil:
		why = err.Error()
	case !fresh:
		why = "this device's view of the network is stale"
	case d.terminatorSilent():
		why = TerminatorNotRunning
	}
	var caa []string
	if name != "" {
		d.pub.mu.Lock()
		caa = d.pub.account.CAA(name)
		d.pub.mu.Unlock()
	}
	out := make([]ipc.Share, 0, len(shs))
	for _, sh := range shs {
		st := ipc.Share{Name: name, To: sh.to, What: sh.what, Path: sh.path, NotShared: why, CAA: caa}
		if !sh.end.IsZero() {
			st.Until = sh.end.Unix()
		}
		out = append(out, st)
	}
	return out
}

// shareCheck is how often a running share checks the network it is in,
// which a restart replaces, and has its announcement renewed.
var shareCheck = 15 * time.Second

// unshare ends the share req names by its path, or every share for none.
func (s *Service) unshare(req *ipc.ShareRequest) error {
	m := s.Mesh()
	if m == nil {
		return errNoNetwork
	}
	if req == nil {
		return m.StopShare("", true)
	}
	return m.StopShare(req.Path, false)
}

// share publishes this device under its own name until the caller hangs
// up or the share's end, telling events the name first.
func (s *Service) share(ctx context.Context, req *ipc.ShareRequest, events func(*ipc.Event) error) error {
	var end time.Time
	if req.Until != 0 {
		if end = time.Unix(req.Until, 0); !end.After(time.Now()) {
			return errors.New("the share ends before it starts")
		}
	}
	m := s.Mesh()
	if m == nil {
		return errNoNetwork
	}
	name, sh, err := m.StartShare(req, end)
	if err != nil {
		return err
	}
	defer func() { m.EndShare(sh) }()
	if err := events(&ipc.Event{Kind: ipc.EventSharing, Name: name}); err != nil {
		return err
	}
	var announced int64
	m.renewShare(&announced)
	check := time.NewTicker(shareCheck)
	defer check.Stop()
	var ended <-chan time.Time
	if !end.IsZero() {
		t := time.NewTimer(time.Until(end))
		defer t.Stop()
		ended = t.C
	}
	for {
		select {
		case <-ctx.Done():
			// The caller hung up, and hears nothing; or juistd stops.
			return errors.New("juistd stops")
		case <-ended:
			return nil
		case <-sh.stopped:
			return nil
		case <-check.C:
			// A network restarted holds no share: it is taken up again, and
			// said again where its name is another, as after a rename.
			switch now := s.Mesh(); {
			case now == nil:
				return errNoNetwork
			case now != m:
				// Taken up first: a share another call made meanwhile is
				// not this one's to end.
				again, nsh, err := now.StartShare(req, end)
				if err != nil {
					return err
				}
				m.EndShare(sh)
				m, sh, announced = now, nsh, 0
				if again != name {
					name = again
					if err := events(&ipc.Event{Kind: ipc.EventSharing, Name: name}); err != nil {
						return err
					}
				}
			default:
				switch again, err := m.ShareName(); {
				case errors.Is(err, ErrNoPublishRole), errors.Is(err, ErrNoDomain):
					return err
				case err == nil && again != name:
					name = again
					if err := events(&ipc.Event{Kind: ipc.EventSharing, Name: name}); err != nil {
						return err
					}
				}
			}
			m.renewShare(&announced)
		}
	}
}
