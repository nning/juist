package daemon

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A share is what this device publishes under its own name while a call
// holds it open: where its connections go, and its end, zero for none but
// the call's.
type share struct {
	to, what, path string
	end            time.Time
	// stopped is closed once [Daemon.StopShare] ends the share.
	stopped chan struct{}
}

// sharePort is the port of this device's overlay addresses its own name is
// reached on.
const sharePort = 443

// shareLease is how far ahead an announced share ends at most; it is
// renewed while the share lasts, so one whose device is gone ends with it.
const shareLease = 10 * time.Minute

// TerminatorNotRunning is why a share reaches nobody where no terminator
// asks what to serve.
const TerminatorNotRunning = "the terminator does not run"

// Why a share does not start.
var (
	ErrNoPublishRole = errors.New("this device holds no publish role")
	ErrNoDomain      = errors.New("the network has no domain to publish under")
	ErrSharing       = errors.New("this device shares already")
	ErrNotSharing    = errors.New("this device shares nothing")
)

// StartShare publishes this device under its own name, its connections
// going where req says, until end where not zero, and returns the name and
// the share, which [Daemon.EndShare] ends.
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
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	if d.pub.share != nil {
		return "", nil, ErrSharing
	}
	sh := &share{to: req.To, what: req.What, path: req.Path, end: end, stopped: make(chan struct{})}
	d.pub.share = sh
	d.flagTerminatorLocked()
	d.MarkDirty()
	return name, sh, nil
}

// EndShare ends sh, where it is still this device's share and no later one.
func (d *Daemon) EndShare(sh *share) {
	d.pub.mu.Lock()
	ended := d.pub.share == sh
	if ended {
		d.pub.share = nil
		d.flagTerminatorLocked()
	}
	d.pub.mu.Unlock()
	if ended {
		d.MarkDirty()
	}
}

// StopShare ends this device's share, and the call that holds it.
func (d *Daemon) StopShare() error {
	d.pub.mu.Lock()
	sh := d.pub.share
	d.pub.share = nil
	d.flagTerminatorLocked()
	d.pub.mu.Unlock()
	if sh == nil {
		return ErrNotSharing
	}
	close(sh.stopped)
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

// shareNow is this device's share, nil for none or one past its end.
func (d *Daemon) shareNow(now time.Time) *share {
	d.pub.mu.Lock()
	defer d.pub.mu.Unlock()
	sh := d.pub.share
	if sh == nil || !sh.end.IsZero() && !now.Before(sh.end) {
		return nil
	}
	c := *sh
	return &c
}

// shareAnnounced is the share this device announces at now, while it can
// serve it: an end half a lease to a lease ahead, so that it changes once
// each half lease, or the share's own where sooner.
func (d *Daemon) shareAnnounced(now time.Time) *gossip.Share {
	sh := d.shareNow(now)
	if sh == nil || !d.freshness(now).Fresh(now.Unix()) {
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
	if !sh.end.IsZero() && sh.end.Unix() < until {
		until = sh.end.Unix()
	}
	return &gossip.Share{Port: sharePort, Until: until}
}

// sharing reports whether id shares at now: this device as it holds one,
// another as its announcement says, which ends no further ahead than a
// lease, so that a share whose device is gone ends with it.
func (d *Daemon) sharing(id types.Identity, now time.Time) bool {
	if id == d.self {
		return d.shareNow(now) != nil
	}
	ep, ok := d.endpoints.Get(id)
	return ok && ep.Share.Live(now) && ep.Share.Port == sharePort &&
		ep.Share.Until <= now.Add(shareLease+clockSkew).Unix()
}

// renewShare has this device's announcement go out where its share's end
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

// shareServed is this device's share as its terminator ends TLS for it, on
// addrs, while state grants the role.
func (d *Daemon) shareServed(state *log.State, addrs []netip.Addr, now time.Time) (ipc.PublishedTarget, bool) {
	sh := d.shareNow(now)
	if sh == nil {
		return ipc.PublishedTarget{}, false
	}
	name, err := shareName(state, d.self)
	if err != nil {
		return ipc.PublishedTarget{}, false
	}
	return ipc.PublishedTarget{Name: name, Addrs: addrs, Port: sharePort, To: sh.to}, true
}

// shareStatus is what the status says of this device's share, nil for none.
func (d *Daemon) shareStatus(state *log.State, fresh bool, now time.Time) *ipc.Share {
	sh := d.shareNow(now)
	if sh == nil {
		return nil
	}
	st := &ipc.Share{To: sh.to, What: sh.what, Path: sh.path}
	if !sh.end.IsZero() {
		st.Until = sh.end.Unix()
	}
	name, err := shareName(state, d.self)
	switch {
	case err != nil:
		st.NotShared = err.Error()
	case !fresh:
		st.NotShared = "this device's view of the network is stale"
	case d.terminatorSilent():
		st.NotShared = TerminatorNotRunning
	}
	st.Name = name
	if name != "" {
		d.pub.mu.Lock()
		st.CAA = d.pub.account.CAA(name)
		d.pub.mu.Unlock()
	}
	return st
}

// shareCheck is how often a running share checks the network it is in,
// which a restart replaces, and has its announcement renewed.
var shareCheck = 15 * time.Second

// share publishes this device under its own name until the caller hangs
// up or the share's end, telling events the name first.
// unshare ends this device's share.
func (s *Service) unshare() error {
	m := s.Mesh()
	if m == nil {
		return errNoNetwork
	}
	return m.StopShare()
}

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
