package daemon

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/internal/host"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// invite offers an invite from this device and runs its sessions. The daemon
// is the side attacker-facing parsers belong on — the invite's TCP port, the
// LAN answers, the public DHT — and holds no admin key: every admission is
// asked of the caller, whose CLI rebuilds and signs it against its own
// verified log, and whose admission statement the guest checks.
func (s *Service) invite(ctx context.Context, offer *ipc.InviteOffer, events func(*ipc.Event) error,
	replies <-chan ipc.Request) error {
	m := s.Mesh()
	if m == nil {
		return errors.New("this device is not connected to a network, so it cannot invite anyone")
	}
	state, err := m.TrustedState()
	if err != nil {
		return err
	}
	o := host.Options{
		Port:          offer.Port,
		LAN:           offer.LAN,
		SkipInterface: s.opts.Mesh.TunName,
		Exclude:       []netip.Prefix{state.ULA()},
		Addrs:         s.opts.InviteAddrs,
		Relays:        m.inviteRelays(state),
		Identity:      s.keys.Identity,
	}
	if offer.DHT {
		o.Helpers = s.helpers()
	}
	noDHT := offer.DHT && o.Helpers == nil
	h, err := host.Listen(o)
	if err != nil {
		return err
	}
	defer h.Close()
	inv := h.Invite()
	if err := events(&ipc.Event{Kind: ipc.EventInviteReady, Code: inv.Code().String(), Link: inv.Link().String(),
		Port: h.Port()}); err != nil {
		return err
	}
	if noDHT {
		_ = events(&ipc.Event{Kind: ipc.EventInviteNoDHT, Text: "juistd is told to use no public DHT or STUN server"})
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(offer.Expires)*time.Second)
	defer cancel()
	adm := &callerAdmitter{events: events, replies: replies}
	chain := func() ([]types.AUM, [][]byte, [][]byte, error) {
		records, err := m.Chain()
		if err != nil {
			return nil, nil, nil, err
		}
		hints := m.bootstrapHints()
		return records, hints.Endpoints, hints.Leases, nil
	}
	return h.Serve(ctx, adm, chain, func(e host.Event) {
		ev := &ipc.Event{Name: e.Name, Addr: e.Addr, Text: e.Err}
		if !e.Identity.IsZero() {
			id := e.Identity
			ev.Identity = &id
		}
		switch e.Kind {
		case host.Failed:
			ev.Kind = ipc.EventInviteFailed
		case host.Joined:
			ev.Kind = ipc.EventInviteJoined
			m.welcome(e.Identity, e.Announcement, e.Addr)
		case host.NoLAN:
			ev.Kind = ipc.EventInviteNoLAN
		case host.NoDHT:
			ev.Kind = ipc.EventInviteNoDHT
		case host.CodeVoided:
			ev.Kind = ipc.EventCodeVoided
		case host.NoRelay:
			ev.Kind = ipc.EventInviteNoRelay
		default:
			return
		}
		_ = events(ev)
	})
}

// A callerAdmitter asks the caller of a [CmdInvite] to admit a guest, and
// waits for its answer.
type callerAdmitter struct {
	events  func(*ipc.Event) error
	replies <-chan ipc.Request
}

func (c *callerAdmitter) Admit(ctx context.Context, req *enroll.JoinRequest, wait func(votes, quorum uint32) error,
	compare func(enroll.Salt) (enroll.Nonce, error)) (string, *enroll.Admission, error) {
	if err := c.events(&ipc.Event{Kind: ipc.EventInviteAdmit, Join: req}); err != nil {
		return "", nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return "", nil, errors.New("the invite ended before the admission was decided")
		case r := <-c.replies:
			p := r.Reply
			switch {
			case p.Waiting != nil:
				if err := wait(p.Waiting.Votes, p.Waiting.Quorum); err != nil {
					return "", nil, err
				}
			case p.Salt != nil:
				nonce, err := compare(*p.Salt)
				if err != nil {
					return "", nil, err
				}
				if err := c.events(&ipc.Event{Kind: ipc.EventInviteReveal, Reveal: &nonce}); err != nil {
					return "", nil, err
				}
			case p.Admission != nil:
				if p.Admission.Guest != req.Identity {
					return "", nil, errors.New("the inviting admin admitted another device")
				}
				return p.Name, p.Admission, nil
			default:
				return "", nil, errors.New(p.Refused)
			}
		}
	}
}
