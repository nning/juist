// Package govern holds what an admin's device does with its admin keys that
// the command line and the Android app share: the admin's side of an invite
// juistd offers, and the checks before anything is signed.
package govern

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/nning/juist/internal/host"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// Admit admits the device a join request names and signs the admission it
// checks, as [host.Admitter] does; wait tells it the votes so far, compare
// hands it the salt and returns its nonce.
type Admit func(ctx context.Context, req *enroll.JoinRequest, wait func(votes, quorum uint32) error,
	compare func(enroll.Salt) (enroll.Nonce, error)) (name string, admission *enroll.Admission, err error)

// An Invite is the admin's side of a [ipc.CmdInvite] conversation. It trusts
// juistd for nothing it signs: the invite it offers is checked and handed to
// Announce with the admin's key added, and it answers one admission at most.
type Invite struct {
	// Key is the admin key the link names.
	Key types.Identity
	// Signing is Key's post-quantum key, which the guest checks too.
	Signing types.SigningKey

	Announce func(code enroll.Code, link enroll.Link, port uint16)
	Admit    Admit
	Event    func(host.Event)

	ready, asked bool

	// reveal carries the guest's nonce from its event to the admission,
	// which runs apart from the events so that it can wait for one.
	reveal    chan enroll.Nonce
	admitting sync.WaitGroup
}

// Wait returns once no admission runs; the conversation's context ending
// ends one.
func (d *Invite) Wait() { d.admitting.Wait() }

// Handle takes one event of the conversation, answering through reply.
func (d *Invite) Handle(ctx context.Context, e *ipc.Event, reply func(ipc.Request) error) error {
	switch e.Kind {
	case ipc.EventInviteReady:
		if d.ready {
			return errors.New("juistd offered a second invite")
		}
		d.ready = true
		code, err := enroll.ParseCode(e.Code)
		if err != nil {
			return fmt.Errorf("juistd offered an invalid code: %w", err)
		}
		link, err := enroll.ParseLink(e.Link)
		if err != nil {
			return fmt.Errorf("juistd offered an invalid link: %w", err)
		}
		// The admin's key goes into the link here, where the daemon cannot
		// change what is shown.
		d.Announce(code, link.WithAdmin(d.Key, new(d.Signing)), e.Port)
	case ipc.EventInviteAdmit:
		// One invite admits one device. A daemon that asks again, or before
		// it offered the invite, is not running the protocol.
		if !d.ready || d.asked {
			return errors.New("juistd asked to admit a device the invite did not bring; nothing more is " +
				"signed. juistd on this device may be compromised")
		}
		d.asked = true
		if e.Join == nil || e.Join.Identity.Validate() != nil || e.Join.Signing.Validate() != nil ||
			(e.Join.Name != "" && types.ValidateName(e.Join.Name) != nil) {
			return errors.New("juistd asked to admit a malformed request")
		}
		wait := func(votes, quorum uint32) error {
			return reply(ipc.Request{Reply: &ipc.InviteReply{
				Waiting: &enroll.Waiting{Votes: votes, Quorum: quorum}}})
		}
		d.reveal = make(chan enroll.Nonce, 1)
		compare := func(s enroll.Salt) (enroll.Nonce, error) {
			if err := reply(ipc.Request{Reply: &ipc.InviteReply{Salt: &s}}); err != nil {
				return enroll.Nonce{}, err
			}
			select {
			case n := <-d.reveal:
				return n, nil
			case <-ctx.Done():
				return enroll.Nonce{}, errors.New("the invite ended before the new device answered")
			}
		}
		join := e.Join
		d.admitting.Add(1)
		go func() {
			defer d.admitting.Done()
			name, admission, err := d.Admit(ctx, join, wait, compare)
			if err != nil {
				// Said once, when the invite ends with it.
				_ = reply(ipc.Request{Reply: &ipc.InviteReply{Refused: enroll.ReasonText(err)}})
				return
			}
			_ = reply(ipc.Request{Reply: &ipc.InviteReply{Name: name, Admission: admission}})
		}()
	case ipc.EventInviteReveal:
		if d.reveal == nil || e.Reveal == nil {
			return errors.New("juistd answered words nobody asked it to compare; nothing more is signed")
		}
		select {
		case d.reveal <- *e.Reveal:
		default:
			return errors.New("juistd answered the words twice; nothing more is signed")
		}
	default:
		ev := host.Event{Name: e.Name, Addr: e.Addr, Err: e.Text}
		switch e.Kind {
		case ipc.EventInviteFailed:
			ev.Kind = host.Failed
		case ipc.EventInviteJoined:
			ev.Kind = host.Joined
		case ipc.EventInviteNoLAN:
			ev.Kind = host.NoLAN
		case ipc.EventInviteNoDHT:
			ev.Kind = host.NoDHT
		case ipc.EventCodeVoided:
			ev.Kind = host.CodeVoided
		case ipc.EventInviteNoRelay:
			ev.Kind = host.NoRelay
		default:
			return nil
		}
		d.Event(ev)
	}
	return nil
}

// Words are the words a person compares with those the joining device shows.
// The salt is drawn now, after the request committed to its nonce, and the
// nonce is held to that commitment: neither the device that asked nor the one
// in between can search for matching words.
func Words(req *enroll.JoinRequest, compare func(enroll.Salt) (enroll.Nonce, error)) (string, error) {
	if req.Commit == ([32]byte{}) {
		return "", errors.New("joining device's juist is too old to compare words; update it")
	}
	var salt enroll.Salt
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	nonce, err := compare(salt)
	if err != nil {
		return "", err
	}
	if enroll.CommitNonce(nonce) != req.Commit {
		return "", errors.New("nonce does not match the join request's commitment; nothing signed. " +
			"juistd here may be compromised")
	}
	return enroll.Fingerprint(salt, nonce, req), nil
}

// SameKeys reports whether n, a member's record, holds the keys req asked
// to join with.
func SameKeys(n types.NodeRecord, req *enroll.JoinRequest) bool {
	return n.WireGuard == req.Keys.WireGuard && n.X25519 == req.Keys.X25519 && n.MLKEM == req.Keys.MLKEM &&
		n.Signing != nil && *n.Signing == req.Signing
}
