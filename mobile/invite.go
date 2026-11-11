package mobile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nning/juist/internal/govern"
	"github.com/nning/juist/internal/host"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// InviteListener hears an invite the phone offers, from another goroutine.
type InviteListener interface {
	// Ready gives the invite's code, for a device on the same Wi-Fi, and its
	// link, which a QR code shows.
	Ready(code, link string)
	// Compare asks the person to compare words with those the device that
	// asks to join as name shows. The app answers with [Core.Admit] once
	// they match, and with [Core.Refuse] where they do not.
	Compare(words, name string)
	// Event says what else befell the invite: kind is a host.EventKind,
	// name the device's, text what went wrong.
	Event(kind int32, name, text string)
}

// MaxInviteMinutes bounds how long an invite stays open.
const MaxInviteMinutes = 60

// Invite offers an invite into slot's network for minutes, on the Wi-Fi and
// through the network's relays and the DHT, and returns once it ends: with
// a device joined, cancelled by CancelInvite, or expired, which return nil. admin is the
// public admin key, as [AdminKeyOf] gives it, the link names and whose seed
// Admit hands in to sign the one admission the invite makes.
func (c *Core) Invite(slot int32, minutes int32, admin string, l InviteListener) error {
	if minutes <= 0 || minutes > MaxInviteMinutes {
		return errors.New("an invite stays open from 1 to 60 minutes")
	}
	n, err := c.on(slot)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(minutes)*time.Minute)
	defer cancel()
	c.mu.Lock()
	if c.cancelInvite != nil {
		c.mu.Unlock()
		return errors.New("an invite is open already")
	}
	c.cancelInvite = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancelInvite, c.inviteAnswer = nil, nil
		c.mu.Unlock()
	}()
	auth, err := n.log()
	if err != nil {
		return err
	}
	key, err := inviteKey(admin, auth)
	if err != nil {
		return err
	}
	conv := &govern.Invite{
		Key:      key.Public,
		Announce: func(code enroll.Code, link enroll.Link, _ uint16) { l.Ready(code.String(), link.String()) },
		Admit: func(ctx context.Context, req *enroll.JoinRequest, wait func(votes, quorum uint32) error,
			compare func(enroll.Salt) (enroll.Nonce, error)) (string, *enroll.Admission, error) {
			return c.admit(ctx, n, req, wait, compare, l, key.Public)
		},
		Event: func(e host.Event) { l.Event(int32(e.Kind), e.Name, e.Err) },
	}
	if key.Signing != nil {
		conv.Signing = *key.Signing
	}
	req := ipc.Request{Command: ipc.CmdInvite, Offer: &ipc.InviteOffer{
		Port: host.DefaultPort, LAN: true, DHT: true, Expires: uint32(minutes) * 60}}
	_, err = ipc.ConverseVia(ctx, n.s.Pipe, req, conv.Handle)
	conv.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// inviteKey is the admin key admin names, refused where it gives no vote in
// auth's network before a guest spends the invite.
func inviteKey(admin string, auth *log.Authority) (types.AdminKey, error) {
	if alarm := auth.Alarm(); alarm != nil {
		return types.AdminKey{}, fmt.Errorf("cannot admit during a log alarm: %v", alarm)
	}
	id, err := types.ParseIdentity(admin)
	if err != nil {
		return types.AdminKey{}, fmt.Errorf("this phone holds no admin key of this network: %w", err)
	}
	k, ok := auth.State().Admin(id)
	if !ok {
		return types.AdminKey{}, errors.New("the admin key here gives no vote in this network")
	}
	return k, nil
}

// CancelInvite ends the invite open.
func (c *Core) CancelInvite() {
	c.mu.Lock()
	cancel := c.cancelInvite
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Admit answers [InviteListener.Compare]: the words matched, and seed's
// admin key admits the device. Where no comparison waits, it signs nothing.
func (c *Core) Admit(seed []byte) error {
	if _, err := types.NewPrivateIdentity(seed); err != nil {
		return err
	}
	// The app's array is lent for this call alone, and wiped after it.
	return c.answer(bytes.Clone(seed))
}

// Refuse answers [InviteListener.Compare]: the words differ, and nothing is
// signed.
func (c *Core) Refuse() { _ = c.answer(nil) }

func (c *Core) answer(seed []byte) error {
	c.mu.Lock()
	ch := c.inviteAnswer
	c.mu.Unlock()
	if ch == nil {
		clear(seed)
		return errors.New("no comparison waits for an answer")
	}
	select {
	case ch <- seed:
		return nil
	default:
		clear(seed)
		return errors.New("answered already")
	}
}

// admit is one admission: the person compares the words, the app hands in
// the admin key, which adds the device where it is no member yet and signs
// the admission it checks. The core takes an answer only while it asks.
func (c *Core) admit(ctx context.Context, n *network, req *enroll.JoinRequest, wait func(votes, quorum uint32) error,
	compare func(enroll.Salt) (enroll.Nonce, error), l InviteListener,
	admitting types.Identity) (string, *enroll.Admission, error) {
	words, err := govern.Words(req, compare)
	if err != nil {
		return "", nil, err
	}
	answers := make(chan []byte, 1)
	c.mu.Lock()
	c.inviteAnswer = answers
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.inviteAnswer = nil
		c.mu.Unlock()
		// An answer that came as the invite ended is wiped too.
		select {
		case s := <-answers:
			clear(s)
		default:
		}
	}()
	l.Compare(words, govern.MemberName(req.Name))
	var seed []byte
	select {
	case seed = <-answers:
	case <-ctx.Done():
		return "", nil, errors.New("the invite ended before the words were compared")
	}
	if seed == nil {
		return "", nil, errors.New("words not confirmed; nothing signed")
	}
	defer clear(seed)
	// Admitted after the invite, a device would be a member that never got
	// the log.
	if err := ctx.Err(); err != nil {
		return "", nil, fmt.Errorf("not admitted: %w", err)
	}
	key, err := types.NewPrivateIdentity(seed)
	if err != nil {
		return "", nil, err
	}
	if key.Public() != admitting {
		return "", nil, errors.New("the admin key handed in is not the one the invite names")
	}
	auth, err := n.log()
	if err != nil {
		return "", nil, err
	}
	id := req.Identity
	if cur, ok := auth.State().Node(id); !ok {
		if err := n.addNode(ctx, auth, req, key, wait); err != nil {
			return "", nil, err
		}
	} else if !govern.SameKeys(cur, req) {
		return "", nil, errors.New("a member already, with other keys")
	}
	if auth, err = n.log(); err != nil {
		return "", nil, err
	}
	cur, ok := auth.State().Node(id)
	if !ok || !govern.SameKeys(cur, req) {
		return "", nil, errors.New("log does not admit the device under the keys it asked with")
	}
	admission, err := enroll.SignAdmission(key, auth.State().GenesisHash(), auth.Head(), id)
	if err != nil {
		return "", nil, err
	}
	return cur.Name, admission, nil
}

// addNode adds the device req asks for, and where the other admins must
// approve, waits for their votes while the invite is open.
func (n *network) addNode(ctx context.Context, auth *log.Authority, req *enroll.JoinRequest, key types.PrivateIdentity,
	wait func(votes, quorum uint32) error) (err error) {
	state := auth.State()
	history, err := n.history()
	if err != nil {
		return err
	}
	v4, err := govern.NextV4(state, history)
	if err != nil {
		return withoutHint(err)
	}
	rec := req.NodeRecord(govern.UniqueName(state, govern.MemberName(req.Name)))
	rec.V4 = &v4
	aum, err := auth.Builder().AddNode(rec, govern.Sealer())
	if err != nil {
		return err
	}
	if err := aum.Sign(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("not admitted: %w", err)
	}
	st := state.SignatureStatus(&aum)
	if st.Authorized() {
		return n.apply(aum)
	}
	// Approved after the invite, the copies would admit a device that never
	// got the log: they are held for as long as the invite is open, at most
	// admissionHold, and handed on anew while it is.
	end, _ := ctx.Deadline()
	hold := func() time.Duration { return max(min(time.Until(end), admissionHold), time.Second) }
	if err := n.carry(auth, &aum, key, hold()); err != nil {
		return err
	}
	// Ended unadmitted, as when cancelled, the copies are cut to
	// withdrawHold: approved later, they would admit a device told it
	// failed. The cut copy replaces the longer one on the admin devices it
	// reaches meanwhile; those it does not keep theirs until it expires.
	defer func() {
		if err != nil {
			_ = n.carry(auth, &aum, key, withdrawHold)
		}
	}()
	renewed := time.Now()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		if err := wait(st.Votes, st.Quorum); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("the invite ended before the other admins approved")
		case <-tick.C:
		}
		if now, err := n.log(); err == nil && now.State().IsMember(req.Identity) {
			return nil
		}
		if time.Since(renewed) > admissionHold/2 {
			if err := n.carry(auth, &aum, key, hold()); err != nil {
				return err
			}
			renewed = time.Now()
		}
	}
}

// admissionHold is the longest an admission waits for votes on the admin
// devices, renewed while its invite is open; withdrawHold is what is left of
// one whose invite ended, long enough to reach them.
var admissionHold = 5 * time.Minute

const withdrawHold = 30 * time.Second

// history is every record the core holds, those off the chain too, whose
// admissions may yet be reissued.
func (n *network) history() ([]types.AUM, error) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdLog, Orphans: true})
	if err != nil {
		return nil, err
	}
	var out []types.AUM
	for _, b := range append(resp.Records, resp.Orphans...) {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, err
		}
		out = append(out, aum)
	}
	return out, nil
}
