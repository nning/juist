package mobile

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/internal/backupline"
	"github.com/nning/juist/internal/govern"
	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// The app keeps each admin key it holds as a seed it seals behind the
// user's authentication, and hands it to one call at a time: the core keeps
// none, and signs nothing without one.

// NewAdminKey is a new admin key's seed.
func NewAdminKey() ([]byte, error) {
	k, err := types.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	return k.Seed(), nil
}

// AdminKeyOf is the public key of the admin key seed is, as `juist admins`
// lists it.
func AdminKeyOf(seed []byte) (string, error) {
	k, err := types.NewPrivateIdentity(seed)
	if err != nil {
		return "", err
	}
	return k.Public().String(), nil
}

// AdminLine is seed as the line `juist admins export` prints, for a
// password manager.
func AdminLine(seed []byte) string { return backupline.Line(backupline.AdminKey, seed) }

// SealAdminLine is seed as a line only password opens, for a file the user
// keeps where they choose.
func SealAdminLine(seed []byte, password string) (string, error) {
	return backupline.Seal(seed, password)
}

// OpenAdminLine is the seed a line [AdminLine] or [SealAdminLine] wrote
// holds, password opening the second.
func OpenAdminLine(line, password string) ([]byte, error) {
	if backupline.Tag(line) == backupline.SealedAdminKey {
		return backupline.Open(line, password)
	}
	seed, err := backupline.Parse(line, backupline.AdminKey)
	if err != nil {
		return nil, err
	}
	if _, err := types.NewPrivateIdentity(seed); err != nil {
		return nil, backupline.ErrDamaged
	}
	return seed, nil
}

// Founded is a network [Core.Create] made: the slot it is in, and its
// break-glass secret as one line, which ends the network for good, shown
// once and kept nowhere.
type Founded struct {
	Slot       int32
	BreakGlass string
}

// Create founds network in the lowest free slot, this phone its one member,
// named name, and seed's admin key its one admin, with a quorum of one. The
// phone holds no role: a network of phones takes no voucher. Its members
// meet through Tailscale's public DERP servers, a network of phones having
// no member relay.
func (c *Core) Create(network, name string, seed []byte) (*Founded, error) {
	if err := govern.CheckName("network name", network); err != nil {
		return nil, err
	}
	if err := govern.CheckName("name", name); err != nil {
		return nil, err
	}
	key, err := types.NewPrivateIdentity(seed)
	if err != nil {
		return nil, err
	}
	release, err := c.begin()
	if err != nil {
		return nil, err
	}
	defer release()
	n, made, err := c.freeSlot()
	if err != nil {
		return nil, err
	}
	secret, err := c.found(n, network, name, key)
	if err != nil {
		if made {
			c.drop(n)
		}
		return nil, err
	}
	return &Founded{Slot: int32(n.slot), BreakGlass: backupline.Line(backupline.BreakGlass, secret[:])}, nil
}

func (c *Core) found(n *network, network, name string, key types.PrivateIdentity) (types.DisablementSecret, error) {
	var secret types.DisablementSecret
	resp, err := n.call(ipc.Request{Command: ipc.CmdSelf})
	if err != nil {
		return secret, err
	}
	self := resp.Self
	if self == nil || self.Signing == nil {
		return secret, errors.New("the core gave no keys of this phone")
	}
	v4Range, err := govern.DrawV4(c.claimedV4)
	if err != nil {
		return secret, withoutHint(err)
	}
	v4, err := govern.FirstFreeV4(types.V4Range(&v4Range), nil)
	if err != nil {
		return secret, err
	}
	founder := types.NodeRecord{
		Identity: self.Identity, Name: name, WireGuard: self.Keys.WireGuard, X25519: self.Keys.X25519,
		MLKEM: self.Keys.MLKEM, V4: &v4, Signing: self.Signing,
	}
	recipient, err := govern.AdminRecipient(key)
	if err != nil {
		return secret, err
	}
	admin := types.AdminKey{Public: key.Public(), Votes: 1, Name: name, Holder: name,
		Signing: new(key.SigningKey()), Endorsement: key.Endorsement(), Recipient: &recipient}
	secret, commitment, err := govern.DrawBreakGlass()
	if err != nil {
		return secret, err
	}
	genesis, err := log.Genesis(network, 1, []types.AdminKey{admin}, []types.Hash{commitment},
		[]types.NodeRecord{founder}, govern.Sealer())
	if err != nil {
		return secret, err
	}
	genesis.State.V4Prefix = &v4Range
	genesis.State.PublicDERP = &types.PublicDERP{Tailscale: true}
	if err := genesis.Sign(key); err != nil {
		return secret, err
	}
	b, err := genesis.Encode()
	if err != nil {
		return secret, err
	}
	_, err = n.call(ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{b}})
	return secret, err
}

// claimedV4 reports whether p overlaps what another of the phone's networks
// claims, or a network the phone is on.
func (c *Core) claimedV4(p netip.Prefix) bool {
	for _, n := range c.networks() {
		for _, q := range n.s.Status().V4Claims {
			if q.Overlaps(p) {
				return true
			}
		}
	}
	if routes := c.routes.Load(); routes != nil {
		for _, q := range *routes {
			if q.Overlaps(p) {
				return true
			}
		}
	}
	return false
}

// begin keeps a join and a creation from running at once; release ends it.
func (c *Core) begin() (release func(), err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelJoin != nil {
		return nil, errors.New("a join is under way")
	}
	c.cancelJoin = func() {}
	return func() {
		c.mu.Lock()
		c.cancelJoin = nil
		c.mu.Unlock()
	}, nil
}

// Remove removes the member identity from slot's network, signed by seed's
// admin key, as `juist remove` does, and reports whether that applied it;
// else it waits for the other admins' votes.
//
// lastVoucher agrees to take the network's last voucher, which leaves
// freshness unchecked; without it that is refused, as `juist remove` asks.
func (c *Core) Remove(slot int32, identity string, seed []byte, lastVoucher bool) (bool, error) {
	return c.change(slot, seed, func(auth *log.Authority) (types.AUM, error) {
		target, err := memberIn(auth, identity)
		if err != nil {
			return types.AUM{}, err
		}
		if target.Identity == c.selfOf(slot) {
			return types.AUM{}, errors.New("this phone leaves a network, rather than removes itself")
		}
		if err := voucherLoss(auth, target, lastVoucher); err != nil {
			return types.AUM{}, err
		}
		return auth.Builder().RemoveNode(target.Identity, govern.Sealer())
	})
}

// voucherLoss refuses what leaves the network fewer vouchers than its
// threshold, and the last voucher but where lastVoucher says the person
// agreed to leave freshness unchecked.
func voucherLoss(auth *log.Authority, target types.NodeRecord, lastVoucher bool) error {
	err := govern.VoucherLoss(auth.State(), target)
	if errors.Is(err, govern.ErrLastVoucher) && lastVoucher {
		return nil
	}
	return withoutHint(err)
}

// withoutHint drops the hint of err, a command for a computer, which the
// app cannot run.
func withoutHint(err error) error {
	if err == nil {
		return nil
	}
	msg, _, cut := strings.Cut(err.Error(), "\nhint:")
	if !cut {
		return err
	}
	return errors.New(msg)
}

// Roles the app grants: relay, voucher and exit.
var appRoles = map[string]types.Role{"relay": types.RoleRelayCapable, "voucher": types.RoleAdmin, "exit": types.RoleExit}

// Grant gives the member identity in slot's network role, one of relay,
// voucher and exit, or takes it where grant is false, signed by seed's admin
// key, as `juist grant` and `juist revoke` do, and reports whether that
// applied it. The member's subnets stay; lastVoucher is as for [Core.Remove].
func (c *Core) Grant(slot int32, identity, role string, grant bool, seed []byte, lastVoucher bool) (bool, error) {
	r, ok := appRoles[role]
	if !ok {
		return false, fmt.Errorf("%q is no role the app grants", role)
	}
	return c.change(slot, seed, func(auth *log.Authority) (types.AUM, error) {
		target, err := memberIn(auth, identity)
		if err != nil {
			return types.AUM{}, err
		}
		roles := slices.DeleteFunc(slices.Clone(target.Roles), func(x types.Role) bool { return x == r })
		if grant {
			roles = append(roles, r)
		}
		slices.Sort(roles)
		if slices.Equal(roles, target.Roles) {
			return types.AUM{}, errUnchanged
		}
		if !grant && r == types.RoleAdmin {
			if err := voucherLoss(auth, target, lastVoucher); err != nil {
				return types.AUM{}, err
			}
		}
		routes := slices.DeleteFunc(slices.Clone(target.Routes), func(p netip.Prefix) bool { return p.Bits() == 0 })
		if slices.Contains(roles, types.RoleExit) {
			routes = append(routes, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
		}
		return auth.Builder().SetNodeRoutes(target.Identity, roles, routes)
	})
}

var errUnchanged = errors.New("unchanged")

// change builds a record against slot's log as it is, signs it by seed's
// admin key, and applies it where that is enough, reporting so; else it
// carries it to the admin devices for the other admins' votes.
func (c *Core) change(slot int32, seed []byte, build func(*log.Authority) (types.AUM, error)) (bool, error) {
	key, err := types.NewPrivateIdentity(seed)
	if err != nil {
		return false, err
	}
	n, err := c.on(slot)
	if err != nil {
		return false, err
	}
	auth, err := n.log()
	if err != nil {
		return false, err
	}
	if _, ok := auth.State().Admin(key.Public()); !ok {
		return false, errors.New("the admin key here gives no vote in this network")
	}
	aum, err := build(auth)
	if errors.Is(err, errUnchanged) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if err := aum.Sign(key); err != nil {
		return false, err
	}
	if auth.State().SignatureStatus(&aum).Authorized() {
		return true, n.apply(aum)
	}
	return false, n.carry(auth, &aum, key, waiting.MaxLifetime)
}

// log is the network's log as the core holds it, verified anew.
func (n *network) log() (*log.Authority, error) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdLog})
	if err != nil {
		return nil, err
	}
	records := make([]types.AUM, 0, len(resp.Records))
	for _, b := range resp.Records {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, err
		}
		records = append(records, aum)
	}
	return log.FromRecords(log.NewMemStorage(), records)
}

func (n *network) apply(aums ...types.AUM) error {
	bodies := make([][]byte, 0, len(aums))
	for i := range aums {
		b, err := aums[i].Encode()
		if err != nil {
			return err
		}
		bodies = append(bodies, b)
	}
	_, err := n.call(ipc.Request{Command: ipc.CmdInform, Records: bodies})
	return err
}

// carry hands aum, sealed to the admins, to the core, which passes it to
// the admin devices.
func (n *network) carry(auth *log.Authority, aum *types.AUM, key types.PrivateIdentity, ttl time.Duration) error {
	resp, err := n.call(ipc.Request{Command: ipc.CmdWaiting})
	if err != nil {
		return err
	}
	c, err := govern.Seal(auth.State(), aum, key, types.Identity{}, resp.Waiting, time.Now(), ttl)
	if errors.Is(err, waiting.ErrNoReaders) {
		return errors.New("no other admin can read the change on an admin device; it needs their votes")
	}
	if err != nil {
		return err
	}
	b, err := c.Encode()
	if err != nil {
		return err
	}
	_, err = n.call(ipc.Request{Command: ipc.CmdWaiting, Waiting: [][]byte{b}})
	return err
}

// memberIn is the member s names, by identity or by name.
func memberIn(auth *log.Authority, s string) (types.NodeRecord, error) {
	for _, n := range auth.State().Nodes() {
		if n.Identity.String() == s || strings.EqualFold(n.Name, s) {
			return n, nil
		}
	}
	return types.NodeRecord{}, fmt.Errorf("no member %s", cmp.Or(s, `""`))
}

// selfOf is this phone's identity in slot's network.
func (c *Core) selfOf(slot int32) types.Identity {
	n, err := c.on(slot)
	if err != nil {
		return types.Identity{}
	}
	return n.s.Status().Self
}
