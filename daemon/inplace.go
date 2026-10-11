package daemon

import (
	"errors"
	"net/netip"
	"slices"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// ownKeys are this device's keys other than its identity, which a rotation
// in place replaces together.
type ownKeys struct {
	recipient *secrets.PrivateKeys
	wg        types.WGKey
}

// errRelaying is a rotation the running mesh does not take while it relays:
// the relay's certificate goes with the keys, and with it every connection.
var errRelaying = errors.New("this device runs a relay")

// adoptKeys has the running mesh take k, a rotation of this device's keys
// that keeps its identity. Where it cannot, the caller restarts the mesh.
func (d *Daemon) adoptKeys(k *keys.Node) error {
	if k.Identity.Public() != d.self {
		return errors.New("a new identity")
	}
	wg := k.WGPrivate.Bytes()
	if len(wg) != 32 {
		return errors.New("a WireGuard key of another size")
	}
	// Before the relay is looked at: one starting from here on draws a
	// certificate for the new keys.
	d.session.rebind(d.self, k.Public)
	d.mu.Lock()
	relaying := d.relay != nil
	d.mu.Unlock()
	if relaying {
		return errRelaying
	}
	d.selfMu.Lock()
	defer d.selfMu.Unlock()
	self := d.connSelf
	self.NodeKey = conn.NodeKeyFromRaw32([32]byte(wg))
	if err := d.manager.SetSelf(self); err != nil {
		return err
	}
	d.connSelf = self
	old := d.own.Swap(&ownKeys{recipient: k.Recipient, wg: k.Public.WireGuard})
	d.gossip.SetRecipient(k.Recipient)
	d.mu.Lock()
	if id, ok := d.peerIDs[old.wg]; ok {
		delete(d.peerIDs, old.wg)
		d.peerIDs[k.Public.WireGuard] = id
	}
	d.announced = nil
	d.mu.Unlock()
	d.keysSaid.Store(false)
	d.followed()
	return nil
}

// followed reconciles on what changed, and pushes it.
func (d *Daemon) followed() {
	if err := d.Reconcile(); err != nil {
		d.logf("daemon: reconcile: %v", err)
	}
	d.MarkDirty()
}

// errOnOwnStack is a change the running mesh cannot take on a network stack
// of its own, whose listeners hold the addresses they were opened at.
var errOnOwnStack = errors.New("the mesh runs on a network stack of its own")

// followAddrs moves the running data plane and log sync onto the overlay
// addresses the log gives this device now. Where it cannot, the caller
// restarts the mesh.
func (d *Daemon) followAddrs() error {
	state, err := d.TrustedState()
	if err != nil {
		return err
	}
	if !state.IsMember(d.self) {
		return ErrNotMember
	}
	if d.stack != nil {
		return errOnOwnStack
	}
	d.selfMu.Lock()
	defer d.selfMu.Unlock()
	addrs := d.overlayAddrs(state, d.self, d.now().Unix())
	if slices.Equal(addrs, d.heldAddrs()) {
		d.movedSaid.Store(false)
		d.followed()
		return nil
	}
	self := d.connSelf
	self.Addrs = addrs
	if err := d.changeSelf(self); err != nil {
		return err
	}
	d.dnsMu.Lock()
	if d.names != nil && !slices.ContainsFunc(addrs, func(p netip.Prefix) bool { return p.Addr() == d.namesAt.Addr() }) {
		// Started again at an address held, by the next reconcile.
		d.names.Close()
		d.names = nil
	}
	d.dnsMu.Unlock()
	d.setStatus(func(s *ipc.Status) { s.Addrs = addrs })
	d.followed()
	return nil
}

// setNoV4 has the running mesh go without IPv4, or take it back, as a lower
// instance on the host comes to hold what this network claims or stops.
// Where it cannot, the caller restarts the mesh.
func (d *Daemon) setNoV4(noV4 bool) error {
	if d.stack != nil {
		return errOnOwnStack
	}
	d.noV4.Store(noV4)
	return d.followAddrs()
}

// changeSelf gives the data plane self, and has log sync listen on its
// addresses. The caller holds selfMu.
func (d *Daemon) changeSelf(self conn.Self) error {
	if err := d.manager.SetSelf(self); err != nil {
		return err
	}
	if m, ok := d.gossipLn.(*multiListener); ok && d.overlayOnly {
		if err := m.rebind(self.Addrs); err != nil {
			d.logf("daemon: log sync on the new addresses: %v", err)
		}
	}
	d.connSelf = self
	d.held.Store(&self.Addrs)
	d.movedSaid.Store(false)
	return nil
}
