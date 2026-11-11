package daemon

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// The network's public DERP setting reaches the data plane, and a peer homed
// at a public region is sent there only while the network names it.
func TestThePublicDERPSettingReachesTheDataPlane(t *testing.T) {
	f := newReconcileFixture(t, 2)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.mgr.publicDERP.Load() {
		t.Fatal("a network naming no public DERP installs one")
	}
	rec, err := f.auth.Builder().SetPublicDERP(types.PublicDERP{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !f.mgr.publicDERP.Load() {
		t.Error("the network's public DERP servers are not installed")
	}
	// Turned off, they go even where the relays fail to install.
	f.mgr.mu.Lock()
	f.mgr.relayErr = errors.New("relays refused")
	f.mgr.mu.Unlock()
	off, err := f.auth.Builder().SetPublicDERP(types.PublicDERP{})
	if err != nil {
		t.Fatal(err)
	}
	if err := off.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{off}); err != nil {
		t.Fatal(err)
	}
	_ = f.d.Reconcile()
	if f.mgr.publicDERP.Load() {
		t.Error("turned off in the log, Tailscale's servers stay behind failing relays")
	}

	var region int
	for r := range conn.PublicRegions() {
		region = r
		break
	}
	ep := gossip.Endpoint{HomeRelay: uint16(region)}
	if homeRelay(ep, nil, false) != 0 {
		t.Error("a peer is sent to a public region the network names none of")
	}
	if homeRelay(ep, nil, true) != region {
		t.Error("a peer homed at a public region is not sent there")
	}
}

// A peer homed at one of Tailscale's regions is relayed by Tailscale, as the
// status says, and is no evidence that this device's relay ports are
// closed: it may not measure the relay for another reason, as far away.
func TestAPeerHomedAtTailscaleIsSaidSo(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	rec, err := f.auth.Builder().SetPublicDERP(types.PublicDERP{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !f.d.Status().PublicDERP {
		t.Error("the status does not say the network names Tailscale's DERP")
	}
	var region int
	var name string
	for r, n := range conn.PublicRegions() {
		region, name = r, n
		break
	}
	live := f.nw.devices[1]
	e := f.signedBy(t, live, t0)
	e.HomeRelay = uint16(region)
	if err := e.SignPQ(live.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	answering := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{answering: true}
	f.mgr.mu.Unlock()
	c.set(t0)
	f.d.refreshReach(t.Context())
	c.set(t0.Add(relayUnreachedAfter))
	f.d.refreshReach(t.Context())
	st := f.d.Status()
	if st.RelayUnreached {
		t.Error("a live peer at Tailscale's relay is blamed on this relay's ports")
	}
	if len(st.Reach) != 1 || st.Reach[0].Relay != name || !st.Reach[0].PublicRelay {
		t.Errorf("reach %+v, want relayed by %s, Tailscale's", st.Reach, name)
	}

	// Nor is one that reaches named relays alone.
	e = f.signedBy(t, live, t0.Add(relayUnreachedAfter+time.Second))
	e.HomeRelay = uint16(region)
	e.Addrs, e.Sealed = nil, nil
	if err := e.SignPQ(live.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !f.installed(t, 1).Walled {
		t.Fatal("the peer is not installed as walled")
	}
	answering = f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{answering: true}
	f.mgr.mu.Unlock()
	t1 := t0.Add(2*relayUnreachedAfter + time.Minute)
	c.set(t1)
	f.d.refreshReach(t.Context())
	c.set(t1.Add(relayUnreachedAfter))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); st.RelayUnreached {
		t.Error("a walled peer at Tailscale's relay is blamed on this relay's port")
	}
}
