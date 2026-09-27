package daemon

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/types"
)

// clock is a settable time for a daemon under test.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (nw *network) renumberNode(t *testing.T, id types.Identity, v4 string, until time.Time) types.AUM {
	t.Helper()
	auth, _ := nw.authorityFor(t)
	aum, err := auth.Builder().RenumberNode(id, netip.MustParseAddr(v4), uint64(until.Unix()))
	if err != nil {
		t.Fatalf("building the renumbering: %v", err)
	}
	if err := aum.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	return aum
}

func peerAddrs(t *testing.T, mgr *fakeManager, dev *device) []netip.Prefix {
	t.Helper()
	want := conn.NodePublicFromRaw32([32]byte(dev.record.WireGuard))
	for _, p := range mgr.snapshot() {
		if p.NodeKey == want {
			return p.Addrs
		}
	}
	t.Fatalf("%s is not a peer", dev.record.Name)
	return nil
}

// A member renumbered on its own is reached at both addresses until the
// deadline, and at the new one only after it; and the status names the
// members not seen holding the change until they are, past the deadline too.
func TestARenumberedPeerIsReachedAtBothAddressesUntilTheDeadline(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	peer, other := f.nw.devices[1], f.nw.devices[2]
	f.learn(t, peer, 4002)
	f.learn(t, other, 4003)
	until := c.get().Add(time.Hour)
	rec := f.nw.renumberNode(t, peer.record.Identity, "198.18.0.9", until)
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatalf("informing the daemon: %v", err)
	}

	v6 := netip.PrefixFrom(f.auth.State().Addr6(peer.record.Identity), 128)
	old, moved := netip.PrefixFrom(*peer.record.V4, 32), netip.MustParsePrefix("198.18.0.9/32")
	if got, want := peerAddrs(t, f.mgr, peer), []netip.Prefix{v6, old, moved}; !slices.Equal(got, want) {
		t.Errorf("before the deadline the peer is at %v, want %v", got, want)
	}
	st := f.d.Status()
	if want := []string{peer.record.Name, other.record.Name}; !slices.Equal(st.Unmoved, want) {
		t.Errorf("the status names %v as not moved, want %v", st.Unmoved, want)
	}
	i := slices.IndexFunc(st.Devices, func(d ipc.Device) bool { return d.Identity == peer.record.Identity })
	if d := st.Devices[i]; d.Retiring != old.Addr().String() || d.RetiringUntil != until.Unix() {
		t.Errorf("the device list has the peer retiring %q until %d", d.Retiring, d.RetiringUntil)
	}

	f.d.onHave(other.record.Identity, []types.Hash{{1}})
	f.d.onHave(peer.record.Identity, []types.Hash{rec.Hash()})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.d.Status().Unmoved; !slices.Equal(got, []string{other.record.Name}) {
		t.Errorf("after the peer's hello names the record, the status names %v as not moved", got)
	}

	c.set(until)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, want := peerAddrs(t, f.mgr, peer), []netip.Prefix{v6, moved}; !slices.Equal(got, want) {
		t.Errorf("after the deadline the peer is at %v, want %v", got, want)
	}
	if st := f.d.Status(); !slices.Equal(st.Unmoved, []string{other.record.Name}) || st.Devices[i].Retiring != "" {
		t.Errorf("after the deadline the status has %v not moved, the peer retiring %q; want %v and none",
			st.Unmoved, st.Devices[i].Retiring, other.record.Name)
	}
	f.d.onHave(other.record.Identity, []types.Hash{rec.Hash()})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status(); st.Unmoved != nil {
		t.Errorf("once every member holds the change, the status still names %v", st.Unmoved)
	}
}

// A device renumbered starts on both addresses, the old one first to send
// from, and asks for a restart once the deadline takes the old one away.
func TestARenumberedDeviceMovesAtTheDeadline(t *testing.T) {
	nw := newNetwork(t, 2)
	self := nw.devices[0]
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	until := c.get().Add(time.Hour)
	auth, st := nw.authorityFor(t, nw.renumberNode(t, self.record.Identity, "198.18.0.9", until))
	var started []netip.Prefix
	d, err := New(Options{
		Authority: auth, Storage: st,
		Identity: self.identity, Recipient: self.recipient, WireGuard: self.wgPrivate,
		Connect: func(o conn.Options) (conn.Manager, error) {
			started = o.Self.Addrs
			return &fakeManager{}, nil
		},
		DisableDiscovery: true,
		DisableDHT:       true,
		Clock:            c.get,
		Logf:             safeLogf(t, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v6 := netip.PrefixFrom(auth.State().Addr6(self.record.Identity), 128)
	old := netip.PrefixFrom(*self.record.V4, 32)
	if want := []netip.Prefix{v6, old, netip.MustParsePrefix("198.18.0.9/32")}; !slices.Equal(started, want) {
		t.Errorf("the data plane starts on %v, want %v", started, want)
	}
	if d.addrsMoved() {
		t.Error("the addresses moved before the deadline")
	}
	if !slices.ContainsFunc(d.v4, func(r netip.Prefix) bool { return r.Contains(old.Addr()) }) {
		t.Errorf("the old address's range %v is not held back from the underlay", d.v4)
	}
	c.set(until)
	if !d.addrsMoved() {
		t.Error("the deadline passed and the mesh keeps the old address")
	}
}
