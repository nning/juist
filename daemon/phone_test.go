package daemon

import (
	"net/netip"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// A member that announces it rests is listed as a phone, as this device is
// where it rests itself; a hint alone makes none.
func TestTheStatusNamesAPhoneByItsAnnouncement(t *testing.T) {
	f := newReconcileFixtureWith(t, 4, func(o *Options) { o.Rests = true })
	phone, laptop, hinted := f.nw.devices[1], f.nw.devices[2], f.nw.devices[3]
	_, disco, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	e := gossip.Endpoint{Identity: phone.record.Identity, Disco: gossip.DiscoKey(disco),
		Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.11:4001")}, GossipPort: 4001, Seq: 1,
		Epoch: f.auth.State().Epoch(), PairStore: 1, Schema: types.CurrentSchema, Rests: true}
	if err := e.SignPQ(phone.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	f.learn(t, laptop, 4002)
	h, err := endpointFor(hinted, 4003)
	if err != nil {
		t.Fatal(err)
	}
	f.learnHint(t, hinted, h, func(h *gossip.Endpoint) { h.Rests = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	phones := map[types.Identity]bool{}
	for _, d := range f.d.Status().Devices {
		phones[d.Identity] = d.Phone
	}
	if !phones[phone.record.Identity] || phones[laptop.record.Identity] || phones[hinted.record.Identity] ||
		!phones[f.nw.devices[0].record.Identity] {
		t.Errorf("phones %v: want the resting member and this device alone", phones)
	}
}
