package log

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

const testTTL = 48 * 3600

// grantAdmin gives a member the admin role.
func (h *harness) grantAdmin(id types.Identity) {
	h.t.Helper()
	aum, err := h.auth.Builder().SetNodeRoutes(id, []types.Role{types.RoleAdmin}, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) lease(signer types.Identity, head types.Hash, issued uint64) types.Lease {
	h.t.Helper()
	l := types.Lease{Network: h.auth.State().GenesisHash(), Head: head, Issued: issued}
	if err := l.Sign(h.nodeIDs[signer], h.auth.State().PQ()); err != nil {
		h.t.Fatal(err)
	}
	return l
}

func TestLeaseRoundTrip(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.addNode("admin-device")
	h.grantAdmin(a.Identity)
	l := h.lease(a.Identity, h.auth.Head(), 1000)
	b, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := types.DecodeLease(b)
	if again, _ := got.Encode(); err != nil || !bytes.Equal(again, b) {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	damaged := bytes.Clone(b)
	damaged[bytes.Index(damaged, l.Sig[:])] ^= 1
	if _, err := types.DecodeLease(damaged); err == nil {
		t.Fatal("a lease with a damaged signature decoded")
	}
	// Past the cut-over the log holds a lease to its ML-DSA signature, which
	// decoding alone cannot check.
	if err := h.auth.CheckLease(&got, 1000); err != nil {
		t.Fatalf("an honest lease: %v", err)
	}
	pqDamaged := got
	pqDamaged.MLDSA = new(*got.MLDSA)
	pqDamaged.MLDSA[0] ^= 1
	if err := h.auth.CheckLease(&pqDamaged, 1000); err == nil {
		t.Fatal("a lease with a damaged ML-DSA signature vouched")
	}
	edOnly := got
	edOnly.MLDSA = nil
	if err := h.auth.CheckLease(&edOnly, 1000); err == nil {
		t.Fatal("a lease signed by Ed25519 alone vouched past the cut-over")
	}
}

func TestCheckLease(t *testing.T) {
	h := newHarness(t, 1, 1)
	signer := h.addNode("admin-device")
	plain := h.addNode("plain")
	h.grantAdmin(signer.Identity)
	head := h.auth.Head()
	const now = 1_000_000

	if err := h.auth.CheckLease(ptr(h.lease(signer.Identity, head, now)), now); err != nil {
		t.Fatalf("a current lease from an admin device was refused: %v", err)
	}
	for name, c := range map[string]struct {
		lease types.Lease
		want  string
	}{
		"not an admin device": {h.lease(plain.Identity, head, now), "not an admin device"},
		"from the future":     {h.lease(signer.Identity, head, now+MaxLeaseSkew+1), "future"},
		"unknown head":        {h.lease(signer.Identity, types.Hash{1}, now), "does not contain"},
		"other network": {func() types.Lease {
			l := h.lease(signer.Identity, head, now)
			l.Network = types.Hash{2}
			return l
		}(), "another network"},
	} {
		err := h.auth.CheckLease(&c.lease, now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error mentioning %q", name, err, c.want)
		}
	}
}

// TestFreshnessEndsExactlyAtTheTTL: the node may act on its state until the
// newest vouching lease is ttl old, and not a second longer.
func TestFreshnessEndsExactlyAtTheTTL(t *testing.T) {
	h := newHarness(t, 1, 1)
	signer := h.addNode("admin-device")
	h.grantAdmin(signer.Identity)
	const issued = 1_000_000
	leases := []types.Lease{h.lease(signer.Identity, h.auth.Head(), issued)}

	f := h.auth.Freshness(leases, issued+testTTL-1, testTTL)
	if !f.Enforced() || !f.Fresh(issued+testTTL-1) {
		t.Fatalf("stale one second before the TTL: %+v", f)
	}
	f = h.auth.Freshness(leases, issued+testTTL, testTTL)
	if f.Fresh(issued + testTTL) {
		t.Fatalf("still fresh at the TTL: %+v", f)
	}
}

// A lease names the head the signer held. A node that holds more than that is
// vouched for by it; a node behind it is not, since it may lack exactly the
// removal the signer had seen.
func TestLeaseVouchesOnlyForStateAtLeastAsNew(t *testing.T) {
	h := newHarness(t, 1, 1)
	signer := h.addNode("admin-device")
	h.grantAdmin(signer.Identity)
	old := h.auth.Head()
	behind := h.fork()
	victim := h.addNode("victim")
	h.removeNode(victim.Identity)
	const now = 1_000_000

	oldLease := h.lease(signer.Identity, old, now)
	if err := h.auth.CheckLease(&oldLease, now); err != nil {
		t.Fatalf("a lease on an ancestor of the head does not vouch: %v", err)
	}
	newLease := h.lease(signer.Identity, h.auth.Head(), now)
	if err := behind.CheckLease(&newLease, now); err == nil {
		t.Fatal("a node missing a removal was vouched for by a lease naming it")
	}
}

// Withdrawing a signer's role withdraws its leases: they must not keep a node
// fresh on the word of a device the network no longer trusts to vouch.
func TestWithdrawnSignerVouchesForNothing(t *testing.T) {
	h := newHarness(t, 1, 1)
	signer := h.addNode("admin-device")
	other := h.addNode("other-admin")
	h.grantAdmin(signer.Identity)
	h.grantAdmin(other.Identity)
	const now = 1_000_000
	leases := []types.Lease{h.lease(signer.Identity, h.auth.Head(), now)}

	aum, err := h.auth.Builder().SetNodeRoutes(signer.Identity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatal(err)
	}
	if f := h.auth.Freshness(leases, now, testTTL); f.Fresh(now) {
		t.Fatalf("a withdrawn signer's lease still vouches: %+v", f)
	}
}

func TestNoSignersMeansNotEnforced(t *testing.T) {
	h := newHarness(t, 1, 1)
	h.addNode("plain")
	if f := h.auth.Freshness(nil, 1, testTTL); f.Enforced() || !f.Fresh(1) {
		t.Fatalf("a network with no admin device enforced freshness: %+v", f)
	}
}

func ptr[T any](v T) *T { return &v }

// setVouchers raises the network to the vouching schema if it is not there,
// then sets the threshold.
func (h *harness) setVouchers(m uint32) error {
	h.t.Helper()
	if h.auth.State().Schema() < types.SchemaVouchers {
		up, err := h.auth.Builder().SchemaUpgrade(types.SchemaVouchers)
		if err != nil {
			h.t.Fatal(err)
		}
		h.signQuorum(&up)
		if err := h.auth.Inform(up); err != nil {
			h.t.Fatal(err)
		}
	}
	aum, err := h.auth.Builder().SetVouchers(m)
	if err != nil {
		return err
	}
	h.signQuorum(&aum)
	return h.auth.Inform(aum)
}

// With a threshold of two, one admin device — dishonest, naming the anchor
// every chain contains — no longer keeps a node fresh; two do, from the
// older of their leases.
func TestFreshnessNeedsTheThresholdOfAdminDevices(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.addNode("admin-a"), h.addNode("admin-b")
	h.grantAdmin(a.Identity)
	h.grantAdmin(b.Identity)
	const now = 5_000_000

	liar := []types.Lease{h.lease(a.Identity, h.auth.Anchor(), now)}
	if !h.auth.Freshness(liar, now, testTTL).Fresh(now) {
		t.Fatal("with the default threshold one admin device should suffice")
	}
	if err := h.setVouchers(2); err != nil {
		t.Fatal(err)
	}
	f := h.auth.Freshness(liar, now, testTTL)
	if f.Fresh(now) || f.Needed != 2 || f.Vouching != 1 {
		t.Fatalf("one admin device of two made the node fresh: %+v", f)
	}
	// The same signer twice is still one device.
	twice := append(liar, h.lease(a.Identity, h.auth.Head(), now-10))
	if h.auth.Freshness(twice, now, testTTL).Fresh(now) {
		t.Fatal("one admin device counted twice")
	}
	both := []types.Lease{h.lease(a.Identity, h.auth.Head(), now), h.lease(b.Identity, h.auth.Head(), now-100)}
	f = h.auth.Freshness(both, now, testTTL)
	if !f.Fresh(now) || f.Since != now-100 {
		t.Fatalf("two admin devices: %+v", f)
	}
}

func TestAVouchingThresholdIsBoundedByTheAdminDevices(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.addNode("admin-a")
	h.grantAdmin(a.Identity)
	if err := h.setVouchers(2); err == nil || !strings.Contains(err.Error(), "cannot meet") {
		t.Fatalf("a threshold above the admin devices: %v", err)
	}
	if err := h.setVouchers(1); err != nil {
		t.Fatal(err)
	}
}

// A schema-0 network has no vouching threshold: the record is refused until
// the network is raised to the schema that defines it.
func TestSetVouchersNeedsItsSchema(t *testing.T) {
	h := newHarnessAt(t, 1, 1, 0)
	a := h.addNode("admin-a")
	h.grantAdmin(a.Identity)
	aum, err := h.auth.Builder().SetVouchers(1)
	if err == nil {
		h.signQuorum(&aum)
		err = h.auth.Inform(aum)
	}
	if err == nil || !strings.Contains(err.Error(), "needs schema 1") {
		t.Fatalf("SetVouchers at schema 0: %v", err)
	}
}

// Vouching counts only admin devices whose lease is within the TTL: one
// that vouched days ago is not vouching now.
func TestAnExpiredLeaseIsNotVouching(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.addNode("admin-a"), h.addNode("admin-b")
	h.grantAdmin(a.Identity)
	h.grantAdmin(b.Identity)
	const now = 5_000_000
	leases := []types.Lease{h.lease(a.Identity, h.auth.Head(), now), h.lease(b.Identity, h.auth.Head(), now-testTTL)}
	if f := h.auth.Freshness(leases, now, testTTL); f.Vouching != 1 {
		t.Fatalf("%d vouching, with one lease past the TTL", f.Vouching)
	}
}

// A genesis cannot ask more admin devices to vouch than it names.
func TestAGenesisThresholdIsBoundedByItsAdminDevices(t *testing.T) {
	h := newHarness(t, 1, 1)
	genesis, err := Genesis("net", 1, h.adminKeys(), h.commitments(), []types.NodeRecord{h.newNode("a")}, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	genesis.State.Vouchers = 1
	if err := genesis.State.StaticValidate(true); err == nil || !strings.Contains(err.Error(), "cannot meet") {
		t.Fatalf("a genesis threshold with no admin devices: %v", err)
	}
	genesis.State.Nodes[0].Roles = []types.Role{types.RoleAdmin}
	if err := genesis.State.StaticValidate(true); err != nil {
		t.Fatal(err)
	}
}
