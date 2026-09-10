package daemon

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// device is one member's key material: everything a daemon needs to be that
// member, plus the record the log carries about it.
type device struct {
	identity  types.PrivateIdentity
	recipient *secrets.PrivateKeys
	wgPrivate [32]byte
	record    types.NodeRecord
}

func newDevice(t *testing.T, name string, v4 netip.Addr) *device {
	t.Helper()
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	recipient, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatalf("generating recipient keys: %v", err)
	}
	x, m, err := recipient.Public()
	if err != nil {
		t.Fatal(err)
	}
	d := &device{identity: id, recipient: recipient}
	// For a peer set that is only ever compared, raw bytes are as good as a
	// derived public half; tests that bring tunnels up use conn's generator.
	priv, pub, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	d.wgPrivate = priv
	d.record = types.NodeRecord{
		Identity:  id.Public(),
		Name:      name,
		WireGuard: types.WGKey(pub),
		X25519:    x,
		MLKEM:     m,
	}
	if v4.IsValid() {
		d.record.V4 = &v4
	}
	return d
}

// network is a genesis ceremony plus the admin key that can change it.
type network struct {
	t       *testing.T
	admin   types.PrivateIdentity
	genesis types.AUM
	devices []*device

	// secretsByEpoch records what each epoch's group secret is, so a test
	// can check that a node opened the right one.
	mu            sync.Mutex
	secretByEpoch map[uint64]secrets.Secret
}

// newNetwork founds a one-admin network with n founding members. A quorum of
// one is not realistic policy but is the right one here: these tests are about
// the mesh, and trust/log's own cover k-of-n ceremonies.
func newNetwork(t *testing.T, n int) *network {
	t.Helper()
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nw := &network{t: t, admin: admin, secretByEpoch: map[uint64]secrets.Secret{}}
	for i := range n {
		v4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
		nw.devices = append(nw.devices, newDevice(t, fmt.Sprintf("n%d", i), v4))
	}
	disablement := make([]byte, types.DisablementSecretSize)
	if _, err := rand.Read(disablement); err != nil {
		t.Fatal(err)
	}
	records := make([]types.NodeRecord, 0, n)
	for _, d := range nw.devices {
		records = append(records, d.record)
	}
	g, err := log.Genesis("m2-testnet", 1,
		[]types.AdminKey{{Public: admin.Public(), Votes: 1, Name: "admin"}},
		[]types.Hash{types.DisablementCommit(disablement)},
		records, nw.sealer())
	if err != nil {
		t.Fatalf("building genesis: %v", err)
	}
	if err := g.Sign(admin); err != nil {
		t.Fatalf("signing genesis: %v", err)
	}
	nw.genesis = g
	return nw
}

// sealer draws a fresh secret per epoch and remembers it.
func (nw *network) sealer() log.Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		secret, rec, err := secrets.NewEpoch(epoch, members)
		if err != nil {
			return nil, err
		}
		nw.mu.Lock()
		nw.secretByEpoch[epoch] = secret
		nw.mu.Unlock()
		return rec, nil
	}
}

// authorityFor gives a device its own independently verified copy of the log:
// the genesis record, plus any later records it is handed at enrollment.
func (nw *network) authorityFor(t *testing.T, extra ...types.AUM) (*log.Authority, log.Storage) {
	t.Helper()
	st := log.NewMemStorage()
	auth, err := log.Create(st, nw.genesis)
	if err != nil {
		t.Fatalf("creating a node's log: %v", err)
	}
	if len(extra) > 0 {
		if err := auth.Inform(extra...); err != nil {
			t.Fatalf("seeding a node's log: %v", err)
		}
	}
	return auth, st
}

// endpointFor builds a signed announcement for a device, the way its own
// daemon would.
func endpointFor(d *device, port uint16) (gossip.Endpoint, error) {
	_, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		return gossip.Endpoint{}, err
	}
	e := gossip.Endpoint{
		Identity:   d.record.Identity,
		Disco:      gossip.DiscoKey(discoPub),
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.50:41641")},
		GossipPort: port,
		Seq:        1,
	}
	return e, e.Sign(d.identity)
}

// removeNode builds and signs a record revoking a member, against the state
// the given authority holds. It is the admin's half of a revocation; getting
// it to the network is the daemon's.
func (nw *network) removeNode(t *testing.T, auth *log.Authority, id types.Identity) types.AUM {
	t.Helper()
	rec, err := auth.Builder().RemoveNode(id, nw.sealer())
	if err != nil {
		t.Fatalf("building the removal: %v", err)
	}
	if err := rec.Sign(nw.admin); err != nil {
		t.Fatalf("signing the removal: %v", err)
	}
	return rec
}

// safeLogf forwards to t.Logf until the test is torn down and drops everything
// afterwards: the embedded engine's goroutines outlive Close by a few
// milliseconds and log as they wind down, which would panic the testing
// package. The silencing cleanup is registered first, so it runs last.
func safeLogf(t *testing.T, prefix string) func(string, ...any) {
	var (
		mu   sync.Mutex
		done bool
	)
	t.Cleanup(func() {
		mu.Lock()
		done = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		t.Logf(prefix+format, args...)
	}
}

// --- a connectivity layer that records rather than connects ----------------

// fakeManager stands in for the data plane where a test is about what the
// reconciler decides rather than about packets moving. It records every peer
// set it is given, which is the whole of the reconciler's output.
type fakeManager struct {
	mu       sync.Mutex
	peers    []conn.Peer
	relays   []conn.Relay
	relaySet int
	sets     int
	closed   bool
	err      error // returned by SetPeers, to exercise the failure path
	relayErr error // returned by SetRelays

	home int
	eps  []netip.AddrPort
}

var _ conn.Manager = (*fakeManager)(nil)

func (m *fakeManager) SetPeers(peers []conn.Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.peers = append([]conn.Peer(nil), peers...)
	m.sets++
	return nil
}

func (m *fakeManager) SetRelays(relays []conn.Relay) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relayErr != nil {
		return m.relayErr
	}
	m.relays = append([]conn.Relay(nil), relays...)
	m.relaySet++
	return nil
}

func (m *fakeManager) HomeRelay() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.home
}

func (m *fakeManager) LocalEndpoints() []netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]netip.AddrPort(nil), m.eps...)
}

func (m *fakeManager) LocalPort() uint16 { return 41641 }

func (m *fakeManager) Ping(netip.Addr, func(conn.PingResult)) {}

func (m *fakeManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *fakeManager) relaySnapshot() []conn.Relay {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]conn.Relay(nil), m.relays...)
}

func (m *fakeManager) snapshot() []conn.Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]conn.Peer(nil), m.peers...)
}

func (m *fakeManager) has(nodeKey [32]byte) bool {
	want := conn.NodePublicFromRaw32(nodeKey)
	for _, p := range m.snapshot() {
		if p.NodeKey == want {
			return true
		}
	}
	return false
}
