package gossip

import (
	"context"
	"crypto/mlkem"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/internal/pairkey"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// bigEpochRecord is a record of the size an epoch bump reaches at
// [types.MaxNodes] members: ~600 KiB, which docs/08-trust-layer-notes.md
// measures and accepts. Nothing here verifies it, so the wraps are filler.
func bigEpochRecord(t *testing.T, signer types.PrivateIdentity, epoch uint64) types.AUM {
	t.Helper()
	prev := types.Hash{byte(epoch)}
	rec := &types.EpochRecord{Epoch: epoch, Commit: types.Hash{1}}
	for i := range types.MaxNodes {
		var id types.Identity
		id[0], id[1], id[31] = byte(i/256), byte(i%256), 1
		rec.Wraps = append(rec.Wraps, types.EpochWrap{
			Recipient: id, Sealed: make([]byte, types.SealedSecretSize),
		})
	}
	aum := types.AUM{Kind: types.KindEpochBump, Prev: &prev, Epoch: rec}
	if err := aum.Sign(signer); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return aum
}

// TestRecordsBatchIsBoundedByBytes covers the failure a large network reaches
// without a byte budget: [MaxRecordsPerFrame] records of the size a
// [types.MaxNodes] epoch bump reaches are far over [MaxFrameSize], so the
// frame would not encode — every round, identically, wedging that pair's sync
// for good rather than converging over more rounds.
func TestRecordsBatchIsBoundedByBytes(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatalf("drawing a secret: %v", err)
	}
	network := types.Hash{7}
	// A frame's worth of records takes long where the CPU is emulated.
	a := newTestNodeTimeout(t, network, 1, s, 30*time.Second)
	b := newTestNodeTimeout(t, network, 1, s, 30*time.Second)

	signer, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating a signer: %v", err)
	}
	// Enough to overflow a frame, and well under [MaxRecordsPerFrame], so
	// what stops the batch is the byte budget and not the count cap.
	big := make([]types.AUM, 20)
	for i := range big {
		big[i] = bigEpochRecord(t, signer, uint64(i+2))
	}
	one, err := big[0].Encode()
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if total := len(one) * len(big); total <= MaxFrameSize {
		t.Fatalf("the batch is %d bytes, which fits in a frame; this test would prove nothing", total)
	}
	b.log.missing = func([]types.Hash, types.Hash) ([]types.AUM, error) { return big, nil }

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.node.SyncWith(ctx, b.addr(), b.id); err != nil {
		t.Fatalf("sync: %v", err)
	}

	a.log.mu.Lock()
	defer a.log.mu.Unlock()
	if len(a.log.informed) == 0 {
		t.Fatal("nothing reached the peer; the oversized batch was not truncated")
	}
	got := a.log.informed[0]
	if len(got) == 0 {
		t.Fatal("an empty batch was applied")
	}
	if len(got) >= len(big) {
		t.Errorf("the whole %d-record batch was sent; it must be cut to the byte budget", len(big))
	}
	if want := maxRecordBytesPerFrame / len(one); len(got) < want/2 {
		t.Errorf("only %d records were sent; the budget has room for about %d", len(got), want)
	}
}

// TestUndecodableTailStillDeliversItsPrefix: after a schema upgrade a peer
// offers records this build cannot read, and the record that explains why is
// the one immediately before them. Refusing the batch whole would discard that
// explanation too, leaving a node that saw only sync going quiet.
func TestUndecodableTailStillDeliversItsPrefix(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatalf("drawing a secret: %v", err)
	}
	n := newTestNode(t, types.Hash{5}, 1, s)

	signer, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating a signer: %v", err)
	}
	prev := types.Hash{1}
	v := types.CurrentSchema + 1
	upgrade := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &v}
	if err := upgrade.Sign(signer); err != nil {
		t.Fatalf("signing: %v", err)
	}
	good, err := upgrade.Encode()
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	// A record of a kind nothing in this tree defines: what a newer schema's
	// records look like from here. The kind is the first pair of the map, so
	// its value is the third byte.
	if good[1] != 0x01 || good[2] != byte(types.KindSchemaUpgrade) {
		t.Fatalf("a record does not begin with its kind: % x", good[:4])
	}
	future := append([]byte(nil), good...)
	future[2] = byte(types.KindSchemaUpgrade) + 1
	if _, err := types.DecodeAUM(future); err == nil {
		t.Fatal("the record built to be unreadable decoded")
	}

	applied, err := n.node.apply([][]byte{good, future})
	if !applied {
		t.Fatalf("nothing was applied; the record explaining the rest never landed (err %v)", err)
	}
	if err == nil {
		t.Error("the unreadable tail was not reported")
	}
	n.log.mu.Lock()
	defer n.log.mu.Unlock()
	if len(n.log.informed) != 1 || len(n.log.informed[0]) != 1 ||
		n.log.informed[0][0].Kind != types.KindSchemaUpgrade {
		t.Fatalf("applied %v; want just the schema upgrade", n.log.informed)
	}
}

// largestEndpoint is an announcement with every field at its cap, signed by
// both keys as past the cut-over.
func largestEndpoint(t *testing.T, priv types.PrivateIdentity) Endpoint {
	t.Helper()
	label := strings.Repeat("a", 63)
	e := Endpoint{
		Identity: priv.Public(), Disco: DiscoKey{1}, GossipPort: 65535, Seq: 1 << 62,
		Relay: &RelayInfo{Port: 65535, STUNPort: 65535, Cert: make([]byte, RelayCertSize),
			HostName: strings.Repeat("a", MaxRelayHostNameLen), Name: label + "." + label + "." + label + "." + label[:61]},
		HomeRelay: 65535, Exit: true, Subnets: true, DNS: 65535, NoV4: true, Published: true,
		Share: &Share{Port: 65535, Until: 1 << 62}, Epoch: 1 << 62, PairStore: 1 << 62, Schema: types.CurrentSchema,
		Sealed: make([]byte, addrkey.MaxSealedSize),
	}
	if err := e.SignPQ(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

func mustEncode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every frame at its caps, past the cut-over, encodes within [MaxFrameSize]:
// a frame over it fails to encode in every round, and wedges the pair's
// sync for good. Exit criterion (5) for frames.
func TestFramesAtTheirCapsFit(t *testing.T) {
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ep := largestEndpoint(t, priv)
	claiming := ep
	if claiming.Signing, err = ClaimSigningKey(priv); err != nil {
		t.Fatal(err)
	}
	if claiming.StaticValidate() == nil {
		t.Fatal("an announcement claiming its signing key and signed by it validated")
	}
	if claiming.MLDSA = nil; len(mustEncode(t, &claiming)) > len(mustEncode(t, &ep)) {
		t.Fatal("an announcement claiming its signing key is the larger; the frames below are not at their caps")
	}
	eps := make([]Endpoint, MaxEndpointsPerFrame)
	for i := range eps {
		eps[i] = ep
	}
	lease := types.Lease{Network: types.Hash{1}, Head: types.Hash{2}, Issued: 1 << 62}
	if err := lease.Sign(priv, true); err != nil {
		t.Fatal(err)
	}
	lb, err := lease.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(lb) > types.MaxLeaseSize {
		t.Fatalf("a lease signed by ML-DSA is %d bytes, over the %d limit", len(lb), types.MaxLeaseSize)
	}
	peer, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pair := &pairkey.Msg{From: priv.Public(), To: peer.Public(), Store: 1 << 62, ToStore: 1 << 62, Gen: 1 << 62,
		Epoch: 1 << 62, Use: 1 << 62, CT: make([]byte, mlkem.CiphertextSize768), Check: make([]byte, 16),
		FromWG: types.WGKey{1}, ToWG: types.WGKey{2}}
	if err := pair.Sign(priv, types.Hash{1}, true); err != nil {
		t.Fatal(err)
	}

	hello := frame{Kind: kindHello, Network: types.Hash{1}, Epoch: 1 << 62, Head: types.Hash{1}, Anchor: types.Hash{1},
		Self: &ep, Endpoints: eps, Pair: pair, Waiting: make([]byte, MaxWaitingPerFrame*40+64)}
	for i := range MaxHashesPerFrame {
		hello.Have = append(hello.Have, types.Hash{byte(i), byte(i >> 8), 1})
	}
	wraps := maxKeyBytesPerFrame / addrkey.WrapSize / MaxEndpointsPerFrame
	for i := range MaxEndpointsPerFrame {
		k := AddrKey{Owner: priv.Public(), Seq: uint64(i)}
		for range wraps {
			k.Wraps = append(k.Wraps, make([]byte, addrkey.WrapSize))
		}
		if err := k.SignPQ(priv); err != nil {
			t.Fatal(err)
		}
		hello.Keys = append(hello.Keys, k)
	}

	records := frame{Kind: kindRecords, Network: types.Hash{1}, Epoch: 1 << 62, Head: types.Hash{1},
		Anchor: types.Hash{1}, Self: &ep, Endpoints: eps, Pair: pair}
	for range MaxLeasesPerFrame {
		records.Leases = append(records.Leases, lb)
	}
	// Records and waiting changes fill their budget whole.
	records.Records = [][]byte{make([]byte, maxRecordBytesPerFrame-recordBytes(&records)-1024)}
	records.Waiting = make([]byte, 1024)

	for _, f := range []*frame{&hello, &records} {
		b, err := encode(f)
		if err != nil {
			t.Fatalf("a %v frame at its caps: %v", f.Kind, err)
		}
		t.Logf("a %v frame at its caps: %.2f MiB of %d", f.Kind, float64(len(b))/(1<<20), MaxFrameSize>>20)
	}
}
