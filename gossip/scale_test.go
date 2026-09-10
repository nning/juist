package gossip

import (
	"context"
	"testing"
	"time"

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
	a := newTestNode(t, network, 1, s)
	b := newTestNode(t, network, 1, s)

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
