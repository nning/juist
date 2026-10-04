package dht

import (
	"context"
	"errors"
	"sync"

	anacrolix "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/bep44"
	k_nearest_nodes "github.com/anacrolix/dht/v2/k-nearest-nodes"
	"github.com/anacrolix/dht/v2/krpc"
	"github.com/anacrolix/dht/v2/traversal"
	"github.com/anacrolix/torrent/bencode"
)

// The library's exts/getput dereferences a reply's seq unchecked, in a
// goroutine without recover: one hostile storage node ends the process. These
// replace it for mutable items without salt, which is all this package stores.

// item is a mutable item a storage node holds, verified against its key.
type item struct {
	seq int64
	v   bencode.Bytes
}

// startGet traverses towards target, sending on the channel every item a node
// returns that k signed. The closest nodes carry their put token as data.
func startGet(s *anacrolix.Server, k [32]byte, target bep44.Target) (<-chan item, *traversal.Operation) {
	items := make(chan item)
	op := traversal.Start(traversal.OperationInput{
		Alpha:  15,
		Target: target,
		DoQuery: func(ctx context.Context, addr krpc.NodeAddr) traversal.QueryResult {
			res := s.Get(ctx, anacrolix.NewAddr(addr.UDP()), target, nil, anacrolix.QueryRateLimiting{})
			if r := res.Reply.R; r != nil && r.K == k && r.Seq != nil &&
				bep44.Verify(k[:], nil, *r.Seq, r.V, r.Sig[:]) {
				select {
				case items <- item{seq: *r.Seq, v: r.V}:
				case <-ctx.Done():
				}
			}
			return res.TraversalQueryResult(addr)
		},
		NodeFilter: s.TraversalNodeFilter,
		DataFilter: func(data any) bool {
			_, ok := data.(string)
			return ok
		},
	})
	nodes, _ := s.TraversalStartingNodes()
	op.AddNodes(nodes)
	return items, op
}

// get returns the item with the highest seq that k signed at target.
func get(ctx context.Context, s *anacrolix.Server, k [32]byte, target bep44.Target) (item, error) {
	items, op := startGet(s, k, target)
	defer op.Stop()
	var best item
	found := false
	for {
		select {
		case it := <-items:
			if !found || it.seq >= best.seq {
				best, found = it, true
			}
		case <-op.Stalled():
			if !found {
				return item{}, errors.New("value not found")
			}
			return best, nil
		case <-ctx.Done():
			return item{}, ctx.Err()
		}
	}
}

// put stores the item build makes, given the highest seq found, at the nodes
// closest to target.
func put(ctx context.Context, s *anacrolix.Server, k [32]byte, target bep44.Target, build func(seq int64) bep44.Put) error {
	items, op := startGet(s, k, target)
	var seq int64
	var err error
traverse:
	for {
		select {
		case it := <-items:
			seq = max(seq, it.seq)
		case <-op.Stalled():
			break traverse
		case <-ctx.Done():
			err = ctx.Err()
			break traverse
		}
	}
	op.Stop()
	p := build(seq)
	var wg sync.WaitGroup
	op.Closest().Range(func(e k_nearest_nodes.Elem) {
		token, ok := e.Data.(string)
		if !ok {
			return
		}
		wg.Go(func() {
			s.Put(ctx, anacrolix.NewAddr(e.Addr.UDP()), p, token, anacrolix.QueryRateLimiting{})
		})
	})
	wg.Wait()
	return err
}
