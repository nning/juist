package gossip

import (
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Waiting is the store of changes waiting for votes, as gossip hands them
// between admin devices. They pass sealed to the device that receives them,
// so a peer claiming another's identity learns nothing from the answer.
type Waiting interface {
	// Held returns the hashes of the changes this node holds, to tell the
	// member peer, or none where the two exchange none.
	Held(peer types.Identity) []types.Hash

	// For returns the encoded changes to hand the member id, but those in
	// held, or none where it may not be handed any.
	For(id types.Identity, held []types.Hash) [][]byte

	// Take offers changes a peer handed over, reporting whether any was new.
	Take(changes [][]byte) bool

	// Handed says which of what For returned a session did hand to id.
	Handed(id types.Identity, changes [][]byte)
}

// claimed is the identity a peer's hello names by its announcement, where
// one verifies and is not this node's.
func (n *Node) claimed(peer *frame) (types.Identity, bool) {
	if peer.Self == nil || peer.Self.Identity == n.opts.Self || peer.Self.Verify() != nil {
		return types.Identity{}, false
	}
	return peer.Self.Identity, true
}

// sealWaiting seals p to the member id, or returns nil where the log lists
// no such member or there is nothing to seal.
func (n *Node) sealWaiting(network types.Hash, id types.Identity, p waitingPayload) []byte {
	if len(p.Held) == 0 && len(p.Changes) == 0 {
		return nil
	}
	rec, listed, err := n.opts.Log.Member(id)
	if err != nil || !listed {
		return nil
	}
	b, err := encode(&p)
	if err != nil {
		n.logf("gossip: encoding waiting changes for %v: %v", id.ShortString(), err)
		return nil
	}
	sealed, err := secrets.SealToPeer(network, &rec, b)
	if err != nil {
		n.logf("gossip: sealing waiting changes to %v: %v", id.ShortString(), err)
		return nil
	}
	return sealed
}

// openWaiting opens what a peer sealed to this node, or returns nothing.
func (n *Node) openWaiting(network types.Hash, sealed []byte) waitingPayload {
	if len(sealed) == 0 || n.opts.CatchUp == nil {
		return waitingPayload{}
	}
	b, err := secrets.OpenFromPeer(network, n.opts.Self, n.recipient.Load(), sealed)
	if err != nil {
		n.logf("gossip: waiting changes not sealed to this device: %v", err)
		return waitingPayload{}
	}
	p, err := types.DecodeCanonical[waitingPayload](decMode, b, MaxFrameSize)
	if err != nil || len(p.Held) > MaxWaitingPerFrame || len(p.Changes) > MaxWaitingPerFrame {
		n.logf("gossip: dropping malformed waiting changes")
		return waitingPayload{}
	}
	return p
}

// waitingSealOverhead bounds what sealing adds to a payload: the hybrid KEM's
// encapsulation, the tag and the payload's own framing. cborHeader bounds a
// byte string's.
const (
	waitingSealOverhead = 2048
	cborHeader          = 9
)

// heldFor is what this node's hello to the member id says it holds.
func (n *Node) heldFor(network types.Hash, id types.Identity) []byte {
	if n.opts.Waiting == nil || id.IsZero() {
		return nil
	}
	held := n.opts.Waiting.Held(id)
	if len(held) > MaxWaitingPerFrame {
		held = held[:MaxWaitingPerFrame]
	}
	return n.sealWaiting(network, id, waitingPayload{Held: held})
}

// waitingFor is what this node's records frame hands the peer whose hello
// it answers: the changes it may have and does not hold, within the frame's
// budget, sealed, and which they are.
func (n *Node) waitingFor(network types.Hash, peer *frame, budget int) ([]byte, [][]byte) {
	id, ok := n.claimed(peer)
	if n.opts.Waiting == nil || !ok {
		return nil, nil
	}
	var p waitingPayload
	budget -= waitingSealOverhead
	for _, c := range n.opts.Waiting.For(id, n.openWaiting(network, peer.Waiting).Held) {
		if len(p.Changes) == MaxWaitingPerFrame || len(c)+cborHeader > budget {
			break
		}
		budget -= len(c) + cborHeader
		p.Changes = append(p.Changes, c)
	}
	sealed := n.sealWaiting(network, id, p)
	if sealed == nil {
		return nil, nil
	}
	return sealed, p.Changes
}

// handed tells the store what a records frame, now written, handed over.
func (n *Node) handed(peer *frame, sent [][]byte) {
	if id, ok := n.claimed(peer); ok && len(sent) > 0 {
		n.opts.Waiting.Handed(id, sent)
	}
}

// takeWaiting offers the changes a records frame handed over, reporting
// whether any was new.
func (n *Node) takeWaiting(network types.Hash, theirs *frame) bool {
	if n.opts.Waiting == nil || len(theirs.Waiting) == 0 {
		return false
	}
	p := n.openWaiting(network, theirs.Waiting)
	return len(p.Changes) > 0 && n.opts.Waiting.Take(p.Changes)
}
