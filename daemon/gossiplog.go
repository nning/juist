package daemon

import (
	"errors"
	"slices"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// logAdapter presents the authority and its store as a [gossip.Log]. A
// distinct type over the same struct, so gossip can reach those three methods
// and nothing else.
type logAdapter Daemon

var _ gossip.Log = (*logAdapter)(nil)

func (a *logAdapter) daemon() *Daemon { return (*Daemon)(a) }

func (a *logAdapter) View() (gossip.View, error) {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	state := d.authority.State()
	have, err := d.storage.Hashes()
	if err != nil {
		return gossip.View{}, err
	}
	return gossip.View{
		Network: state.GenesisHash(),
		Head:    state.Head(),
		Epoch:   state.Epoch(),
		Anchor:  d.authority.Anchor(),
		Have:    have,
	}, nil
}

// Missing returns records the peer lacks and can accept, parents first. The
// walk starts at the *peer's* anchor: after a compaction a record below it is
// one the peer's log refuses, and Inform is atomic, so one refused record
// poisons the whole batch. Children are visited in hash order, so two nodes
// holding the same store offer the same batch; losing fork branches are
// included, since a peer must see a fork in full to alarm on it.
func (a *logAdapter) Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error) {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if _, err := d.storage.AUM(anchor); err != nil {
		if errors.Is(err, log.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	held := make(map[types.Hash]bool, len(have))
	for _, h := range have {
		held[h] = true
	}
	out := make([]types.AUM, 0, gossip.MaxRecordsPerFrame)
	// First, and whatever the peer's anchor: it may hang where no walk from
	// there reaches, and the peer takes it in wherever it hangs.
	if dis := d.authority.Disabled(); dis != nil && !held[dis.At] {
		aum, err := d.storage.AUM(dis.At)
		if err != nil {
			return nil, err
		}
		out = append(out, aum)
		held[dis.At] = true
	}
	queue := []types.Hash{anchor}
	visited := map[types.Hash]bool{anchor: true}
	for len(queue) > 0 && len(out) < gossip.MaxRecordsPerFrame {
		h := queue[0]
		queue = queue[1:]
		if !held[h] {
			aum, err := d.storage.AUM(h)
			if err != nil {
				return nil, err
			}
			out = append(out, aum)
		}
		children, err := d.storage.Children(h)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(children, types.Hash.Compare)
		for _, ch := range children {
			if !visited[ch] {
				visited[ch] = true
				queue = append(queue, ch)
			}
		}
	}
	return out, nil
}

// Member grants a catch-up to a live member of the trusted state. A node
// under an alarm, or no longer a member itself, answers none: it cannot say
// who is listed. A disabled one still does, so the record reaches them.
func (a *logAdapter) Member(id types.Identity) (types.NodeRecord, bool, error) {
	d := a.daemon()
	state, err := d.gossipState()
	if err != nil {
		return types.NodeRecord{}, false, err
	}
	now := d.now().Unix()
	if self, ok := state.Node(d.self); !ok || self.Expired(now) {
		return types.NodeRecord{}, false, errors.New("this device is no longer a member")
	}
	n, ok := state.Node(id)
	if !ok || n.Expired(now) || id == d.self {
		return types.NodeRecord{}, false, nil
	}
	return n, true, nil
}

func (a *logAdapter) Inform(records []types.AUM) error {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authority.Inform(records...)
}
