package daemon

import (
	"errors"
	"slices"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// logAdapter presents the authority and its store as a [gossip.Log]. A
// distinct type over the same struct, so gossip can reach those methods
// and nothing else.
type logAdapter Daemon

var _ gossip.Log = (*logAdapter)(nil)

func (a *logAdapter) daemon() *Daemon { return (*Daemon)(a) }

func (a *logAdapter) View() (gossip.View, error) {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	state := d.authority.State()
	have, err := d.haveLocked()
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

// haveLocked lists the records this node resolves from its anchor. Past what
// a hello carries, those nothing held hangs from come first, as a peer takes
// each as standing for its ancestors, and then the rest, deepest first. The
// caller holds authMu.
func (d *Daemon) haveLocked() ([]types.Hash, error) {
	held := d.authority.Held()
	if len(held) <= gossip.MaxHashesPerFrame {
		return held, nil
	}
	in := make(map[types.Hash]bool, len(held))
	for _, h := range held {
		in[h] = true
	}
	order, err := d.descendants(d.authority.Anchor(), in)
	if err != nil {
		return nil, err
	}
	depth := make(map[types.Hash]int, len(order))
	leaf := make(map[types.Hash]bool, len(held))
	for i, h := range order {
		depth[h] = i
	}
	for _, h := range held {
		children, err := d.storage.Children(h)
		if err != nil {
			return nil, err
		}
		leaf[h] = !slices.ContainsFunc(children, func(c types.Hash) bool { return in[c] })
	}
	slices.SortStableFunc(held, func(x, y types.Hash) int {
		if leaf[x] != leaf[y] {
			if leaf[x] {
				return -1
			}
			return 1
		}
		return depth[y] - depth[x]
	})
	return held, nil
}

// descendants returns root and what hangs from it within in, or from it at
// all where in is nil, parents first. The caller holds authMu.
func (d *Daemon) descendants(root types.Hash, in map[types.Hash]bool) ([]types.Hash, error) {
	order := []types.Hash{root}
	seen := map[types.Hash]bool{root: true}
	for i := 0; i < len(order); i++ {
		children, err := d.storage.Children(order[i])
		if err != nil {
			return nil, err
		}
		slices.SortFunc(children, types.Hash.Compare)
		for _, c := range children {
			if !seen[c] && (in == nil || in[c]) {
				seen[c] = true
				order = append(order, c)
			}
		}
	}
	return order, nil
}

// Missing returns records the peer lacks and can accept, parents first. The
// walk starts at the *peer's* anchor: after a compaction a record below it is
// one the peer's log refuses, and Inform is atomic, so one refused record
// poisons the whole batch. A peer anchored where this node holds nothing, below
// its own anchor, is walked from that. Children are visited in hash order, so two nodes
// holding the same store offer the same batch; losing fork branches are
// included, since a peer must see a fork in full to alarm on it.
func (a *logAdapter) Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error) {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	if _, err := d.storage.AUM(anchor); errors.Is(err, log.ErrNotFound) {
		// A peer anchored below this node's anchor, as one that has not
		// compacted yet, takes what hangs from it where it holds its parent.
		anchor = d.authority.Anchor()
	} else if err != nil {
		return nil, err
	}
	out := make([]types.AUM, 0, gossip.MaxRecordsPerFrame)
	queue := []types.Hash{anchor}
	// The anchor stands for its content; a build that predates the schema
	// refuses a copy of it, and with it the whole batch.
	if d.authority.State().Schema() >= types.SchemaContentForkChoice {
		copies, err := d.authority.Copies(anchor)
		if err != nil {
			return nil, err
		}
		queue = copies
	}
	held, err := d.heldBy(have, queue)
	if err != nil {
		return nil, err
	}
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
	visited := map[types.Hash]bool{}
	for _, h := range queue {
		visited[h] = true
	}
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

// heldBy returns what a peer listing have holds of the records hanging from
// roots: those and, where the list was cut short, their ancestors, which a
// peer holds with what it lists. A full list says it all: an older build
// lists a record stored without its parent. The caller holds authMu.
func (d *Daemon) heldBy(have []types.Hash, roots []types.Hash) (map[types.Hash]bool, error) {
	held := make(map[types.Hash]bool, len(have))
	for _, h := range have {
		held[h] = true
	}
	if len(have) < gossip.MaxHashesPerFrame {
		return held, nil
	}
	var order []types.Hash
	for _, r := range roots {
		o, err := d.descendants(r, nil)
		if err != nil {
			return nil, err
		}
		order = append(order, o...)
	}
	// Children before parents: a record is held where one hanging from it is.
	for i := len(order) - 1; i >= 0; i-- {
		h := order[i]
		children, err := d.storage.Children(h)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(children, func(c types.Hash) bool { return held[c] }) {
			held[h] = true
		}
	}
	return held, nil
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

func (a *logAdapter) SigningKey(id types.Identity) *types.SigningKey {
	state, err := a.daemon().gossipState()
	if err != nil {
		return nil
	}
	return state.SigningKey(id)
}

func (a *logAdapter) ListedSigningKey(id types.Identity) *types.SigningKey {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authority.ListedSigningKey(id)
}

func (a *logAdapter) Inform(records []types.AUM) error {
	d := a.daemon()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	news, err := d.authority.Learn(records...)
	d.noteBehind(records, news, err)
	if err == nil && !news {
		return gossip.ErrNothingNew
	}
	return err
}
