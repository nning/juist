package pairkey

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/trust/secrets"
)

// The exchange runs as models/log/PairKey.tla says: every trace the model
// generates, replayed against two Stores, leaves each side on the
// generation the model's is on, and the two on one key exactly where the
// model's are.
func TestTheCodeFollowsThePairKeyModel(t *testing.T) {
	files, err := filepath.Glob("../../models/log/traces/PairKey*.tla.gz")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no pair key traces; make model-traces writes them")
	}
	// The traces must reach a pair key in use and a probe, or the replay
	// passes with the exchange broken.
	var inUse, probed atomic.Int32
	t.Cleanup(func() {
		if inUse.Load() == 0 || probed.Load() == 0 {
			t.Errorf("of the traces, %d reach a pair key in use and %d a probe; make model-traces writes them",
				inUse.Load(), probed.Load())
		}
	})
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".tla.gz"), func(t *testing.T) {
			t.Parallel()
			states, err := modelspec.ReadTrace(f)
			if err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(states, func(st map[string]any) bool { return num(rec(st["L"], "cur"), "n") > 0 }) {
				inUse.Add(1)
			}
			if slices.ContainsFunc(states, func(st map[string]any) bool { return st[modelspec.Action] == "DoProbe" }) {
				probed.Add(1)
			}
			replayPairKey(t, states)
		})
	}
}

func num(v any, name string) int64 { return v.(map[string]any)[name].(int64) }
func rec(v any, name string) any   { return v.(map[string]any)[name] }

// pairReplay is the two sides, the model's store IDs by the code's, what
// each side believes the other's store is, and the messages sent.
type pairReplay struct {
	t     *testing.T
	l, f  *member
	ids   map[int64]uint64
	viewL uint64
	viewF uint64
	sent  map[string]Msg
	kept  []byte
	step  int
}

func (r *pairReplay) now() time.Time {
	return time.Unix(1_700_000_000, 0).Add(time.Duration(r.step) * time.Minute)
}

func (r *pairReplay) envL(epoch uint64) *Env {
	e := r.l.env(r.f)
	e.PeerStore, e.Epoch, e.Now = r.viewL, epoch, r.now()
	return e
}

func (r *pairReplay) envF(epoch uint64) *Env {
	e := r.f.env(r.l)
	e.PeerStore, e.Epoch, e.Now = r.viewF, epoch, r.now()
	return e
}

func replayPairKey(t *testing.T, states []map[string]any) {
	group, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	l, f := pair(t, group, 1, 2, 3)
	r := &pairReplay{t: t, l: l, f: f, sent: map[string]Msg{},
		ids: map[int64]uint64{num(states[0]["L"], "store"): l.store.ID(), num(states[0]["F"], "store"): f.store.ID()}}
	r.viewL, r.viewF = f.store.ID(), l.store.ID()
	if r.kept, err = f.store.Encode(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(states); i++ {
		r.step = i
		prev, st := states[i-1], states[i]
		if err := r.apply(prev, st); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if err := r.check(st); err != nil {
			t.Fatalf("after step %d: %v", i, err)
		}
	}
}

func key(m any) string { return fmt.Sprint(m) }

// apply takes the step from prev to st, the action st names, into the code.
func (r *pairReplay) apply(prev, st map[string]any) error {
	epoch := uint64(st["epoch"].(int64))
	switch act := st[modelspec.Action].(string); act {
	case "DoSendL", "DoSendF":
		side, env := r.l, r.envL(epoch)
		if act == "DoSendF" {
			side, env = r.f, r.envF(epoch)
		}
		msg := side.store.Outgoing(env)
		if err := msg.Sign(side.priv, network); err != nil {
			return err
		}
		for _, m := range st["net"].([]any) {
			if rec(m, "from") == map[string]string{"DoSendL": "L", "DoSendF": "F"}[act] {
				if _, ok := r.sent[key(m)]; !ok {
					r.sent[key(m)] = msg
				}
			}
		}
	case "DoTakeL", "DoTakeF":
		msg, ok := r.sent[key(st["took"])]
		if !ok {
			return fmt.Errorf("a message the code never sent: %v", st["took"])
		}
		side, from, env := r.l, r.f, r.envL(epoch)
		if act == "DoTakeF" {
			side, from, env = r.f, r.l, r.envF(epoch)
		}
		if err := msg.Verify(network, new(from.priv.SigningKey())); err != nil {
			return err
		}
		_, err := side.store.Take(env, &msg)
		return err
	case "DoAdvance":
		changed, err := r.l.store.Advance(r.envL(epoch))
		if err == nil && !changed {
			err = fmt.Errorf("the leader started no generation")
		}
		return err
	case "DoProbe":
		if !r.l.store.Probe(r.envL(epoch)) {
			return fmt.Errorf("the leader would not probe")
		}
	case "DoResetL", "DoResetF":
		side, name := r.l, "L"
		if act == "DoResetF" {
			side, name = r.f, "F"
		}
		if !side.store.Reset() {
			return fmt.Errorf("%s's store kept nothing to give up", name)
		}
		r.ids[num(st[name], "store")] = side.store.ID()
	case "DoAnnounceToL":
		r.viewL = r.ids[num(st["L"], "peer")]
	case "DoAnnounceToF":
		r.viewF = r.ids[num(st["F"], "peer")]
	case "DoKeepF":
		b, err := r.f.store.Encode()
		r.kept = b
		return err
	case "DoRestoreF":
		// What was kept names the leader's store as the follower knew it then.
		r.viewF = r.ids[num(st["F"], "peer")]
		return r.f.store.Restore(r.kept)
	case "DoBump":
	default:
		return fmt.Errorf("an action the replay does not know: %q", act)
	}
	return nil
}

// check holds the two sides to the model's: the generation each uses, and
// whether they use one key.
func (r *pairReplay) check(st map[string]any) error {
	epoch := uint64(st["epoch"].(int64))
	L, F := st["L"], st["F"]
	genL := num(rec(L, "cur"), "n")
	if next := rec(L, "next"); num(next, "n") != 0 && !rec(L, "flip").(bool) {
		genL = num(next, "n")
	}
	genF := num(rec(F, "cur"), "n")
	if got := r.l.store.Generation(r.envL(epoch)); got != uint64(genL) {
		return fmt.Errorf("the leader uses generation %d, the model's %d", got, genL)
	}
	if got := r.f.store.Generation(r.envF(epoch)); got != uint64(genF) {
		return fmt.Errorf("the follower uses generation %d, the model's %d", got, genF)
	}
	gen := func(g *Gen) int64 {
		if g == nil {
			return 0
		}
		return int64(g.N)
	}
	r.l.store.mu.Lock()
	pl := *r.l.store.pair(r.envL(epoch), false)
	r.l.store.mu.Unlock()
	r.f.store.mu.Lock()
	pf := *r.f.store.pair(r.envF(epoch), false)
	r.f.store.mu.Unlock()
	pend := int64(0)
	if pl.Pend != nil {
		pend = int64(pl.Pend.N)
	}
	for _, c := range []struct {
		what       string
		code, want any
	}{
		{"leader's generation in use", int64(pl.Cur.N), num(rec(L, "cur"), "n")},
		{"leader's committed generation", gen(pl.Next), num(rec(L, "next"), "n")},
		{"leader's offered generation", pend, num(rec(L, "pend"), "n")},
		{"leader's probe", pl.Flip, rec(L, "flip")},
		{"follower's generation in use", int64(pf.Cur.N), num(rec(F, "cur"), "n")},
		{"follower's answered generation", gen(pf.Offered), num(rec(F, "offered"), "n")},
	} {
		if fmt.Sprint(c.code) != fmt.Sprint(c.want) {
			return fmt.Errorf("the %s is %v, the model's %v", c.what, c.code, c.want)
		}
	}
	kl, _ := r.l.store.Key(r.envL(epoch))
	kf, _ := r.f.store.Key(r.envF(epoch))
	keyL := rec(L, "cur")
	if next := rec(L, "next"); num(next, "n") != 0 && !rec(L, "flip").(bool) {
		keyL = next
	}
	same := key(keyL) == key(rec(F, "cur"))
	if num(keyL, "n") == 0 && num(rec(F, "cur"), "n") == 0 {
		same = true // both on the group key of the epoch
	}
	if (kl == kf) != same {
		return fmt.Errorf("the code's two keys agree: %v, the model's: %v", kl == kf, same)
	}
	return nil
}
