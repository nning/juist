package pairkey

import (
	"bytes"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// FuzzTake drives each side of a pair with what a peer may sign: any
// message at all. Whatever it says, nothing panics and the pair is given a
// key that is not none.
func FuzzTake(f *testing.F) {
	group, _ := secrets.NewSecret()
	l, fo := newFuzzPair(f, group)
	exchangeF(f, l, fo)
	for _, m := range []Msg{l.store.Outgoing(l.env(fo)), fo.store.Outgoing(fo.env(l))} {
		b, err := encMode.Marshal(&m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, false)
		f.Add(b, true)
	}
	dec, err := types.StrictDecOptions(4, 16, 16).DecMode()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte, toLeader bool) {
		var m Msg
		if err := dec.Unmarshal(data, &m); err != nil || m.StaticValidate() != nil {
			return
		}
		l, fo := newFuzzPair(t, group)
		self, from := fo, l
		if toLeader {
			self, from = l, fo
		}
		m.From, m.To, m.Store, m.ToStore = from.side.ID, self.side.ID, from.store.ID(), self.store.ID()
		m.FromWG, m.ToWG = from.side.WG, self.side.WG
		for range 2 {
			_, _ = self.store.Take(self.env(from), &m)
			if k, s := self.key(from); k.IsZero() || s < StageGroup {
				t.Fatalf("a message left the pair with %v", s)
			}
		}
	})
}

// FuzzDecodeStore reads the store file: whatever it holds, a store that
// decodes encodes again to what was read.
func FuzzDecodeStore(f *testing.F) {
	group, _ := secrets.NewSecret()
	l, fo := newFuzzPair(f, group)
	exchangeF(f, l, fo)
	for _, s := range []*Store{l.store, fo.store} {
		b, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeStore(data)
		if err != nil {
			return
		}
		b, err := s.Encode()
		if err != nil {
			t.Fatalf("a store that decoded does not encode: %v", err)
		}
		again, err := DecodeStore(b)
		if err != nil {
			t.Fatalf("a store encoded does not decode: %v", err)
		}
		b2, _ := again.Encode()
		if !bytes.Equal(b, b2) {
			t.Fatal("a store does not encode alike twice")
		}
	})
}

func newFuzzPair(t testing.TB, group secrets.Secret) (leader, follower *member) {
	t.Helper()
	a, b := newMember(t, group, 1), newMember(t, group, 1)
	if Leads(b.side.WG, a.side.WG) {
		a, b = b, a
	}
	return a, b
}

func exchangeF(t testing.TB, l, f *member) {
	t.Helper()
	if _, err := l.store.Advance(l.env(f)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		m := l.store.Outgoing(l.env(f))
		if _, err := f.store.Take(f.env(l), &m); err != nil {
			t.Fatal(err)
		}
		m = f.store.Outgoing(f.env(l))
		if _, err := l.store.Take(l.env(f), &m); err != nil {
			t.Fatal(err)
		}
	}
}
