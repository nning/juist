package daemon

import (
	"testing"

	"github.com/nning/juist/types"
)

func TestRestartedRelayKeepsItsCertificate(t *testing.T) {
	home := t.TempDir()
	id := types.Identity{1}
	keys := types.NodeKeys{WireGuard: types.WGKey{2}}
	hash := func(id types.Identity, keys types.NodeKeys) [32]byte {
		t.Helper()
		s, err := NewStoredSession(home, id, keys)
		if err != nil {
			t.Fatal(err)
		}
		c, err := s.relayCertificate(t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		return c.Hash()
	}
	first := hash(id, keys)
	if again := hash(id, keys); again != first {
		t.Fatal("a restart on the same keys announced a new relay certificate")
	}
	rotated := keys
	rotated.WireGuard = types.WGKey{3}
	if hash(id, rotated) == first {
		t.Fatal("new device keys kept the old relay certificate")
	}
}

// A certificate drawn before the keys were rotated in place is no longer
// the session's: a relay starting on it gives way.
func TestARotationTakesTheRelaysCertificate(t *testing.T) {
	s, err := NewStoredSession(t.TempDir(), types.Identity{1}, types.NodeKeys{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.relayCertificate(t.Logf)
	if err != nil || !s.holds(c) {
		t.Fatalf("the certificate drawn is not held: %v", err)
	}
	s.rebind(types.Identity{1}, types.NodeKeys{WireGuard: types.WGKey{2}})
	if s.holds(c) {
		t.Fatal("the certificate for the keys before is held after a rotation")
	}
	if again, _ := s.relayCertificate(t.Logf); again == c {
		t.Fatal("a rotation keeps the relay's certificate")
	}
}
