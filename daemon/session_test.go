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
