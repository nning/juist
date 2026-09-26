package daemon

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/nning/juist/trust/secrets"
)

// Saves racing each other leave the newest secrets in the file: Run's
// backfill writes the keyring outside reconcileMu, beside a reconcile that
// adopts an epoch.
func TestConcurrentKeyringSavesKeepTheNewest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.secret")
	f := newReconcileFixtureWith(t, 1, func(o *Options) { o.KeyringPath = path })
	const writers = 16
	for round := range 5 {
		base := uint64(round * writers)
		var wg sync.WaitGroup
		for i := range uint64(writers) {
			wg.Go(func() {
				f.d.keyring.Adopt(base+i+1, secrets.Secret{byte(i + 1)})
				f.d.saveKeyring()
			})
		}
		wg.Wait()
		kept := f.d.loadKeyring()
		epochs, _ := f.d.keyring.Held()
		for _, e := range epochs {
			if _, ok := kept[e]; !ok {
				t.Fatalf("round %d: the file lacks epoch %d the keyring holds; it has %v", round, e, kept)
			}
		}
	}
}
