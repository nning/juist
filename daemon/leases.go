package daemon

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"slices"
	"sync"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/types"
)

// A leaseStore is the newest freshness lease held per signer, and the file
// they are kept in, where path is not empty. saveMu → mu.
type leaseStore struct {
	path   string
	saveMu sync.Mutex // serializes writing the file
	mu     sync.Mutex
	held   map[types.Identity]types.Lease
}

func newLeaseStore(path string) leaseStore {
	return leaseStore{path: path, held: map[types.Identity]types.Lease{}}
}

func (s *leaseStore) get(signer types.Identity) (types.Lease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.held[signer]
	return l, ok
}

// replace holds l where what is held of its signer is still was, read before
// l was checked, or older than l, reporting whether it did: another session
// may have stored a newer one meanwhile.
func (s *leaseStore) replace(l, was types.Lease) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.held[l.Signer]; !ok || cur == was || cur.Issued < l.Issued {
		s.held[l.Signer] = l
		return true
	}
	return false
}

// drop forgets signer's lease, reporting whether one was held.
func (s *leaseStore) drop(signer types.Identity) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.held[signer]
	delete(s.held, signer)
	return ok
}

// dropEach forgets each of ls that is still the one held of its signer.
func (s *leaseStore) dropEach(ls []types.Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range ls {
		if s.held[l.Signer] == l {
			delete(s.held, l.Signer)
		}
	}
}

func (s *leaseStore) all() []types.Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.Lease, 0, len(s.held))
	for _, l := range s.held {
		out = append(out, l)
	}
	return out
}

// encoded is the held leases for a peer, newest first.
func (s *leaseStore) encoded() [][]byte {
	held := s.all()
	slices.SortFunc(held, func(a, b types.Lease) int { return cmp.Compare(b.Issued, a.Issued) })
	out := make([][]byte, 0, len(held))
	for i := range held {
		if b, err := held[i].Encode(); err == nil {
			out = append(out, b)
		}
		if len(out) == gossip.MaxLeasesPerFrame {
			break
		}
	}
	return out
}

// load takes the leases the file holds, the newest per signer.
func (s *leaseStore) load(logf func(string, ...any)) {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		logf("daemon: reading %s: %v", s.path, err)
		return
	}
	raw, err := statedir.DecodeLeaseFile(b)
	if err != nil {
		// A hint that does not decode costs freshness until the next lease
		// arrives, which is the fail-closed direction.
		logf("daemon: %s did not decode and was ignored: %v", s.path, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range raw {
		l, err := types.DecodeLease(r)
		if err != nil {
			continue
		}
		if held, ok := s.held[l.Signer]; !ok || held.Issued < l.Issued {
			s.held[l.Signer] = l
		}
	}
}

// save writes the held leases out.
func (s *leaseStore) save(logf func(string, ...any)) {
	if s.path == "" {
		return
	}
	// Serialized, and the snapshot taken inside, so a writer holding an older
	// set cannot rename over a newer one.
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	b, err := statedir.EncodeLeaseFile(s.encoded())
	if err != nil {
		logf("daemon: encoding leases: %v", err)
		return
	}
	if err := statedir.WriteFilePrivate(s.path, b); err != nil {
		logf("daemon: writing %s: %v", s.path, err)
	}
}
