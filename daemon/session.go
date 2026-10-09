package daemon

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/types"
)

// A Session is the connectivity material a device announces and its peers
// pin: the NAT-traversal key, and its relay's certificate. A mesh restarted
// in the same process on the same keys takes the same one, so peers reach it
// on the announcement they hold rather than after finding a new one. The
// certificate is also kept on disk for the same keys, so a restarted process
// keeps the hash members pinned.
type Session struct {
	discoPrivate [32]byte
	discoPublic  gossip.DiscoKey

	certPath  string
	certOwner [32]byte

	mu   sync.Mutex
	cert *relay.Certificate

	seqMu sync.Mutex // apart from mu, which is held across file I/O
	seq   uint64     // the last announcement's; a restarted mesh must exceed it
}

// NewSession draws a fresh session.
func NewSession() (*Session, error) {
	priv, pub, err := conn.NewDiscoKey()
	if err != nil {
		return nil, err
	}
	return &Session{discoPrivate: priv, discoPublic: gossip.DiscoKey(pub)}, nil
}

// NewStoredSession draws a fresh session whose relay certificate is the one
// stored in home for these device keys, or a new one stored there.
func NewStoredSession(home string, id types.Identity, keys types.NodeKeys) (*Session, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	if home != "" {
		s.certPath = statedir.RelayCertPath(home)
	}
	s.certOwner = relayCertOwner(id, keys)
	return s, nil
}

// relayCertOwner binds a stored certificate to the device keys it was drawn
// for, so a rotation draws a new one.
func relayCertOwner(id types.Identity, keys types.NodeKeys) [32]byte {
	h := sha256.New()
	h.Write([]byte("juist relay certificate owner\x00"))
	h.Write(id[:])
	h.Write(keys.WireGuard[:])
	h.Write(keys.X25519[:])
	h.Write(keys.MLKEM[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// relayCertificate returns the relay's certificate: the stored one, or one
// drawn the first time and stored. A store that fails costs only the next
// restart's hash, so it is reported and not fatal.
func (s *Session) relayCertificate(logf func(string, ...any)) (*relay.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert != nil {
		return s.cert, nil
	}
	if s.certPath != "" {
		b, err := os.ReadFile(s.certPath)
		switch {
		case err == nil:
			c, err := relay.DecodeCertificate(b, s.certOwner, time.Now())
			if err == nil {
				s.cert = c
				return c, nil
			}
			logf("daemon: drawing a new relay certificate: %v", err)
		case !errors.Is(err, fs.ErrNotExist):
			logf("daemon: drawing a new relay certificate: %v", err)
		}
	}
	c, err := relay.NewCertificate()
	if err != nil {
		return nil, err
	}
	s.cert = c
	if s.certPath != "" {
		if err := s.store(c); err != nil {
			logf("daemon: storing the relay certificate: %v; the next start announces a new one", err)
		}
	}
	return c, nil
}

// nextSeq returns an announcement number above every one this session gave,
// seeded from now: peers dismiss one that does not exceed what they hold.
func (s *Session) nextSeq(now time.Time) uint64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.seq = max(uint64(now.Unix()), s.seq+1)
	return s.seq
}

// passSeq makes the next announcement number exceed seq.
func (s *Session) passSeq(seq uint64) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.seq = max(s.seq, seq)
}

// follow carries prev's announcement numbers on, for a session that replaces
// it under the same identity.
func (s *Session) follow(prev *Session) {
	prev.seqMu.Lock()
	seq := prev.seq
	prev.seqMu.Unlock()
	s.passSeq(seq)
}

func (s *Session) store(c *relay.Certificate) error {
	b, err := c.Encode(s.certOwner)
	if err != nil {
		return err
	}
	return statedir.WriteFilePrivate(s.certPath, b)
}
