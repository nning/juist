package daemon

import (
	"sync"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/relay"
)

// A Session is the connectivity material a device announces and its peers
// pin: the NAT-traversal key, and its relay's certificate. A mesh restarted
// in the same process on the same keys takes the same one, so peers reach it
// on the announcement they hold rather than after finding a new one.
type Session struct {
	discoPrivate [32]byte
	discoPublic  gossip.DiscoKey

	mu   sync.Mutex
	cert *relay.Certificate
}

// NewSession draws a fresh session.
func NewSession() (*Session, error) {
	priv, pub, err := conn.NewDiscoKey()
	if err != nil {
		return nil, err
	}
	return &Session{discoPrivate: priv, discoPublic: gossip.DiscoKey(pub)}, nil
}

// relayCertificate returns the relay's certificate, drawn the first time.
func (s *Session) relayCertificate() (*relay.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert == nil {
		c, err := relay.NewCertificate()
		if err != nil {
			return nil, err
		}
		s.cert = c
	}
	return s.cert, nil
}
