package quicinitial

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"slices"
)

// MaxHello bounds the CRYPTO data a Hello takes, and MaxSegments the pieces
// it holds out of order: a ClientHello with a post-quantum key share takes
// under 2 KiB, which a browser may send in pieces, out of order on purpose.
const (
	MaxHello    = 8 << 10
	MaxSegments = 32
)

// A Hello gathers the CRYPTO data of one client's Initial packets, which
// may come out of order and in several datagrams, until its ClientHello is
// whole, and tells the server name it asks for, read by crypto/tls. Close
// it once done with it: crypto/tls reads in a goroutine of its own.
type Hello struct {
	version uint32
	dcid    []byte
	have    []byte    // the data from offset 0 on, without a gap
	pending []segment // what came past a gap
	tls     *tls.QUICConn
	name    string
	done    bool
}

type segment struct {
	off  uint64
	data []byte
}

// errPeeked ends crypto/tls's handshake once it read the ClientHello.
var errPeeked = errors.New("quicinitial: client hello read")

// Add takes the Initial packets of one datagram, and returns the server
// name once the ClientHello is whole; done is false until then. An error
// means the client is none to serve: its packets do not parse, belong to
// another connection, or its ClientHello names nothing or is too large.
func (h *Hello) Add(packets []Packet) (name string, done bool, err error) {
	if h.done {
		return h.name, true, nil
	}
	for _, p := range packets {
		switch {
		case h.dcid == nil:
			h.version, h.dcid = p.Version, bytes.Clone(p.DCID)
		case p.Version != h.version || !bytes.Equal(p.DCID, h.dcid):
			return "", false, errors.New("quicinitial: packets of another connection")
		}
		if err := Frames(p.Payload, h.take); err != nil {
			return "", false, err
		}
	}
	if h.done {
		if h.name == "" {
			return "", false, errors.New("quicinitial: a client hello naming no server")
		}
		return h.name, true, nil
	}
	return "", false, nil
}

// take keeps a CRYPTO frame's data, and hands crypto/tls what follows on
// what it read without a gap.
func (h *Hello) take(off uint64, data []byte) error {
	if h.done {
		return nil
	}
	if off+uint64(len(data)) > MaxHello {
		return errors.New("quicinitial: a client hello past the bound")
	}
	if len(h.pending) >= MaxSegments {
		return errors.New("quicinitial: too many pieces of a client hello")
	}
	h.pending = append(h.pending, segment{off, bytes.Clone(data)})
	slices.SortFunc(h.pending, func(a, b segment) int { return cmp.Compare(a.off, b.off) })
	var next []byte
	for len(h.pending) > 0 && h.pending[0].off <= uint64(len(h.have)) {
		s := h.pending[0]
		h.pending = h.pending[1:]
		if end := s.off + uint64(len(s.data)); end > uint64(len(h.have)) {
			fresh := s.data[uint64(len(h.have))-s.off:]
			h.have = append(h.have, fresh...)
			next = append(next, fresh...)
		}
	}
	if len(next) == 0 {
		return nil
	}
	if h.tls == nil {
		h.tls = tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
			GetConfigForClient: func(c *tls.ClientHelloInfo) (*tls.Config, error) {
				h.name = c.ServerName
				return nil, errPeeked
			}}})
		if err := h.tls.Start(context.Background()); err != nil {
			return err
		}
	}
	err := h.tls.HandleData(tls.QUICEncryptionLevelInitial, next)
	switch {
	case errors.Is(err, errPeeked):
		h.done = true
		h.Close()
		return nil
	case err != nil:
		return err
	}
	return nil
}

// Close lets go of what h holds.
func (h *Hello) Close() {
	if h.tls != nil {
		h.tls.Close()
		h.tls = nil
	}
	h.pending, h.have = nil, nil
}
