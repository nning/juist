package gossip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/malformed"
	"github.com/nning/juist/trust/secrets"
)

// Frames are sealed with internal/aead under the epoch's gossip key. See that
// package for the layout and for what the sealing does and does not buy.
const (
	sealOverhead  = aead.Overhead
	maxSealedSize = MaxFrameSize + sealOverhead
)

// seal encrypts a frame under an epoch's group secret.
func seal(s secrets.Secret, epoch uint64, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxFrameSize {
		return nil, fmt.Errorf("gossip: frame is %d bytes, over the %d limit", len(plaintext), MaxFrameSize)
	}
	key := s.GossipKey(epoch)
	return aead.Seal(key, epoch, plaintext)
}

// errUnknownEpoch reports a frame sealed under an epoch this node cannot open:
// an ordinary condition, and a peer far behind looks the same as a non-member.
var errUnknownEpoch = errors.New("gossip: frame is sealed under an epoch this node does not hold")

// open decrypts a sealed frame with whichever epoch key it names, returning
// that epoch so a reply can be sealed under the same one.
func open(kr *keyring.Keyring, blob []byte) (epoch uint64, plaintext []byte, err error) {
	defer malformed.Recover(&err)
	if len(blob) > maxSealedSize {
		return 0, nil, fmt.Errorf("gossip: sealed frame is %d bytes, over the %d limit",
			len(blob), maxSealedSize)
	}
	epoch, err = aead.Epoch(blob)
	if err != nil {
		return 0, nil, fmt.Errorf("gossip: %w", err)
	}
	s, ok := kr.Secret(epoch)
	if !ok {
		return epoch, nil, fmt.Errorf("%w: epoch %d", errUnknownEpoch, epoch)
	}
	key := s.GossipKey(epoch)
	pt, err := aead.Open(key, blob)
	if err != nil {
		return epoch, nil, fmt.Errorf("gossip: frame sealed under epoch %d: %w", epoch, err)
	}
	return epoch, pt, nil
}

// Frames on the stream are length-prefixed sealed blobs. The prefix is
// checked against the sealed-size limit before a single byte is buffered, so
// a peer cannot announce a gigabyte and have this node try to hold it.
func (n *Node) writeSealed(c net.Conn, ss *sessionSeal, f *frame) error {
	pt, err := encode(f)
	if err != nil {
		return err
	}
	var blob []byte
	if ss.catchUp != nil {
		blob, err = aead.Seal(*ss.catchUp, catchUpEpoch, pt)
	} else {
		s, ok := n.opts.Keyring.Secret(ss.epoch)
		if !ok {
			return fmt.Errorf("gossip: no secret for epoch %d, which this session is sealed under", ss.epoch)
		}
		blob, err = seal(s, ss.epoch, pt)
	}
	if err != nil {
		return err
	}
	return writeBlob(c, blob, f.Kind.String())
}

func writeBlob(c net.Conn, blob []byte, what string) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := c.Write(hdr[:]); err != nil {
		return fmt.Errorf("gossip: writing a %v frame: %w", what, err)
	}
	if _, err := c.Write(blob); err != nil {
		return fmt.Errorf("gossip: writing a %v frame: %w", what, err)
	}
	return nil
}

// readSealed reads one frame. A session sealed under an epoch takes it from
// its first frame and holds every later one to it, so a session cannot be
// walked from one epoch's key to another's.
func (n *Node) readSealed(c net.Conn, ss *sessionSeal) (frame, error) {
	blob, err := readBlob(c)
	if err != nil {
		return frame{}, err
	}
	return n.openSealed(blob, ss)
}

func (n *Node) openSealed(blob []byte, ss *sessionSeal) (frame, error) {
	if ss.catchUp != nil {
		if len(blob) > maxSealedSize {
			return frame{}, fmt.Errorf("gossip: sealed frame is %d bytes, over the %d limit", len(blob), maxSealedSize)
		}
		if !isCatchUp(blob) {
			return frame{}, errors.New("gossip: a catch-up session's frame is sealed under an epoch")
		}
		pt, err := aead.Open(*ss.catchUp, blob)
		if err != nil {
			return frame{}, fmt.Errorf("gossip: catch-up frame: %w", err)
		}
		return decodeFrame(pt)
	}
	got, pt, err := open(n.opts.Keyring, blob)
	if err != nil {
		return frame{}, err
	}
	if ss.epoch == 0 {
		ss.epoch = got
	} else if got != ss.epoch {
		return frame{}, fmt.Errorf("gossip: session began at epoch %d and this frame is sealed under %d",
			ss.epoch, got)
	}
	return decodeFrame(pt)
}

// readBlob reads one length-prefixed blob off the stream.
func readBlob(c net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, fmt.Errorf("gossip: reading a frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > maxSealedSize {
		return nil, fmt.Errorf("gossip: peer announced a %d-byte frame, over the %d limit",
			size, maxSealedSize)
	}
	// Grown as bytes arrive, never allocated from the announced size: that
	// size is an unauthenticated claim, and trusting it lets a peer hold
	// hundreds of megabytes here by announcing frames it never sends.
	blob, err := readN(c, int(size))
	if err != nil {
		return nil, fmt.Errorf("gossip: reading a frame body: %w", err)
	}
	return blob, nil
}

// readN reads exactly n bytes, growing its buffer as they arrive, so an
// announced size costs nothing until bytes back it.
func readN(r io.Reader, n int) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(min(n, 32<<10))
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
