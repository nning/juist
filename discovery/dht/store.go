package dht

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"

	anacrolix "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/bep44"
	"github.com/anacrolix/dht/v2/exts/getput"
	alog "github.com/anacrolix/log"
	"github.com/anacrolix/torrent/bencode"
	"golang.org/x/time/rate"
)

// A Store puts and gets one opaque value at an address derived from a seed,
// for two parties that share a secret and nothing else — the invite
// rendezvous, and each member's announcement. Whoever knows the seed can also
// overwrite the value, so what is stored must be sealed by the caller, and
// losing it only costs the meeting.
type Store struct {
	srv *anacrolix.Server
}

// StoreOptions configures a [Store].
type StoreOptions struct {
	// Bootstrap overrides the public DHT routers.
	Bootstrap []string

	// NoSecurity disables the node-ID-from-IP rule, for a loopback swarm.
	NoSecurity bool
}

// NewStore joins the DHT on a socket of its own, and bootstraps.
func NewStore(opts StoreOptions) (*Store, error) {
	s, err := newStore(nil, opts.Bootstrap, opts.NoSecurity)
	if err != nil {
		return nil, err
	}
	// A fresh node knows nobody until it has bootstrapped; a put or get
	// before that traverses nothing.
	if _, err := s.srv.Bootstrap(); err != nil {
		s.Close()
		return nil, fmt.Errorf("dht: bootstrapping: %w", err)
	}
	return s, nil
}

// newStore joins the DHT on conn, or on a socket of its own where conn is
// nil, without bootstrapping. conn is closed if the node cannot start.
func newStore(conn net.PacketConn, bootstrap []string, noSecurity bool) (*Store, error) {
	if conn == nil {
		var err error
		if conn, err = net.ListenPacket("udp", ":0"); err != nil {
			return nil, fmt.Errorf("dht: binding a UDP socket: %w", err)
		}
	}
	cfg := anacrolix.NewDefaultServerConfig()
	cfg.Conn = conn
	cfg.NoSecurity = noSecurity
	// A client of the DHT, not one of its storage nodes (BEP 43): a node
	// that answered queries would keep any stranger's BEP 44 puts, with no
	// bound but memory.
	cfg.Passive = true
	// Its own send budget rather than the library's process-global one. That
	// one is shared by every DHT server in the process and sized for a
	// torrent client; sharing it means another node's burst silently costs
	// this one its replies, which look exactly like an unreachable peer.
	cfg.SendLimiter = rate.NewLimiter(sendRate, sendBurst)
	// The library logs to the standard logger by default, which in a daemon
	// means DHT chatter on stderr no operator asked for.
	cfg.Logger = quiet
	if len(bootstrap) > 0 {
		cfg.StartingNodes = func() ([]anacrolix.Addr, error) { return resolveAll(bootstrap) }
	}
	srv, err := anacrolix.NewServer(cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("dht: starting the DHT node: %w", err)
	}
	return &Store{srv: srv}, nil
}

func resolveAll(hostPorts []string) ([]anacrolix.Addr, error) {
	out := make([]anacrolix.Addr, 0, len(hostPorts))
	for _, hp := range hostPorts {
		ua, err := net.ResolveUDPAddr("udp", hp)
		if err != nil {
			continue
		}
		out = append(out, anacrolix.NewAddr(ua))
	}
	if len(out) == 0 {
		return nil, errors.New("dht: no bootstrap address resolved")
	}
	return out, nil
}

func storeKey(seed [32]byte) (ed25519.PrivateKey, bep44.Target) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, bep44.MakeMutableTarget([32]byte(priv.Public().(ed25519.PublicKey)), nil)
}

// Put stores value at seed's address.
func (s *Store) Put(ctx context.Context, seed [32]byte, value []byte) error {
	if len(value) > MaxValueSize {
		return fmt.Errorf("dht: a %d-byte value is over BEP 44's %d-byte limit", len(value), MaxValueSize)
	}
	priv, target := storeKey(seed)
	ctx, cancel := operation(ctx)
	defer cancel()
	_, err := getput.Put(ctx, target, s.srv, nil, func(seq int64) bep44.Put {
		put := bep44.Put{V: value, K: (*[32]byte)([]byte(priv.Public().(ed25519.PublicKey))), Seq: seq + 1}
		put.Sign(priv)
		return put
	})
	return err
}

// Get fetches the value at seed's address.
func (s *Store) Get(ctx context.Context, seed [32]byte) ([]byte, error) {
	_, target := storeKey(seed)
	ctx, cancel := operation(ctx)
	defer cancel()
	res, _, err := getput.Get(ctx, target, s.srv, nil, nil)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if err := bencode.Unmarshal(res.V, &raw); err != nil {
		return nil, errors.New("dht: the item is not a byte string")
	}
	return raw, nil
}

// Close leaves the DHT.
func (s *Store) Close() error {
	s.srv.Close()
	return nil
}

// quiet is the library's logger with everything below critical dropped.
var quiet = alog.Default.FilterLevel(alog.Critical)

// operation bounds one traversal. The traversals log through the context, not
// the server's logger — every node that refuses a put is a warning on stderr
// otherwise — so the context carries the quiet one.
func operation(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(alog.ContextWithLogger(ctx, quiet), OperationTimeout)
}
