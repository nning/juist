package gossip

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func testSecret(t *testing.T) secrets.Secret {
	t.Helper()
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatalf("drawing a group secret: %v", err)
	}
	return s
}

func testEndpoint(t *testing.T) (Endpoint, types.PrivateIdentity) {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	e := Endpoint{
		Identity:   priv.Public(),
		Disco:      DiscoKey{9, 8, 7},
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.7:41641")},
		GossipPort: 41642,
		Seq:        12,
	}
	if err := e.Sign(priv); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return e, priv
}

func TestEndpointRoundTrip(t *testing.T) {
	e, _ := testEndpoint(t)
	b, err := e.Encode()
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	got, err := DecodeEndpoint(b)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Identity != e.Identity || got.Disco != e.Disco || got.Seq != e.Seq {
		t.Errorf("round trip changed the record: %+v vs %+v", got, e)
	}
}

// TestEndpointRejectsTampering is the property the reconciler depends on: an
// announcement says where its author is, and nothing a relay does to it
// survives.
func TestEndpointRejectsTampering(t *testing.T) {
	e, _ := testEndpoint(t)
	other, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		break_ func(*Endpoint)
	}{
		{"a different disco key", func(e *Endpoint) { e.Disco = DiscoKey{1} }},
		{"a redirected address", func(e *Endpoint) {
			e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:41641")}
		}},
		{"a different gossip port", func(e *Endpoint) { e.GossipPort = 1 }},
		{"a replayed-forward sequence", func(e *Endpoint) { e.Seq = 99 }},
		{"a stolen identity", func(e *Endpoint) { e.Identity = other.Public() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *e.Clone()
			tc.break_(&tampered)
			if err := tampered.Verify(); err == nil {
				t.Fatal("a tampered announcement verified")
			}
		})
	}
}

func TestEndpointRejectsBadShape(t *testing.T) {
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	base := func() Endpoint {
		return Endpoint{
			Identity: priv.Public(), Disco: DiscoKey{1}, GossipPort: 7,
			Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")},
		}
	}
	for _, tc := range []struct {
		name string
		make func() Endpoint
		want string
	}{
		{"no disco key", func() Endpoint { e := base(); e.Disco = DiscoKey{}; return e }, "no disco key"},
		{"no gossip port", func() Endpoint { e := base(); e.GossipPort = 0; return e }, "no gossip port"},
		{"unspecified address", func() Endpoint {
			e := base()
			e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:1")}
			return e
		}, "unspecified"},
		{"multicast address", func() Endpoint {
			e := base()
			e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("224.0.0.251:1")}
			return e
		}, "multicast"},
		{"zero port", func() Endpoint {
			e := base()
			e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:0")}
			return e
		}, "no port"},
		{"unsorted addresses", func() Endpoint {
			e := base()
			e.Addrs = []netip.AddrPort{
				netip.MustParseAddrPort("192.0.2.2:1"),
				netip.MustParseAddrPort("192.0.2.1:1"),
			}
			return e
		}, "unsorted"},
		{"limited broadcast", func() Endpoint {
			e := base()
			e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("255.255.255.255:1")}
			return e
		}, "not a global unicast"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.make()
			err := e.StaticValidate()
			if err == nil {
				t.Fatal("accepted an announcement that must be rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestSignRefusesTheWrongKey catches the misconfiguration that would otherwise
// only show up as a node nobody can reach.
func TestSignRefusesTheWrongKey(t *testing.T) {
	e, _ := testEndpoint(t)
	other, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Sign(other); err == nil {
		t.Fatal("signed an announcement with a key it does not name")
	}
}

func TestFrameSealRoundTrip(t *testing.T) {
	s := testSecret(t)
	kr := secrets.NewKeyring()
	kr.Adopt(5, s)

	f := frame{Kind: kindHello, Network: types.Hash{3}, Epoch: 5, Head: types.Hash{4}, Anchor: types.Hash{5}}
	pt, err := encode(&f)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := seal(s, 5, pt)
	if err != nil {
		t.Fatal(err)
	}
	epoch, got, err := open(kr, blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if epoch != 5 {
		t.Errorf("opened at epoch %d, want 5", epoch)
	}
	if !bytes.Equal(got, pt) {
		t.Error("plaintext changed through the seal")
	}
	if _, err := decodeFrame(got); err != nil {
		t.Errorf("decoding the opened frame: %v", err)
	}
}

// TestFrameSealBindsItsEpoch is why the epoch is additional data rather than
// only a lookup hint: relabelling a frame must not silently succeed against a
// node that holds both keys.
func TestFrameSealBindsItsEpoch(t *testing.T) {
	s := testSecret(t)
	kr := secrets.NewKeyring()
	kr.Adopt(5, s)
	kr.Adopt(6, s)

	blob, err := seal(s, 5, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	blob[7] = 6 // rewrite the cleartext epoch from 5 to 6
	if _, _, err := open(kr, blob); err == nil {
		t.Fatal("a relabelled frame opened")
	}
}

func TestFrameSealRejectsUnknownEpoch(t *testing.T) {
	s := testSecret(t)
	kr := secrets.NewKeyring()
	kr.Adopt(5, s)
	blob, err := seal(s, 9, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := open(kr, blob); err == nil {
		t.Fatal("a frame from an epoch this node does not hold opened")
	}
}

func TestFrameSealRejectsTampering(t *testing.T) {
	s := testSecret(t)
	kr := secrets.NewKeyring()
	kr.Adopt(5, s)
	blob, err := seal(s, 5, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	if _, _, err := open(kr, blob); err == nil {
		t.Fatal("a tampered frame opened")
	}
}

func TestDecodeFrameRejectsBadShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    frame
	}{
		{"no kind", frame{Network: types.Hash{1}, Anchor: types.Hash{2}}},
		{"unknown kind", frame{Kind: frameKind(9), Network: types.Hash{1}, Anchor: types.Hash{2}}},
		{"no network", frame{Kind: kindHello, Anchor: types.Hash{2}}},
		{"no anchor", frame{Kind: kindHello, Network: types.Hash{1}}},
		{"a hello carrying records", frame{
			Kind: kindHello, Network: types.Hash{1}, Anchor: types.Hash{2}, Records: [][]byte{{1}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := encode(&tc.f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeFrame(b); err == nil {
				t.Fatal("accepted a frame that must be rejected")
			}
		})
	}
}

// TestDecodeFrameRejectsNonCanonical keeps one frame from having two
// encodings, which for the endpoint records inside it is what keeps a
// signature bound to one byte string.
func TestDecodeFrameRejectsNonCanonical(t *testing.T) {
	f := frame{Kind: kindHello, Network: types.Hash{1}, Epoch: 1, Anchor: types.Hash{2}}
	b, err := encode(&f)
	if err != nil {
		t.Fatal(err)
	}
	// Append a byte: a trailing item must not be silently dropped.
	if _, err := decodeFrame(append(b, 0)); err == nil {
		t.Fatal("accepted a frame with trailing bytes")
	}
}

func TestCacheKeepsTheNewestAnnouncement(t *testing.T) {
	c := NewCache()
	e, priv := testEndpoint(t)
	if !c.Add(e) {
		t.Fatal("first announcement was not accepted")
	}
	if c.Add(e) {
		t.Error("the same announcement was accepted twice")
	}

	older := *e.Clone()
	older.Seq = e.Seq - 1
	if err := older.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if c.Add(older) {
		t.Error("an older announcement replaced a newer one")
	}

	newer := *e.Clone()
	newer.Seq = e.Seq + 1
	newer.GossipPort = 4242
	if err := newer.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if !c.Add(newer) {
		t.Fatal("a newer announcement was refused")
	}
	got, ok := c.Get(e.Identity)
	if !ok || got.GossipPort != 4242 {
		t.Errorf("cache holds %+v, want the newer record", got)
	}

	c.Forget(e.Identity)
	if _, ok := c.Get(e.Identity); ok {
		t.Error("Forget left the announcement behind")
	}
}

// TestAFullCacheStillAdmitsMembers: identity keys cost nothing to mint, so any
// holder of an epoch secret can flood the cache with signature-valid
// announcements for invented nodes. The bound must not let that crowd out the
// announcement of an actual member — that is the record the reconciler needs
// to build a tunnel, and losing it would be a silent, restart-persistent way
// for one insider to keep a new member unreachable.
func TestAFullCacheStillAdmitsMembers(t *testing.T) {
	c := NewCache()
	for i := 0; c.Len() < maxCachedEndpoints; i++ {
		var id types.Identity
		id[0], id[1], id[2] = byte(i>>16), byte(i>>8), byte(i)
		id[3] = 1 // distinct from the member below, whose identity is zero-led
		// Add does not verify (its documented contract is that callers do),
		// so the flood does not need real signatures.
		if !c.Add(Endpoint{Identity: id, Disco: DiscoKey{1}, GossipPort: 1, Seq: 1}) {
			t.Fatalf("the cache refused announcement %d of %d", i, maxCachedEndpoints)
		}
	}

	member := Endpoint{Identity: types.Identity{0: 0}, Disco: DiscoKey{2}, GossipPort: 2, Seq: 1}
	stranger := Endpoint{Identity: types.Identity{0: 255, 1: 255, 2: 255, 3: 255}, Disco: DiscoKey{3}, GossipPort: 3, Seq: 1}

	// Without a membership view, a full cache refuses everyone equally.
	if c.Add(member) {
		t.Fatal("a full cache admitted a new announcement before any membership view existed")
	}

	c.SetMembership([]types.Identity{member.Identity}, nil)
	if !c.Add(member) {
		t.Fatal("a full cache refused a member's announcement")
	}
	if _, ok := c.Get(member.Identity); !ok {
		t.Fatal("the member's announcement did not survive the flood")
	}
	if c.Len() != maxCachedEndpoints {
		t.Fatalf("cache holds %d announcements, want the bound %d", c.Len(), maxCachedEndpoints)
	}
	if c.Add(stranger) {
		t.Fatal("a full cache admitted a non-member's announcement")
	}

	// Relays lead with the members, so a flooded cache still relays what a
	// peer can actually use.
	if all := c.All(); all[0].Identity != member.Identity {
		t.Errorf("All() leads with %v, want the member", all[0].Identity.ShortString())
	}
}

// TestCacheRefusesFormerMembers: a revoked or expired device keeps announcing
// until it learns of its own removal, and both ways into the cache — a LAN
// beacon and a peer relaying its cache in a gossip session — must refuse it.
// Otherwise each announcement is cached, reported as new, and pruned again on
// the next reconcile: a reconcile and a push round per member per interval,
// for as long as the device is powered on.
func TestCacheRefusesFormerMembers(t *testing.T) {
	c := NewCache()
	e, priv := testEndpoint(t)
	if !c.Add(e) {
		t.Fatal("a first announcement was refused")
	}

	c.SetMembership(nil, []types.Identity{e.Identity})
	if _, ok := c.Get(e.Identity); ok {
		// SetMembership does not evict; the reconciler's Forget does. What it
		// must do is refuse what comes next.
		c.Forget(e.Identity)
	}
	newer := *e.Clone()
	newer.Seq = e.Seq + 1
	if err := newer.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if c.Add(newer) {
		t.Error("a former member's announcement was cached again")
	}

	// Re-enrollment makes it live again, and it is accepted from then on.
	c.SetMembership([]types.Identity{e.Identity}, nil)
	if !c.Add(newer) {
		t.Error("a re-enrolled member's announcement was still refused")
	}
}

// TestEndpointRefusesAddressesItsAuthorDoesNotOwn: an announcement points the
// whole member set at an address — the data plane sends UDP there and the sync
// layer opens TCP sessions to it — so the addresses a member may claim are
// exactly the ones a correct node announces about itself. Loopback would aim
// peers at services on their own hosts, and any of these would make the member
// set into a connection source pointed wherever the announcer likes.
func TestEndpointRefusesAddressesItsAuthorDoesNotOwn(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:41641",
		"[::1]:41641",
		"169.254.10.1:41641",
		"[fe80::1]:41641",
		"0.0.0.0:41641",
		"224.0.0.251:41641",
	} {
		e, priv := testEndpoint(t)
		e.Addrs = []netip.AddrPort{netip.MustParseAddrPort(addr)}
		if err := e.Sign(priv); err == nil {
			t.Errorf("an announcement claiming %s was accepted", addr)
		}
	}
}
