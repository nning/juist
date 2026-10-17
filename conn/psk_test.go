package conn

import (
	"maps"
	"testing"
	"time"
)

// withPSK is n's peer set for other, every handshake mixing in psk.
func withPSK(t *testing.T, n, other *node, psk [32]byte) {
	t.Helper()
	p := other.peer()
	p.PSK = psk
	if err := n.mgr.SetPeers([]Peer{p}); err != nil {
		t.Fatal(err)
	}
}

func lastHandshake(n, other *node) time.Time {
	return n.mgr.Tunnels()[other.id].LastHandshake
}

// handshakeAgain has n's next packet to other start a handshake, and sends
// one, reporting whether a handshake completed after since within wait.
func handshakeAgain(t *testing.T, n, other *node, since time.Time, wait time.Duration) bool {
	t.Helper()
	n.mgr.(*tsManager).eng.MarkDevicePeerForHandshake(other.nodeKey.Public())
	until := time.Now().Add(wait)
	for time.Now().Before(until) {
		ping(t, n, other.pingAddr(), time.Second)
		if lastHandshake(n, other).After(since) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// Exit criterion (1) of M15, through both paths a preshared key takes into
// the engine (docs/07-embedding-notes.md): a peer created on first contact
// takes it from the config lookup, and one already active from SetPeers in
// place, keeping its session, so the next handshake mixes it in. A peer
// holding the right WireGuard key but another preshared key completes no
// handshake.
func TestHandshakesCarryThePresharedKey(t *testing.T) {
	t.Parallel()
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	k1, k2, k3 := [32]byte{1}, [32]byte{2}, [32]byte{3}

	withPSK(t, a, b, k1)
	withPSK(t, b, a, k2)
	if res, ok := pingUntil(t, a, b.pingAddr(), 12*time.Second); ok {
		t.Fatalf("a peer holding another preshared key was reached: %+v", res)
	}
	if !lastHandshake(a, b).IsZero() || !lastHandshake(b, a).IsZero() {
		t.Fatal("a handshake completed under two preshared keys")
	}

	// b's peer for a exists by now, created by a's initiations: the key
	// reaches it in place.
	withPSK(t, b, a, k1)
	if _, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second); !ok {
		t.Fatal("a and b holding one preshared key did not reach each other")
	}

	// Both change keys: the session stays, and the next handshake mixes in
	// the new key.
	before := lastHandshake(a, b)
	withPSK(t, a, b, k2)
	withPSK(t, b, a, k2)
	if _, ok := ping(t, a, b.pingAddr(), 2*time.Second); !ok {
		t.Fatal("changing the preshared key dropped the session")
	}
	time.Sleep(10 * time.Millisecond)
	if !handshakeAgain(t, a, b, before, 10*time.Second) {
		t.Fatal("no handshake completed under the new preshared key")
	}

	// One side alone changes: the session still carries traffic, but no
	// handshake completes.
	before = lastHandshake(a, b)
	withPSK(t, a, b, k3)
	if _, ok := ping(t, a, b.pingAddr(), 2*time.Second); !ok {
		t.Fatal("a preshared key changed on one side dropped the session")
	}
	if handshakeAgain(t, a, b, before, 8*time.Second) {
		t.Fatal("a handshake completed under two preshared keys")
	}
}

// A peer given a preshared key where it had none loses the session it had,
// which mixes in none: what it carries next takes a handshake under the key.
func TestAKeyWhereThereWasNoneEndsTheSession(t *testing.T) {
	t.Parallel()
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	withPSK(t, a, b, [32]byte{})
	withPSK(t, b, a, [32]byte{})
	if _, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second); !ok {
		t.Fatal("a and b holding no preshared key did not reach each other")
	}
	before := lastHandshake(a, b)
	withPSK(t, a, b, [32]byte{1})
	if res, ok := pingUntil(t, a, b.pingAddr(), 6*time.Second); ok {
		t.Fatalf("the session without a key still carried traffic: %+v", res)
	}
	withPSK(t, b, a, [32]byte{1})
	if _, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second); !ok {
		t.Fatal("no tunnel under the key both hold")
	}
	if !lastHandshake(a, b).After(before) {
		t.Error("no handshake under the key")
	}
}

// A peer the engine creates with the key it had, from a lookup made before
// SetPeers gave it one, passes nothing, and loses whatever session it made
// once the reset is repeated.
func TestAPeerCreatedWithTheKeyItHadPassesNothing(t *testing.T) {
	t.Parallel()
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	withPSK(t, a, b, [32]byte{})
	withPSK(t, b, a, [32]byte{})
	if _, ok := pingUntil(t, b, a.pingAddr(), 30*time.Second); !ok {
		t.Fatal("a and b holding no preshared key did not reach each other")
	}
	m := a.mgr.(*tsManager)
	withPSK(t, a, b, [32]byte{1})
	// The race: a's engine creates its peer for b from the snapshot before.
	m.apply.Lock()
	keyed := m.state.Load()
	keyless := *keyed
	keyless.peers = maps.Clone(keyed.peers)
	p := keyless.peers[b.nodeKey.Public()]
	p.PSK = [32]byte{}
	keyless.peers[b.nodeKey.Public()] = p
	m.state.Store(&keyless)
	m.apply.Unlock()
	withPSK(t, b, a, [32]byte{2})
	withPSK(t, b, a, [32]byte{})
	before := time.Now()
	for !lastHandshake(b, a).After(before) && time.Since(before) < keyingSettle {
		ping(t, b, a.pingAddr(), 200*time.Millisecond)
	}
	m.apply.Lock()
	m.state.Store(keyed)
	m.apply.Unlock()
	if !lastHandshake(b, a).After(before) {
		t.Skip("no handshake within the window this test needs")
	}
	if _, ok := ping(t, b, a.pingAddr(), time.Second); ok {
		t.Error("a peer newly keyed passed traffic before its reset was repeated")
	}
	time.Sleep(keyingSettle)
	if res, ok := pingUntil(t, b, a.pingAddr(), 6*time.Second); ok {
		t.Fatalf("a session without the key outlived the repeated reset: %+v", res)
	}
}
