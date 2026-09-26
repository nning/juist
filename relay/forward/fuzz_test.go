package forward

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"io"
	"net"
	"testing"
)

// relayed runs one side of the protocol, on a connection accepted from ln,
// against a relay that sends data and stops sending, and returns what that
// side wrote.
func relayed(t *testing.T, ln net.Listener, data []byte, run func(net.Conn, *bufio.Reader)) []byte {
	t.Helper()
	theirs, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer theirs.Close()
	ours, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	wrote := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(theirs)
		wrote <- b
	}()
	go func() {
		_, _ = theirs.Write(data)
		_ = theirs.(*net.TCPConn).CloseWrite()
	}()
	run(ours, bufio.NewReader(ours))
	ours.Close()
	return <-wrote
}

// FuzzRelayAnswers feeds a host and a guest whatever a relay may answer once
// the upgrade is through: a relay is a member's, but the guest cannot check
// which, and neither side may trust what it is told.
func FuzzRelayAnswers(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}
	identity := [32]byte(pub)
	sign := func(m []byte) ([]byte, error) { return ed25519.Sign(priv, m), nil }
	certHash, id := [32]byte{1}, [16]byte{2}
	nonce := bytes.Repeat([]byte{7}, 32)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Fatal(err)
	}
	defer ln.Close()
	after := func(b ...byte) []byte { return append(bytes.Clone(nonce), b...) }
	f.Add(append(after(Waiting, Joined, 11), "192.0.2.1:9"...))
	f.Add(after(Waiting, Joined, 0))
	f.Add(after(Waiting))
	f.Add([]byte{Joined, 'x'})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var (
			conn net.Conn
			who  string
			herr error
		)
		wrote := relayed(t, ln, data, func(c net.Conn, br *bufio.Reader) {
			conn, who, herr = hold(t.Context(), c, br, certHash, id, identity, sign)
		})
		if len(data) >= 32 {
			msg := Message(certHash, id, [32]byte(data[:32]))
			if len(wrote) < 32+ed25519.SignatureSize || !bytes.Equal(wrote[:32], identity[:]) ||
				!ed25519.Verify(pub, msg, wrote[32:32+ed25519.SignatureSize]) {
				t.Fatalf("the host's proof does not answer the relay's nonce")
			}
		}
		if herr == nil {
			if len(data) < 35 || data[32] != Waiting || data[33] != Joined || int(data[34]) != len(who) ||
				len(data) < 35+len(who) || who != string(data[35:35+len(who)]) {
				t.Fatalf("the host took %q from a relay that said %x", who, data)
			}
			conn.Close()
		}

		var gerr error
		relayed(t, ln, data, func(c net.Conn, br *bufio.Reader) {
			conn, gerr = joined(t.Context(), c, br)
		})
		if (gerr == nil) != (len(data) > 0 && data[0] == Joined) {
			t.Fatalf("the guest's answer to %x: %v", data, gerr)
		}
		if gerr == nil {
			conn.Close()
		}
	})
}
