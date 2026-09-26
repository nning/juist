package relay

import (
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nning/juist/relay/forward"
)

// FuzzForwardRequests sends the relay's invite forwarding what anyone who can
// reach its port may send: a path, and whatever follows the upgrade. Even
// with every key admitted, nothing registers without answering the relay's
// fresh nonce, and no guest is let in where no host waits.
func FuzzForwardRequests(f *testing.F) {
	fwd := newForwarder(func([32]byte) bool { return true }, [32]byte{1}, func(string, ...any) {})
	mux := http.NewServeMux()
	mux.HandleFunc(forward.HostPath, fwd.serveHost)
	mux.HandleFunc(forward.GuestPath, fwd.serveGuest)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: time.Second}
	go srv.Serve(ln)
	defer srv.Close()
	defer fwd.close()

	id := hex.EncodeToString(make([]byte, 16))
	f.Add(true, id, make([]byte, 96))
	f.Add(true, id, []byte{})
	f.Add(false, id, []byte{})
	f.Add(true, "zz", []byte("x"))

	f.Fuzz(func(t *testing.T, host bool, path string, body []byte) {
		prefix := forward.GuestPath
		if host {
			prefix = forward.HostPath
		}
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		req := "GET " + prefix + path + " HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: " +
			forward.Upgrade + "\r\n\r\n"
		if _, err := io.WriteString(c, req); err != nil {
			return
		}
		_, _ = c.Write(body)
		_ = c.(*net.TCPConn).CloseWrite()
		// A reset is a hang-up with bytes unread, which is fine; a timeout is
		// a connection held.
		if _, err := io.ReadAll(c); isTimeout(err) {
			t.Fatalf("the relay held a connection that proved nothing: %v", err)
		}
		fwd.mu.Lock()
		registered := len(fwd.ids)
		fwd.mu.Unlock()
		if registered != 0 || fwd.waiting.Len() != 0 {
			t.Fatalf("%d invites registered and %d guests waiting after a request that proved nothing",
				registered, fwd.waiting.Len())
		}
	})
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
