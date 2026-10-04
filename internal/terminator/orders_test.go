package terminator

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/nning/juist/ipc"
)

// recorder takes every request the ACME client sends, answering none.
type recorder struct {
	mu     sync.Mutex
	bodies []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var b []byte
	if req.Body != nil {
		b, _ = io.ReadAll(req.Body)
	}
	r.mu.Lock()
	r.bodies = append(r.bodies, string(b))
	r.mu.Unlock()
	return nil, errors.New("no CA here")
}

func (r *recorder) saw(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.bodies {
		if strings.Contains(b, s) {
			return true
		}
	}
	return false
}

func orderFor(t *testing.T, name string) *http.Request {
	t.Helper()
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"identifiers":[{"type":"dns","value":"` + name + `"}]}`))
	body := `{"protected":"e30","payload":"` + payload + `","signature":"c2ln"}`
	req, err := http.NewRequest(http.MethodPost, "https://ca.example/new-order", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// An order for a name no longer served, as a renewal makes, never reaches the
// CA; one for a name served does.
func TestANameNotServedIsNotOrdered(t *testing.T) {
	rec := &recorder{}
	client := &acme.Client{DirectoryURL: "https://ca.example/dir", HTTPClient: &http.Client{Transport: rec}}
	src := &source{asked: make(chan struct{}, 1), p: &ipc.Published{Names: []ipc.PublishedTarget{{
		Name: "immich.pub.example.org", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: 1, To: "127.0.0.1:1"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, Options{Serving: src.serving, Poll: 50 * time.Millisecond, ACME: client,
			Cache:  autocert.DirCache(filepath.Join(t.TempDir(), "cache")),
			Listen: func(string, string) (net.Listener, error) { return nil, errors.New("no listening here") }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	<-src.asked
	<-src.asked
	rt := client.HTTPClient.Transport
	payload := func(name string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"identifiers":[{"type":"dns","value":"` + name + `"}]}`))
	}
	if _, err := rt.RoundTrip(orderFor(t, "photos.pub.example.org")); err == nil || !strings.Contains(err.Error(), "not served here") {
		t.Errorf("an order for a name not served: %v", err)
	}
	if rec.saw(payload("photos.pub.example.org")) {
		t.Error("an order for a name not served reached the CA")
	}
	_, _ = rt.RoundTrip(orderFor(t, "immich.pub.example.org"))
	if !rec.saw(payload("immich.pub.example.org")) {
		t.Error("an order for a name served did not reach the CA")
	}
}
