package relay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"tailscale.com/tailcfg"
)

// The relay's membership check reaches the DERP server through its admission
// controller hook, which posts each client's node key to a URL. There is no
// in-process hook, and the two shapes upstream offers — a query to a local
// tailscaled, and an HTTP admission controller — both assume a coordination
// server. So the hook is answered in this process, over a scheme registered on
// the default transport: no socket is opened, nothing listens, and a local
// user cannot turn the check into an oracle for who is a member.
//
// The hazard this carries is an upgrade one, and it is silent: if the DERP
// server ever stops consulting the hook, every non-member is admitted and
// nothing looks wrong. TestNonMemberCannotUseTheRelay is the guard, and it is
// the reason that test drives a real DERP client rather than calling
// admitRequest.
const admissionScheme = "juist-relay-admit"

var (
	registerOnce sync.Once

	admissionMu sync.Mutex
	admissions  = map[string]*Server{}
)

// admissionToken names one server's hook, so that two relays in one process —
// which is what the tests run — cannot answer for each other.
func admissionToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("relay: drawing an admission token: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func admissionURL(token string) string {
	return admissionScheme + "://" + token + "/admit"
}

func registerAdmission(token string, s *Server) {
	registerOnce.Do(func() {
		// A process that replaced the default transport is one this cannot
		// reach. Failing here is safe: the admission request then gets no
		// handler, the DERP server reads that as an error, and with
		// fail-open off every client is refused.
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			t.RegisterProtocol(admissionScheme, admissionTransport{})
		}
	})
	admissionMu.Lock()
	defer admissionMu.Unlock()
	admissions[token] = s
}

func unregisterAdmission(token string) {
	admissionMu.Lock()
	defer admissionMu.Unlock()
	delete(admissions, token)
}

// admissionTransport answers the DERP server's admission request from the
// membership check the relay was built with.
type admissionTransport struct{}

func (admissionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	admissionMu.Lock()
	s := admissions[req.URL.Host]
	admissionMu.Unlock()
	if s == nil {
		// A closed relay, or a stale token. Refusing is the only safe
		// answer: the caller treats an error as "do not admit".
		return nil, fmt.Errorf("relay: no relay is registered for admission token %q", req.URL.Host)
	}
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(req.Body, 4<<10))
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("relay: reading the admission request: %w", err)
		}
	}
	var ask tailcfg.DERPAdmitClientRequest
	if err := json.Unmarshal(body, &ask); err != nil {
		return nil, fmt.Errorf("relay: decoding the admission request: %w", err)
	}
	res, err := json.Marshal(tailcfg.DERPAdmitClientResponse{
		Allow: s.admitRequest(req.Context(), ask.NodePublic),
	})
	if err != nil {
		return nil, fmt.Errorf("relay: encoding the admission response: %w", err)
	}
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(res))),
		Request:    req,
	}, nil
}
