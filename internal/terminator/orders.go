package terminator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// orderLocations gives an order's response the Location a CA leaves out of
// it. x/crypto/acme waits on an order still processing by the URL a finalize
// response carries in Location, which RFC 8555 does not ask for and Pebble
// does not send; without it, the wait posts to "" and no certificate comes.
type orderLocations struct {
	rt http.RoundTripper

	mu    sync.Mutex
	order map[string]string // by finalize URL and by order URL, the order's
}

func withOrderLocations(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &orderLocations{rt: rt, order: map[string]string{}}
}

func (o *orderLocations) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := o.rt.RoundTrip(req)
	if err != nil {
		return res, err
	}
	loc := res.Header.Get("Location")
	if loc == "" {
		o.mu.Lock()
		if order, ok := o.order[req.URL.String()]; ok {
			res.Header.Set("Location", order)
			loc = order
		}
		o.mu.Unlock()
	}
	if loc == "" || !strings.Contains(res.Header.Get("Content-Type"), "json") {
		return res, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return res, nil
	}
	var v struct{ Finalize string }
	if json.Unmarshal(body, &v) == nil && v.Finalize != "" {
		o.mu.Lock()
		o.order[v.Finalize], o.order[loc] = loc, loc
		o.mu.Unlock()
	}
	return res, nil
}

// servedOrders refuses, without asking the CA, an order for a name not
// served here: autocert renews a certificate it holds whatever its host
// policy says, so a name withdrawn would be ordered, and fail, every half hour.
type servedOrders struct {
	rt     http.RoundTripper
	served func(name string) bool
}

func (s servedOrders) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := s.rt
	if rt == nil {
		rt = http.DefaultTransport
	}
	if req.Method != http.MethodPost || req.Body == nil {
		return rt.RoundTrip(req)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	var jws struct{ Payload string }
	var order struct{ Identifiers []struct{ Value string } }
	if json.Unmarshal(body, &jws) == nil {
		if payload, err := base64.RawURLEncoding.DecodeString(jws.Payload); err == nil && json.Unmarshal(payload, &order) == nil {
			for _, id := range order.Identifiers {
				if !s.served(id.Value) {
					return nil, fmt.Errorf("terminator: %s is not served here, so not ordered", id.Value)
				}
			}
		}
	}
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(bytes.NewReader(body))
	return rt.RoundTrip(out)
}
