package conn

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"tailscale.com/feature"
)

// The data plane's DERP client asks one process-wide hook which proxy a
// relay's connection takes. It answers for the names of an HTTPS-only
// manager's relays alone: a member's own port, and every name another
// manager uses, is dialled directly.
var (
	proxiedMu   sync.Mutex
	proxied     = map[*tsManager]struct{}{}
	credentials = map[string]*url.Userinfo{} // by the proxy's host
)

// maxProxiedNames bounds the relay names a manager has the proxy answer for,
// those of relays dropped since included.
const maxProxiedNames = 64

// nowhere is a proxy no connection reaches, leaving the host by no wire.
var nowhere = &url.URL{Scheme: "http", Host: "0.0.0.0:0"}

func init() {
	feature.HookProxyFromEnvironment.Set(proxyFor)
	feature.HookProxyGetAuthHeader.Set(proxyAuth)
}

func registerProxied(m *tsManager) {
	proxiedMu.Lock()
	defer proxiedMu.Unlock()
	proxied[m] = struct{}{}
}

func unregisterProxied(m *tsManager) {
	proxiedMu.Lock()
	defer proxiedMu.Unlock()
	delete(proxied, m)
	if len(proxied) == 0 {
		clear(credentials)
	}
}

// proxyFor is the proxy the DERP client dials req's host through, or nil.
func proxyFor(req *http.Request) (*url.URL, error) {
	host := strings.ToLower(req.URL.Hostname())
	proxiedMu.Lock()
	var through func(string) (*url.URL, error)
	for m := range proxied {
		if m.proxy != nil && m.namesRelay(host) {
			through = m.proxy
			break
		}
	}
	proxiedMu.Unlock()
	if through == nil {
		return nil, nil
	}
	u, err := through(host)
	if err != nil {
		// Failing closed: the DERP client dials direct on an error.
		return nowhere, nil
	}
	if u == nil {
		return nil, nil
	}
	if u.User == nil {
		proxiedMu.Lock()
		delete(credentials, u.Host)
		proxiedMu.Unlock()
		return u, nil
	}
	// Without its user: the DERP client logs the URL of a proxy that
	// refuses. proxyAuth finds the credentials by the proxy's host.
	proxiedMu.Lock()
	credentials[u.Host] = u.User
	proxiedMu.Unlock()
	bare := *u
	bare.User = nil
	return &bare, nil
}

// namesRelay reports whether host is the name of a relay m has installed.
func (m *tsManager) namesRelay(host string) bool {
	for _, r := range *m.named.Load() {
		if r == host {
			return true
		}
	}
	return false
}

// proxyAuth is the Proxy-Authorization the user and password of the proxy at
// u's host make, as proxyFor last gave it.
func proxyAuth(u *url.URL) (string, error) {
	proxiedMu.Lock()
	user := credentials[u.Host]
	proxiedMu.Unlock()
	return ProxyAuthorization(&url.URL{User: user}), nil
}

// ProxyAuthorization is the Basic credentials of u's user, or "" for none.
func ProxyAuthorization(u *url.URL) string {
	if u == nil || u.User == nil {
		return ""
	}
	pass, _ := u.User.Password()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))
}
