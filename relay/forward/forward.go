// Package forward is the wire protocol of invite forwarding at a member
// relay, and its two clients: the inviting host, which waits at the relay,
// and the guest, which asks for it there. The relay's side is in package
// relay. See relay/forward.go there for why a relay can pass the bytes and
// learn nothing it could use against the handshake running over them.
package forward

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/nning/juist/internal/underlay"
)

const (
	HostPath  = "/juist/invite/host/"
	GuestPath = "/juist/invite/guest/"
	Upgrade   = "juist-invite-v1"

	// Label starts what a registering host signs.
	Label = "juist relay forward v1\x00"

	// Waiting tells a host it is registered and waits for a guest; Joined
	// tells both sides the other is on the line. To the host it is followed
	// by one length byte and the guest's address, for the host's own bounds
	// per source.
	Waiting byte = 1
	Joined  byte = 2

	dialTimeout = 10 * time.Second
	guestAnswer = 20 * time.Second
)

// ErrNotWaiting is a relay's answer that no host waits under the id asked
// for, as before the host has registered.
var ErrNotWaiting = errors.New("no invite waits at the relay under this id")

// Message is what a host signs to register id at the relay whose certificate
// hashes to certHash, answering the relay's nonce.
func Message(certHash [32]byte, id [16]byte, nonce [32]byte) []byte {
	msg := []byte(Label)
	msg = append(msg, certHash[:]...)
	msg = append(msg, id[:]...)
	return append(msg, nonce[:]...)
}

// A Relay is where a host waits: the addresses and certificate a member
// relay announces, and the public name it serves on 443, "" for none.
type Relay struct {
	Addrs      []netip.AddrPort
	CertHash   [32]byte
	ServerName string
	Name       string
}

// A Proxy is the HTTP proxy a connection to a relay's public name goes
// through, nil for none; a nil Proxy is none.
type Proxy func(host string) (*url.URL, error)

// Wait registers id at r as identity, which sign signs for, and blocks until
// a guest is joined to the connection or ctx ends. It returns the
// connection, carrying the guest's bytes from there, and the guest's address
// as the relay saw it.
func Wait(ctx context.Context, r Relay, id [16]byte, identity [32]byte, sign func([]byte) ([]byte, error)) (net.Conn, string, error) {
	c, br, err := dial(ctx, r.Addrs, HostPath+hex.EncodeToString(id[:]), &tls.Config{
		ServerName: r.ServerName,
		// The relay's certificate is self-signed, and its hash is what the
		// log's members announce; nothing else vouches for it.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the relay showed no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], r.CertHash[:]) != 1 {
				return errors.New("the relay's certificate is not the one it announced")
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
	}, dialTimeout)
	if err != nil {
		return nil, "", err
	}
	return hold(ctx, c, br, r.CertHash, id, identity, sign)
}

// WaitNamed is [Wait] at r's public name on 443, whose certificate a public
// CA issued, through proxy: how a host that reaches nothing but TLS on 443
// waits. It still proves itself for r's pinned certificate, which the relay
// checks against its own.
func WaitNamed(ctx context.Context, r Relay, id [16]byte, identity [32]byte, sign func([]byte) ([]byte, error),
	proxy Proxy) (net.Conn, string, error) {
	c, br, err := dialNamed(ctx, r.Name, HostPath+hex.EncodeToString(id[:]), proxy, dialTimeout)
	if err != nil {
		return nil, "", err
	}
	return hold(ctx, c, br, r.CertHash, id, identity, sign)
}

// hold runs a host's side of the protocol on c, once upgraded: the proof the
// relay asks for, then the wait for a guest.
func hold(ctx context.Context, c net.Conn, br *bufio.Reader, certHash [32]byte, id [16]byte, identity [32]byte,
	sign func([]byte) ([]byte, error)) (net.Conn, string, error) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(dialTimeout))
	var nonce [32]byte
	if _, err := io.ReadFull(br, nonce[:]); err != nil {
		c.Close()
		return nil, "", fmt.Errorf("the relay did not ask this device to prove itself: %w", err)
	}
	sig, err := sign(Message(certHash, id, nonce))
	if err != nil {
		c.Close()
		return nil, "", err
	}
	if _, err := c.Write(append(identity[:], sig...)); err != nil {
		c.Close()
		return nil, "", err
	}
	if b, err := br.ReadByte(); err != nil || b != Waiting {
		c.Close()
		return nil, "", errors.New("the relay refused to hold the invite for this device")
	}
	_ = c.SetDeadline(time.Time{})
	// Now wait, for as long as the invite is open.
	if b, err := br.ReadByte(); err != nil || b != Joined {
		c.Close()
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		return nil, "", errors.New("the relay ended the wait")
	}
	_ = c.SetDeadline(time.Now().Add(dialTimeout))
	n, err := br.ReadByte()
	var who []byte
	if err == nil {
		who = make([]byte, n)
		_, err = io.ReadFull(br, who)
	}
	if err != nil {
		c.Close()
		return nil, "", err
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, r: br}, string(who), nil
}

// Dial asks the relay at addr for the host waiting under id, and returns the
// connection once the host is on the line. The relay's certificate is not
// checked: the guest has no way to know it, and needs none, since the
// handshake that follows is keyed by the invite's secret.
func Dial(ctx context.Context, addr netip.AddrPort, id [16]byte) (net.Conn, error) {
	c, br, err := dial(ctx, []netip.AddrPort{addr}, GuestPath+hex.EncodeToString(id[:]),
		// The relay answers once the host's next connection is there, which
		// it waits some seconds for.
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, guestAnswer)
	if err != nil {
		return nil, err
	}
	return joined(ctx, c, br)
}

// DialNamed is [Dial] at the relay serving name on 443, through proxy, its
// certificate verified by WebPKI, as a name's can be.
func DialNamed(ctx context.Context, name string, id [16]byte, proxy Proxy) (net.Conn, error) {
	c, br, err := dialNamed(ctx, name, GuestPath+hex.EncodeToString(id[:]), proxy, guestAnswer)
	if err != nil {
		return nil, err
	}
	return joined(ctx, c, br)
}

// dialNamed opens TLS to name on 443, through proxy where it gives one, and
// upgrades to path.
func dialNamed(ctx context.Context, name, path string, proxy Proxy, answerIn time.Duration) (net.Conn, *bufio.Reader, error) {
	target := net.JoinHostPort(name, "443")
	var via *url.URL
	if proxy != nil {
		var err error
		if via, err = proxy(name); err != nil {
			return nil, nil, err
		}
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	raw, err := connect(dctx, target, via)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(dialTimeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return upgrade(ctx, tc, name, path, answerIn)
}

// connect opens TCP to target, by an HTTP CONNECT through via where set.
func connect(ctx context.Context, target string, via *url.URL) (net.Conn, error) {
	d := underlay.Dialer(dialTimeout)
	if via == nil {
		return d.DialContext(ctx, "tcp", target)
	}
	port := via.Port()
	if port == "" {
		port = map[string]string{"https": "443"}[via.Scheme]
		if port == "" {
			port = "80"
		}
	}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(via.Hostname(), port))
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if via.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: via.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		c = tc
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if via.User != nil {
		pass, _ := via.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(via.User.Username()+":"+pass)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	head := &headCap{r: c, left: maxResponseHead}
	br := bufio.NewReader(head)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("the proxy refused to connect to %s: %s", target, resp.Status)
	}
	if br.Buffered() > 0 {
		c.Close()
		return nil, errors.New("the proxy spoke before the relay")
	}
	return c, nil
}

// maxResponseHead bounds what a proxy's or a relay's answer may say before
// its body, which net/http reads without bound.
const maxResponseHead = 16 << 10

// headCap reads at most left bytes from r until lifted.
type headCap struct {
	r      io.Reader
	left   int
	lifted bool
}

var errLongHead = errors.New("an answer whose head is over 16 KiB")

func (h *headCap) Read(p []byte) (int, error) {
	if h.lifted {
		return h.r.Read(p)
	}
	if h.left <= 0 {
		return 0, errLongHead
	}
	n, err := h.r.Read(p[:min(len(p), h.left)])
	h.left -= n
	return n, err
}

// lift lets every later read through.
func (h *headCap) lift() { h.lifted = true }

// joined runs a guest's side of the protocol on c, once upgraded: the relay's
// word that the host is on the line.
func joined(ctx context.Context, c net.Conn, br *bufio.Reader) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(dialTimeout))
	if b, err := br.ReadByte(); err != nil || b != Joined {
		c.Close()
		return nil, errors.New("the relay has no inviting device waiting for this invite")
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, r: br}, nil
}

// dial opens TLS to the first of addrs that answers and upgrades to path.
func dial(ctx context.Context, addrs []netip.AddrPort, path string, cfg *tls.Config, answerIn time.Duration) (
	net.Conn, *bufio.Reader, error) {
	var lastErr error = errors.New("no address to reach the relay at")
	for _, a := range addrs {
		d := tls.Dialer{NetDialer: underlay.Dialer(dialTimeout), Config: cfg}
		c, err := d.DialContext(ctx, "tcp", a.String())
		if err != nil {
			lastErr = err
			continue
		}
		uc, br, err := upgrade(ctx, c, a.String(), path, answerIn)
		if err != nil {
			lastErr = err
			continue
		}
		return uc, br, nil
	}
	return nil, nil, lastErr
}

// upgrade asks the relay on c, as host, to take the connection over for path,
// waiting answerIn for its answer; it closes c where it fails.
func upgrade(ctx context.Context, c net.Conn, host, path string, answerIn time.Duration) (net.Conn, *bufio.Reader, error) {
	// The upgrade can wait on the relay for a while; ending ctx ends it.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(answerIn))
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: " +
		Upgrade + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		stop()
		c.Close()
		return nil, nil, err
	}
	head := &headCap{r: c, left: maxResponseHead}
	br := bufio.NewReader(head)
	resp, err := http.ReadResponse(br, nil)
	head.lift()
	if err != nil {
		stop()
		c.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		resp.Body.Close()
		stop()
		c.Close()
		if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(path, GuestPath) {
			return nil, nil, fmt.Errorf("the relay at %v: %w", host, ErrNotWaiting)
		}
		return nil, nil, fmt.Errorf("the relay at %v answered %s: %s", host, resp.Status, trimmed(body))
	}
	stop()
	if ctx.Err() != nil {
		c.Close()
		return nil, nil, ctx.Err()
	}
	_ = c.SetDeadline(time.Time{})
	return c, br, nil
}

func trimmed(b []byte) string {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return string(b)
}

// bufferedConn reads what the upgrade's reader already holds first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
