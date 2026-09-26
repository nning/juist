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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
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

// Message is what a host signs to register id at the relay whose certificate
// hashes to certHash, answering the relay's nonce.
func Message(certHash [32]byte, id [16]byte, nonce [32]byte) []byte {
	msg := []byte(Label)
	msg = append(msg, certHash[:]...)
	msg = append(msg, id[:]...)
	return append(msg, nonce[:]...)
}

// A Relay is where a host waits: the addresses and certificate a member
// relay announces.
type Relay struct {
	Addrs      []netip.AddrPort
	CertHash   [32]byte
	ServerName string
}

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
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: cfg}
		c, err := d.DialContext(ctx, "tcp", a.String())
		if err != nil {
			lastErr = err
			continue
		}
		// The upgrade can wait on the relay for a while; ending ctx ends it.
		stop := context.AfterFunc(ctx, func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(answerIn))
		req := "GET " + path + " HTTP/1.1\r\nHost: " + a.String() + "\r\nConnection: Upgrade\r\nUpgrade: " +
			Upgrade + "\r\n\r\n"
		if _, err := io.WriteString(c, req); err != nil {
			stop()
			c.Close()
			lastErr = err
			continue
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			stop()
			c.Close()
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
			resp.Body.Close()
			stop()
			c.Close()
			lastErr = fmt.Errorf("the relay at %v answered %s: %s", a, resp.Status, trimmed(body))
			continue
		}
		stop()
		if ctx.Err() != nil {
			c.Close()
			return nil, nil, ctx.Err()
		}
		_ = c.SetDeadline(time.Time{})
		return c, br, nil
	}
	return nil, nil, lastErr
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
