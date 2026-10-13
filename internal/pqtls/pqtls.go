// Package pqtls is the TLS between juist's own ends: 1.3 with
// X25519MLKEM768 alone, which every juist build offers, so that no session
// either end could be made to fall back opens to a quantum computer.
package pqtls

import "crypto/tls"

// Config sets c to require it, and returns c.
func Config(c *tls.Config) *tls.Config {
	c.MinVersion = tls.VersionTLS13
	c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	return c
}
