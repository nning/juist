//go:build !linux || android

package conn

import (
	"errors"
	"net/netip"
)

// RedirectLocalDNS takes the host's own DNS on port 53 to another port: on
// Linux alone.
func RedirectLocalDNS(to []netip.AddrPort) error {
	if len(to) == 0 {
		return nil
	}
	return errors.New("conn: redirecting the host's DNS is Linux's alone")
}
