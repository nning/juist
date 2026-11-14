package plumber

import (
	"errors"
	"net/netip"
)

// SetDomains refuses: resolvconf(8) routes no domains.
func (FreeBSD) SetDomains(dev string, servers []netip.Addr, port uint16, domains, search []string) error {
	if len(domains) == 0 {
		return nil
	}
	return errors.New("this host's resolver routes no domains")
}
