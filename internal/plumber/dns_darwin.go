package plumber

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// resolverDir is where macOS's resolver reads a file per domain it routes.
const resolverDir = "/etc/resolver"

// SetDomains writes a resolver file per domain naming servers and port, and
// one searching search, and removes dev's others; a file of the same name
// that is not dev's stays, and is said.
func (Darwin) SetDomains(dev string, servers []netip.Addr, port uint16, domains, search []string) error {
	return writeResolvers(resolverDir, dev, servers, port, domains, search)
}

// SetDNS makes servers the host's default resolvers, on port 53, with search
// its search domains, by a key of dev's in SystemConfiguration's dynamic
// store, or removes that key; /etc/resolver cannot say a default.
func (Darwin) SetDNS(dev string, servers []netip.Addr, search []string) error {
	out, err := runScutil(scutilDNS(dev, servers, search))
	if err != nil {
		return err
	}
	if out = strings.TrimSpace(out); out != "" && !(len(servers) == 0 && out == "No such key") {
		return fmt.Errorf("scutil: %s", out)
	}
	return nil
}

func runScutil(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
