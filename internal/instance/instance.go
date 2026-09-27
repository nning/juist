// Package instance numbers the juist nodes one host runs, one per network.
// The default node is instance 0; the others are juist1 to juist9. The number
// decides everything two nodes on one host must not share — the TUN device,
// the ports, the routing table and the policy rule priorities — so each
// follows from it, and nothing needs a registry to stay apart.
package instance

import (
	"fmt"
	"strconv"
	"strings"
)

// Max is the highest instance number. The policy rules leave room for ten
// between juist's first priority and Tailscale's.
const Max = 9

// prefix begins every instance's name, which is also its TUN device's.
const prefix = "juist"

// PortStride is how far apart two instances' ports are: instance n listens
// on the default ports plus n times this, so that each one's ports are known
// before it starts and a firewall can be told them.
const PortStride = 10

// Name is instance n's name: juist0 for the default, which only its TUN
// device is called, and juist1 to juist9 for the others.
func Name(n int) string { return prefix + strconv.Itoa(n) }

// Parse reads the name of an instance other than the default.
func Parse(name string) (int, error) {
	digits, ok := strings.CutPrefix(name, prefix)
	n, err := strconv.Atoi(digits)
	switch {
	case !ok || err != nil || len(digits) != 1:
		return 0, fmt.Errorf("%q: want juist1 to juist%d", name, Max)
	case n == 0:
		return 0, fmt.Errorf("%s is the default instance, which runs without --instance", name)
	}
	return n, nil
}

// IsName reports whether name is an instance's other than the default.
func IsName(name string) bool {
	_, err := Parse(name)
	return err == nil
}

// IsDevice reports whether name is the TUN device of an instance, the
// default's included.
func IsDevice(name string) bool {
	return name == Name(0) || IsName(name)
}

// Port is port as instance n listens on it.
func Port(port uint16, n int) uint16 { return port + uint16(n*PortStride) }
