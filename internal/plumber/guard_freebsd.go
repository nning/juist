package plumber

import (
	"errors"
	"net/netip"
)

// SetGuard keeps dev's overlay to it in pf, which it has run, as Linux's
// in table does; where g holds no address, no longer.
func (FreeBSD) SetGuard(dev string, g GuardSpec) error {
	if len(g.Own) == 0 && len(g.Overlay) == 0 {
		return unguard(dev)
	}
	name := guardAnchor(dev)
	if err := hold(name, false); err != nil {
		return err
	}
	return loadAnchor(name, guardRules(dev, DeviceGroup, g))
}

// unguard flushes dev's guard and lets go of pf for it.
func unguard(dev string) error {
	name := guardAnchor(dev)
	return errors.Join(flushAnchor(name), release(name))
}

func (FreeBSD) HostAddrs() []netip.Addr { return hostAddrs() }
