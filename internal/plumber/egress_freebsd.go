package plumber

import (
	"errors"
)

// SetEgress sends the host's traffic outside the overlay as e asks.
func (FreeBSD) SetEgress(dev string, e EgressSpec, uid int) error {
	if e.Mode == EgressDirect {
		return errors.Join(setCapture(dev, nil), flushAnchor(egressAnchor(dev)), release(egressAnchor(dev)))
	}
	if err := hold(egressAnchor(dev), false); err != nil {
		return err
	}
	gw4, gw6 := gateways()
	// Answers pass what comes in, which only juist's own ruleset, passing
	// everything, leaves them nothing to open; the host's own decides else.
	rules := e
	rules.Isolate = e.Isolate || !onlyJuists()
	// The guard first, so that nothing leaves outside the tunnel meanwhile.
	if err := loadAnchor(egressAnchor(dev), egressRules(dev, rules, uid, gw4, gw6)); err != nil {
		return err
	}
	return setCapture(dev, e.Capture)
}
