package plumber

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// anchorPath is the pf anchor juist's anchor name is loaded as: under
// com.apple, which macOS's /etc/pf.conf calls.
func anchorPath(name string) string { return "com.apple/juist." + name }

// macosPF holds pf on for the anchors, its state kept across helpers.
var macosPF = macPF{pfctl: runPfctl, state: lockDir + "/juistd.pf"}

func hold(user string, forward bool) error {
	if forward {
		return errors.New("forwarding: not on macOS")
	}
	return macosPF.hold(user)
}

func release(user string) error { return macosPF.release(user) }

func runPfctl(args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.String(), errOut.String(), fmt.Errorf("pfctl %v: %v: %s", args, err, bytes.TrimSpace(errOut.Bytes()))
	}
	return out.String(), errOut.String(), nil
}

// SetGuard keeps dev's overlay to it in pf, as Linux's in table does; where
// g holds no address, no longer.
func (Darwin) SetGuard(dev string, g GuardSpec) error {
	if len(g.Own) == 0 && len(g.Overlay) == 0 {
		return unguard(dev)
	}
	name := guardAnchor(dev)
	if err := hold(name, false); err != nil {
		return err
	}
	return loadAnchor(name, macGuardRules(dev, g))
}

// unguard flushes dev's guard and lets go of pf for it.
func unguard(dev string) error {
	name := guardAnchor(dev)
	return errors.Join(flushAnchor(name), release(name))
}

// SetEgress sends the host's traffic outside the overlay as e asks, juistd's
// own by the host's default routes.
func (Darwin) SetEgress(dev string, e EgressSpec, uid int) error {
	if e.Mode == EgressDirect {
		return errors.Join(setCapture(dev, nil), flushAnchor(egressAnchor(dev)), release(egressAnchor(dev)))
	}
	if err := hold(egressAnchor(dev), false); err != nil {
		return err
	}
	gw4, gw6 := gateways()
	// The guard first, so that nothing leaves outside the tunnel meanwhile.
	if err := loadAnchor(egressAnchor(dev), macEgressRules(dev, e, uid, gw4, gw6)); err != nil {
		return err
	}
	return setCapture(dev, e.Capture)
}
