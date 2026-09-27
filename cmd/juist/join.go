package main

import (
	"fmt"

	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func cmdJoin(a *app, args []string) error {
	s := spec{name: "juist join", args: "CODE", min: 1, max: 1, anyNetwork: true, about: `
Join a network with the code or link "juist invite" printed, such as
42-drumbeat-tolerance-glucose. The device verifies the network's log itself.
Under sudo on a device with no operator, the sudo user becomes its operator
unless --operator names another. A device in a network already joins the
next beside it, with a juistd of its own.`}
	fs := newFlags(s.name)
	name := fs.String("name", "", "`NAME` to join as (default: the hostname)")
	var operator optionalString
	fs.Var(&operator, "operator", "local `USER` who manages this device without sudo")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if *name != "" {
		if err := checkName("--name", *name); err != nil {
			return err
		}
	}
	// Checked here, before anything reaches the network, so a typo costs
	// nothing and is explained in terms of the code.
	if _, err := guest.ParseInvite(pos[0]); err != nil {
		return err
	}
	// On a device already in a network, the new one gets a juistd of its own.
	// $JUIST_NETWORK names a network the device is in, which an invite need
	// not be for; --network, given here, names the instance to join with.
	a.purpose = forJoining
	if a.networkFromEnv {
		a.network = ""
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	op, err := defaultOperator(operator, n.status())
	if err != nil {
		return err
	}
	var shown guest.Event // the last votes reported, which the host repeats as a keepalive
	_, err = n.join(a.ctx, pos[0], *name, op, func(e guest.Event) {
		switch e.Kind {
		case guest.Looking:
			a.printf("%s\n", a.dim("looking for the inviting device on the LAN"))
		case guest.Meeting:
			a.printf("%s\n", a.dim("no direct answer; meeting through the DHT (up to a minute)"))
		case guest.Connected:
			if e.Relayed {
				a.printf("connected to %v via relay\n", e.Addr)
			} else {
				a.printf("connected to %v\n", e.Addr)
			}
		case guest.Compare:
			a.printf("tell the inviting admin these words:\n")
			a.command("%s", e.Words)
		case guest.Waiting:
			if e.Quorum == 0 || e.Votes == shown.Votes && e.Quorum == shown.Quorum {
				break // the admin is still deciding, or nothing changed
			}
			shown = e
			a.printf("%s\n", a.dim(fmt.Sprintf("waiting for approval (%d of %d votes)", e.Votes, e.Quorum)))
		}
	})
	if err != nil {
		a.unmake()
		if a.ctx.Err() != nil {
			return fmt.Errorf("cancelled")
		}
		return err
	}
	a.node = nil
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	id, _, err := a.selfID()
	if err != nil {
		return err
	}
	a.reportJoined(auth.State(), id)
	return nil
}

func (a *app) reportJoined(state *log.State, id types.Identity) {
	self, _ := state.Node(id)
	a.ok("joined %q as %s", state.Network(), displayMember(self))
	a.field("Addresses", "%s", addrList(state, self.Identity))
	a.field("Devices", "%d", len(state.Nodes()))
	if st := a.node.status(); st != nil {
		if st.Operator != "" {
			a.field("Operator", "%s", st.Operator)
		}
		a.startWarning()
		a.warnHostOverlap()
		return
	}
	a.startHint()
}

// startHint says how to start juistd for the device in this home: the
// packaged service for its state directory, juistd on any other. juistd does
// not run next to admin keys, so a device kept in a keystore holding some has
// no command to give.
func (a *app) startHint() {
	keys, _ := a.home.adminKeys()
	switch {
	case a.home.path == systemHome:
		a.hint("sudo systemctl enable --now juistd")
	case len(keys) > 0:
		a.hint("no juistd runs for a keystore (%s); install the juist package", a.home.path)
	default:
		a.hint("juistd --home %s", a.home.path)
	}
}
