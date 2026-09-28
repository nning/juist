package main

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

func subnetFamily() family {
	return family{name: "juist subnet", intro: "Reach networks behind a device, or route this device's for the others.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: subnetList, forms: [][2]string{{"", "the subnets, and which this device uses"}}},
			{name: "serve", run: subnetServe, forms: [][2]string{
				{"serve", "route what the network grants this device;\nsets the host up with sudo where needed"},
				{"serve --stop", "stop, and undo that"},
			}},
			{name: "off", run: subnetOff, forms: [][2]string{{"off", "reach none of them through the network"}}},
			{name: "on", run: subnetOn, forms: [][2]string{{"on", "reach them again"}}},
		}, footer: `An admin grants a device a subnet: juist grant DEVICE 192.168.1.0/24. Every
member then reaches it through that device, but a member that reaches those
addresses by a route of its own, as on its LAN.`}
}

func cmdSubnet(a *app, args []string) error { return subnetFamily().run(a, args) }

func subnetList(a *app, args []string) error {
	s := spec{name: "juist subnet", args: "[SUBCOMMAND]", about: subnetFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	if listed, err := a.forEachNetwork(a.listSubnets); listed {
		return err
	}
	return a.listSubnets()
}

// listSubnets is "juist subnet" for one network.
func (a *app) listSubnets() error {
	if _, err := a.daemonStatus(); err != nil {
		return err
	}
	// A reader's status says not who routes what.
	if err := a.requireOperator(); err != nil {
		return err
	}
	st, err := a.restatus()
	if err != nil {
		return err
	}
	sub := cmp.Or(st.Subnets, &ipc.Subnets{})
	if len(sub.Routes) == 0 {
		a.ok("no subnets")
		a.hint("an admin grants one: juist grant DEVICE 192.168.1.0/24")
		return nil
	}
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PREFIX\tROUTER\tSTATE")
	for _, r := range sub.Routes {
		router := cmp.Or(r.Name, r.Router.ShortString())
		var state string
		switch {
		case r.Router == st.Self:
			router += " (this device)"
			state = a.selfSubnetState(sub, r)
		case r.InUse && r.Why != "":
			state = a.paint("32", "in use") + ", " + r.Why
		case r.InUse:
			state = a.paint("32", "in use")
		default:
			state = a.paint("33", "not in use: "+r.Why)
		}
		if reach := exitReach(st, r.Router); reach != "" && r.InUse {
			state += ", " + a.paint("33", "its router "+reach)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Prefix, router, state)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	switch {
	case sub.Off:
		a.hint("juist subnet on")
	case hasOwnSubnets(sub, st) && !sub.Consent:
		a.hint("juist subnet serve")
	}
	return nil
}

// selfSubnetState says what becomes of a subnet this device is granted.
func (a *app) selfSubnetState(sub *ipc.Subnets, r ipc.SubnetRoute) string {
	switch {
	case containsPrefix(sub.Serving, r.Prefix):
		return "routed"
	case sub.Consent:
		return a.paint("33", "not routed: "+sub.NotServing)
	}
	return a.paint("33", "not routed: not agreed to on this device")
}

func subnetServe(a *app, args []string) error {
	s := spec{name: "juist subnet serve", about: `
Route the subnets the network grants this device for its members. Where the
host does not forward yet, sudo sets that up and lets the traffic through
the firewall; --stop stops, and undoes it.`}
	fs := newFlags(s.name)
	stop := fs.Bool("stop", false, "stop routing")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("a subnet router runs on Linux alone so far")
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	sub := cmp.Or(st.Subnets, &ipc.Subnets{})
	dev := instance.Name(st.Instance)
	if *stop {
		if sub.Consent {
			if _, err := n.exit(ipc.Request{Command: ipc.CmdSubnet, ServeSubnets: new(bool)}); err != nil {
				return err
			}
			a.ok("stopped routing")
		} else {
			a.ok("unchanged: not routing")
		}
		// Forwarding stays for as long as this device serves as an exit node.
		if exitSetUp(a.system, dev) && (st.Exit == nil || !st.Exit.Consent) {
			return a.exitSetup("off", dev, "juist subnet serve")
		}
		return nil
	}
	if other, _ := a.otherEgress(st.Instance, false); other != nil {
		return fmt.Errorf("%s uses an exit node, which would take what this device routes\n"+
			"hint: juist exit off %s", other.label(), other.word())
	}
	if !exitSetUp(a.system, dev) || !forwarding(a.system) {
		if err := a.exitSetup("on", dev, "juist subnet serve"); err != nil {
			return err
		}
	}
	on := true
	after, err := n.exit(ipc.Request{Command: ipc.CmdSubnet, ServeSubnets: &on})
	if err != nil {
		return err
	}
	sub = cmp.Or(after.Subnets, &ipc.Subnets{})
	switch {
	case len(sub.Serving) > 0:
		a.ok("routing %s", listPrefixes(sub.Serving))
		a.warnDocker(sub.Serving)
	case !hasOwnSubnets(sub, st):
		a.ok("will route once an admin grants this device a subnet")
		a.hint("juist grant %s PREFIX", cmp.Or(st.SelfName, st.Self.ShortString()))
	default:
		return fmt.Errorf("not routing: %s", sub.NotServing)
	}
	return nil
}

// warnDocker warns of a routed prefix holding a Docker network: Docker drops
// what is routed to its containers from any device but their bridge.
func (a *app) warnDocker(routed []netip.Prefix) {
	if a.host.dockerNets == nil {
		return
	}
	nets := a.host.dockerNets()
	for _, bridge := range slices.Sorted(maps.Keys(nets)) {
		for _, n := range nets[bridge] {
			if slices.ContainsFunc(routed, n.Overlaps) {
				a.warn("docker shields its containers on %s (%s) from routed traffic", bridge, n)
				a.hint("docker lets it through on a network with gateway_mode_ipv4=nat-unprotected")
				return
			}
		}
	}
}

func containsPrefix(ps []netip.Prefix, p netip.Prefix) bool { return slices.Contains(ps, p) }

func hasOwnSubnets(sub *ipc.Subnets, st *ipc.Status) bool {
	for _, r := range sub.Routes {
		if r.Router == st.Self {
			return true
		}
	}
	return false
}

func subnetOff(a *app, args []string) error {
	return setAccepting(a, args, false, spec{name: "juist subnet off", about: `
Reach none of the network's subnets through it: the host routes them by
itself, as before. juist subnet on undoes it.`})
}

func subnetOn(a *app, args []string) error {
	return setAccepting(a, args, true, spec{name: "juist subnet on", about: `
Reach the network's subnets through it again.`})
}

func setAccepting(a *app, args []string, on bool, s spec) error {
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	word := map[bool]string{true: "subnets on", false: "subnets off"}[on]
	if off := st.Subnets != nil && st.Subnets.Off; off != on {
		a.ok("unchanged: %s", word)
		return nil
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if _, err := n.exit(ipc.Request{Command: ipc.CmdSubnet, AcceptSubnets: &on}); err != nil {
		return err
	}
	a.ok("%s", word)
	return nil
}

// subnetSummary is the status line of what this device makes of subnets,
// "" for nothing to say.
func subnetSummary(sub *ipc.Subnets, paint func(code, s string) string) string {
	if sub == nil {
		return ""
	}
	var parts []string
	used, unused := 0, 0
	for _, r := range sub.Routes {
		// This device's own grants are neither: they say neither.
		switch {
		case r.InUse:
			used++
		case r.Why != "":
			unused++
		}
	}
	if len(sub.Serving) > 0 {
		parts = append(parts, "this device routes "+listPrefixes(sub.Serving))
	} else if sub.Consent {
		parts = append(parts, paint("33", "this device routes none: "+sub.NotServing))
	}
	switch {
	case sub.Off:
		parts = append(parts, "off on this device")
	case used > 0 && unused > 0:
		parts = append(parts, fmt.Sprintf("%d in use, %s", used, paint("33", fmt.Sprintf("%d not", unused))))
	case used > 0:
		parts = append(parts, fmt.Sprintf("%d in use", used))
	case unused > 0:
		parts = append(parts, paint("33", fmt.Sprintf("%d not in use", unused)))
	}
	return strings.Join(parts, "; ")
}
