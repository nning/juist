package main

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// instanceLabel names instance n as the status of another instance mentions
// it: by its network, where it answers.
func (a *app) instanceLabel(n int) string {
	for _, i := range a.hostInstances() {
		if i.n == n {
			return i.label()
		}
	}
	return instance.Name(n)
}

// anyInstanceRuns reports whether a juistd answers on the host.
func (a *app) anyInstanceRuns() bool {
	return slices.ContainsFunc(a.hostInstances(), func(i hostInstance) bool { return i.st != nil })
}

// statusInstances are the host instances "juist status" reports on where it
// is not told which: those in a network, and those set to run that do not.
// It is nil where the node is not the host's — a --socket, a home's own.
func (a *app) statusInstances() []hostInstance {
	if a.network != "" || !a.hostScope() {
		return nil
	}
	return a.networkInstances()
}

// instanceStatusAt reports whether a juistd answers on sock.
func (a *app) instanceStatusAt(sock string) bool {
	_, err := ipc.Call(sock, ipc.Request{Command: ipc.CmdStatus})
	return err == nil
}

// printHostStatus is "juist status" for a host in several networks: each
// one's, apart, headed by the instance it runs in.
func (a *app) printHostStatus(insts []hostInstance, verbose bool) {
	for k, i := range insts {
		if k > 0 {
			a.printf("\n")
		}
		if i.st == nil {
			a.printDown(i, len(insts) > 1)
			continue
		}
		a.printStatusIn(i.st, i.name(), verbose)
		a.healthHint(i.st, i.name(), true)
	}
}

// printDown is the status of instance i, whose juistd does not answer, on a
// host in several networks where several says so.
func (a *app) printDown(i hostInstance, several bool) {
	a.printf("%s · %s\n", a.bold(i.name()), a.paint("1;31", "not running"))
	a.pointAtHealth(1, 0, i.name(), several) // juistd not running
}

// networkClaiming names a network this host is in whose IPv4 claims overlap
// p, or returns "". The node's own network does not count.
func (a *app) networkClaiming(p netip.Prefix) string {
	for _, i := range a.hostInstances() {
		if i.st == nil || !i.st.InNetwork || a.instance != nil && i.n == a.instance.n {
			continue
		}
		for _, c := range i.st.V4Claims {
			if c.Overlaps(p) {
				return fmt.Sprintf("%q (%v)", i.st.NetworkName, c)
			}
		}
	}
	return ""
}

// warnHostOverlap warns, after this device joined or founded a network, where
// that network's IPv4 range overlaps another the host is in: the higher of
// the two instances runs without IPv4 until one of them renumbers.
func (a *app) warnHostOverlap() {
	d := daemonOf(a.node)
	if a.instance == nil || d == nil {
		return
	}
	st, err := d.restatus()
	if err != nil || !st.InNetwork {
		return
	}
	a.hostChanged()
	for _, o := range a.hostInstances() {
		if o.n == a.instance.n || o.st == nil || !o.st.InNetwork || o.st.NotMember {
			continue
		}
		for _, mine := range st.V4Claims {
			if !slices.ContainsFunc(o.st.V4Claims, mine.Overlaps) {
				continue
			}
			yields, word := st.NetworkName, instance.Name(a.instance.n)
			if o.n > a.instance.n {
				yields, word = o.st.NetworkName, o.name()
			}
			a.warn("%q's IPv4 range overlaps %q's (%s) here; %q runs here without IPv4 until one of them "+
				"renumbers", st.NetworkName, o.st.NetworkName, o.name(), yields)
			a.hint("juist network renumber %s PREFIX", word)
			return
		}
	}
}

// otherNetworks names, quoted, the networks the host is in through instances
// other than the node's.
func (a *app) otherNetworks() []string {
	if !a.hostScope() {
		return nil
	}
	var out []string
	for _, i := range a.hostInstances() {
		if (a.instance == nil || i.n != a.instance.n) && i.st != nil && i.st.InNetwork && !i.st.NotMember {
			out = append(out, fmt.Sprintf("%q", i.st.NetworkName))
		}
	}
	return out
}
