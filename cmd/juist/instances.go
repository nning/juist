package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// A host in several networks runs one juistd per network: the packaged
// service, juistd.service, is instance 0, and juistd@juist1 … juistd@juist9
// run beside it (internal/instance). The CLI finds them by their sockets,
// picks the one a command is about — by --network, or because only one is
// in a network — and makes a new one where a device already in a network
// joins or founds another. See docs/13-multi-network-notes.md.

// A hostInstance is one of the host's juistds, running or set to.
type hostInstance struct {
	n  int
	st *ipc.Status // nil where no juistd answers
}

func (i hostInstance) name() string { return instance.Name(i.n) }

// label names the instance by its network, as a person knows it.
func (i hostInstance) label() string {
	switch {
	case i.st == nil:
		return i.name() + " (not running)"
	case i.st.InNetwork:
		return fmt.Sprintf("%s (%s)", i.st.NetworkName, i.name())
	}
	return i.name()
}

// word is what --network takes to name it: its network's name where that
// is what the person knows, else the instance's own.
func (i hostInstance) word() string {
	if i.st != nil && i.st.InNetwork {
		return shellWord(i.st.NetworkName)
	}
	return i.name()
}

// shellWord is s as one word of a command line.
func shellWord(s string) string {
	if shellSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// hostInstances lists the host's juistds that answer or are enabled, lowest
// first. It asks every socket once, until [app.hostChanged].
func (a *app) hostInstances() []hostInstance {
	if a.instances != nil {
		return *a.instances
	}
	var out []hostInstance
	for n := 0; n <= instance.Max; n++ {
		st := a.instanceStatus(n)
		if st != nil || a.host.enabled(n) {
			out = append(out, hostInstance{n: n, st: st})
		}
	}
	a.instances = &out
	return out
}

// hostChanged has the next [app.hostInstances] ask every socket again. A
// command calls it once it made or removed an instance, or one of them joined
// or left a network.
func (a *app) hostChanged() { a.instances = nil }

// instanceStatus asks instance n for its status, or returns nil where
// nothing answers on its socket.
func (a *app) instanceStatus(n int) *ipc.Status {
	resp, err := ipc.Call(a.host.socket(n), ipc.Request{Command: ipc.CmdStatus})
	if err != nil || resp.Status == nil {
		return nil
	}
	return resp.Status
}

// A purpose is what a command wants of the host's instances.
type purpose int

const (
	// forNetwork: the one instance in a network, or the one named.
	forNetwork purpose = iota
	// forFounding: one in no network, made where there is none; init.
	forFounding
	// forJoining: as forFounding; on a device in one network only, one the
	// network removed, which a join may take back into it.
	forJoining
)

// hostNode picks the host instance the command is about; found is false
// where none of them answers.
func (a *app) hostNode() (n node, found bool, err error) {
	// A command that reopens its node, as after a change, is still about the
	// instance it chose, as it answers now.
	if a.instance != nil {
		a.hostChanged()
		inst, err := a.instanceNumber(a.instance.n)
		if err != nil {
			return nil, false, err
		}
		return a.nodeOf(inst), true, nil
	}
	insts := a.hostInstances()
	if a.network != "" {
		inst, err := a.namedInstance(insts)
		if err != nil {
			return nil, false, err
		}
		return a.nodeOf(inst), true, nil
	}
	var running, down, inNetwork []hostInstance
	for _, i := range insts {
		switch {
		case i.st == nil:
			down = append(down, i)
		case i.st.InNetwork:
			inNetwork = append(inNetwork, i)
			running = append(running, i)
		default:
			running = append(running, i)
		}
	}
	if len(running) == 0 {
		return nil, false, nil
	}
	if a.purpose != forNetwork {
		if i := slices.IndexFunc(running, func(i hostInstance) bool { return !i.st.InNetwork }); i >= 0 {
			return a.nodeOf(running[i]), true, nil
		}
		// One that does not answer may be some network's device; it is
		// started, not stood in for.
		if len(down) > 0 {
			return nil, false, fmt.Errorf("%s is not running, so this device's networks are not all known\nhint: %s",
				unitOf(down[0].n), startCmd(down[0].n))
		}
		// On a device in one network, the one it was removed from: joining
		// it again is what a removed device does.
		if a.purpose == forJoining && len(inNetwork) == 1 && inNetwork[0].st.NotMember {
			return a.nodeOf(inNetwork[0]), true, nil
		}
		inst, err := a.newInstance(inNetwork)
		if err != nil {
			return nil, false, err
		}
		return a.nodeOf(inst), true, nil
	}
	// A command for one network: the one in a network, where no other may
	// be; one that does not answer may be.
	candidates := append(slices.Clone(inNetwork), down...)
	slices.SortFunc(candidates, func(x, y hostInstance) int { return x.n - y.n })
	switch {
	case len(candidates) == 0:
		return a.nodeOf(running[0]), true, nil
	case len(candidates) == 1 && candidates[0].st == nil:
		return nil, false, notRunning(candidates[0])
	case len(candidates) == 1:
		return a.nodeOf(candidates[0]), true, nil
	}
	return nil, false, a.ambiguous(candidates)
}

func notRunning(i hostInstance) error {
	return fmt.Errorf("%s is not running\nhint: %s", unitOf(i.n), startCmd(i.n))
}

func (a *app) nodeOf(i hostInstance) node {
	a.instance = &i
	n := &daemonNode{sock: a.host.socket(i.n), st: i.st, home: a.home}
	// The networks this host is a member of through its other instances,
	// which a join through this one must not join again.
	for _, other := range a.hostInstances() {
		if other.n != i.n && other.st != nil && other.st.InNetwork && !other.st.NotMember {
			n.elsewhere = append(n.elsewhere, other.st.Network)
		}
	}
	a.node = n
	return n
}

// namedInstance is the instance --network names: by its network's name, its
// genesis hash's start, or its own name.
func (a *app) namedInstance(insts []hostInstance) (hostInstance, error) {
	want := a.network
	var matches []hostInstance
	for _, i := range insts {
		if i.named(want) {
			matches = append(matches, i)
		}
	}
	switch len(matches) {
	case 0:
		if len(insts) == 0 {
			return hostInstance{}, fmt.Errorf("no juistd runs here, so no network %q\nhint: %s", want, enableCmd())
		}
		return hostInstance{}, fmt.Errorf("this device is in no network %q%s\nhint: %s", want,
			didYouMean(want, networkNames(insts)...), a.networksHint(insts))
	case 1:
		if matches[0].st == nil {
			return hostInstance{}, notRunning(matches[0])
		}
		return matches[0], nil
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.name()
	}
	return hostInstance{}, fmt.Errorf("two networks here are called %q\nhint: name the instance instead: %s",
		want, strings.Join(names, ", or "))
}

// networkNames are the names --network takes for insts.
func networkNames(insts []hostInstance) []string {
	var out []string
	for _, i := range insts {
		if i.st != nil && i.st.InNetwork {
			out = append(out, i.st.NetworkName)
		}
		out = append(out, i.name())
	}
	return out
}

// networksHint lists the networks this device is in, for an error.
func (a *app) networksHint(insts []hostInstance) string {
	var labels []string
	for _, i := range insts {
		if i.st == nil || i.st.InNetwork {
			labels = append(labels, i.label())
		}
	}
	if len(labels) == 0 {
		return "juist status"
	}
	return "this device is in " + strings.Join(labels, ", ")
}

// ambiguous is the error for a command that could be about any of the
// networks in: it asks nothing, and says how to name one.
func (a *app) ambiguous(in []hostInstance) error {
	var labels []string
	for _, i := range in {
		labels = append(labels, i.label())
	}
	name, args := cmp.Or(a.spec.name, "juist COMMAND"), a.spec.args
	if strings.Contains(args, "SUBCOMMAND") {
		args = ""
	}
	example := strings.TrimSpace(name + " " + in[0].word() + " " + args)
	return fmt.Errorf("this device is in %d networks: %s\nhint: name one first: %s",
		len(in), strings.Join(labels, ", "), example)
}

// hostScope reports whether the command's node is one of the host's
// instances, rather than one --socket or a home of its own names.
func (a *app) hostScope() bool {
	return !a.socketExplicit && !holdsNode(a.home) && !a.instanceStatusAt(ipc.SocketPath(a.home.path))
}

// namesNetwork reports whether word names one of the host's instances: by
// its network's name, its genesis hash's start, or its own name.
func (a *app) namesNetwork(word string) bool {
	if !a.hostScope() {
		return false
	}
	return slices.ContainsFunc(a.hostInstances(), func(i hostInstance) bool { return i.named(word) })
}

// named reports whether word names the instance.
func (i hostInstance) named(word string) bool {
	switch {
	case i.name() == word:
		return true
	case i.st == nil || !i.st.InNetwork:
		return false
	}
	return strings.EqualFold(i.st.NetworkName, word) ||
		len(word) >= 8 && strings.HasPrefix(fmt.Sprintf("%x", i.st.Network[:]), strings.ToLower(word))
}

// networkInstances are the instances a command may be about where none is
// named: those in a network, and those enabled that do not answer.
func (a *app) networkInstances() []hostInstance {
	var out []hostInstance
	for _, i := range a.hostInstances() {
		if i.st == nil || i.st.InNetwork {
			out = append(out, i)
		}
	}
	return out
}

// inSeveralNetworks reports whether a command could be about more than one
// of the host's networks.
func (a *app) inSeveralNetworks() bool { return a.hostScope() && len(a.networkInstances()) > 1 }

// forEachNetwork runs a listing command once for each network the device is
// in, each under a heading, where none is named and there are several; it
// reports whether it did.
func (a *app) forEachNetwork(run func() error) (bool, error) {
	if a.network != "" || !a.inSeveralNetworks() {
		return false, nil
	}
	for k, i := range a.networkInstances() {
		if k > 0 {
			a.printf("\n")
		}
		if i.st == nil {
			a.printf("%s · %s\n", a.bold(i.name()), a.paint("1;31", "not running"))
			a.hint("%s", startCmd(i.n))
			continue
		}
		if !a.listingHeads {
			a.printf("%s · %s\n", a.bold(i.st.NetworkName), a.dim(i.name()))
		}
		restore := a.within(i.name())
		a.listing = i.name()
		err := run()
		restore()
		if err != nil {
			return true, err
		}
	}
	return true, nil
}

// within turns the command to the network of the instance named network;
// restore turns it back, listing included.
func (a *app) within(network string) (restore func()) {
	was, node, inst, listing := a.network, a.node, a.instance, a.listing
	a.network, a.node, a.instance = network, nil, nil
	return func() { a.network, a.node, a.instance, a.listing = was, node, inst, listing }
}

// instanceNumber is instance n as it answers now.
func (a *app) instanceNumber(n int) (hostInstance, error) {
	st := a.instanceStatus(n)
	if st == nil {
		return hostInstance{}, fmt.Errorf("%s does not answer on %s", unitOf(n), a.host.socket(n))
	}
	return hostInstance{n: n, st: st}, nil
}
