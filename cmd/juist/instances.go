package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go4.org/netipx"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// A host in several networks runs one juistd per network: the packaged
// service, juistd.service, is instance 0, and juistd@juist1 … juistd@juist9
// run beside it (internal/instance). The CLI finds them by their sockets,
// picks the one a command is about — by --network, or because only one is
// in a network — and makes a new one where a device already in a network
// joins or founds another. See docs/13-multi-network-notes.md.

// A hostLayout is where the packaged services keep their sockets and state
// and how an instance is started and stopped; tests move all of it.
type hostLayout struct {
	runDir   string   // sockets: juistd.sock, and juistN.sock for the others
	stateDir string   // the default's home, holding the others' as juistN
	wantsDir string   // an enabled instance has its unit linked here
	unitDirs []string // where instanceUnit may be installed
	systemd  string   // exists while systemd runs the host; "" for always
	// instanceUnit is what runs another network's instance, and enabledBy,
	// where set, says whether instance n starts with the host.
	instanceUnit string
	enabledBy    func(n int) bool

	// start enables and starts instance n, stop stops and disables it, and
	// firewall lets its device through the host firewall ("allow") or
	// takes that back ("revoke").
	start, stop func(ctx context.Context, n int) error
	firewall    func(ctx context.Context, action string, n int) error

	// exitScript, ingressScript and serveScript are the package's
	// exit-node.sh, ingress.sh and serve.sh, "" for none; answers says
	// whether a service just started takes connections at an address.
	exitScript, ingressScript, serveScript string
	answers                                func(ctx context.Context, addr string) error
	// relayScript is the package's relay.sh, which lets juistd bind 443 for
	// its relay, "" where juistd needs no help to; relayGrant is the file it
	// leaves while it does.
	relayScript, relayGrant string
	// answersTLS says whether what answers at addr ends TLS.
	answersTLS func(ctx context.Context, addr string) error
	// terminatorOn says whether the terminator's service is enabled and
	// running, so that serveScript need not be run; nil for unknown.
	// terminatorStarts says whether systemd starts it once juistd needs it,
	// and juistd then stops it, so that serveScript is never run; nil for
	// never.
	terminatorOn, terminatorStarts func(ctx context.Context) bool
	// caaWait is how long a terminator just started may take to have an
	// ACME account, which the CAA records name, and terminatorWait to say
	// where it listens; zero for not waiting.
	caaWait, terminatorWait time.Duration
	// dockerNets are the host's Docker bridges' networks, by bridge.
	dockerNets func() map[string][]netip.Prefix
	// firewalled says whether the host firewall keeps TCP to port from
	// arriving on device; nil for none known.
	firewalled func(ctx context.Context, device string, port uint16) (blocked, unsure bool)
}

var dockerBridge = regexp.MustCompile(`^br-[0-9a-f]{12}$`)

// dockerNets are the networks of Docker's bridges, docker0 and br-<id>.
func dockerNets() map[string][]netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := map[string][]netip.Prefix{}
	for _, ifc := range ifs {
		if ifc.Name != "docker0" && !dockerBridge.MatchString(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if p, ok := netipx.FromStdIPNet(n); ok {
					out[ifc.Name] = append(out[ifc.Name], p.Masked())
				}
			}
		}
	}
	return out
}

func (l *hostLayout) socket(n int) string {
	if n == 0 {
		return filepath.Join(l.runDir, filepath.Base(ipc.SystemSocket))
	}
	return filepath.Join(l.runDir, instance.Name(n)+".sock")
}

func (l *hostLayout) home(n int) string {
	if n == 0 {
		return l.stateDir
	}
	return filepath.Join(l.stateDir, instance.Name(n))
}

// homeOf is the instance whose home path is.
func (l *hostLayout) homeOf(path string) (int, bool) {
	for n := 0; n <= instance.Max; n++ {
		if filepath.Clean(path) == filepath.Clean(l.home(n)) {
			return n, true
		}
	}
	return 0, false
}

// enabled reports whether instance n is set to start with the host.
func (l *hostLayout) enabled(n int) bool {
	if l.enabledBy != nil {
		return l.enabledBy(n)
	}
	if n == 0 {
		return fileExists(l.stateDir)
	}
	return fileExists(filepath.Join(l.wantsDir, unitOf(n)))
}

// canMakeInstances reports whether instances can be started here: systemd
// runs the host, and the package's instance unit is installed.
func (l *hostLayout) canMakeInstances() bool {
	if l.systemd != "" && !fileExists(l.systemd) {
		return false
	}
	return slices.ContainsFunc(l.unitDirs, func(d string) bool { return fileExists(filepath.Join(d, l.instanceUnit)) })
}

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
// first. It asks every socket once per invocation.
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

// hostNode picks the host instance the command is about, and returns nil
// where none of them answers.
func (a *app) hostNode() (node, error) {
	// A command that reopens its node, as after a change, is still about the
	// instance it chose, as it answers now.
	if a.instance != nil {
		a.instances = nil
		inst, err := a.instanceNumber(a.instance.n)
		if err != nil {
			return nil, err
		}
		return a.nodeOf(inst), nil
	}
	insts := a.hostInstances()
	if a.network != "" {
		inst, err := a.namedInstance(insts)
		if err != nil {
			return nil, err
		}
		return a.nodeOf(inst), nil
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
		return nil, nil
	}
	if a.purpose != forNetwork {
		if i := slices.IndexFunc(running, func(i hostInstance) bool { return !i.st.InNetwork }); i >= 0 {
			return a.nodeOf(running[i]), nil
		}
		// One that does not answer may be some network's device; it is
		// started, not stood in for.
		if len(down) > 0 {
			return nil, fmt.Errorf("%s is not running, so this device's networks are not all known\nhint: %s",
				unitOf(down[0].n), startCmd(down[0].n))
		}
		// On a device in one network, the one it was removed from: joining
		// it again is what a removed device does.
		if a.purpose == forJoining && len(inNetwork) == 1 && inNetwork[0].st.NotMember {
			return a.nodeOf(inNetwork[0]), nil
		}
		inst, err := a.newInstance(inNetwork)
		if err != nil {
			return nil, err
		}
		return a.nodeOf(inst), nil
	}
	// A command for one network: the one in a network, where no other may
	// be; one that does not answer may be.
	candidates := append(slices.Clone(inNetwork), down...)
	slices.SortFunc(candidates, func(x, y hostInstance) int { return x.n - y.n })
	switch {
	case len(candidates) == 0:
		return a.nodeOf(running[0]), nil
	case len(candidates) == 1 && candidates[0].st == nil:
		return nil, notRunning(candidates[0])
	case len(candidates) == 1:
		return a.nodeOf(candidates[0]), nil
	}
	return nil, a.ambiguous(candidates)
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
		a.network, a.node, a.instance, a.listing = i.name(), nil, nil, i.name()
		err := run()
		a.network, a.node, a.instance, a.listing = "", nil, nil, ""
		if err != nil {
			return true, err
		}
	}
	return true, nil
}

// newInstance makes another instance for a network beside those in, having
// asked where the host is not root's to change without sudo.
func (a *app) newInstance(in []hostInstance) (hostInstance, error) {
	var labels []string
	for _, i := range in {
		labels = append(labels, fmt.Sprintf("%q", i.st.NetworkName))
	}
	already := "this device is in " + strings.Join(labels, " and ")
	if !a.host.canMakeInstances() {
		return hostInstance{}, fmt.Errorf("%s, and another network needs %s, which "+
			"the juist package installs\nhint: or leave %s first: juist reset %s --force", already, instanceNeed,
			labels[0], in[0].word())
	}
	if a.asRoot() {
		n, err := a.makeInstance(operatorChoice{})
		if err != nil {
			return hostInstance{}, err
		}
		a.made = n
		a.printf("%s\n", a.dim(fmt.Sprintf("%s; this network gets a juistd of its own, %s", already, instance.Name(n))))
		return a.instanceNumber(n)
	}
	if !a.interactive && !a.yes {
		hint := "run it with sudo"
		if a.purpose == forFounding {
			hint = "add --yes, which runs sudo for it"
		}
		return hostInstance{}, fmt.Errorf("%s; another network beside it takes a juistd of its own, which "+
			"takes sudo to start\nhint: %s", already, hint)
	}
	if !a.yes {
		ok, err := a.ask(a.ctx, question{text: already + "; start a juistd for this network beside it (sudo)?",
			yes: true})
		if err != nil {
			return hostInstance{}, err
		}
		if !ok {
			return hostInstance{}, errAborted
		}
	}
	args := []string{"__instance", "new"}
	if me, err := user.Current(); err == nil {
		args = append(args, "--operator="+me.Username)
	}
	var out strings.Builder
	if err := a.sudo(args, &out); err != nil {
		return hostInstance{}, err
	}
	n, err := instance.Parse(strings.TrimSpace(out.String()))
	if err != nil {
		return hostInstance{}, fmt.Errorf("sudo juist __instance new answered %q", strings.TrimSpace(out.String()))
	}
	a.made = n
	a.printf("%s\n", a.dim(fmt.Sprintf("this network gets a juistd of its own, %s", instance.Name(n))))
	return a.instanceNumber(n)
}

// sudo runs this juist again under sudo with args, its output to out, or to
// the terminal where out is nil.
func (a *app) sudo(args []string, out *strings.Builder) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		// FreeBSD's base system has none.
		return errors.New("this takes root, and there is no sudo here\nhint: run it as root")
	}
	cmd := exec.CommandContext(a.ctx, "sudo", append([]string{self}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.out, a.errOut
	if out != nil {
		cmd.Stdout = out
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo juist %s: %w", strings.Join(args[:min(len(args), 2)], " "), err)
	}
	return nil
}

// instanceNumber is instance n as it answers now.
func (a *app) instanceNumber(n int) (hostInstance, error) {
	a.instances = nil
	st := a.instanceStatus(n)
	if st == nil {
		return hostInstance{}, fmt.Errorf("%s does not answer on %s", unitOf(n), a.host.socket(n))
	}
	return hostInstance{n: n, st: st}, nil
}

// instanceStartWait bounds how long a new instance may take to answer.
const instanceStartWait = 15 * time.Second

// makeInstance starts the lowest free instance and appoints op its
// operator: one that neither answers nor is enabled, with no network in a
// home left behind. One that fails to come up is taken back. It needs root.
func (a *app) makeInstance(op operatorChoice) (int, error) {
	n := 0
	for c := 1; c <= instance.Max && n == 0; c++ {
		if a.instanceStatus(c) == nil && !a.host.enabled(c) && !fileExists(filepath.Join(a.host.home(c), logDir, "anchor")) {
			n = c
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("this host runs %d juistds already, the most it may: one per network", instance.Max+1)
	}
	undo := func() {
		ctx, cancel := context.WithTimeout(context.Background(), instanceStartWait)
		defer cancel()
		_ = a.host.stop(ctx, n)
		_ = os.RemoveAll(a.host.home(n))
	}
	if err := a.host.start(a.ctx, n); err != nil {
		undo()
		return 0, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, instanceStartWait)
	defer cancel()
	for a.instanceStatus(n) == nil {
		select {
		case <-ctx.Done():
			undo()
			return 0, fmt.Errorf("%s did not answer on %s\nhint: %s", unitOf(n), a.host.socket(n), logCmd(n))
		case <-time.After(100 * time.Millisecond):
		}
	}
	// As the package does for juist0 at install: log sync runs in the
	// tunnel, and a firewall that drops it there loses removals too.
	if err := a.host.firewall(a.ctx, "allow", n); err != nil {
		a.warn("letting %s through the firewall: %v", instance.Name(n), err)
	}
	if op.set {
		if _, err := ipc.Call(a.host.socket(n), ipc.Request{Command: ipc.CmdSetOperator, SetOperator: true,
			OperatorUID: op.uid}); err != nil {
			undo()
			return 0, fmt.Errorf("appointing %s's operator: %w", instance.Name(n), err)
		}
	}
	return n, nil
}

// removeInstance stops instance n for good and deletes its home, which a
// reset has emptied of everything but the device's fresh keys. One that
// still holds a network is left alone. It needs root.
func (a *app) removeInstance(n int) error {
	if n == 0 {
		return errors.New("the default juistd stays; juist reset leaves it in no network")
	}
	if st := a.instanceStatus(n); st != nil && st.InNetwork {
		return fmt.Errorf("%s still holds %q\nhint: juist reset %s --force first", instance.Name(n),
			st.NetworkName, instance.Name(n))
	}
	// One that does not answer is judged by its home: a log in it is a
	// network's, and its keys that network's device.
	if fileExists(filepath.Join(a.host.home(n), logDir, "anchor")) {
		return fmt.Errorf("%s holds a network's log in %s\nhint: %s, then juist reset %s --force",
			instance.Name(n), a.host.home(n), startCmd(n), instance.Name(n))
	}
	if err := a.host.stop(a.ctx, n); err != nil {
		return err
	}
	if err := a.host.firewall(a.ctx, "revoke", n); err != nil {
		a.warn("revoking %s's firewall rule: %v", instance.Name(n), err)
	}
	home := a.host.home(n)
	if err := os.RemoveAll(home); err != nil {
		return fmt.Errorf("removing %s: %w", home, err)
	}
	// The next network this number goes to must not read as a juistd that
	// swapped networks under a keystore that saw this one: this keystore,
	// root's, and the sudo user's.
	_ = removeIfPresent(a.home.daemonPinPath(a.host.socket(n)))
	a.forgetSudoUsersPin(n)
	return nil
}

// forgetSudoUsersPin removes, from the keystore of the user who ran sudo, the
// record of which network instance n's socket held: the next network the
// number goes to would otherwise read there as a juistd swapping networks
// under it. The keystore of root, which ran the reset, forgot it already.
// A keystore that $JUIST_HOME moves elsewhere is not found.
func (a *app) forgetSudoUsersPin(n int) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	h := &home{path: filepath.Join(u.HomeDir, ".config", "juist")}
	if fileExists(h.path) {
		_ = removeIfPresent(h.daemonPinPath(a.host.socket(n)))
	}
}

// unmake removes the instance this invocation made for a network it then
// did not get into, so that a mistyped code leaves no juistd behind.
func (a *app) unmake() {
	if a.made == 0 {
		return
	}
	// One that got a network after all, by a step that failed only later,
	// stays: it is that network's device now.
	if st := a.instanceStatus(a.made); st != nil && st.InNetwork {
		return
	}
	n := a.made
	a.made = 0
	if a.asRoot() {
		if err := a.removeInstance(n); err != nil {
			a.warn("%s stays, in no network: %v", unitOf(n), err)
		}
		return
	}
	// sudo -n: the one just asked for is likely still valid, and a second
	// password prompt after a failure would be one too many.
	self, err := os.Executable()
	if err == nil {
		err = exec.Command("sudo", "-n", self, "__instance", "remove", instance.Name(n)).Run()
	}
	if err != nil {
		a.hint("%s stays, in no network, for the next one; %s removes it", unitOf(n), disableCmd(n))
	}
}

// runFirewallScript lets a juist device through the host firewall, or takes
// that back; see packaging/firewall.sh. Without the package's script there
// is no firewall juist knows how to change.
func runFirewallScript(ctx context.Context, action string, n int) error {
	const script = "/usr/lib/juist/firewall.sh"
	if !fileExists(script) {
		return nil
	}
	if out, err := exec.CommandContext(ctx, script, action, instance.Name(n)).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s %s: %v: %s", script, action, instance.Name(n), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// cmdInstance is "juist __instance", which the CLI runs under sudo to make
// or remove an instance for a user who is not root: new prints the new
// instance's name, remove NAME removes one. It is not a command of its own.
func cmdInstance(a *app, args []string) error {
	if !a.asRoot() {
		return errors.New("juist __instance needs root")
	}
	switch {
	case len(args) >= 1 && args[0] == "new":
		op := operatorChoice{}
		for _, arg := range args[1:] {
			name, ok := strings.CutPrefix(arg, "--operator=")
			if !ok {
				return fmt.Errorf("juist __instance new: unexpected %q", arg)
			}
			var err error
			if op, err = operatorFor(name); err != nil {
				return err
			}
		}
		n, err := a.makeInstance(op)
		if err != nil {
			return err
		}
		a.printf("%s\n", instance.Name(n))
		return nil
	case len(args) == 2 && args[0] == "remove":
		n, err := instance.Parse(args[1])
		if err != nil {
			return err
		}
		return a.removeInstance(n)
	}
	return errors.New("usage: juist __instance new [--operator=USER] | remove NAME")
}

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
func (a *app) printHostStatus(insts []hostInstance) {
	for k, i := range insts {
		if k > 0 {
			a.printf("\n")
		}
		if i.st == nil {
			a.printf("%s · %s\n", a.bold(i.name()), a.paint("1;31", "not running"))
			a.hint("%s", startCmd(i.n))
			continue
		}
		a.printStatusIn(i.st, i.name())
		a.network, a.node, a.instance = i.name(), nil, nil
		a.adminNotes(i.st, true)
		a.network, a.node, a.instance = "", nil, nil
	}
}

// dropInstance removes instance n after a reset left it in no network: as
// root at once, else with sudo once asked, or told to by yes. Where it may
// not ask, the instance stays: a juistd in no network does no harm, and the
// next network takes it.
func (a *app) dropInstance(n int, yes bool) error {
	if a.asRoot() {
		if err := a.removeInstance(n); err != nil {
			return err
		}
		a.ok("removed %s", unitOf(n))
		return nil
	}
	if !a.interactive && !yes {
		a.hint("%s stays, in no network, for the next one; %s removes it", unitOf(n), disableCmd(n))
		return nil
	}
	if !a.interactive {
		// Told to, with nobody to type a password: sudo -n, or the hint.
		self, err := os.Executable()
		if err == nil {
			err = exec.Command("sudo", "-n", self, "__instance", "remove", instance.Name(n)).Run()
		}
		if err != nil {
			a.hint("%s stays, in no network, for the next one; %s removes it", unitOf(n), disableCmd(n))
			return nil
		}
		a.ok("removed %s", unitOf(n))
		return nil
	}
	if !yes {
		ok, err := a.ask(a.ctx, question{text: fmt.Sprintf("remove %s too (sudo)?", unitOf(n)), yes: true})
		if err != nil || !ok {
			return err
		}
	}
	if err := a.sudo([]string{"__instance", "remove", instance.Name(n)}, nil); err != nil {
		return err
	}
	a.ok("removed %s", unitOf(n))
	return nil
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
	if a.instance == nil || a.node == nil {
		return
	}
	st, err := a.node.restatus()
	if err != nil || st == nil || !st.InNetwork {
		return
	}
	a.instances = nil
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
