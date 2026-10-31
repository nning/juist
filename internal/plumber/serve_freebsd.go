package plumber

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
)

// anchorRef is what the host's main pf ruleset calls juist's anchors by.
const anchorRef = `nat-anchor "juist/*"
rdr-anchor "juist/*"
anchor "juist/*"
`

const (
	// hostState keeps what juist changed of the host, and for which
	// devices, across helpers: forwarding as it was, and whether pf was
	// off before juist.
	hostState = lockDir + "/juistd.host"
	// forwardingKeys are the sysctls serving sets to 1; rfc6204w3 keeps
	// router advertisements taken while forwarding.
	forwardingKeys = "net.inet.ip.forwarding net.inet6.ip6.forwarding net.inet6.ip6.rfc6204w3"
)

var loaded struct {
	sync.Mutex
	rules map[string]string // the anchor last loaded, by device
}

// SetServe has the host serve dev as s asks, or no longer where s serves
// nothing.
func (FreeBSD) SetServe(dev string, s ServeSpec) error {
	if len(s.Sources) == 0 {
		return unserve(dev)
	}
	if err := hold(dev, true); err != nil {
		return err
	}
	ups, err := uplinks()
	if err != nil {
		return err
	}
	return loadAnchor(dev, serveRules(dev, s, ups))
}

// unserve flushes dev's anchor and lets go of what serving held for it.
func unserve(dev string) error {
	return errors.Join(flushAnchor(dev), release(dev))
}

// loadAnchor loads juist/name with rules where they changed, or where pf no
// longer holds them, as after its rules were reloaded: every reconcile gives
// them again, which must put back what someone took.
func loadAnchor(name, rules string) error {
	loaded.Lock()
	defer loaded.Unlock()
	if loaded.rules[name] == rules {
		if held, err := pfOutput("-a", "juist/"+name, "-s", "rules"); err == nil && strings.TrimSpace(held) != "" {
			return nil
		}
	}
	if err := pfctl(rules, "-a", "juist/"+name, "-f", "-"); err != nil {
		return err
	}
	if loaded.rules == nil {
		loaded.rules = map[string]string{}
	}
	loaded.rules[name] = rules
	return nil
}

func flushAnchor(name string) error {
	loaded.Lock()
	defer loaded.Unlock()
	delete(loaded.rules, name)
	if err := pfctl("", "-s", "info"); err != nil {
		return nil // no pf, so no anchor
	}
	anchor := "juist/" + name
	errs := []error{pfctl("", "-a", anchor, "-F", "rules"), pfctl("", "-a", anchor, "-F", "nat")}
	// -F all and -F Tables fail in an anchor on FreeBSD 15.1, so its tables go one by one.
	tables, err := pfOutput("-a", anchor, "-s", "Tables")
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) && bytes.Contains(ee.Stderr, []byte("Anchor does not exist")) {
		err = nil
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("pfctl -a %s -s Tables: %w", anchor, err))
	}
	for _, t := range strings.Fields(tables) {
		errs = append(errs, pfctl("", "-a", anchor, "-t", t, "-T", "kill"))
	}
	return errors.Join(errs...)
}

// uplinks are the host's devices but juist's and the loopback, with their
// first global address in each family.
func uplinks() ([]uplink, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []uplink
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || devicePattern.MatchString(ifc.Name) {
			continue
		}
		u := uplink{name: ifc.Name}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok || !ip.IsGlobalUnicast() && !ip.IsPrivate() {
				continue
			}
			ip = ip.Unmap()
			switch {
			case ip.Is4() && !u.addr4.IsValid():
				u.addr4 = ip
			case ip.Is6() && !u.addr6.IsValid() && !ip.IsPrivate():
				u.addr6 = ip
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// hold has pf run with juist's anchors for user, an anchor, and the host
// forward where forward is set, recording what each was before where
// nothing of juist's held it yet.
func hold(user string, forward bool) error {
	return withHostState(func(st *hostChanges) error {
		// Every time: someone may have turned pf off since, or loaded rules
		// that call no juist anchor.
		turnedOn, err := ensurePF()
		if err != nil {
			return err
		}
		if len(st.pfUsers) == 0 {
			// One still to be turned off, as after a failed release, stays so.
			st.pfOff = st.pfOff || turnedOn
		}
		if !slices.Contains(st.pfUsers, user) {
			st.pfUsers = append(st.pfUsers, user)
		}
		if !forward {
			return nil
		}
		if len(st.forwarders) == 0 && len(st.forwarding) == 0 {
			was, err := sysctls(strings.Fields(forwardingKeys))
			if err != nil {
				return err
			}
			st.forwarding = was
		}
		if !slices.Contains(st.forwarders, user) {
			st.forwarders = append(st.forwarders, user)
		}
		var set []string
		for _, k := range strings.Fields(forwardingKeys) {
			set = append(set, k+"=1")
		}
		return run("/sbin/sysctl", set...)
	})
}

// release lets go of user's hold, putting forwarding and pf back as they
// were once nothing holds them.
func release(user string) error {
	return withHostState(func(st *hostChanges) error {
		var errs []error
		if slices.Contains(st.forwarders, user) {
			st.forwarders = slices.DeleteFunc(st.forwarders, func(d string) bool { return d == user })
			if len(st.forwarders) == 0 && len(st.forwarding) > 0 {
				var set []string
				for k, v := range st.forwarding {
					set = append(set, k+"="+v)
				}
				slices.Sort(set)
				// Kept where it fails, for the next release, or clear, to do.
				if err := run("/sbin/sysctl", set...); err != nil {
					errs = append(errs, err)
				} else {
					st.forwarding = map[string]string{}
				}
			}
		}
		if slices.Contains(st.pfUsers, user) {
			st.pfUsers = slices.DeleteFunc(st.pfUsers, func(d string) bool { return d == user })
		}
		if len(st.pfUsers) == 0 && st.pfOff {
			switch {
			case !onlyJuists() || pfAtBoot():
				// A ruleset the host loaded since, or a pf it turns on
				// itself, is left be.
				st.pfOff = false
			default:
				// Off as found, or kept to be turned off where that fails.
				if err := errors.Join(pfctl("", "-F", "all"), pfctl("", "-d")); err != nil {
					errs = append(errs, err)
				} else {
					st.pfOff = false
				}
			}
		}
		return errors.Join(errs...)
	})
}

// errAnchors says what the host's pf.conf lacks for juist.
var errAnchors = errors.New(`pf's rules call no juist anchor first: nat-anchor "juist/*", rdr-anchor "juist/*" ` +
	`and anchor "juist/*" belong in /etc/pf.conf, before any rule that passes quick`)

// ensurePF has pf run and its main ruleset call juist's anchors, first. Off
// with no rules, it is turned on with that ruleset alone, which it reports;
// otherwise the host's own rules must call them already, and pass nothing
// quick before them, which the guard would then never see.
func ensurePF() (turnedOn bool, err error) {
	_ = run("/sbin/kldload", "-n", "pf")
	info, err := pfOutput("-s", "info")
	if err != nil {
		return false, err
	}
	off := strings.Contains(info, "Status: Disabled")
	nat, _ := pfOutput("-s", "nat")
	rules, _ := pfOutput("-s", "rules")
	if off && strings.TrimSpace(nat) == "" && strings.TrimSpace(rules) == "" {
		if err := pfctl(anchorRef, "-f", "-"); err != nil {
			return false, err
		}
		nat, rules = `nat-anchor "juist/*" all`+"\n"+`rdr-anchor "juist/*" all`, `anchor "juist/*" all`
	}
	if !callsAnchors(nat, rules) {
		return false, errAnchors
	}
	if off {
		if err := pfctl("", "-e"); err != nil {
			return false, err
		}
	}
	return off, nil
}

// Answers is why the anchors' answer rules would not decide: the host's own
// ruleset passes what comes in itself, its state carrying no reply-to.
func (FreeBSD) Answers() string {
	info, err := pfOutput("-s", "info")
	if err != nil {
		return "" // pf is not loaded: juist's ruleset will be the one
	}
	nat, _ := pfOutput("-s", "nat")
	rules, _ := pfOutput("-s", "rules")
	if strings.Contains(info, "Status: Disabled") && strings.TrimSpace(nat) == "" && strings.TrimSpace(rules) == "" ||
		onlyJuists() {
		return ""
	}
	return "the host's own pf rules pass what comes in, and their answers go by the routes, into the tunnel"
}

// pfAtBoot reports whether rc.conf has pf start with the host, which then
// is the host's to run.
func pfAtBoot() bool {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "/usr/sbin/sysrc", "-n", "pf_enable").Output()
	switch strings.ToLower(strings.TrimSpace(string(out))) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// onlyJuists reports whether pf's main ruleset is still the one juist loaded.
func onlyJuists() bool {
	nat, _ := pfOutput("-s", "nat")
	rules, _ := pfOutput("-s", "rules")
	return strings.TrimSpace(rules) == `anchor "juist/*" all` &&
		strings.Join(strings.Fields(nat), " ") == `nat-anchor "juist/*" all rdr-anchor "juist/*" all`
}

// hostChanges is what hostState records: the anchors using pf, the devices
// having the host forward, and what each was before.
type hostChanges struct {
	pfUsers    []string
	forwarders []string
	forwarding map[string]string
	pfOff      bool
}

// withHostState runs fn on the recorded host changes under a lock, and
// records what fn leaves, or removes the record where no device holds any.
func withHostState(fn func(*hostChanges) error) error {
	f, err := os.OpenFile(hostState+".lock", os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	st := &hostChanges{forwarding: map[string]string{}}
	if b, err := os.ReadFile(hostState); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(l, " ")
			switch k {
			case "pf":
				st.pfUsers = strings.Fields(v)
			case "forwarding":
				st.forwarders = strings.Fields(v)
			case "pf-off":
				st.pfOff = true
			case "was":
				if name, val, ok := strings.Cut(v, "="); ok {
					st.forwarding[name] = val
				}
			}
		}
	}
	err = fn(st)
	if len(st.pfUsers) == 0 && len(st.forwarders) == 0 && len(st.forwarding) == 0 && !st.pfOff {
		return errors.Join(err, removeIfThere(hostState))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pf %s\nforwarding %s\n", strings.Join(st.pfUsers, " "), strings.Join(st.forwarders, " "))
	if st.pfOff {
		b.WriteString("pf-off\n")
	}
	for k, v := range st.forwarding {
		fmt.Fprintf(&b, "was %s=%s\n", k, v)
	}
	// Whole or not at all: a crash half-way would lose what to put back.
	if werr := os.WriteFile(hostState+".new", []byte(b.String()), 0o600); werr != nil {
		return errors.Join(err, werr)
	}
	return errors.Join(err, os.Rename(hostState+".new", hostState))
}

func removeIfThere(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func sysctls(keys []string) (map[string]string, error) {
	out := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	for _, k := range keys {
		v, err := exec.CommandContext(ctx, "/sbin/sysctl", "-n", k).Output()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", k, err)
		}
		out[k] = strings.TrimSpace(string(v))
	}
	return out, nil
}

func pfctl(stdin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %v: %v: %s", args, err, bytes.TrimSpace(out))
	}
	return nil
}

func pfOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/pfctl", args...).Output()
	return string(out), err
}
