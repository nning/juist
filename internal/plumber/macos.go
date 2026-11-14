//go:build unix

// What macOS's helper writes, here so that every platform tests it.

package plumber

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// searchFile is dev's file that carries the search domains alone, under a
// name no network's domain takes.
func searchFile(dev string) string { return "search." + dev + ".juist-device" }

// resolverHeader opens every file the helper writes for dev, and tells it
// from files it must not touch.
func resolverHeader(dev string) string { return "# juistd " + dev + "\n" }

// writeResolvers writes into dir, as macOS's /etc/resolver takes them, a
// file per domain naming servers and port, and one searching search, and
// removes dev's others. A file of the same name that is another device's of
// juist's stays its, as a reverse zone two networks share, whose other
// network then gets no reverse names (M29 review 8); one not juist's stays
// too, and is said.
func writeResolvers(dir, dev string, servers []netip.Addr, port uint16, domains, search []string) error {
	want := map[string]string{}
	if len(domains) > 0 {
		var b strings.Builder
		b.WriteString(resolverHeader(dev))
		for _, s := range servers {
			b.WriteString("nameserver " + s.String() + "\n")
		}
		b.WriteString("port " + strconv.Itoa(int(port)) + "\n")
		for _, d := range domains {
			want[d] = b.String()
		}
		if len(search) > 0 {
			want[searchFile(dev)] = resolverHeader(dev) + "search " + strings.Join(search, " ") + "\n"
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var errs []error
	for name, text := range want {
		switch owner, err := ownerOf(root, name); {
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			errs = append(errs, err)
			continue
		case err == nil && owner != dev && owner != "":
			continue
		case err == nil && owner != dev:
			errs = append(errs, fmt.Errorf("%s/%s is not juist's", dir, name))
			continue
		}
		if err := root.WriteFile(name, []byte(text), 0o644); err != nil {
			errs = append(errs, err)
		}
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, e := range entries {
		if _, kept := want[e.Name()]; kept || !e.Type().IsRegular() {
			continue
		}
		if owner, err := ownerOf(root, e.Name()); err == nil && owner == dev {
			if err := root.Remove(e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// ownerOf is the device whose helper wrote name in root, "" for a file no
// helper wrote or that is no regular file.
func ownerOf(root *os.Root, name string) (string, error) {
	fi, err := root.Lstat(name)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", nil
	}
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	dev, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "# juistd ")
	if !ok || !strings.HasSuffix(line, "\n") {
		return "", nil
	}
	return dev, nil
}

// scutilDNS is the scutil(8) script that makes servers the host's default
// resolvers, with search, under dev's key, or removes the key where there
// are none. Servers are addresses and search domains plain names, as the
// helper checked them.
func scutilDNS(dev string, servers []netip.Addr, search []string) string {
	key := "State:/Network/Service/juist-" + dev + "/DNS"
	if len(servers) == 0 {
		return "remove " + key + "\nquit\n"
	}
	var b strings.Builder
	b.WriteString("d.init\n")
	b.WriteString("d.add SearchOrder # 100000\n")
	b.WriteString("d.add ServerAddresses *")
	for _, s := range servers {
		b.WriteString(" " + s.String())
	}
	// An empty supplemental domain makes it a default resolver.
	b.WriteString("\nd.add SupplementalMatchDomains * \"\"\n")
	if len(search) > 0 {
		b.WriteString("d.add SearchDomains * " + strings.Join(search, " ") + "\n")
	}
	b.WriteString("set " + key + "\nquit\n")
	return b.String()
}

var pfTokenLine = regexp.MustCompile(`(?m)^Token : (\d+)\s*$`)

// pfToken is the reference pfctl -E printed, by which pfctl -X gives it back,
// "" where it printed none.
func pfToken(out string) string {
	if m := pfTokenLine.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// A macPF holds pf on, under macOS's own rules, for juist's anchors: by a
// token pfctl -E gives, recorded in state with the anchors holding it.
type macPF struct {
	// pfctl runs pfctl with args, saying what it printed on each stream.
	pfctl func(args ...string) (stdout, stderr string, err error)
	state string
}

// errAppleAnchors says what the host's pf rules lack for juist.
var errAppleAnchors = errors.New(`pf's rules call no com.apple anchor first: nat-anchor, rdr-anchor and anchor "com.apple/*" ` +
	`belong in /etc/pf.conf, as macOS ships it, before any rule that passes quick`)

// hold has pf run, with rules that call juist's anchors, for user, an
// anchor. Every time: someone may have turned pf off since, which voids the
// token, or loaded rules that call none. A token voided while another
// program turned pf on again is kept: pf may give the next program the same
// value, so no check of it is sure (M29 review 5).
func (p macPF) hold(user string) error {
	return p.withState(func(users []string, token string) ([]string, string, error) {
		if err := p.ensureAnchors(); err != nil {
			return users, token, err
		}
		info, _, err := p.pfctl("-s", "info")
		if err != nil {
			return users, token, err
		}
		if token == "" || !strings.Contains(info, "Status: Enabled") {
			out, errOut, err := p.pfctl("-E")
			if err != nil {
				return users, "", err
			}
			if token = pfToken(out + errOut); token == "" {
				return users, "", fmt.Errorf("pfctl -E gave no token: %s", strings.TrimSpace(out+errOut))
			}
		}
		if !slices.Contains(users, user) {
			users = append(users, user)
		}
		return users, token, nil
	})
}

// release lets go of user's hold, giving pf's reference back once nothing
// holds it. A token pf no longer knows, as after pfctl -d, is forgotten.
func (p macPF) release(user string) error {
	return p.withState(func(users []string, token string) ([]string, string, error) {
		users = slices.DeleteFunc(users, func(u string) bool { return u == user })
		if len(users) > 0 || token == "" {
			return users, token, nil
		}
		_, _, _ = p.pfctl("-X", token)
		return users, "", nil
	})
}

// ensureAnchors has pf's main ruleset call com.apple's anchors first: an
// empty one is given /etc/pf.conf, as macOS loads it at boot; another is
// the host's, and refused where it calls none or passes quick before them.
func (p macPF) ensureAnchors() error {
	rules, _, err := p.pfctl("-s", "rules")
	if err != nil {
		return err
	}
	nat, _, _ := p.pfctl("-s", "nat")
	if strings.TrimSpace(rules) == "" && strings.TrimSpace(nat) == "" {
		if _, _, err := p.pfctl("-f", "/etc/pf.conf"); err != nil {
			return err
		}
		rules, _, _ = p.pfctl("-s", "rules")
		nat, _, _ = p.pfctl("-s", "nat")
	}
	if !callsAnchorsUnder(nat, rules, `"com.apple/*"`) {
		return errAppleAnchors
	}
	return nil
}

// withState runs fn on the recorded holders and token under a lock, and
// records what fn leaves, or removes the record where nothing is held.
func (p macPF) withState(fn func(users []string, token string) ([]string, string, error)) error {
	f, err := os.OpenFile(p.state+".lock", os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	var users []string
	var token string
	if b, err := os.ReadFile(p.state); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(l, " ")
			switch k {
			case "pf":
				users = strings.Fields(v)
			case "token":
				token = strings.TrimSpace(v)
			}
		}
	}
	users, token, err = fn(users, token)
	if len(users) == 0 && token == "" {
		if rerr := os.Remove(p.state); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			err = errors.Join(err, rerr)
		}
		return err
	}
	text := fmt.Sprintf("pf %s\ntoken %s\n", strings.Join(users, " "), token)
	if werr := os.WriteFile(p.state+".new", []byte(text), 0o600); werr != nil {
		return errors.Join(err, werr)
	}
	return errors.Join(err, os.Rename(p.state+".new", p.state))
}

// macGuardRules is the guard's anchor on macOS: no interface groups there,
// so the overlay comes in by dev alone.
func macGuardRules(dev string, g GuardSpec) string { return guardRules(dev, dev, g) }

// daemonAnchor passes the traffic of dev's daemon: pf runs com.apple's
// anchors in the order of their names, and this one's comes before every
// device's, whose exit node would block another network's daemon.
func daemonAnchor(dev string) string { return "daemon_" + dev }

// macDaemonRules is daemonAnchor's anchor for dev's daemon of uid; not on
// dev, where its own exit node routes what the daemon sends out of it.
func macDaemonRules(dev string, uid int) string {
	return fmt.Sprintf("pass out quick on ! %s proto { tcp udp } all user %d no state\n", dev, uid)
}

// macEgressRules is an exit node's anchor on macOS. Its answer rules stay
// out: the host's own pf rules always surround the anchor, and pf's last
// match would pass what they block, as on FreeBSD over a ruleset not juist's.
func macEgressRules(dev string, e EgressSpec, uid int, gw4, gw6 gateway) string {
	e.Isolate = true
	return egressRules(dev, e, uid, gw4, gw6)
}
