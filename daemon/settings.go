package daemon

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// loadSettings reads the device's settings of 443 from home, leaving out
// what does not parse, as a file edited by hand may.
func loadSettings(home string, logf func(string, ...any)) (httpsOnly bool, proxy, relayName string) {
	_, err := os.Stat(filepath.Join(home, statedir.HTTPSOnlyFile))
	httpsOnly = err == nil
	read := func(name string, valid func(string) error) string {
		b, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				logf("daemon: reading %s: %v", name, err)
			}
			return ""
		}
		v := strings.TrimSpace(string(b))
		if err := valid(v); err != nil {
			logf("daemon: leaving out %s: %v", name, err)
			return ""
		}
		return v
	}
	proxy = read(statedir.ProxyFile, ipc.ValidProxy)
	relayName = read(statedir.RelayNameFile, func(v string) error {
		if v == "" {
			return nil
		}
		return types.ValidateHostName(v)
	})
	return httpsOnly, proxy, relayName
}

// setSettings records what req sets of the device's settings, once all of
// them may be set, and restarts the mesh once on those of 443 and multicast
// where they changed; DNS it hands the running mesh.
func (s *Service) setSettings(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.prefs
	if req.DNS != nil {
		next.DNSOff = !*req.DNS
	}
	if req.HTTPSOnly != nil {
		next.HTTPSOnly = *req.HTTPSOnly
	}
	if req.Proxy != nil {
		next.Proxy = *req.Proxy
	}
	if req.RelayName != nil {
		next.RelayName = *req.RelayName
	}
	if req.Multicast != nil {
		next.MulticastOff = !*req.Multicast
	}
	if req.Groups != nil {
		next.Groups = nil
		for _, g := range *req.Groups {
			a, err := ipc.ParseGroup(g)
			if err != nil {
				return err
			}
			if !slices.Contains(next.Groups, a) {
				next.Groups = append(next.Groups, a)
			}
		}
	}
	o := s.opts.Mesh
	if next.HTTPSOnly && !s.prefs.HTTPSOnly && o.TunName == "" && !o.Netstack {
		return errors.New(`HTTPS alone runs log sync in the tunnel, and juistd runs with --tun ""`)
	}
	// Turning multicast off and routing no groups take no device, so that
	// what one left kept elsewhere can be undone.
	if (req.Multicast != nil && *req.Multicast || req.Groups != nil && len(next.Groups) > 0) &&
		(o.TunName == "" || o.Netstack || runtime.GOOS == "android") {
		return errors.New("multicast takes a device of juistd's own")
	}
	if req.Groups != nil && len(next.Groups) > 0 && !routesGroups(o) {
		return errors.New("groups are routed into the device on Linux alone")
	}
	if err := writeSettings(s.opts.Home, req, next, s.prefs); err != nil {
		return err
	}

	prev := s.prefs
	s.prefs = next
	if s.mesh == nil {
		return nil
	}
	if next.HTTPSOnly != prev.HTTPSOnly || next.Proxy != prev.Proxy || next.RelayName != prev.RelayName ||
		s.carried(next) != s.carried(prev) {
		s.logf("daemon: restarting on this device's new settings")
		s.restartMeshLocked(nil, "new settings")
		return nil
	}
	if next.DNSOff != prev.DNSOff {
		s.mesh.SetPrefs(s.prefs)
		_ = s.mesh.Reconcile() // so that the status answered says what came of it
	}
	return nil
}

// writeSettings keeps in home what req sets, as next has it; where one
// fails, those written are put back as prev had them.
func writeSettings(home string, req *ipc.Request, next, prev Prefs) error {
	groups := func(p Prefs) string {
		var lines []string
		for _, g := range p.Groups {
			lines = append(lines, g.String())
		}
		return strings.Join(lines, "\n")
	}
	type file struct {
		set  bool
		name string
		flag bool // a flag file, else a text file
		on   func(Prefs) bool
		text func(Prefs) string
	}
	files := []file{
		{set: req.DNS != nil, name: statedir.DNSOffFile, flag: true, on: func(p Prefs) bool { return p.DNSOff }},
		{set: req.HTTPSOnly != nil, name: statedir.HTTPSOnlyFile, flag: true, on: func(p Prefs) bool { return p.HTTPSOnly }},
		{set: req.Multicast != nil, name: statedir.MulticastOffFile, flag: true, on: func(p Prefs) bool { return p.MulticastOff }},
		{set: req.Proxy != nil, name: statedir.ProxyFile, text: func(p Prefs) string { return p.Proxy }},
		{set: req.RelayName != nil, name: statedir.RelayNameFile, text: func(p Prefs) string { return p.RelayName }},
		{set: req.Groups != nil, name: statedir.GroupsFile, text: groups},
	}
	write := func(f file, p Prefs) error {
		if f.flag {
			return setFlagFile(home, f.name, f.on(p))
		}
		return setTextFile(home, f.name, f.text(p))
	}
	for i, f := range files {
		if !f.set {
			continue
		}
		if err := write(f, next); err != nil {
			// The one that failed too, which may have changed before it did.
			for _, done := range files[:i+1] {
				if done.set {
					_ = write(done, prev)
				}
			}
			return err
		}
	}
	return nil
}

// carried is what of p's multicast the mesh takes: whether it carries
// multicast, and the groups it routes, in order.
func (s *Service) carried(p Prefs) string {
	o := s.opts.Mesh
	o.Prefs = p
	if !carriesMulticast(o) {
		return "off"
	}
	if !routesGroups(o) {
		return "on"
	}
	gs := slices.SortedFunc(slices.Values(p.Groups), netip.Addr.Compare)
	return fmt.Sprint("on ", gs)
}

// routesGroups reports whether a device of opts's routes groups into it:
// one of Linux's own.
func routesGroups(o Options) bool {
	return o.TunName != "" && !o.Netstack && o.Plumber == nil && runtime.GOOS == "linux"
}

// setTextFile keeps v in name in home, durably, or no file where v is "".
func setTextFile(home, name, v string) error {
	if v == "" {
		return setFlagFile(home, name, false)
	}
	return statedir.WriteFilePrivate(filepath.Join(home, name), []byte(v+"\n"))
}

// loadGroups reads the groups routed into the device from home, leaving
// out a line that is no IPv4 multicast group.
func loadGroups(home string, logf func(string, ...any)) []netip.Addr {
	b, err := os.ReadFile(filepath.Join(home, statedir.GroupsFile))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logf("daemon: reading %s: %v", statedir.GroupsFile, err)
		}
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Fields(string(b)) {
		g, err := ipc.ParseGroup(line)
		if err != nil {
			logf("daemon: leaving out %s: %v", statedir.GroupsFile, err)
			continue
		}
		if slices.Contains(out, g) {
			continue
		}
		if len(out) == ipc.MaxGroups {
			logf("daemon: %s holds more than %d groups; leaving out the rest", statedir.GroupsFile, ipc.MaxGroups)
			break
		}
		out = append(out, g)
	}
	return out
}

// carriesMulticast reports whether a device of opts's carries multicast: one
// of its own, as the Android app's is not, and not turned off.
func carriesMulticast(opts Options) bool {
	return !opts.MulticastOff && opts.TunName != "" && !opts.Netstack && runtime.GOOS != "android"
}
