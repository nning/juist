package daemon

import (
	"errors"
	"os"
	"path/filepath"
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

// setSettings records what req sets of the device's settings, and restarts
// the mesh on those of 443 where they changed; DNS it hands the running mesh.
func (s *Service) setSettings(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.DNS != nil {
		if err := setFlagFile(s.opts.Home, statedir.DNSOffFile, !*req.DNS); err != nil {
			return err
		}
		s.prefs.DNSOff = !*req.DNS
		if s.mesh != nil {
			s.mesh.SetPrefs(s.prefs)
			_ = s.mesh.Reconcile() // so that the status answered says what came of it
		}
	}
	if req.HTTPSOnly == nil && req.Proxy == nil && req.RelayName == nil {
		return nil
	}
	httpsOnly, proxy, relayName := s.prefs.HTTPSOnly, s.prefs.Proxy, s.prefs.RelayName
	if req.HTTPSOnly != nil {
		httpsOnly = *req.HTTPSOnly
	}
	if req.Proxy != nil {
		proxy = *req.Proxy
	}
	if req.RelayName != nil {
		relayName = *req.RelayName
	}
	if httpsOnly && !s.prefs.HTTPSOnly && s.opts.Mesh.TunName == "" && !s.opts.Mesh.Netstack {
		return errors.New(`HTTPS alone runs log sync in the tunnel, and juistd runs with --tun ""`)
	}
	home := s.opts.Home
	if err := setFlagFile(home, statedir.HTTPSOnlyFile, httpsOnly); err != nil {
		return err
	}
	for _, f := range []struct{ name, v string }{{statedir.ProxyFile, proxy}, {statedir.RelayNameFile, relayName}} {
		if err := setTextFile(home, f.name, f.v); err != nil {
			return err
		}
	}
	if httpsOnly == s.prefs.HTTPSOnly && proxy == s.prefs.Proxy && relayName == s.prefs.RelayName {
		return nil
	}
	s.prefs.HTTPSOnly, s.prefs.Proxy, s.prefs.RelayName = httpsOnly, proxy, relayName
	if s.mesh != nil {
		s.logf("daemon: restarting on this device's new settings of 443")
		s.restartMeshLocked(nil, "new settings of 443")
	}
	return nil
}

// setTextFile keeps v in name in home, durably, or no file where v is "".
func setTextFile(home, name, v string) error {
	if v == "" {
		return setFlagFile(home, name, false)
	}
	return statedir.WriteFilePrivate(filepath.Join(home, name), []byte(v+"\n"))
}
