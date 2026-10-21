package daemon

import (
	"maps"
	"os"
	"path/filepath"

	"github.com/nning/juist/internal/statedir"
)

// Prefs are the device's settings: its owner's and its operator's word.
type Prefs struct {
	// Exit is the exit node the owner chose, and ServeExit whether the
	// operator agreed to serve as one.
	Exit      ExitChoice
	ServeExit bool

	// ServeSubnets says the operator agreed to route the subnets the log
	// grants this device, and SubnetsOff that its owner routes none of its
	// peers'.
	ServeSubnets bool
	SubnetsOff   bool

	// ServePublished says the operator agreed to serve the names the log
	// publishes on this device, and ServeTo where those go, by label, whose
	// TLS juist ends; ServeMembers are the labels of ServeTo whose service
	// is for members alone.
	ServePublished bool
	ServeTo        map[string]string
	ServeMembers   map[string]bool

	// AcceptNames says the owner agreed that this device resolves the
	// public names the network points at members to them, and DNSOff has
	// juistd leave the host's DNS alone.
	AcceptNames bool
	DNSOff      bool

	// HTTPSOnly sends nothing but TLS to 443/tcp of the relays' public
	// names, and DNS for them: no LAN discovery, DHT, STUN or other UDP, so
	// every tunnel goes through a relay, and members are looked for at the
	// relays. It needs [Options.TunName] or [Options.Netstack], since log
	// sync runs in the tunnel. Proxy is the HTTP proxy it goes through, ""
	// for HTTPS_PROXY's. RelayName is the public DNS name this device's
	// relay serves on 443/tcp too, where the log makes it a relay, none where
	// empty. A running Daemon does not take these: the service starts a new
	// one.
	HTTPSOnly bool
	Proxy     string
	RelayName string
}

// LoadPrefs reads the settings kept in home, each in a file of its own,
// leaving out what does not parse.
func LoadPrefs(home string, logf func(string, ...any)) Prefs {
	var p Prefs
	var err error
	if p.Exit, err = LoadExitChoice(filepath.Join(home, statedir.ExitFile)); err != nil {
		logf("daemon: %v; internet traffic is refused until an exit node is chosen again", err)
		// Isolated too: the choice kept may have been.
		p.Exit = ExitChoice{Chosen: true, Unreadable: true, Isolate: true}
	}
	has := func(name string) bool {
		_, err := os.Stat(filepath.Join(home, name))
		return err == nil
	}
	p.ServeExit = has(statedir.ServeFile)
	p.ServeSubnets = has(statedir.SubnetServeFile)
	p.SubnetsOff = has(statedir.SubnetsFile)
	p.AcceptNames = has(statedir.NamesFile)
	p.DNSOff = has(statedir.DNSOffFile)
	p.ServePublished, p.ServeTo, p.ServeMembers = loadServeTo(home, logf)
	p.HTTPSOnly, p.Proxy, p.RelayName = loadSettings(home, logf)
	return p
}

// SetPrefs makes p the device's settings from the next reconcile on, but for
// those of 443 and the exit node chosen, which the mesh follows as it rotates
// and [Daemon.SetExitChoice] changes.
func (d *Daemon) SetPrefs(p Prefs) {
	d.mu.Lock()
	d.serveConsent = p.ServeExit
	d.subnetConsent, d.subnetsOff = p.ServeSubnets, p.SubnetsOff
	d.acceptNames = p.AcceptNames
	d.mu.Unlock()
	d.dnsOff.Store(p.DNSOff)
	d.pub.mu.Lock()
	d.pub.consent, d.pub.to, d.pub.members = p.ServePublished, maps.Clone(p.ServeTo), maps.Clone(p.ServeMembers)
	d.flagTerminatorLocked()
	d.pub.mu.Unlock()
	d.MarkDirty()
}
