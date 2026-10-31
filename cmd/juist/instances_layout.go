package main

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
	"go4.org/netipx"
)

// A hostLayout is where the packaged services keep their sockets and state
// and how an instance is started and stopped; tests move all of it.
type hostLayout struct {
	runDir   string   // the default's socket, juistd.sock; instance N's is in juistN beside it
	stateDir string   // the default's home; instance N's is juistN beside it
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
	return filepath.Join(filepath.Dir(l.runDir), instance.Name(n), filepath.Base(ipc.SystemSocket))
}

func (l *hostLayout) home(n int) string {
	if n == 0 {
		return l.stateDir
	}
	return filepath.Join(filepath.Dir(l.stateDir), instance.Name(n))
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
