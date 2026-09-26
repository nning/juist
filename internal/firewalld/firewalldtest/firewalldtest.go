// Package firewalldtest runs a private message bus with stand-ins for
// firewalld and polkit on it, for tests of what asks them.
package firewalldtest

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

const (
	busName   = "org.fedoraproject.FirewallD1"
	objPath   = "/org/fedoraproject/FirewallD1"
	zoneIface = busName + ".zone"

	// ActionInfo and ActionConfigInfo are the polkit actions firewalld
	// checks its runtime queries against.
	ActionInfo       = busName + ".info"
	ActionConfigInfo = busName + ".config.info"
)

// A Bus is a private message bus on which firewalld's name is activatable,
// as it is on a real host.
type Bus struct {
	Addr    string
	started string
}

// Start runs a bus for the length of t, skipping t where there is no
// dbus-daemon.
func Start(t *testing.T) *Bus {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("no dbus-daemon")
	}
	dir := t.TempDir()
	services := filepath.Join(dir, "services")
	if err := os.Mkdir(services, 0o700); err != nil {
		t.Fatal(err)
	}
	b := &Bus{started: filepath.Join(dir, "started")}
	service := "[D-BUS Service]\nName=" + busName + "\nExec=/bin/touch " + b.started + "\n"
	if err := os.WriteFile(filepath.Join(services, busName+".service"), []byte(service), 0o600); err != nil {
		t.Fatal(err)
	}
	config := `<busconfig>
  <type>session</type>
  <listen>unix:path=` + filepath.Join(dir, "bus") + `</listen>
  <servicedir>` + services + `</servicedir>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>`
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("dbus-daemon printed no address: %v", err)
	}
	b.Addr = strings.TrimSpace(line)
	return b
}

// Connect opens a connection to the bus for the length of t.
func (b *Bus) Connect(t *testing.T) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(b.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// Started reports whether anything had the bus start firewalld. A start
// it began has left its mark by the time the call that caused it returns.
func (b *Bus) Started() bool {
	_, err := os.Stat(b.started)
	return err == nil
}

// A Firewalld answers as firewalld does and records what it was asked. Its
// answers are changed with [Firewalld.Set].
type Firewalld struct {
	conn *dbus.Conn

	mu sync.Mutex
	// Zones maps interfaces to zones, Default is the default zone and
	// Targets each zone's target. Ports holds "zone port/proto" and
	// Services "zone service" for each let in. Refuse answers every
	// question NotAuthorized.
	Zones    map[string]string
	Default  string
	Targets  map[string]string
	Ports    map[string]bool
	Services map[string]bool
	Refuse   bool
	calls    []string
}

// Firewalld claims firewalld's name on b.
func (b *Bus) Firewalld(t *testing.T) *Firewalld {
	t.Helper()
	f := &Firewalld{conn: b.Connect(t), Zones: map[string]string{}, Targets: map[string]string{},
		Ports: map[string]bool{}, Services: map[string]bool{}}
	refused := func() *dbus.Error {
		if f.Refuse {
			return &dbus.Error{Name: busName + ".NotAuthorizedException", Body: []any{"not authorized"}}
		}
		return nil
	}
	main := map[string]any{
		"getDefaultZone": func() (string, *dbus.Error) {
			defer f.record("getDefaultZone")()
			return f.Default, refused()
		},
	}
	zone := map[string]any{
		"getZoneOfInterface": func(iface string) (string, *dbus.Error) {
			defer f.record("getZoneOfInterface")()
			return f.Zones[iface], refused()
		},
		"getZoneSettings2": func(zone string) (map[string]dbus.Variant, *dbus.Error) {
			defer f.record("getZoneSettings2")()
			return map[string]dbus.Variant{"target": dbus.MakeVariant(f.Targets[zone])}, refused()
		},
		"queryPort": func(zone, port, proto string) (bool, *dbus.Error) {
			defer f.record("queryPort")()
			return f.Ports[zone+" "+port+"/"+proto], refused()
		},
		"queryService": func(zone, service string) (bool, *dbus.Error) {
			defer f.record("queryService")()
			return f.Services[zone+" "+service], refused()
		},
	}
	if err := f.conn.ExportMethodTable(main, objPath, busName); err != nil {
		t.Fatal(err)
	}
	if err := f.conn.ExportMethodTable(zone, objPath, zoneIface); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.conn.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("claiming firewalld's name: %v %v", reply, err)
	}
	return f
}

// record notes a call and holds mu until the handler returns.
func (f *Firewalld) record(method string) func() {
	f.mu.Lock()
	f.calls = append(f.calls, method)
	return f.mu.Unlock
}

// Set changes the answers.
func (f *Firewalld) Set(change func(f *Firewalld)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// Asked returns the methods called, in order.
func (f *Firewalld) Asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Stop gives firewalld's name up, as a firewalld that stopped does.
func (f *Firewalld) Stop(t *testing.T) {
	t.Helper()
	if _, err := f.conn.ReleaseName(busName); err != nil {
		t.Fatal(err)
	}
}

// A Polkit authorizes the actions it was started with and would authorize
// the rest only after a challenge, recording each check.
type Polkit struct {
	mu     sync.Mutex
	allow  map[string]bool
	checks []Check
}

// A Check is one question polkit was asked.
type Check struct {
	Subject, Action string
	Flags           uint32
}

type subject struct {
	Kind    string
	Details map[string]dbus.Variant
}

type result struct {
	Authorized, Challenge bool
	Details               map[string]string
}

// Polkit claims polkit's name on b.
func (b *Bus) Polkit(t *testing.T, allow ...string) *Polkit {
	t.Helper()
	p := &Polkit{allow: map[string]bool{}}
	for _, a := range allow {
		p.allow[a] = true
	}
	conn := b.Connect(t)
	methods := map[string]any{
		"CheckAuthorization": func(s subject, action string, _ map[string]string, flags uint32, _ string) (result, *dbus.Error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			name, _ := s.Details["name"].Value().(string)
			p.checks = append(p.checks, Check{Subject: s.Kind + ":" + name, Action: action, Flags: flags})
			return result{Authorized: p.allow[action], Challenge: !p.allow[action], Details: map[string]string{}}, nil
		},
	}
	if err := conn.ExportMethodTable(methods, "/org/freedesktop/PolicyKit1/Authority", "org.freedesktop.PolicyKit1.Authority"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.RequestName("org.freedesktop.PolicyKit1", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	return p
}

// Asked returns the checks made, in order.
func (p *Polkit) Asked() []Check {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Check(nil), p.checks...)
}
