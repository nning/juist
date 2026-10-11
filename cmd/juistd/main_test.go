package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/ingress"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/internal/terminator"
	"github.com/nning/juist/ipc"
)

// Help is short, lists every option, and takes its defaults from the daemon
// rather than from text that could drift from them.
func TestHelpListsEveryOptionWithItsDefault(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out, io.Discard); err != nil {
		t.Fatalf("--help: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		fmt.Sprintf("(default %d)", daemon.DefaultListenPort),
		fmt.Sprintf("(default %d)", daemon.DefaultGossipPort),
		fmt.Sprintf("(default %d)", daemon.DefaultRelayPort),
		"(default " + shortDuration(daemon.DefaultFreshnessTTL) + ")",
		"(default " + strings.Join(rendezvous.DefaultSTUN, ",") + ")",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("help lacks %q:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "\n"); n > 30 {
		t.Errorf("help is %d lines", n)
	}
	if _, err := parse([]string{"--help"}, io.Discard); !errors.Is(err, errHelp) {
		t.Fatalf("parse --help: %v", err)
	}
	// Every option parse knows is listed, under both its spellings.
	opts := map[string]bool{}
	for _, o := range optionOrder {
		opts[o.long] = true
		if !strings.Contains(got, fmt.Sprintf("-%c, --%s", o.short, o.long)) {
			t.Errorf("help lacks -%c, --%s", o.short, o.long)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if _, rest, ok := strings.Cut(line, ", --"); ok {
			if name, _, _ := strings.Cut(rest, " "); !opts[name] && name != "help" {
				t.Errorf("--%s is in help but not in optionOrder", name)
			}
		}
	}
}

// Bad arguments are errors in the CLI's form: lowercase, no trailing period,
// and a usage line where the arguments themselves are wrong.
func TestBadArgumentsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		want  string
		usage bool
	}{
		{[]string{"--no-such"}, "unknown option --no-such", true},
		{[]string{"-home", "/x"}, "as --home", true},
		{[]string{"start"}, `unexpected argument "start"`, true},
		{[]string{"--port", "70000"}, "a port must be below 65536", false},
		{[]string{"-f", "1h"}, "--freshness-ttl must be at least 2h", false},
		{[]string{"--instance", "juist0"}, "juist0 is the default instance", false},
		{[]string{"-i", "work"}, "want juist1 to juist9", false},
		{[]string{"--instance", "juist10"}, "want juist1 to juist9", false},
	} {
		_, err := parse(tc.args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("juistd %q: %v, want %q", tc.args, err, tc.want)
			continue
		}
		lines := strings.Split(err.Error(), "\n")
		if first := lines[0]; strings.ToLower(first[:1]) != first[:1] && first[0] != '-' || strings.HasSuffix(first, ".") {
			t.Errorf("juistd %q: %q is not in the CLI's form", tc.args, first)
		}
		if hasUsage := lines[len(lines)-1] == synopsis; hasUsage != tc.usage {
			t.Errorf("juistd %q: %q, usage line %v, want %v", tc.args, err, hasUsage, tc.usage)
		}
	}
}

// Options reach the service as given, and ports are held to only where named.
func TestOptionsReachTheService(t *testing.T) {
	t.Setenv("JUIST_HOME", "/var/lib/juist-test")
	o, err := parse(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	m := o.service.Mesh
	if o.service.Home != "/var/lib/juist-test" || m.ListenPort != daemon.DefaultListenPort || !m.PortFallback ||
		!slices.Equal(m.STUN, rendezvous.DefaultSTUN) || m.TunName != "juist0" || m.FreshnessTTL != daemon.DefaultFreshnessTTL {
		t.Errorf("defaults: %+v", o.service)
	}
	o, err = parse([]string{"-H", "/tmp/h", "-p", "5000", "--no-stun", "-t", "", "-v", "--stun", "a:1"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	m = o.service.Mesh
	if o.service.Home != "/tmp/h" || m.ListenPort != 5000 || m.PortFallback || m.STUN != nil || m.TunName != "" ||
		!o.verbose {
		t.Errorf("given: %+v", o.service)
	}
	o, _ = parse([]string{"--stun", " a:1, ,b:2 "}, io.Discard)
	if !slices.Equal(o.service.Mesh.STUN, []string{"a:1", "b:2"}) {
		t.Errorf("--stun: %q", o.service.Mesh.STUN)
	}
}

// A helper's bounds reach it, and are a helper's alone.
func TestTheBoundsAreAHelpers(t *testing.T) {
	t.Setenv("JUIST_HOME", "/var/lib/juist-test")
	o, err := parse([]string{"--helper", "ingress", "-M", "40000", "-m", "512"}, io.Discard)
	if err != nil || o.maxConns != 40000 || o.maxPerSource != 512 {
		t.Errorf("an ingress's bounds: %d, %d, %v", o.maxConns, o.maxPerSource, err)
	}
	o, err = parse([]string{"--helper", "tls"}, io.Discard)
	if err != nil || o.maxConns != 0 || o.maxPerSource != ingress.DefaultMaxPerSource {
		t.Errorf("a terminator's defaults: %d, %d, %v", o.maxConns, o.maxPerSource, err)
	}
	for _, args := range [][]string{
		{"--max-conns", "100"},
		{"--helper", "tls", "--max-per-source", "10"},
		{"--helper", "ingress", "--max-per-source", "0"},
		{"--helper", "ingress", "--max-conns", "2000000"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%q: taken", args)
		}
	}
	if ingress.DefaultMaxConns < 16384 || ingress.DefaultMaxPerSource < 256 || terminator.DefaultMaxConns < 8192 {
		t.Error("the bounds a launch day needs are lowered")
	}
}

// An instance takes everything two nodes on a host must not share from its
// number, and what is given explicitly stays as given.
func TestAnInstanceTakesItsOwnDeviceAndPorts(t *testing.T) {
	t.Setenv("JUIST_HOME", "/var/lib/juist-test")
	o, err := parse([]string{"--instance", "juist3"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	m := o.service.Mesh
	if o.service.Home != "/var/lib/juist-test/juist3" || m.Instance != 3 || m.TunName != "juist3" ||
		m.ListenPort != daemon.DefaultListenPort+30 || m.GossipPort != daemon.DefaultGossipPort+30 ||
		m.RelayPort != daemon.DefaultRelayPort+30 || !m.PortFallback {
		t.Errorf("--instance juist3: home %s, %+v", o.service.Home, m)
	}
	o, err = parse([]string{"-i", "juist2", "-H", "/h", "-t", "tun9", "-p", "5000"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	m = o.service.Mesh
	if o.service.Home != "/h" || m.Instance != 2 || m.TunName != "tun9" || m.ListenPort != 5000 ||
		m.GossipPort != daemon.DefaultGossipPort+20 || m.PortFallback {
		t.Errorf("--instance juist2 with overrides: home %s, %+v", o.service.Home, m)
	}
	if o, _ := parse(nil, io.Discard); o.service.Mesh.Instance != 0 {
		t.Errorf("without --instance the node is instance %d", o.service.Mesh.Instance)
	}
}

// The start report says what happened on stdout, and what needs attention as
// warnings and hints on stderr.
func TestTheStartReportSpeaksLikeTheCLI(t *testing.T) {
	for _, tc := range []struct {
		st        ipc.Status
		tun       string
		out, errs []string
	}{
		{ipc.Status{Derived: ipc.Derived{SelfName: "laptop"}}, "juist0", []string{"juistd: laptop ("}, []string{"hint: juist create, or juist join CODE"}},
		{ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", NotMember: true}}, "juist0",
			[]string{`network "home"`}, []string{"warning: not a member", "hint: rejoin with a new invite"}},
		{ipc.Status{InNetwork: true, SchemaAlarm: "schema 9", Addrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}, ListenPort: 41643, Derived: ipc.Derived{NetworkName: "home", Alarm: "fork"}}, "",
			[]string{"overlay     198.18.0.1", "device      none", "udp/41643"}, []string{"warning: schema 9", "warning: fork"}},
		{ipc.Status{InNetwork: true, StartError: "open /dev/net/tun: permission denied", Derived: ipc.Derived{NetworkName: "home"}}, "juist0",
			nil, []string{"warning: tunnels cannot start yet, retrying: open", fmt.Sprintf("hint: "+permHint, "juist0")}},
	} {
		var out, errs bytes.Buffer
		report(&out, &errs, tc.st, tc.tun)
		for _, w := range tc.out {
			if !strings.Contains(out.String(), w) {
				t.Errorf("stdout lacks %q:\n%s", w, out.String())
			}
		}
		for _, w := range tc.errs {
			if !strings.Contains(errs.String(), w) {
				t.Errorf("stderr lacks %q:\n%s", w, errs.String())
			}
		}
		for _, l := range strings.Split(strings.TrimSpace(errs.String()), "\n") {
			if l != "" && !strings.HasPrefix(l, "warning: ") && !strings.HasPrefix(l, "hint: ") {
				t.Errorf("stderr line %q is neither a warning nor a hint", l)
			}
		}
		if all := out.String() + errs.String(); strings.Contains(all, "ALARM") || strings.Contains(all, "NOT A") {
			t.Errorf("shouts:\n%s", all)
		}
	}
}

// juistd(8) lists every option juistd takes, from the flags themselves.
func TestTheManPageListsEveryOption(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"__manpage"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	if !strings.HasPrefix(page, ".TH JUISTD 8") || !strings.Contains(page, ".BR juist (1)") {
		t.Fatalf("not a juistd(8):\n%s", page)
	}
	for _, o := range optionOrder {
		if want := `\-\-` + strings.ReplaceAll(o.long, "-", `\-`); !strings.Contains(page, want) {
			t.Errorf("the page lacks --%s", o.long)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// A man page that could not be written fails the build that asked for it.
func TestAFailedManPageIsAnError(t *testing.T) {
	if _, err := parse([]string{"__manpage"}, failingWriter{}); err == nil || errors.Is(err, errHelp) {
		t.Fatalf("writing the man page failed, and parse said %v", err)
	}
}

// An ingress that cannot bind its port says why: another program holds it.
func TestAnIngressSaysWhoHoldsItsPort(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = listenIngress(uint16(ln.Addr().(*net.TCPAddr).Port))
	if err == nil || !strings.Contains(err.Error(), "another program serves port") {
		t.Fatalf("a port taken: %v", err)
	}
}

// --serve makes a service member: on a network stack, no device, serving
// what it names, @ the domain itself; beside a device or as a helper it is
// refused, and so is a NAME=ADDR that is none.
// --join, or $JUIST_JOIN, reaches the service, which --help does not show,
// and no helper takes one.
func TestJoinTakesTheInviteFromTheEnvironment(t *testing.T) {
	t.Setenv("JUIST_JOIN", "juist:secret@192.0.2.1:41642")
	o, err := parse(nil, io.Discard)
	if err != nil || o.service.Join != "juist:secret@192.0.2.1:41642" {
		t.Fatalf("from the environment: %q, %v", o.service.Join, err)
	}
	if o, err = parse([]string{"-j", "juist:given@192.0.2.2:1"}, io.Discard); err != nil || o.service.Join != "juist:given@192.0.2.2:1" {
		t.Fatalf("given: %q, %v", o.service.Join, err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out, io.Discard); err != nil || strings.Contains(out.String(), "secret") {
		t.Errorf("--help shows the invite (%v):\n%s", err, out.String())
	}
	if o, err := parse([]string{"--helper", "tls"}, io.Discard); err != nil || o.service.Join != "" {
		t.Errorf("a helper took $JUIST_JOIN: %q, %v", o.service.Join, err)
	}
	if _, err := parse([]string{"--helper", "tls", "--join", "juist:given@192.0.2.2:1"}, io.Discard); err == nil {
		t.Error("a helper took --join")
	}
}

// The Compose example runs juistd with options it takes, and joins by
// $JUIST_JOIN.
func TestTheComposeExampleRunsAServiceMember(t *testing.T) {
	b, err := os.ReadFile("../../examples/service-member/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s+command: (\[.*\])$`).FindSubmatch(b)
	var args []string
	if m == nil || json.Unmarshal(m[1], &args) != nil {
		t.Fatalf("no command in the example:\n%s", b)
	}
	o, err := parse(args, io.Discard)
	if err != nil || o.service.ServeTo["whoami"] != "whoami:80" {
		t.Fatalf("juistd %q: %+v, %v", args, o.service.ServeTo, err)
	}
	if !bytes.Contains(b, []byte("JUIST_JOIN:")) {
		t.Error("the example does not pass $JUIST_JOIN")
	}
}

func TestServeMakesAServiceMember(t *testing.T) {
	opts, err := parse([]string{"--serve", "immich=immich-server:2283", "--serve", "photos=10.0.0.5:80",
		"--serve", "@=web:80"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.service.Mesh.Netstack || opts.service.Mesh.TunName != "" || opts.service.ServeTo["immich"] != "immich-server:2283" ||
		opts.service.ServeTo["photos"] != "10.0.0.5:80" || opts.service.ServeTo[""] != "web:80" {
		t.Errorf("parsed as %+v", opts.service)
	}
	for _, args := range [][]string{
		{"--serve", "immich=immich-server:2283", "--tun", "juist0"},
		{"--serve", "immich=immich-server:2283", "--helper", "tls"},
		{"--serve", "immich"},
		{"--serve", "=127.0.0.1:80"},
		{"--helper", "egress"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%q taken", args)
		}
	}
}

// A helper and a service member plumb no device, so root starts them as
// they are, with no helper split off.
func TestOnNoDevice(t *testing.T) {
	for args, want := range map[string]bool{
		"--helper ingress": true, "--helper=tls": true, "-I tls": true, "--serve a=b:1": true, "-S=a=b:1": true,
		"--home /var/db/juist": false, "--tun juist0": false, "": false,
	} {
		if got := onNoDevice(strings.Fields(args)); got != want {
			t.Errorf("%q: %v", args, got)
		}
	}
}

// The ingress says when juistd stops answering, without --verbose.
func TestTheIngressSaysJuistdIsGone(t *testing.T) {
	var out strings.Builder
	o := ingressOptions(t.TempDir()+"/none.sock", &out)
	o.Logf("ingress: juistd does not answer")
	if !strings.Contains(out.String(), "juistd does not answer") {
		t.Errorf("the ingress said %q", out.String())
	}
}

// --http3 offers HTTP/3 for every name a service member serves, the status
// page offering it already, and is for a service member alone.
func TestHTTP3IsForAServiceMember(t *testing.T) {
	o, err := parse([]string{"--serve", "immich=immich-server:2283", "-S", "status=status-page:all", "--http3"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := o.service.ServeTo["immich"]; got != ipc.HTTP3To("immich-server:2283") {
		t.Errorf("immich goes to %q", got)
	}
	if got := o.service.ServeTo["status"]; got != "status-page:all" {
		t.Errorf("the status page goes to %q", got)
	}
	if _, err := parse([]string{"--http3"}, io.Discard); err == nil || !strings.Contains(err.Error(), "beside --serve") {
		t.Errorf("--http3 alone: %v", err)
	}
}

// --members marks every service a service member serves for members alone,
// the mark its daemon then holds, and is for a service member alone.
func TestMembersMarksAServiceMembersServices(t *testing.T) {
	o, err := parse([]string{"--serve", "photos=immich:2283", "-S", "wiki=wiki:80", "--members"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if m := o.service.ServeMembers; !m["photos"] || !m["wiki"] || len(m) != 2 {
		t.Errorf("marked %v", m)
	}
	if o, err := parse([]string{"--serve", "photos=immich:2283"}, io.Discard); err != nil || o.service.ServeMembers != nil {
		t.Errorf("unmarked: %v, %v", o.service.ServeMembers, err)
	}
	if _, err := parse([]string{"--members"}, io.Discard); err == nil || !strings.Contains(err.Error(), "beside --serve") {
		t.Errorf("--members alone: %v", err)
	}
}
