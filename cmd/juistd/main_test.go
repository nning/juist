package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/rendezvous"
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
	if n := strings.Count(got, "\n"); n > 25 {
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

// The start report says what happened on stdout, and what needs attention as
// warnings and hints on stderr.
func TestTheStartReportSpeaksLikeTheCLI(t *testing.T) {
	for _, tc := range []struct {
		st        ipc.Status
		tun       string
		out, errs []string
	}{
		{ipc.Status{Derived: ipc.Derived{SelfName: "laptop"}}, "juist0", []string{"juistd: laptop ("}, []string{"hint: juist init, or juist join CODE"}},
		{ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", NotMember: true}}, "juist0",
			[]string{`network "home"`}, []string{"warning: not a member", "hint: rejoin with a new invite"}},
		{ipc.Status{InNetwork: true, SchemaAlarm: "schema 9", Addrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}, ListenPort: 41643, Derived: ipc.Derived{NetworkName: "home", Alarm: "fork"}}, "",
			[]string{"overlay     198.18.0.1", "device      none", "udp/41643"}, []string{"warning: schema 9", "warning: fork"}},
		{ipc.Status{InNetwork: true, StartError: "open /dev/net/tun: permission denied", Derived: ipc.Derived{NetworkName: "home"}}, "juist0",
			nil, []string{"warning: tunnels cannot start yet, retrying: open", `hint: creating "juist0" needs CAP_NET_ADMIN`}},
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
