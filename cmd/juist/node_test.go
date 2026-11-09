package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// refusingDaemon is a juistd at a socket that calls this user its operator
// in its status, holding one share, and refuses every other call as from one
// who is not: an operator replaced between two calls.
func refusingDaemon(t *testing.T) (string, *ipc.Status) {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	self := types.Identity{1}
	st := &ipc.Status{InNetwork: true, CanOperate: true, Self: self,
		Derived: ipc.Derived{NetworkName: "home", Shares: []ipc.Share{{Path: "x", What: "/srv/x"}},
			Devices: []ipc.Device{{Identity: self, Roles: []types.Role{types.RoleIngress}}}}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := ipc.ReadMessage(c, 1<<20)
			req, derr := ipc.DecodeRequest(b)
			if err == nil && derr == nil {
				resp := ipc.Response{Err: ipc.ErrNotOperator}
				if req.Command == ipc.CmdStatus {
					resp = ipc.Response{Status: st}
				}
				_ = ipc.WriteMessage(c, resp, 1<<20)
			}
			c.Close()
		}
	}()
	return sock, st
}

// An instance's juistd that did not answer is no daemon to ask: a command
// says it is not running.
func TestAnInstanceThatDidNotAnswerIsNoDaemon(t *testing.T) {
	t.Parallel()
	a := newCLI(t).app(&syncBuffer{}, "")
	a.node, a.instance = &daemonNode{sock: "/nonexistent"}, &hostInstance{n: 1}
	if d := daemonOf(a.node); d != nil || liveStatus(a.node) != nil {
		t.Fatalf("a juistd without a status: %v", d)
	}
	if _, err := a.daemon(); err == nil || !strings.Contains(err.Error(), "juistd not running\nhint: "+startCmd(1)) {
		t.Errorf("a.daemon: %v", err)
	}
	if err := a.requireOperator(); err != nil {
		t.Errorf("requireOperator: %v", err)
	}
}

// A command for juistd, run where none is installed, says how to start one
// there, as juist health does, and not the packaged service.
func TestADaemonCommandSaysHowToStartJuistdHere(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	health := c.mustRun("health")
	_, err := c.run("exit")
	if err == nil || strings.Contains(err.Error(), startCmd(0)) || !strings.Contains(health, "hint: ") ||
		!strings.Contains(err.Error(), strings.TrimSpace(health[strings.Index(health, "hint: "):])) {
		t.Errorf("juist exit: %v; juist health:\n%s", err, health)
	}
}

// What an ingress, a terminator and a share's end ask juistd for is refused
// with the way to become the operator, as every other call is.
func TestTheCallsOfIngressTerminatorAndShareSayHowToOperate(t *testing.T) {
	t.Parallel()
	want := "juist set --operator=" + currentUser()
	sock, st := refusingDaemon(t)
	script := filepath.Join(t.TempDir(), "serve.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func(a *app) error{
		"ingress":    func(a *app) error { _, err := a.published(); return err },
		"terminator": func(a *app) error { return a.startTerminator("") },
		"share stop": func(a *app) error { return a.stopShare("") },
	} {
		a := newCLI(t).app(&syncBuffer{}, "")
		a.host = &hostLayout{serveScript: script, terminatorWait: time.Second}
		a.asRoot = func() bool { return true }
		a.node = &daemonNode{sock: sock, st: st}
		if err := call(a); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want the hint %q", name, err, want)
		}
	}
}

// A device on HTTPS alone in no network is asked for a link, which it can
// use, by every command that needs a network, not for a code.
func TestNoNetworkAsksHTTPSAloneForALink(t *testing.T) {
	t.Parallel()
	h, err := openHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	httpsAlone := &ipc.Status{CanOperate: true, Derived: ipc.Derived{HTTPS: &ipc.HTTPS{Only: true}}}
	for _, c := range []struct {
		what  string
		err   func() error
		wants string
	}{
		{"a daemon", func() error { _, err := (&daemonNode{st: &ipc.Status{}}).records(); return err }, "juist join CODE"},
		{"a daemon on HTTPS alone", func() error { _, err := (&daemonNode{st: httpsAlone}).records(); return err }, "juist join LINK"},
		{"a command for juistd on HTTPS alone", func() error {
			a := newCLI(t).app(&syncBuffer{}, "")
			a.node = &daemonNode{sock: "/nonexistent", st: httpsAlone}
			_, err := a.daemon()
			return err
		}, "juist join LINK"},
		{"a home", func() error { _, err := (&localNode{h: h}).chain(); return err }, "juist join CODE"},
		{"a home on HTTPS alone", func() error {
			if err := os.WriteFile(h.join(statedir.HTTPSOnlyFile), []byte("\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := (&localNode{h: h}).chain()
			return err
		}, "juist join LINK"},
		{"a home's log on HTTPS alone", func() error { _, err := (&localNode{h: h}).log(); return err }, "juist join LINK"},
	} {
		err := c.err()
		if !errors.Is(err, errNoNetwork) || !strings.Contains(fmt.Sprint(err), c.wants) {
			t.Errorf("%s in no network says %v, want %q", c.what, err, c.wants)
		}
	}
}
