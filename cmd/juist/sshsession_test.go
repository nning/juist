package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Under sudo, which drops SSH_CONNECTION, the session is found in an
// ancestor's environment, past a command name that holds parentheses.
func TestTheSSHSessionIsFoundPastSudo(t *testing.T) {
	c := newCLI(t)
	parent := os.Getppid()
	c.system = map[string]string{
		fmt.Sprintf("/proc/%d/environ", parent): "HOME=/root\x00USER=root\x00",
		fmt.Sprintf("/proc/%d/stat", parent):    fmt.Sprintf("%d (sudo (x) y) S 4242 1 1", parent),
		"/proc/4242/environ":                    "TERM=xterm\x00SSH_CONNECTION=2001:db8::7 50000 2001:db8::1 22\x00",
	}
	a := c.app(&syncBuffer{}, "")
	client, ok := a.sshClient()
	if !ok || client.String() != "2001:db8::7" {
		t.Fatalf("the session's client is %v, %v", client, ok)
	}
	c.system = nil
	if _, ok := c.app(&syncBuffer{}, "").sshClient(); ok {
		t.Error("a session found outside ssh")
	}
	// Under another user's sshd, whose environment cannot be read, the
	// session is one all the same, its client unknown, and taken to be cut.
	c.system = map[string]string{
		fmt.Sprintf("/proc/%d/stat", parent): fmt.Sprintf("%d (sudo) S 4242 1 1", parent),
		"/proc/4242/stat":                    "4242 (sshd-session) S 1 1 1",
	}
	a = c.app(&syncBuffer{}, "")
	if client, ok := a.sshClient(); !ok || client.IsValid() {
		t.Errorf("under sshd: %v, %v", client, ok)
	}
	if why, cut := a.cutsSSH(nil); !cut || !strings.Contains(why, "cannot see") {
		t.Errorf("a session of an unknown client is not cut: %q", why)
	}
}
