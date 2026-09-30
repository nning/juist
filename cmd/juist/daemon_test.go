package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
)

// TestTheDaemonHoldsTheDeviceAndThePersonHoldsTheKeys walks the product loop
// the way a packaged install runs it, and checks the split it exists for:
// admin keys never land where the daemon can read them.
func TestTheDaemonHoldsTheDeviceAndThePersonHoldsTheKeys(t *testing.T) {
	t.Parallel()
	laptop := newDaemonDevice(t, nil)
	mustContain(t, laptop.mustRun("status"), "no network", "juist join CODE")

	mustContain(t, laptop.mustRun("create", "home", "--device", "laptop"),
		`created network "home"`, "laptop", "198.18.4.1")
	if _, err := os.Stat(filepath.Join(laptop.state, adminsDir)); !os.IsNotExist(err) {
		t.Fatal("an admin key was written into the daemon's state directory")
	}
	if keys, err := laptop.home2().adminKeys(); err != nil || len(keys) != 1 {
		t.Fatalf("the admin key is not in the person's keystore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(laptop.cli.home, nodeKeysFile)); !os.IsNotExist(err) {
		t.Fatal("device keys were written into the person's keystore")
	}
	mustContain(t, laptop.mustRun("status"), "home · ", "laptop", "198.18.4.1")

	phone := newDaemonDevice(t, nil)
	inv := laptop.start("invite", "--no-lan", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	out := phone.mustRun("join", link, "--name", "phone")
	mustContain(t, out, "connected to", `joined "home" as phone`,
		"198.18.4.2")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	mustContain(t, phone.mustRun("status"), "home · ", "phone")
	mustContain(t, laptop.mustRun("devices"), "laptop (this device)", "phone")
	mustContain(t, phone.mustRun("devices"), "phone (this device)", "laptop")

	laptop.mustRun("remove", "phone", "--yes")
	if strings.Contains(laptop.mustRun("devices"), "phone") {
		t.Fatal("the removed device is still listed")
	}
}

func TestSetOperator(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if me.Uid == "0" {
		t.Skip("root needs no appointment")
	}
	mustContain(t, d.mustRun("set", "--operator", me.Username), "operator "+me.Username)
	resp, err := ipc.Call(d.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil || resp.Status.Operator != me.Username {
		t.Fatalf("the daemon's operator is %q, %v", resp.Status.Operator, err)
	}
	mustContain(t, d.mustRun("set", "--operator="), "operator cleared")
	if _, err := d.run("set", "--operator", "no-such-user-here"); err == nil {
		t.Fatal("appointed a user that does not exist")
	}
	if _, err := d.run("set"); err == nil {
		t.Fatal("set with nothing to set succeeded")
	}
}

// TestANonOperatorIsToldHowToBecomeOne: with no terminal to ask on, the
// answer is instructions rather than a prompt nobody can answer.
func TestANonOperatorIsToldHowToBecomeOne(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
	err := a.requireOperator()
	want := asRoot("juist set --operator=" + currentUser())
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want %q", err, want)
	}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home"}})
	mustContain(t, out.String(), "read-only", "juist set --operator=")
}
