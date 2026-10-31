package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// olderNetwork is a network founded by laptop's juistd a schema below this
// build's, once juistd says which schema laptop implements.
func olderNetwork(t *testing.T) *daemonDevice {
	t.Helper()
	laptop := newDaemonDevice(t, nil)
	laptop.genesisSchema = types.CurrentSchema - 1
	laptop.mustRun("create", "home", "--device", "laptop")
	self := statusOfDaemon(t, laptop).Self
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		st := statusOfDaemon(t, laptop)
		if slices.Contains(st.Builds, ipc.Build{Identity: self, Schema: types.CurrentSchema}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("juistd says no build of its own device: %v", st.Builds)
		}
	}
	if got := daemonLog(t, laptop).State().Schema(); got != types.CurrentSchema-1 {
		t.Fatalf("the network starts at %v", got)
	}
	return laptop
}

func TestLogUpgradeWhenEveryDeviceIsReady(t *testing.T) {
	t.Parallel()
	laptop := olderNetwork(t)
	mustContain(t, laptop.mustRun("health"), "every device implements "+types.CurrentSchema.String()+": juist log upgrade")
	mustContain(t, laptop.mustRun("log", "upgrade", "--when-ready"), "upgraded to "+types.CurrentSchema.String())
	if got := daemonLog(t, laptop).State().Schema(); got != types.CurrentSchema {
		t.Fatalf("the network is at %v", got)
	}
	if out := laptop.mustRun("log", "upgrade", "--when-ready"); out != "" {
		t.Fatalf("--when-ready said, at the current schema: %q", out)
	}
}

// A device juistd has heard nothing of holds the upgrade back as one that
// announced an older schema does.
func TestLogUpgradeWaitsForEveryDevice(t *testing.T) {
	t.Parallel()
	laptop := olderNetwork(t)
	inv := laptop.start("invite", "--no-lan", "--port", "0", "--yes")
	newCLI(t).mustRun("join", inv.waitFor(t, linkRE)[1], "--name", "phone")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	older := types.CurrentSchema - 1

	_, err := laptop.run("log", "upgrade", "--yes")
	if err == nil || !strings.Contains(err.Error(), "not every device implements "+types.CurrentSchema.String()+": phone (-)") ||
		!strings.Contains(err.Error(), "juist log upgrade --force") {
		t.Fatalf("upgrade with phone unheard: %v", err)
	}
	if out := laptop.mustRun("log", "upgrade", "--when-ready"); out != "" {
		t.Fatalf("--when-ready said, while phone lags: %q", out)
	}
	if got := daemonLog(t, laptop).State().Schema(); got != older {
		t.Fatalf("raised to %v while phone lags", got)
	}
	if out := laptop.mustRun("health"); strings.Contains(out, "juist log upgrade") {
		t.Fatalf("health suggests the upgrade while phone lags:\n%s", out)
	}
	if _, err := laptop.run("log", "upgrade", "--force", "--when-ready"); err == nil {
		t.Fatal("--force and --when-ready were taken together")
	}
	mustContain(t, laptop.mustRun("log", "upgrade", "--force", "--yes"), "upgraded to "+types.CurrentSchema.String())
}

// Where this keystore's vote is not enough, --when-ready proposes nothing, so
// that a timer leaves no change behind on each run.
func TestLogUpgradeWhenReadyProposesNothing(t *testing.T) {
	t.Parallel()
	laptop := olderNetwork(t)
	_, bob := adminKeyOf(t, "bob")
	laptop.mustRun("admins", "add", "bob", bob)
	laptop.mustRun("admins", "quorum", "2", "--yes")
	_, err := laptop.run("log", "upgrade", "--when-ready")
	if err == nil || !strings.Contains(err.Error(), "needs other admins' votes") {
		t.Fatalf("upgrade needing bob's vote: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir(t), "schema-upgrade.rec")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a proposal was left: %v", err)
	}
}

func TestUnreadyReadsEveryMembersBuild(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, c, "phone")
	state := openLog(t, c).State()
	ids := map[string]types.Identity{}
	for _, n := range state.Nodes() {
		ids[n.Name] = n.Identity
	}
	laptop, phone := ids["laptop"], ids["phone"]
	cur := types.CurrentSchema
	for _, tc := range []struct {
		name string
		st   ipc.Status
		want []string
	}{
		{"both ready", ipc.Status{Derived: ipc.Derived{Builds: []ipc.Build{{Identity: laptop, Schema: cur}, {Identity: phone, Schema: cur}}}}, nil},
		{"phone older", ipc.Status{Derived: ipc.Derived{Builds: []ipc.Build{{Identity: laptop, Schema: cur}, {Identity: phone, Schema: cur - 1}}}},
			[]string{"phone (" + strconv.Itoa(int(cur-1)) + ")"}},
		{"phone unheard", ipc.Status{Derived: ipc.Derived{Builds: []ipc.Build{{Identity: laptop, Schema: cur}}}}, []string{"phone (-)"}},
		// The access policy keeps phone from Devices, not from Builds.
		{"phone apart", ipc.Status{Derived: ipc.Derived{Devices: []ipc.Device{{Identity: laptop, Build: cur}},
			Builds: []ipc.Build{{Identity: laptop, Schema: cur}, {Identity: phone, Schema: cur}}}}, nil},
		// A juistd from before Builds says it in Devices alone.
		{"an older juistd", ipc.Status{Derived: ipc.Derived{Devices: []ipc.Device{{Identity: laptop, Build: cur},
			{Identity: phone, Build: cur}}}}, nil},
	} {
		if got := unready(state, &tc.st, cur); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
