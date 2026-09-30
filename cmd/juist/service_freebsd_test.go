package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rcTools replaces rc's tools with fail, which answers each command line.
func rcTools(t *testing.T, fail func(line string) error, out string) *[]string {
	t.Helper()
	var ran []string
	run, output := runCmd, rcOutput
	t.Cleanup(func() { runCmd, rcOutput = run, output })
	// Run as root, each by its path, not by whatever PATH finds first.
	abs := func(name string) {
		if !filepath.IsAbs(name) {
			t.Errorf("%s is run by PATH", name)
		}
	}
	runCmd = func(_ context.Context, name string, args ...string) error {
		abs(name)
		line := strings.Join(append([]string{filepath.Base(name)}, args...), " ")
		ran = append(ran, line)
		return fail(line)
	}
	rcOutput = func(name string, _ ...string) (string, error) { abs(name); return out, nil }
	return &ran
}

// An instance that does not run is removed from rc.conf all the same, and
// one that will not stop is said to.
func TestStoppingAnInstanceDisablesIt(t *testing.T) {
	ran := rcTools(t, func(line string) error {
		if strings.HasPrefix(line, "service juistd stop") || strings.HasPrefix(line, "service juistd status") {
			return errors.New("juistd_juist3 is not running?")
		}
		return nil
	}, "")
	if err := stopRC(context.Background(), 3); err != nil {
		t.Errorf("stopping one not running: %v", err)
	}
	if !slices.Contains(*ran, "sysrc juistd_instances-=juist3") {
		t.Errorf("ran %q", *ran)
	}
	rcTools(t, func(line string) error {
		if strings.HasPrefix(line, "service juistd stop") {
			return errors.New("stuck")
		}
		return nil
	}, "")
	if err := stopRC(context.Background(), 3); err == nil {
		t.Error("one that will not stop was taken for stopped")
	}
}

// rc.conf's words for enabled are rc.subr's, and an instance is enabled
// where juistd_instances names it.
func TestAnInstanceIsEnabledByRCConf(t *testing.T) {
	ran := rcTools(t, func(string) error { return nil }, "juist1 juist3\n")
	if !enabledRC(0) || !slices.Contains(*ran, "service juistd enabled") {
		t.Errorf("the default: ran %q", *ran)
	}
	if !enabledRC(3) || enabledRC(2) {
		t.Error("juistd_instances misread")
	}
	rcTools(t, func(string) error { return errors.New("no") }, "")
	if enabledRC(0) {
		t.Error("disabled, the default reads enabled")
	}
}
