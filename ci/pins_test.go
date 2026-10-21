//go:build linux

package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// workflowRuns are the targets of the workflow that run a step of make check
// whose target it does not name.
var workflowRuns = map[string]string{"build-test": "cross", "test-race": "cover"}

// GitHub's workflow runs every step make check gates on.
func TestTheWorkflowRunsWhatMakeCheckDoes(t *testing.T) {
	out, err := exec.Command("make", "-s", "--no-print-directory", "-C", "..", "print-CHECK_STEPS").Output()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+- run: make ([\w -]+)$`).FindAllStringSubmatch(string(b), -1) {
		for _, target := range strings.Fields(m[1]) {
			runs[target] = true
		}
	}
	steps := strings.Fields(string(out))
	if len(steps) == 0 {
		t.Fatal("make check has no steps")
	}
	for _, s := range steps {
		if !runs[s] && !runs[workflowRuns[s]] {
			t.Errorf("make check runs %s, which the workflow does not", s)
		}
	}
}

// Every place that names the Go release names the same.
func TestOneGoReleaseIsPinned(t *testing.T) {
	pins := map[string]*regexp.Regexp{
		"../Makefile":                      regexp.MustCompile(`(?m)^export GOTOOLCHAIN \?= go(\S+)$`),
		"../website/Makefile":              regexp.MustCompile(`(?m)^export GOTOOLCHAIN \?= go(\S+)$`),
		"../go.mod":                        regexp.MustCompile(`(?m)^go (\S+)$`),
		"../tools/go.mod":                  regexp.MustCompile(`(?m)^go (\S+)$`),
		"../website/go.mod":                regexp.MustCompile(`(?m)^go (\S+)$`),
		"../.github/workflows/ci.yml":      regexp.MustCompile(`(?m)^  GO_VERSION: '(\S+)'$`),
		"../.github/workflows/interop.yml": regexp.MustCompile(`(?m)^  GO_VERSION: '(\S+)'$`),
	}
	want := ""
	for file, re := range pins {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(b)
		if m == nil {
			t.Errorf("%s names no Go release where it did", file)
			continue
		}
		if want == "" {
			want = string(m[1])
		}
		if string(m[1]) != want {
			t.Errorf("%s names Go %s, another file %s", file, m[1], want)
		}
	}
}
