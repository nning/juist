package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The handbook's command reference is what juist's own help says now on
// Linux, in either language: make commands-page writes it again.
func TestTheCommandReferenceIsCurrent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the reference is Linux's help, which says how the host is set up there")
	}
	t.Parallel()
	var out syncBuffer
	a := newCLI(t).app(&out, "")
	if err := a.main([]string{"__commands"}); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"en", "de"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "website", "content", lang, "docs", "commands.md"))
		if err != nil {
			t.Fatal(err)
		}
		_, generated, ok := strings.Cut(string(b), "\n## ")
		if !ok || "## "+generated != out.String() {
			t.Errorf("website/content/%s/docs/commands.md is not what juist's help says; run make commands-page", lang)
		}
	}
}
