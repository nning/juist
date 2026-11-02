package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// WireGuard and Tailscale are spelled and acknowledged as their owners ask,
// and Tailscale's name never describes juist.
func TestTrademarksAreNamedAsTheirOwnersAsk(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	misspelt := regexp.MustCompile(`Wireguard|WIREGUARD|Wire[ -][Gg]uard|wireGuard`)
	// Lowercase is a path, module, URL or anchor where a character of one surrounds it.
	lower := regexp.MustCompile(`(^|[^-/.#_A-Za-z0-9{])wireguard($|[^-/._:A-Za-z0-9}])`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "build", "node_modules", "public":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".md" && ext != ".yaml" && ext != ".toml" && ext != ".html" && ext != ".xml" && ext != ".in" && ext != ".spec" && ext != ".json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for n, l := range strings.Split(string(b), "\n") {
			if misspelt.MatchString(l) || (ext == ".md" && lower.MatchString(l)) {
				t.Errorf("%s:%d spells WireGuard otherwise: %s", path, n+1, strings.TrimSpace(l))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	const notice = "registered trademarks of Jason A. Donenfeld"
	read := func(f string) string {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	for f, want := range map[string][]string{
		"README.md":                             {notice, "registered trademark of Tailscale Inc", "affiliated with nor endorsed by"},
		"website/i18n/en.toml":                  {notice, "registered trademark of Tailscale Inc"},
		"website/i18n/de.toml":                  {"eingetragene Marken von Jason A. Donenfeld", "eingetragene Marke der Tailscale Inc"},
		"website/layouts/_partials/footer.html": {`i18n "wireguard"`, `i18n "tailscale"`},
	} {
		for _, w := range want {
			if !strings.Contains(read(f), w) {
				t.Errorf("%s lacks %q", f, w)
			}
		}
	}
	// Tailscale's BSD license forbids its name in promoting what derives from its code.
	likened := regexp.MustCompile(`(?i)tailscale-like|spirit of tailscale|like tailscale|wie tailscale`)
	for _, f := range []string{"README.md", "packaging/deb/control.in", "packaging/rpm/juist.spec", "packaging/freebsd/manifest.json",
		"website/content/en/_index.md", "website/content/de/_index.md", "website/data/features.yaml"} {
		if likened.MatchString(read(f)) {
			t.Errorf("%s likens juist to Tailscale", f)
		}
	}
	var out syncBuffer
	if err := newCLI(t).app(&out, "").main([]string{"__manpage"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), notice) {
		t.Error("juist(1) names WireGuard without its trademark notice")
	}
}
