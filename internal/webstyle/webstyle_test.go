package webstyle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The pages look as the website does: their colours are design/tokens.json's
// and their wordmark design/logo's.
func TestThePagesLookAsTheWebsiteDoes(t *testing.T) {
	var tokens struct {
		Color  map[string]map[string]string
		Status map[string]map[string]string
	}
	b, err := os.ReadFile("../../design/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &tokens); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"bg": "background", "panel": "surface", "panel-2": "surfaceVariant", "line": "outlineVariant",
		"line-2": "outline", "text": "onBackground", "text-2": "onSurfaceVariant", "muted": "outline", "accent": "primary",
		"accent-ink": "onPrimary", "sand": "secondary", "red": "error"}
	blocks := strings.SplitN(baseHTML, "@media (prefers-color-scheme: light)", 2)
	for i, theme := range []string{"night", "day"} {
		for v, role := range vars {
			if want := "--" + v + ": " + tokens.Color[theme][role] + ";"; !strings.Contains(blocks[i], want) {
				t.Errorf("%s: the style lacks %s", theme, want)
			}
		}
		for v, c := range tokens.Status[theme] {
			if want := "--" + v + ": " + c + ";"; !strings.Contains(blocks[i], want) {
				t.Errorf("%s: the style lacks %s", theme, want)
			}
		}
	}
	svg, err := os.ReadFile("../../design/logo/wordmark.svg")
	if err != nil {
		t.Fatal(err)
	}
	mark := strings.Replace(strings.TrimSpace(regexp.MustCompile(`(?s)<!--.*?-->\s*`).ReplaceAllString(string(svg), "")),
		"<svg ", `<svg aria-hidden="true" `, 1)
	if !strings.Contains(baseHTML, mark) {
		t.Error("the wordmark is not design/logo/wordmark.svg")
	}
	svg, err = os.ReadFile("../../design/logo/icon.svg")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?s)<!--.*?-->\s*`).ReplaceAllString(string(svg), "") != string(icon) {
		t.Error("the icon is not design/logo/icon.svg")
	}
}

// ibmFonts are the fonts as IBM/plex publishes them, at 763c36e: the OFL
// reserves the name Plex, so a font subset or otherwise changed here would
// have to be renamed.
var ibmFonts = map[string]string{
	"internal/webstyle/fonts/ibm-plex-sans-400-latin1.woff2": "b5ad7bd39f996144915f0ad9849a90183b27d8c28ad97ed98af5b1bebc51f6b1",
	"internal/webstyle/fonts/ibm-plex-sans-600-latin1.woff2": "fff0ab3a88b0b4aa0b693e4f0201359a15183b08e3fa5696d1918d8f0ade8ad5",
	"internal/webstyle/fonts/ibm-plex-mono-400-latin1.woff2": "e8993d946649b9d01abb1ed06d574b19d8ea3e66b5c3948602db335c44c18e56",
	"website/static/fonts/ibm-plex-sans-var-latin1.woff2":    "a18d94ea83c93f0a465d0976d8bc8ecbb031225dbaf76fd201d4e724a972034f",
	"website/static/fonts/ibm-plex-sans-var-latin2.woff2":    "53de8a1640c42f45de9483f816dfc71dad3e87c24fbd115f4c312b8eddf39545",
	"website/static/fonts/ibm-plex-mono-var-latin1.woff2":    "632cb6cee5e90d89bd4354ff362bcffcef1384c19b603ddd2830561716e1f440",
	"website/static/fonts/ibm-plex-mono-var-latin2.woff2":    "a00cbadcf0f6cb76ef82593ac4b7c8810a8aea61b8bf5744aa8e9b6fc7e0ea03",
}

// Every font the pages and the website load is IBM's, unchanged.
func TestTheFontsAreIBMs(t *testing.T) {
	var shipped []string
	for _, dir := range []string{"internal/webstyle/fonts", "website/static/fonts"} {
		names, err := filepath.Glob(filepath.Join("../..", dir, "*.woff2"))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			shipped = append(shipped, filepath.Join(dir, filepath.Base(n)))
		}
	}
	if len(shipped) != len(ibmFonts) {
		t.Errorf("fonts shipped: %q", shipped)
	}
	for _, f := range shipped {
		b, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != ibmFonts[f] {
			t.Errorf("%s is not IBM's", f)
		}
	}
	for _, file := range FontFiles {
		if _, ok := ibmFonts[filepath.Join("internal/webstyle", file)]; !ok {
			t.Errorf("the pages load %s, which is not IBM's", file)
		}
	}
}
